"""Read-only, package-bound UI observation.

Never accepts permission/consent dialogs, fills credentials or submits forms.
Planned actions are data for explicit operator review, not automatic commands.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager

logger = logging.getLogger(__name__)

# Standard permission and consent dialog dismiss terms
_SYSTEM_DIALOG_TERMS = re.compile(
    r"(?i)\b(allow|grant|while using the app|only this time|accept|continue|agree|ok|got it|dismiss)\b"
)
_ACTION_BUTTON_TERMS = re.compile(
    r"(?i)\b(next|submit|login|sign in|search|explore|enter|start|proceed|open)\b"
)
_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


class UICrawler:
    """Autonomous UI crawler driving on-device state exploration via UIAutomator."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    async def dump_ui_hierarchy(self, serial: str, guard=None) -> str:
        """Dump the current foreground window UIAutomator hierarchy XML."""
        # Do not overwrite a user's predictable uidump.xml or read stale output.
        path='/data/local/tmp/mobileag-observe-'+uuid.uuid4().hex+'.xml'
        try:
            if guard: guard()
            code, _, _ = await self.adb._exec_cmd(["-s",serial,"shell","uiautomator","dump",path],timeout=6,output_limit=16384)
            if guard: guard()
            if code:return ""
            code, stdout, _ = await self.adb._exec_cmd(["-s",serial,"shell","cat",path],timeout=4,output_limit=1024*1024)
            if guard: guard()
            if code == 0 and 0 < len(stdout) <= 1024*1024:
                return stdout.decode("utf-8",errors="replace").strip()
            return ""
        finally:
            await self.adb._exec_cmd(["-s",serial,"shell","rm","-f",path],timeout=3,output_limit=16384)

    def parse_ui_elements(self, xml_content: str) -> list[dict[str, Any]]:
        """Parse UIAutomator XML hierarchy into structured interactable element objects."""
        elements: list[dict[str, Any]] = []
        if not xml_content or not xml_content.startswith("<?xml") and "<hierarchy" not in xml_content:
            return elements

        try:
            root = ET.fromstring(xml_content)
            for node in root.iter("node"):
                has_children = len(list(node)) > 0
                clickable = node.attrib.get("clickable", "false") == "true"
                if has_children and not clickable:
                    continue

                res_id = node.attrib.get("resource-id", "")
                cls_name = node.attrib.get("class", "")
                text = node.attrib.get("text", "")
                desc = node.attrib.get("content-desc", "")
                bounds_str = node.attrib.get("bounds", "")

                bounds_match = _BOUNDS_RE.match(bounds_str)
                if bounds_match:
                    x1, y1, x2, y2 = map(int, bounds_match.groups())
                    cx = (x1 + x2) // 2
                    cy = (y1 + y2) // 2
                else:
                    cx, cy = 0, 0

                elements.append({
                    "package": node.attrib.get("package", ""),
                    "resource_id": res_id,
                    "class": cls_name,
                    "text": text,
                    "content_desc": desc,
                    "clickable": clickable,
                    "center": (cx, cy),
                })
        except Exception as e:
            logger.debug(f"Failed to parse UIAutomator XML: {e}")

        return elements

    async def tap_element(self, serial: str, center: tuple[int, int]) -> None:
        """Send tap input to element center coordinates."""
        cx, cy = center
        if cx > 0 and cy > 0:
            await self.adb._exec_cmd(["-s", serial, "shell", "input", "tap", str(cx), str(cy)], timeout=3.0)

    async def input_text(self, serial: str, text: str) -> None:
        """Send text input via ADB shell input."""
        # Sanitize spaces for adb input text
        escaped = text.replace(" ", "%s")
        await self.adb._exec_cmd(["-s", serial, "shell", "input", "text", escaped], timeout=3.0)

    async def handle_system_dialogs(self, serial, elements):
        """Consent belongs to the operator; never automatically accept it."""
        return False

    async def fill_input_fields(self, serial, elements):
        """No automatic account/credential input in read-only observation mode."""
        return 0

    async def click_action_buttons(self, serial, elements, max_clicks=2):
        return 0

    async def crawl_app(self, serial: str, package_name: str, max_steps: int = 5,
                        step_delay: float = 1.0, guard=None) -> dict[str, Any]:
        if not 1 <= max_steps <= 20:
            raise ValueError("UI observation steps must be between 1 and 20")
        base = {"package_name": package_name, "device_serial": serial,
                "screens_explored": 0, "dialogs_dismissed": 0, "inputs_filled": 0,
                "buttons_clicked": 0, "mode": "observe_only", "planned_actions": []}
        xml = await self.dump_ui_hierarchy(serial, guard=guard)
        elements = self.parse_ui_elements(xml)
        if not elements:
            return {**base, "status": "inconclusive", "reason": "Foreground UI is unavailable"}
        # Missing package identity is not safe enough to assume the intended app.
        if any(el.get("package") != package_name for el in elements):
            return {**base, "status": "blocked", "reason": "Foreground is outside the intended package or includes a system dialog"}
        from mobileag.security.privacy import redact
        plans = [{"label": redact(el["text"] or el["content_desc"]),
                  "resource_id": el["resource_id"], "requires_explicit_review": True}
                 for el in elements if el["clickable"]][:50]
        return {**base, "status": "observed", "screens_explored": 1, "planned_actions": plans,
                "reason": "Read-only snapshot; no taps, consent, text input or transactions were performed"}

    def get_smart_crawler(self, test_user: str | None = None, test_pass: str | None = None,
                          allow_form_submit: bool = False,
                          allow_exploratory_clicks: bool = False,
                          allow_test_credential_entry: bool = False,
                          allow_back_navigation: bool = False) -> Any:
        """Instantiate a crawler with separate explicit opt-ins for mutations."""
        from mobileag.dast.smart_crawler import SmartUICrawler
        return SmartUICrawler(test_user=test_user, test_pass=test_pass,
                              allow_form_submit=allow_form_submit,
                              allow_exploratory_clicks=allow_exploratory_clicks,
                              allow_test_credential_entry=allow_test_credential_entry,
                              allow_back_navigation=allow_back_navigation)

