"""Autonomous UI Explorer and State Crawler for Android DAST.

Uses ADB and Android UIAutomator to autonomously navigate the target application:
1. Dumps UI layout hierarchies to discover on-screen interactive components
2. Automatically dismisses system permission dialogues and consent prompts
3. Contextually populates text and credential input fields
4. Clicks navigation and action buttons to maximize dynamic execution coverage
"""

from __future__ import annotations

import asyncio
import logging
import re
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

    async def dump_ui_hierarchy(self, serial: str) -> str:
        """Dump the current foreground window UIAutomator hierarchy XML."""
        # Dump to device temp
        await self.adb._exec_cmd(
            ["-s", serial, "shell", "uiautomator dump /data/local/tmp/uidump.xml"],
            timeout=4.0,
        )
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", "cat /data/local/tmp/uidump.xml"],
            timeout=4.0,
        )
        if code == 0 and stdout:
            return stdout.decode("utf-8", errors="replace").strip()
        return ""

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

    async def handle_system_dialogs(self, serial: str, elements: list[dict[str, Any]]) -> bool:
        """Automatically detect and dismiss permissions or consent popups."""
        for el in elements:
            label = f"{el['text']} {el['content_desc']}".strip()
            if _SYSTEM_DIALOG_TERMS.search(label):
                await self.tap_element(serial, el["center"])
                await asyncio.sleep(0.8)
                return True
        return False

    async def fill_input_fields(self, serial: str, elements: list[dict[str, Any]]) -> int:
        """Find EditText inputs and enter contextual test payloads."""
        filled = 0
        for el in elements:
            if "EditText" in el["class"]:
                label = f"{el['resource_id']} {el['text']} {el['content_desc']}".lower()
                payload = "mobileag_test"
                if "email" in label:
                    payload = "test.audit@example.com"
                elif "pass" in label:
                    payload = "AuditPass123!"
                elif "search" in label or "query" in label:
                    payload = "security_audit_query"

                await self.tap_element(serial, el["center"])
                await asyncio.sleep(0.5)
                await self.input_text(serial, payload)
                await asyncio.sleep(0.5)
                filled += 1
        return filled

    async def click_action_buttons(self, serial: str, elements: list[dict[str, Any]], max_clicks: int = 2) -> int:
        """Click primary action buttons to advance user flow."""
        clicked = 0
        for el in elements:
            if clicked >= max_clicks:
                break
            if not el["clickable"]:
                continue

            label = f"{el['text']} {el['content_desc']}".strip()
            if _ACTION_BUTTON_TERMS.search(label):
                await self.tap_element(serial, el["center"])
                await asyncio.sleep(1.0)
                clicked += 1

        return clicked

    async def crawl_app(
        self,
        serial: str,
        package_name: str,
        max_steps: int = 5,
        step_delay: float = 1.0,
    ) -> dict[str, Any]:
        """Autonomously crawl app views, dismiss dialogs, fill inputs, and click buttons."""
        dialogs_dismissed = 0
        inputs_filled = 0
        buttons_clicked = 0
        screens_explored = 0

        for step in range(max_steps):
            xml = await self.dump_ui_hierarchy(serial)
            if not xml:
                break

            elements = self.parse_ui_elements(xml)
            if not elements:
                break

            screens_explored += 1

            # 1. First priority: dismiss blocking dialogs
            dismissed = await self.handle_system_dialogs(serial, elements)
            if dismissed:
                dialogs_dismissed += 1
                continue

            # 2. Second priority: fill input fields if present
            filled = await self.fill_input_fields(serial, elements)
            inputs_filled += filled

            # 3. Third priority: click forward action buttons
            clicked = await self.click_action_buttons(serial, elements, max_clicks=1)
            buttons_clicked += clicked

            await asyncio.sleep(step_delay)

        return {
            "package_name": package_name,
            "device_serial": serial,
            "screens_explored": screens_explored,
            "dialogs_dismissed": dialogs_dismissed,
            "inputs_filled": inputs_filled,
            "buttons_clicked": buttons_clicked,
            "status": "completed",
        }
