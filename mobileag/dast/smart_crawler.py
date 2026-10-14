"""Autonomous Dynamic UI Crawler with Semantic Element Recognition.

Parses active screen hierarchy (uiautomator dump XML), semantically classifies inputs
(credentials, searches, permissions), dismisses OS security prompts, and maintains
screen state hashes to prevent navigation loops.
"""
from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class UIElement:
    resource_id: str
    class_name: str
    text: str
    content_desc: str
    bounds: str
    is_clickable: bool = False
    is_editable: bool = False
    semantic_role: str = "generic"  # username, password, permission_allow, search, button


@dataclass
class CrawlerDecision:
    action: str  # CLICK, TYPE_TEXT, DISMISS_DIALOG, BACK, WAIT
    target_bounds: Optional[str] = None
    input_text: Optional[str] = None
    explanation: str = ""


class SmartUICrawler:
    """Intelligently navigates Android application UIs based on semantic element detection."""

    def __init__(self, test_user: Optional[str] = None, test_pass: Optional[str] = None,
                 allow_form_submit: bool = False, allow_exploratory_clicks: bool = False):
        # Credentials are supplied only by the authorized operator. Never ship
        # reusable-looking defaults that could be entered into an unintended app.
        self.test_user = test_user
        self.test_pass = test_pass
        self.allow_form_submit = allow_form_submit
        self.allow_exploratory_clicks = allow_exploratory_clicks
        self.visited_states: Dict[str, int] = {}  # state_hash -> visit_count

    def parse_hierarchy_xml(self, xml_content: str) -> List[UIElement]:
        """Parse uiautomator dump XML into structured UIElements."""
        elements: List[UIElement] = []
        if not xml_content or "<hierarchy" not in xml_content:
            return elements

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return elements

        for node in root.iter("node"):
            r_id = node.get("resource-id", "")
            cls = node.get("class", "")
            text = node.get("text", "")
            desc = node.get("content-desc", "")
            bounds = node.get("bounds", "")
            clickable = node.get("clickable", "false") == "true"
            editable = (
                node.get("focused", "false") == "true"
                or "EditText" in cls
                or node.get("password", "false") == "true"
            )

            role = self._classify_semantic_role(r_id, cls, text, desc, node.get("password") == "true")

            el = UIElement(
                resource_id=r_id,
                class_name=cls,
                text=text,
                content_desc=desc,
                bounds=bounds,
                is_clickable=clickable,
                is_editable=editable,
                semantic_role=role,
            )
            elements.append(el)

        return elements

    def _classify_semantic_role(self, r_id: str, cls: str, text: str, desc: str, is_pwd_attr: bool) -> str:
        combined = f"{r_id} {text} {desc}".lower()

        # Permission allow & biometric prompt bypass buttons
        if any(w in combined for w in (
            "while using the app", "only this time", "allow", "grant", "permission_allow",
            "use password", "cancel biometric", "accept", "continue", "i agree"
        )):
            return "permission_allow"

        # Passwords
        if is_pwd_attr or any(w in combined for w in ("password", "passcode", "pin", "secret", "pwd")):
            return "password"

        # Usernames / Emails
        if any(w in combined for w in ("username", "email", "phone", "mobile", "user_id", "login_id")):
            return "username"

        # Search inputs
        if any(w in combined for w in ("search", "find", "query")):
            return "search"

        # Submit / Login buttons
        if any(w in combined for w in ("sign in", "login", "continue", "submit", "next", "confirm")):
            return "submit_button"

        return "generic"

    def compute_state_hash(self, current_activity: str, elements: List[UIElement]) -> str:
        """Compute stable hash for screen state deduplication."""
        sig = [current_activity]
        for el in elements:
            if el.resource_id:
                sig.append(el.resource_id)
            elif el.text and len(el.text) < 30:
                sig.append(el.text)
        raw = "|".join(sorted(sig))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def decide_next_action(self, current_activity: str, xml_content: str) -> CrawlerDecision:
        """Analyze current screen and select best next exploratory action."""
        elements = self.parse_hierarchy_xml(xml_content)
        state_hash = self.compute_state_hash(current_activity, elements)

        visits = self.visited_states.get(state_hash, 0)
        self.visited_states[state_hash] = visits + 1

        # OS permission and consent prompts are authorization boundaries. A
        # classifier may recognize them, but the crawler must not consent.
        for el in elements:
            if el.semantic_role == "permission_allow":
                return CrawlerDecision(action="WAIT", explanation=(
                    f"Permission/consent prompt requires explicit operator review: "
                    f"{el.text or el.content_desc}"
                ))

        # Priority 2: Fill empty username fields
        for el in elements:
            if el.semantic_role == "username" and not el.text and self.test_user:
                return CrawlerDecision(
                    action="TYPE_TEXT",
                    target_bounds=el.bounds,
                    input_text=self.test_user,
                    explanation=f"Filling test username into: {el.resource_id or el.class_name}",
                )

        # Priority 3: Fill empty password fields
        for el in elements:
            if el.semantic_role == "password" and not el.text and self.test_pass:
                return CrawlerDecision(
                    action="TYPE_TEXT",
                    target_bounds=el.bounds,
                    input_text=self.test_pass,
                    explanation=f"Filling test password into: {el.resource_id or el.class_name}",
                )

        if any(el.semantic_role == "username" and not el.text for el in elements) and not self.test_user:
            return CrawlerDecision(action="WAIT", explanation="Username field detected; no operator-supplied test identity")
        if any(el.semantic_role == "password" and not el.text for el in elements) and not self.test_pass:
            return CrawlerDecision(action="WAIT", explanation="Password field detected; no operator-supplied test credential")

        # Priority 4: Click login/submit if credentials are populated
        for el in elements:
            if el.semantic_role == "submit_button" and el.is_clickable:
                if not self.allow_form_submit:
                    return CrawlerDecision(action="WAIT", explanation=(
                        "Form submission requires explicit operator approval"
                    ))
                return CrawlerDecision(
                    action="CLICK",
                    target_bounds=el.bounds,
                    explanation=f"Tapping submit button: {el.text or el.resource_id}",
                )

        # Priority 5: If screen has been visited many times (> 3), press BACK to escape loop
        if visits >= 3:
            return CrawlerDecision(
                action="BACK",
                explanation=f"Screen state {state_hash} visited {visits} times; pressing BACK to escape loop.",
            )

        # Priority 6: Click an unvisited clickable element
        clickables = [e for e in elements if e.is_clickable and e.bounds]
        if clickables:
            if not self.allow_exploratory_clicks:
                return CrawlerDecision(action="WAIT", explanation=(
                    "Exploratory UI interaction is disabled pending explicit operator approval"
                ))
            target = clickables[visits % len(clickables)]
            return CrawlerDecision(
                action="CLICK",
                target_bounds=target.bounds,
                explanation=f"Exploring clickable element: {target.text or target.resource_id or target.class_name}",
            )

        return CrawlerDecision(action="WAIT", explanation="No actionable UI elements detected.")
