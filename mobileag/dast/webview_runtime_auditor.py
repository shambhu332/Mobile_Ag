"""Privacy-first WebView widget observations from a UIAutomator snapshot.

This identifies visible WebView widget classes only. It does not inspect page
content, origins, JavaScript settings, bridges, TLS decisions, or hidden views.
"""
from __future__ import annotations

import re
from typing import Any


_PACKAGE_RE = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\Z")
_WEBVIEW_CLASSES = {"android.webkit.WebView", "androidx.webkit.WebView"}
_MAX_NODES = 5_000


class WebViewRuntimeAuditor:
    """Summarize WebView-class presence without retaining UI text or URLs."""

    def audit_elements(self, elements: Any, package_name: str) -> dict[str, Any]:
        base = {
            "status": "not_tested",
            "visible_webview_count": 0,
            "snapshot_node_count": 0,
            "proof_status": "not_proven",
            "limitations": [
                "A UIAutomator snapshot observes only the current visible foreground hierarchy.",
                "Widget presence does not establish content origin, bridge exposure, JavaScript execution, or exploitability.",
                "A zero count is not evidence that the app has no WebViews.",
            ],
        }
        if not isinstance(package_name, str) or not _PACKAGE_RE.fullmatch(package_name):
            return {**base, "status": "invalid_package"}
        if not isinstance(elements, list) or len(elements) > _MAX_NODES:
            return {**base, "status": "incomplete_snapshot"}
        if any(not isinstance(element, dict) for element in elements):
            return {**base, "status": "incomplete_snapshot"}
        if any(element.get("package") != package_name for element in elements):
            return {**base, "status": "foreground_package_mismatch"}
        count = sum(
            1 for element in elements
            if isinstance(element.get("class"), str)
            and (element["class"] in _WEBVIEW_CLASSES
                 or element["class"].endswith("WebView"))
        )
        return {
            **base,
            "status": "observed" if count else "not_observed_in_snapshot",
            "visible_webview_count": count,
            "snapshot_node_count": len(elements),
        }
