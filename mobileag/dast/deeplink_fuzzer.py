"""Dynamic Deep Link and App Link Fuzzing Matrix for Android DAST.

Identifies and actively exercises deep links, custom schemes, and intent filters to detect:
1. Open Redirect / OAuth Token Hijacking via deep links (CWE-601)
2. Local Sandbox File Disclosure via file:// URIs (CWE-22)
3. Cross-Site Scripting / JavaScript Execution in internal WebViews (CWE-79 / CWE-749)
4. Unhandled intent URI parsing crashes & DoS (CWE-755)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


class DeepLinkFuzzer:
    """Fuzzes Android custom schemes and app deep links for logic and injection vulnerabilities."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    def extract_deep_links_from_manifest(self, manifest_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract all registered schemes, hosts, and paths from manifest intent-filters."""
        deep_links: list[dict[str, Any]] = []

        for activity in manifest_data.get("activities", []):
            act_name = activity.get("name", "")
            for filter_data in activity.get("intent_filters", []):
                actions = filter_data.get("actions", [])
                categories = filter_data.get("categories", [])
                data_elements = filter_data.get("data", [])

                # Check if it handles VIEW or BROWSABLE
                has_view = any("android.intent.action.VIEW" in a for a in actions)
                has_browsable = any("android.intent.category.BROWSABLE" in c for c in categories)

                if has_view or has_browsable or data_elements:
                    for d in data_elements:
                        scheme = d.get("scheme", "")
                        host = d.get("host", "")
                        path = d.get("pathPrefix", "") or d.get("path", "")
                        if scheme and scheme not in ("http", "https"):
                            deep_links.append({
                                "activity": act_name,
                                "scheme": scheme,
                                "host": host,
                                "path": path,
                                "uri": f"{scheme}://{host}{path}" if host else f"{scheme}://",
                            })

        return deep_links

    def generate_fuzz_payloads(self, base_uri: str, package_name: str) -> list[dict[str, str]]:
        """Generate targeted mutation payloads across high-impact vulnerability classes."""
        clean_base = base_uri.rstrip("/")
        # Ensure scheme structure
        if not "://" in clean_base:
            clean_base = f"{clean_base}://"

        return [
            # 1. Open Redirect / OAuth Theft
            {
                "category": "Open Redirect / OAuth Hijack",
                "cwe": "CWE-601",
                "uri": f"{clean_base}/auth?redirect_uri=https://attacker.evil/oauth/callback",
                "desc": "Tests if the deep link router allows redirecting authentication tokens to an arbitrary external host.",
            },
            {
                "category": "Open Redirect / OAuth Hijack",
                "cwe": "CWE-601",
                "uri": f"{clean_base}/webview?url=https://attacker.evil",
                "desc": "Tests if internal webview navigation opens external attacker domains without domain whitelist validation.",
            },
            # 2. Local File Traversal / Sandbox Leak
            {
                "category": "Local File Disclosure",
                "cwe": "CWE-22",
                "uri": f"{clean_base}/open?url=file:///data/data/{package_name}/shared_prefs/user_session.xml",
                "desc": "Tests if the deep link allows reading protected application sandbox XML files via file:// URI.",
            },
            # 3. JavaScript Execution in WebViews
            {
                "category": "WebView Script Injection",
                "cwe": "CWE-749",
                "uri": f"{clean_base}/view?url=javascript:alert(document.domain)",
                "desc": "Tests if the deep link executes javascript: pseudourls inside an embedded WebView.",
            },
            # 4. Privilege & Parameter Pollution
            {
                "category": "Parameter Pollution",
                "cwe": "CWE-926",
                "uri": f"{clean_base}/account?role=admin&is_admin=true&debug=1",
                "desc": "Tests for parameter pollution and state tampering via custom scheme query arguments.",
            },
        ]

    async def exercise_deep_link(
        self,
        serial: str,
        package_name: str,
        target_uri: str,
        activity_name: str = "",
    ) -> tuple[int, str, list[str]]:
        """Execute a deep link intent on the device and monitor logcat output."""
        await self.adb.clear_logcat(serial)

        # Build am start command
        cmd = ["-s", serial, "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", target_uri]
        if activity_name:
            cmd.extend(["-n", f"{package_name}/{activity_name}"])

        code, stdout, stderr = await self.adb._exec_cmd(cmd, timeout=4.0)
        out_msg = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()

        # Let the activity process the intent
        await asyncio.sleep(1.0)
        logs = await self.adb.get_logcat_dump(serial, lines=50)

        return code, out_msg, logs

    async def fuzz_deep_links(
        self,
        serial: str,
        package_name: str,
        deep_links: list[str],
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Execute the full deep link fuzzing matrix across discovered schemes."""
        results: list[dict[str, Any]] = []
        findings: list[Finding] = []

        for link_uri in deep_links:
            payloads = self.generate_fuzz_payloads(link_uri, package_name)

            for item in payloads:
                test_uri = item["uri"]
                category = item["category"]
                cwe = item["cwe"]

                code, am_out, logs = await self.exercise_deep_link(serial, package_name, test_uri)

                # Check for runtime crash in logcat
                crash_lines = [l for l in logs if "FATAL EXCEPTION" in l or "AndroidRuntime" in l]
                if crash_lines:
                    score, vector = get_default_cvss_for_cwe("CWE-755")
                    findings.append(Finding(
                        title=f"Unhandled Crash in Deep Link Handler: {link_uri}",
                        description=(
                            f"Firing deep link payload `{test_uri}` caused an unhandled crash in the target app.\n\n"
                            f"Logcat stack trace excerpt:\n`{crash_lines[0][:250]}`"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.95,
                        cwe_id="CWE-755",
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-PLATFORM-1",
                        affected_component=link_uri,
                        file_path=link_uri,
                        line_number=1,
                        code_snippet=crash_lines[0].strip(),
                        detection_method="DeepLinkFuzzer (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation="Wrap deep link intent URI parsing and parameter handling in structured try/catch blocks.",
                    ))

                # Check for WebView URI handling indicators
                webview_suspicious = [
                    l for l in logs
                    if ("file://" in l and "shared_prefs" in l) or ("javascript:" in l and "WebView" in l)
                ]
                if webview_suspicious:
                    score, vector = get_default_cvss_for_cwe(cwe)
                    findings.append(Finding(
                        title=f"Insecure Deep Link Reflection: {category}",
                        description=(
                            f"The deep link `{test_uri}` resulted in suspicious internal sink reflection "
                            f"or file URI processing:\n`{webview_suspicious[0][:200]}`"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.90,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-PLATFORM-1",
                        affected_component=link_uri,
                        file_path=link_uri,
                        line_number=1,
                        code_snippet=webview_suspicious[0].strip(),
                        detection_method="DeepLinkFuzzer (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation="Validate and sanitize incoming deep link URIs using strict domain allowlists before loading in WebViews or resolving files.",
                    ))

                results.append({
                    "scheme_uri": link_uri,
                    "payload_uri": test_uri,
                    "category": category,
                    "status_code": code,
                    "crashed": bool(crash_lines),
                })

        return results, findings
