"""Dynamic Deep Link and App Link Fuzzing Matrix for Android DAST.

Identifies and actively exercises deep links, custom schemes, and intent filters to detect:
1. Open Redirect / OAuth Token Hijacking via deep links (CWE-601)
2. Local Sandbox File Disclosure via file:// URIs (CWE-22)
3. WebView script injection review markers (CWE-79)
4. Unhandled intent URI parsing crashes & DoS (CWE-755)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from mobileag.security.privacy import redact

from mobileag.dast.adb_manager import ADBManager
from mobileag.dast.runtime_evidence import new_lines, attributed_crashes
from mobileag.ingestion.intent_filters import inventory_links
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


class DeepLinkFuzzer:
    """Fuzzes Android custom schemes and app deep links for logic and injection vulnerabilities."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    @staticmethod
    def _check_scope_guard(guard) -> None:
        """Fail closed when a supplied scope guard explicitly denies access."""
        if guard is None:
            return
        if not callable(guard):
            raise PermissionError("Deep-link scope guard is invalid")
        try:
            allowed = guard()
        except Exception as exc:
            raise PermissionError("Deep-link scope guard denied access") from exc
        if allowed is False:
            raise PermissionError("Deep-link scope guard denied access")

    def extract_deep_links_from_manifest(self, manifest_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract all registered schemes, hosts, and paths from manifest intent-filters."""
        components=manifest_data.get('components') or manifest_data.get('activities',[])
        return inventory_links(components)[0]

    def generate_fuzz_payloads(self, base_uri: str, package_name: str) -> list[dict[str, str]]:
        """Generate bounded synthetic diagnostic markers, not exploit proofs."""
        parts=urlsplit(base_uri)
        if not parts.scheme or len(base_uri)>8192:raise ValueError('An exact bounded URI scheme is required')
        original=parse_qsl(parts.query,keep_blank_values=True,max_num_fields=100)
        def uri(key,value):
            query=[(k,v) for k,v in original if k!=key]+[(key,value)]
            return urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(query),parts.fragment))
        # Preserve the researcher-supplied route. No guessed /auth /account paths,
        # external callback hosts, real sandbox files or privilege toggles.
        return [
            {'category':'Redirect parameter marker','cwe':'CWE-601','uri':uri('redirect_uri','urn:mobileag:synthetic-marker'),'desc':'Inert redirect marker; token theft is not tested or proven.'},
            {'category':'URI parameter marker','cwe':'CWE-601','uri':uri('url','urn:mobileag:synthetic-marker'),'desc':'Inert URI marker; remote content is not contacted by this payload.'},
            {'category':'Nonexistent file marker','cwe':'CWE-22','uri':uri('url','file:///mobileag-synthetic-nonexistent.txt'),'desc':'Nonexistent synthetic path; no real sensitive file is selected.'},
            {'category':'No-op script marker','cwe':'CWE-79','uri':uri('url','javascript:void(0)'),'desc':'Inert JavaScript-scheme marker; log reflection or launch is not script-execution proof.'},
            {'category':'Synthetic parameter marker','cwe':'CWE-926','uri':uri('mobileag_canary','synthetic'),'desc':'Synthetic marker only; no role/admin/debug change.'},
        ]

    async def exercise_deep_link(
        self,
        serial: str,
        package_name: str,
        target_uri: str,
        activity_name: str = "",
        guard=None,
    ) -> tuple[int, str, list[str]]:
        """Execute a deep link intent on the device and monitor logcat output."""

        self._check_scope_guard(guard)
        baseline=await self.adb.get_logcat_dump(serial,lines=100)
        self._check_scope_guard(guard)
        # Build am start command
        cmd = ["-s", serial, "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", target_uri, "-p", package_name]
        if activity_name:
            cmd.extend(["-n", f"{package_name}/{activity_name}"])

        code, stdout, stderr = await self.adb._exec_cmd(cmd, timeout=4.0)
        out_msg = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()

        self._check_scope_guard(guard)
        if code!=0 or "Error:" in out_msg:return code if code else -1,out_msg,[]
        # Let the activity process the intent
        await asyncio.sleep(1.0)
        self._check_scope_guard(guard)
        logs = await self.adb.get_logcat_dump(serial, lines=100)
        self._check_scope_guard(guard)

        return code, out_msg, new_lines(baseline,logs)

    async def fuzz_deep_links(
        self,
        serial: str,
        package_name: str,
        deep_links: list[str],
        guard=None,
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Execute the full deep link fuzzing matrix across discovered schemes."""
        results: list[dict[str, Any]] = []
        def evidence_uri(value):
            parsed=urlsplit(value)
            return redact(urlunsplit((parsed.scheme,parsed.netloc,parsed.path,
                urlencode([(key,"[REDACTED]") for key,_ in parse_qsl(parsed.query,keep_blank_values=True,max_num_fields=100)]),"")))
        findings: list[Finding] = []

        for link_uri in deep_links:
            payloads = self.generate_fuzz_payloads(link_uri, package_name)

            for item in payloads:
                test_uri = item["uri"]
                category = item["category"]
                cwe = item["cwe"]

                code, am_out, logs = await self.exercise_deep_link(serial, package_name, test_uri,guard=guard)

                # Check for runtime crash in logcat
                crash_lines = attributed_crashes(logs,package_name) if code==0 else []
                if crash_lines:
                    score, vector = get_default_cvss_for_cwe("CWE-755")
                    findings.append(Finding(
                        title=f"Review new target-process crash after link exercise: {evidence_uri(link_uri)}",
                        description=(
                            f"Firing deep link payload `{evidence_uri(test_uri)}` was followed by a newly observed target-process crash. Causation, reproducibility and ordinary-app exploitability are not established.\n\n"
                            "The stack trace and runtime values are intentionally omitted from the report."
                        ),
                        severity=Severity.INFO,
                        confidence=0.5,
                        cwe_id="CWE-755",
                        cvss_score=0,
                        cvss_vector="",
                        owasp_masvs="MASVS-PLATFORM-1",
                        affected_component=evidence_uri(link_uri),
                        file_path=evidence_uri(link_uri),
                        line_number=1,
                        code_snippet="Target PID fatal exception (runtime values omitted)",
                        detection_method="DeepLinkFuzzer (Dynamic)",
                        status=FindingStatus.UNVERIFIED,
                        metadata={"proof_state":"not_proven","attacker_context":"adb_shell_diagnostic","log_attribution":"new_matching_process_pid"},
                        remediation="Wrap deep link intent URI parsing and parameter handling in structured try/catch blocks.",
                    ))

                # Check for WebView URI handling indicators
                webview_suspicious = [
                    l for l in logs
                    if ("file://" in l and "shared_prefs" in l) or ("javascript:" in l and "WebView" in l)
                ]
                # String reflection alone is retained as an observation, not XSS/file disclosure.
                results.append({
                    "scheme_uri": evidence_uri(link_uri),
                    "payload_uri": evidence_uri(test_uri),
                    "category": category,
                    "status_code": code,
                    "crashed": bool(crash_lines),
                    "executed":code==0,
                    "sink_string_observations":len(webview_suspicious),
                    "proof_state":"not_proven",
                    "attacker_context":"adb_shell_diagnostic",
                })

        return redact(results), findings
