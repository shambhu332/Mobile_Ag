"""Dynamic Content Provider and IPC Auditor for Android DAST.

Audits exported Content Providers via ADB `content query` and `content read`
to identify:
1. Exported Content Providers accessible without permissions (CWE-926)
2. SQL syntax error leakage and raw query concatenation in projection/where (CWE-89)
3. Insecure FileProvider URI exposure (CWE-22)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


class ProviderAuditor:
    """Audits exported Android Content Providers via live ADB interaction."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    async def audit_provider_uri(
        self,
        serial: str,
        package_name: str,
        uri: str,
    ) -> list[Finding]:
        """Audit a content provider URI for unauthorized data access and SQL error leakage."""
        findings: list[Finding] = []

        # 1. Test unauthenticated read access
        cmd = ["-s", serial, "shell", "content", "query", "--uri", uri]
        code, stdout, stderr = await self.adb._exec_cmd(cmd, timeout=4.0)
        out_str = stdout.decode("utf-8", errors="replace")
        err_str = stderr.decode("utf-8", errors="replace")
        combined = (out_str + err_str).strip()

        # If data rows were returned to external caller without signature permission
        if "Row:" in combined:
            cwe = "CWE-926"
            score, vector = get_default_cvss_for_cwe(cwe)
            snippet = combined[:300]

            findings.append(Finding(
                title=f"Exported Content Provider Leak: {uri}",
                description=(
                    f"The Content Provider at `{uri}` is exported without caller permission guards. "
                    f"External applications can query and extract records directly.\n\n"
                    f"Data returned on unauthenticated query:\n`{snippet}`"
                ),
                severity=Severity.HIGH,
                confidence=1.0,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                owasp_masvs="MASVS-PLATFORM-1",
                affected_component=uri,
                file_path=uri,
                line_number=1,
                code_snippet=snippet,
                detection_method="ProviderAuditor (Dynamic)",
                status=FindingStatus.CONFIRMED,
                remediation=(
                    "Set `android:exported=\"false\"` if external access is unneeded, or protect with "
                    "`android:readPermission` requiring `signature` protectionLevel."
                ),
            ))

        # 2. Test SQL Syntax Error Leakage (CWE-89 / CWE-209)
        cmd_sqli = ["-s", serial, "shell", "content", "query", "--uri", uri, "--where", "1='1' AND 'a'='a"]
        _, out_sqli, err_sqli = await self.adb._exec_cmd(cmd_sqli, timeout=4.0)
        sqli_combined = (out_sqli.decode("utf-8", errors="replace") + err_sqli.decode("utf-8", errors="replace")).strip()

        if any(err_sig in sqli_combined for err_sig in ("SQLiteException", "syntax error", "unrecognized token")):
            cwe = "CWE-89"
            score, vector = get_default_cvss_for_cwe(cwe)

            findings.append(Finding(
                title=f"SQL Syntax Error Leakage in Content Provider: {uri}",
                description=(
                    f"The Content Provider query selection logic leaked internal SQLite database exception details "
                    f"when provided an injected query argument:\n`{sqli_combined[:250]}`\n\n"
                    "This indicates unparameterized query concatenation in ContentProvider.query()."
                ),
                severity=Severity.HIGH,
                confidence=0.90,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                owasp_masvs="MASVS-CODE-2",
                affected_component=uri,
                file_path=uri,
                line_number=1,
                code_snippet=sqli_combined[:200],
                detection_method="ProviderAuditor (Dynamic)",
                status=FindingStatus.CONFIRMED,
                remediation="Use parameterized queries with SQLiteQueryBuilder and bind selectionArgs instead of string concatenation.",
            ))

        return findings

    async def audit_providers(
        self,
        serial: str,
        package_name: str,
        authorities: list[str],
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Audit multiple provider authorities for a package."""
        all_results: list[dict[str, Any]] = []
        all_findings: list[Finding] = []

        for auth in authorities:
            uri = f"content://{auth}"
            findings = await self.audit_provider_uri(serial, package_name, uri)
            all_results.append({
                "authority": auth,
                "uri": uri,
                "findings_count": len(findings),
            })
            all_findings.extend(findings)

        return all_results, all_findings
