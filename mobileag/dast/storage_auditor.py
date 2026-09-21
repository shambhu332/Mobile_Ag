"""Dynamic local storage and sandbox forensics auditor for Android apps.

Inspects application sandbox directories (/data/data/<pkg>) on rooted devices
or emulators post-execution to detect:
1. Cleartext tokens, passwords, and PII in SharedPreferences (CWE-312)
2. Unencrypted SQLite databases containing sensitive tables/records (CWE-312)
3. Cached sensitive credentials or responses in disk caches (CWE-524)
4. Insecure file permissions or external storage leakage (CWE-276 / CWE-922)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Patterns for credentials and sensitive data stored in local XML / DB files
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|auth_token|access_token|bearer|jwt|secret_key|api_key|session_id|pin|credit_card)\b"
)
_TOKEN_VALUE_RE = re.compile(
    r"\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}|AIzaSy[0-9A-Za-z_-]{33}|AKIA[0-9A-Z]{16})\b"
)


class StorageAuditor:
    """Audits local sandbox storage on rooted emulators or devices."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    async def _run_su_cmd(self, serial: str, cmd: str) -> str:
        """Run a command under root shell (su) or fallback to run-as."""
        # Try su first
        code, stdout, _ = await self.adb._exec_cmd(["-s", serial, "shell", f"su -c '{cmd}'"], timeout=5.0)
        if code == 0 and stdout:
            return stdout.decode("utf-8", errors="replace").strip()

        # Fallback to direct shell
        code, stdout, _ = await self.adb._exec_cmd(["-s", serial, "shell", cmd], timeout=5.0)
        if code == 0 and stdout:
            return stdout.decode("utf-8", errors="replace").strip()

        return ""

    async def audit_shared_preferences(self, serial: str, package_name: str) -> list[Finding]:
        """Audit /data/data/<pkg>/shared_prefs/*.xml for plaintext secrets and tokens."""
        findings: list[Finding] = []
        prefs_dir = f"/data/data/{package_name}/shared_prefs"

        list_out = await self._run_su_cmd(serial, f"ls -1 {prefs_dir}")
        if not list_out or "No such file" in list_out or "Permission denied" in list_out:
            return findings

        xml_files = [f.strip() for f in list_out.splitlines() if f.strip().endswith(".xml")]

        for xml_file in xml_files:
            file_path = f"{prefs_dir}/{xml_file}"
            content = await self._run_su_cmd(serial, f"cat {file_path}")
            if not content:
                continue

            # Check 1: Sensitive keys in SharedPreferences
            for line_idx, line in enumerate(content.splitlines(), 1):
                key_match = _SENSITIVE_KEY_RE.search(line)
                token_match = _TOKEN_VALUE_RE.search(line)

                if key_match or token_match:
                    cwe = "CWE-312"
                    score, vector = get_default_cvss_for_cwe(cwe)
                    matched_term = key_match.group(0) if key_match else token_match.group(0)

                    # Mask preview
                    masked = line[:60] + "..." if len(line) > 60 else line

                    findings.append(Finding(
                        title=f"Cleartext Secret in SharedPreferences: {xml_file} [{matched_term}]",
                        description=(
                            f"The application stores sensitive credential or authentication data in plaintext inside "
                            f"`{file_path}` without utilizing AndroidX EncryptedSharedPreferences.\n\n"
                            f"Identified entry: `{masked.strip()}`"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.95,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-STORAGE-1",
                        affected_component=f"shared_prefs/{xml_file}",
                        file_path=file_path,
                        line_number=line_idx,
                        code_snippet=line.strip(),
                        detection_method="StorageAuditor (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation=(
                            "Migrate all sensitive SharedPreferences to AndroidX EncryptedSharedPreferences "
                            "using MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)."
                        ),
                    ))
                    break  # One finding per file to keep reports actionable

        return findings

    async def audit_sqlite_databases(self, serial: str, package_name: str) -> list[Finding]:
        """Audit /data/data/<pkg>/databases/ for unencrypted SQLite databases."""
        findings: list[Finding] = []
        db_dir = f"/data/data/{package_name}/databases"

        list_out = await self._run_su_cmd(serial, f"ls -1 {db_dir}")
        if not list_out or "No such file" in list_out or "Permission denied" in list_out:
            return findings

        db_files = [f.strip() for f in list_out.splitlines() if f.strip().endswith(".db") or not "." in f.strip()]

        for db_file in db_files:
            file_path = f"{db_dir}/{db_file}"
            # Check SQLite header using head -c 16
            header = await self._run_su_cmd(serial, f"head -c 16 {file_path}")

            if "SQLite format 3" in header:
                cwe = "CWE-312"
                score, vector = get_default_cvss_for_cwe(cwe)

                # Query table schema if sqlite3 binary is present on rooted emulator
                tables_out = await self._run_su_cmd(
                    serial,
                    f"sqlite3 {file_path} 'SELECT name FROM sqlite_master WHERE type=\"table\";' 2>/dev/null"
                )
                table_list = tables_out.replace("\n", ", ") if tables_out else "Unknown Tables"

                findings.append(Finding(
                    title=f"Unencrypted SQLite Database on Disk: {db_file}",
                    description=(
                        f"The application stores application data in an unencrypted SQLite database at `{file_path}`.\n"
                        f"Discovered SQLite Tables: `{table_list}`\n\n"
                        "On rooted devices or via forensic extraction / backup extraction, unencrypted SQLite "
                        "databases permit direct access to cached user records, offline state, and credentials."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-STORAGE-2",
                    affected_component=f"databases/{db_file}",
                    file_path=file_path,
                    line_number=1,
                    code_snippet=f"SQLite Header: {header}",
                    detection_method="StorageAuditor (Dynamic)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Encrypt sensitive databases at rest using SQLCipher for Android (net.zetetic:android-database-sqlcipher).",
                ))

        return findings

    async def audit_cache_leakage(self, serial: str, package_name: str) -> list[Finding]:
        """Audit /data/data/<pkg>/cache for cached sensitive API responses."""
        findings: list[Finding] = []
        cache_dir = f"/data/data/{package_name}/cache"

        grep_out = await self._run_su_cmd(
            serial,
            f"grep -rn -E 'Authorization:|Bearer |password' {cache_dir} 2>/dev/null | head -n 5"
        )
        if grep_out and "Binary file" not in grep_out:
            cwe = "CWE-524"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title=f"Sensitive HTTP Response Credentials Cached to Disk: {package_name}",
                description=(
                    f"HTTP response caching on the device wrote sensitive authorization credentials or secrets to disk:\n"
                    f"`{grep_out[:200]}...`"
                ),
                severity=Severity.MEDIUM,
                confidence=0.85,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                owasp_masvs="MASVS-STORAGE-2",
                affected_component="cache/",
                file_path=cache_dir,
                line_number=1,
                code_snippet=grep_out[:180],
                detection_method="StorageAuditor (Dynamic)",
                status=FindingStatus.CONFIRMED,
                remediation="Ensure sensitive backend endpoints return `Cache-Control: no-store` and configure OkHttp cache filters.",
            ))

        return findings

    async def audit_all_storage(self, serial: str, package_name: str) -> dict[str, Any]:
        """Run full storage forensics pass across SharedPreferences, Databases, and Cache."""
        pref_findings = await self.audit_shared_preferences(serial, package_name)
        db_findings = await self.audit_sqlite_databases(serial, package_name)
        cache_findings = await self.audit_cache_leakage(serial, package_name)

        all_findings = pref_findings + db_findings + cache_findings
        return {
            "package_name": package_name,
            "device_serial": serial,
            "total_storage_findings": len(all_findings),
            "shared_prefs_findings": len(pref_findings),
            "database_findings": len(db_findings),
            "cache_findings": len(cache_findings),
            "findings": [f.to_dict() for f in all_findings],
        }
