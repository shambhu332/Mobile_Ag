"""Bounded memory-pattern indicators for explicitly scoped Android research.

The root-shell scanner emits fixed category labels only; it does not return
matched strings, read process environments, or establish ordinary-app access.
"""

from __future__ import annotations

import logging
import inspect
import re
import shlex
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

_MEMORY_INDICATOR_LABELS = (
    "JWT Bearer Token",
    "Bearer Authentication Token",
    "Google API Key",
    "AWS Access Key",
    "Plaintext Password Parameter",
    "Private Key Header",
)


class MemoryForensicsAuditor:
    """Audits process memory through redacted category-only indicators."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    @staticmethod
    def _check_scope_guard(guard) -> None:
        if not callable(guard):
            raise PermissionError('Memory audit scope guard is required')
        allowed = guard()
        if inspect.isawaitable(allowed):
            close = getattr(allowed, 'close', None)
            if callable(close):
                close()
            raise PermissionError('Memory audit scope guard must be synchronous')
        if allowed is False:
            raise PermissionError('Memory audit scope guard denied access')

    async def get_process_pid(self, serial: str, package_name: str, guard=None) -> Optional[int]:
        """Retrieve target package process PID on the device."""
        if (not isinstance(serial, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', serial)
                or not isinstance(package_name, str)
                or not re.fullmatch(r'[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+', package_name)):
            raise ValueError('Invalid Android package name')
        self._check_scope_guard(guard)
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", "pidof", package_name],
            timeout=3.0,
        )
        self._check_scope_guard(guard)
        if code == 0 and stdout:
            pids = stdout.decode("utf-8", errors="replace").strip().split()
            if pids and pids[0].isdigit():
                return int(pids[0])

        # Fallback to ps -A and exact process-name comparison; never interpolate
        # a package name into grep regular-expression or shell syntax.
        self._check_scope_guard(guard)
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", "ps", "-A"],
            timeout=3.0,
        )
        self._check_scope_guard(guard)
        if code == 0 and stdout:
            lines = stdout.decode("utf-8", errors="replace").strip().splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit() and (parts[-1] == package_name or parts[-1].startswith(package_name + ':')):
                    return int(parts[1])

        return None

    async def extract_memory_indicators(
        self,
        serial: str,
        pid: int,
        max_lines: int = 200,
        guard=None,
    ) -> list[str]:
        """Return fixed indicator labels only; never transfer matched strings or environ."""
        if (not isinstance(serial, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', serial)
                or type(pid) is not int or not 1 <= pid <= 2_147_483_647
                or type(max_lines) is not int or not 1 <= max_lines <= 200):
            raise ValueError('Invalid bounded memory-indicator input')

        # AWK emits only fixed category labels. Matched memory strings remain
        # in the on-device pipeline and are never returned to MobileAg.
        awk_program = r'''
/eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+/ { if (!seen["JWT Bearer Token"]++) print "JWT Bearer Token"; next }
/[Bb]earer[[:space:]]+/ { if (!seen["Bearer Authentication Token"]++) print "Bearer Authentication Token"; next }
/AIzaSy[0-9A-Za-z_-]+/ { if (!seen["Google API Key"]++) print "Google API Key"; next }
/AKIA[0-9A-Z]+/ { if (!seen["AWS Access Key"]++) print "AWS Access Key"; next }
tolower($0) ~ /(password|passwd|auth_token|user_secret)[[:space:]]*[:=]/ { if (!seen["Plaintext Password Parameter"]++) print "Plaintext Password Parameter"; next }
/-----BEGIN ([A-Za-z]+ )?PRIVATE KEY-----/ { if (!seen["Private Key Header"]++) print "Private Key Header"; next }
'''
        pipeline = (
            f"strings /proc/{pid}/mem 2>/dev/null | awk {shlex.quote(awk_program)} "
            f"| head -n {max_lines}"
        )
        cmd = f"su -c {shlex.quote(pipeline)}"
        self._check_scope_guard(guard)
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", cmd], timeout=6.0, output_limit=8192,
        )
        self._check_scope_guard(guard)
        if code != 0 or not stdout:
            return []
        allowed = set(_MEMORY_INDICATOR_LABELS)
        return [line for line in stdout.decode("utf-8", errors="replace").splitlines()
                if line in allowed]

    async def audit_process_memory(
        self,
        serial: str,
        package_name: str,
        guard=None,
    ) -> tuple[Optional[int], list[Finding]]:
        """Audit target application's active RAM for un-zeroized credentials and tokens."""
        pid = await self.get_process_pid(serial, package_name, guard)
        if not pid:
            logger.warning(f"Could not locate running process for package: {package_name}")
            return None, []

        indicators = set(await self.extract_memory_indicators(serial, pid, guard=guard))
        findings: list[Finding] = []
        for category in _MEMORY_INDICATOR_LABELS:
            if category not in indicators:
                continue
            findings.append(Finding(
                title=f"Sensitive-Memory Pattern Candidate: {category}",
                description=(
                    f"A fixed pattern category was observed by a root-shell scanner for process PID `{pid}`. "
                    "MobileAg receives only this category label; the matched text/value is not returned or "
                    "persisted. The marker does not establish secret validity, attacker access, a zeroization "
                    "failure, or ordinary-app exploitability."
                ),
                severity=Severity.INFO,
                confidence=0.4,
                cwe_id="CWE-316",
                cvss_score=0.0,
                cvss_vector="",
                owasp_masvs="MASVS-STORAGE-2",
                affected_component=f"PID:{pid}",
                file_path=f"/proc/{pid}/mem",
                line_number=1,
                code_snippet="[fixed pattern category only; raw value not collected]",
                detection_method="MemoryForensicsAuditor (Bounded Dynamic Indicator)",
                status=FindingStatus.UNVERIFIED,
                remediation=(
                    "Minimize sensitive-value lifetime and review platform-supported memory handling. "
                    "Validate any indicator with controlled synthetic data; do not infer impact from this marker alone."
                ),
                metadata={"evidence_state": "pattern_indicator", "raw_value_collected": False,
                          "ordinary_app_access": "not_established"},
            ))

        return pid, findings

    async def run_memory_audit(self, serial: str, package_name: str, guard=None) -> dict[str, Any]:
        """Execute complete memory forensics pass and return structured summary."""
        self._check_scope_guard(guard)
        pid, findings = await self.audit_process_memory(serial, package_name, guard)
        self._check_scope_guard(guard)
        return {
            "package_name": package_name,
            "device_serial": serial,
            "pid": pid,
            "process_found": pid is not None,
            "memory_findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "analysis_mode": "category_only_indicators",
            "raw_memory_values_collected": False,
            "ordinary_app_access_established": False,
        }
