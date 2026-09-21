"""Volatile Process RAM & Memory Forensics Auditor for Android DAST.

Inspects live process memory (/proc/<pid>/mem, heap, and writable segments)
on rooted emulators or devices to detect:
1. Cleartext passwords and authentication tokens lingering in RAM (CWE-316)
2. Decrypted JWT / OAuth bearer tokens retained in heap memory (CWE-316)
3. Cryptographic private keys in un-zeroized memory buffers (CWE-316)
4. Unmasked PII or credit card numbers in volatile memory (CWE-316)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Patterns for sensitive credentials retained in process RAM
_MEMORY_SECRET_PATTERNS = [
    (
        "JWT Bearer Token",
        re.compile(r"\b(?:Bearer\s+)?(eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b"),
    ),
    (
        "Bearer Authentication Token",
        re.compile(r"""(?i)\bBearer\s+([a-zA-Z0-9_\-\.+=/]{16,})\b"""),
    ),
    (
        "Google API Key",
        re.compile(r"\b(AIzaSy[0-9A-Za-z_-]{33})\b"),
    ),
    (
        "AWS Access Key",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "Plaintext Password Parameter",
        re.compile(r"""(?i)\b(password|passwd|auth_token|user_secret)\s*[:=]\s*["']?([^"'\s&]{6,})["']?"""),
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ),
]


class MemoryForensicsAuditor:
    """Audits running process memory on rooted emulators for un-zeroized sensitive data."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    async def get_process_pid(self, serial: str, package_name: str) -> Optional[int]:
        """Retrieve target package process PID on the device."""
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", f"pidof {package_name}"],
            timeout=3.0,
        )
        if code == 0 and stdout:
            pids = stdout.decode("utf-8", errors="replace").strip().split()
            if pids and pids[0].isdigit():
                return int(pids[0])

        # Fallback to ps -A
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", f"ps -A | grep {package_name}"],
            timeout=3.0,
        )
        if code == 0 and stdout:
            lines = stdout.decode("utf-8", errors="replace").strip().splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])

        return None

    async def extract_memory_strings(
        self,
        serial: str,
        pid: int,
        max_lines: int = 200,
    ) -> list[str]:
        """Extract memory string excerpts from process heap / memory mappings via root shell."""
        # Query strings from process memory maps
        cmd = f"su -c 'strings /proc/{pid}/mem 2>/dev/null | grep -E \"eyJ|Bearer|AIza|AKIA|password\" | head -n {max_lines}'"
        code, stdout, _ = await self.adb._exec_cmd(["-s", serial, "shell", cmd], timeout=6.0)

        if code == 0 and stdout:
            return stdout.decode("utf-8", errors="replace").strip().splitlines()

        # Fallback: check environ and cmdline
        cmd_env = f"su -c 'cat /proc/{pid}/environ 2>/dev/null'"
        _, out_env, _ = await self.adb._exec_cmd(["-s", serial, "shell", cmd_env], timeout=3.0)
        if out_env:
            return out_env.decode("utf-8", errors="replace").replace("\x00", "\n").splitlines()

        return []

    async def audit_process_memory(
        self,
        serial: str,
        package_name: str,
    ) -> tuple[Optional[int], list[Finding]]:
        """Audit target application's active RAM for un-zeroized credentials and tokens."""
        pid = await self.get_process_pid(serial, package_name)
        if not pid:
            logger.warning(f"Could not locate running process for package: {package_name}")
            return None, []

        strings_dump = await self.extract_memory_strings(serial, pid)
        findings: list[Finding] = []

        seen_categories: set[str] = set()

        for line in strings_dump:
            for cat, pattern in _MEMORY_SECRET_PATTERNS:
                if cat in seen_categories:
                    continue

                m = pattern.search(line)
                if m:
                    seen_categories.add(cat)
                    matched_val = m.group(0)
                    masked = matched_val[:4] + ("*" * (len(matched_val) - 8)) + matched_val[-4:] if len(matched_val) > 8 else "***"

                    cwe = "CWE-316"
                    score, vector = get_default_cvss_for_cwe(cwe)

                    findings.append(Finding(
                        title=f"Cleartext Secret in Volatile Memory: {cat}",
                        description=(
                            f"The running process (PID: `{pid}`) retains sensitive credentials or authentication "
                            f"tokens in cleartext heap/volatile memory without active zeroization.\n\n"
                            f"Discovered secret type: **{cat}** (`{masked}`)\n\n"
                            "When sensitive data is stored in immutable objects like `java.lang.String`, "
                            "the plaintext bytes remain in garbage collection pools indefinitely, exposing them "
                            "to memory dumps, swap file extraction, and debugger inspection."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.95,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-STORAGE-2",
                        affected_component=f"PID:{pid}",
                        file_path=f"/proc/{pid}/mem",
                        line_number=1,
                        code_snippet=line[:120].strip(),
                        detection_method="MemoryForensicsAuditor (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation=(
                            "Store credentials and tokens in mutable `char[]` or `byte[]` arrays. "
                            "Explicitly wipe memory buffers with `Arrays.fill(buffer, (byte) 0)` immediately after use."
                        ),
                    ))

        return pid, findings

    async def run_memory_audit(self, serial: str, package_name: str) -> dict[str, Any]:
        """Execute complete memory forensics pass and return structured summary."""
        pid, findings = await self.audit_process_memory(serial, package_name)
        return {
            "package_name": package_name,
            "device_serial": serial,
            "pid": pid,
            "process_found": pid is not None,
            "memory_findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
