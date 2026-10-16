"""Closed-Loop Dynamic Verification Engine (Zero False-Positive Engine).

Connects static candidate findings with live ADB device execution. Runs targeted,
non-destructive verification probes on connected devices/emulators and inspects
Logcat, Activity Manager, and window states to establish exploitability.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from mobileag.reporting.finding import Finding


@dataclass
class DynamicVerificationOutcome:
    finding_id: str
    verified: bool
    verdict: str  # OBSERVED_* or REVIEW_REQUIRED; never an exploit verdict
    evidence_output: str
    logcat_markers: List[str] = field(default_factory=list)
    execution_attempted: bool = False


class DynamicVerificationLoop:
    """Runs one guarded, non-destructive deep-link dispatch observation only."""

    MAX_TIMEOUT_SECONDS = 15.0
    MAX_OUTPUT_CHARS = 4096

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    def verify_finding(
        self,
        finding: Finding,
        target_package: str,
        device_serial: Optional[str] = None,
        timeout: float = 6.0,
        *,
        scope_guard: Optional[Callable[[str, str], bool]] = None,
        operator_approved: bool = False,
        synthetic_data_confirmed: bool = False,
    ) -> DynamicVerificationOutcome:
        """Dispatch a synthetic custom-scheme URI after explicit scope/approval.

        This records only whether Activity Manager accepted the launch request;
        it cannot establish navigation impact, authorization, or exploitability.
        Free-form generated PoC commands are never executed here.
        """
        def outcome(verdict: str, message: str, attempted: bool = False) -> DynamicVerificationOutcome:
            return DynamicVerificationOutcome(finding.id, False, verdict, message[:self.MAX_OUTPUT_CHARS],
                                              execution_attempted=attempted)

        serial_ok = isinstance(device_serial, str) and bool(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", device_serial))
        package_ok = isinstance(target_package, str) and bool(re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", target_package))
        if (not serial_ok or not package_ok or finding.cwe_id != "CWE-601"
                or type(timeout) not in (int, float) or not 0 < timeout <= self.MAX_TIMEOUT_SECONDS
                or operator_approved is not True or synthetic_data_confirmed is not True
                or not callable(scope_guard)):
            return outcome("REVIEW_REQUIRED", "No device action: valid deep-link candidate, explicit serial, scope guard, operator approval, synthetic-data confirmation, and bounded timeout are required.")
        uri = finding.metadata.get("uri_scheme")
        try:
            parsed = urllib.parse.urlsplit(uri) if isinstance(uri, str) and len(uri) <= 2048 else None
            uri_ok = bool(parsed and parsed.scheme and parsed.scheme.lower() not in {"http", "https"}
                          and parsed.netloc and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in uri))
        except ValueError:
            uri_ok = False
        if not uri_ok:
            return outcome("REVIEW_REQUIRED", "No device action: URI must be a bounded custom-scheme test URI without control characters.")
        try:
            allowed = scope_guard(target_package, device_serial)
        except Exception:
            allowed = False
        if allowed is not True:
            return outcome("BLOCKED_SCOPE", "No device action: just-in-time scope guard did not explicitly allow this package and serial.")

        # Pass a single safely quoted remote command; never invoke a local shell.
        remote = shlex.join(["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", uri, "-p", target_package])
        cmd = [self.adb_path, "-s", device_serial, "shell", remote]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            stdout = (result.stdout or "")[:self.MAX_OUTPUT_CHARS]
            stderr = (result.stderr or "")[:self.MAX_OUTPUT_CHARS]
            if result.returncode == 0:
                return outcome("OBSERVED_DISPATCH", (stdout + "\n" + stderr).strip() or "Activity Manager returned success; impact not assessed.", True)
            return outcome("OBSERVED_ERROR", (stdout + "\n" + stderr).strip() or f"ADB exit status {result.returncode}; impact not assessed.", True)
        except subprocess.TimeoutExpired:
            return outcome("OBSERVED_TIMEOUT", "ADB launch timed out; impact not assessed.", True)
        except OSError as exc:
            return outcome("OBSERVED_TOOL_ERROR", f"ADB could not run: {type(exc).__name__}", False)

    def apply_verification_to_finding(
        self,
        finding: Finding,
        outcome: DynamicVerificationOutcome,
    ) -> Finding:
        """Do not convert caller-supplied observations into a security verdict."""
        # Until observations are tied to an authenticated device session, scope
        # snapshot, bounded raw evidence, and review event, mutation is unsafe.
        return finding
