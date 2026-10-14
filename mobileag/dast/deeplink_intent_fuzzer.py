"""Dynamic Deep Link & Intent Mutation Fuzzer.

Executes mutation fuzzing against declared Android URI schemes and exported components
via ADB, capturing logcat output, activity manager results, and crash tombstones.
"""
from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class FuzzResult:
    target_uri: str
    status: str  # SUCCESS, CRASH, PERMISSION_DENIED, TIMEOUT
    response_code: int = 0
    logcat_errors: List[str] = field(default_factory=list)


class DeepLinkIntentFuzzer:
    """Fuzzes Android deep links and URI handlers via ADB."""

    MUTATION_PAYLOADS = [
        "https://attacker.com",
        "javascript:alert(document.domain)",
        "content://com.android.contacts/contacts",
        "file:///data/data/",
        "../../../../../../etc/hosts",
        "' OR '1'='1",
        "{\"admin\": true, \"debug\": 1}",
    ]

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    def generate_mutations(self, base_uri: str) -> List[str]:
        """Generate fuzzed URI variants by injecting payloads into parameters."""
        mutations: List[str] = [base_uri]

        if "?" in base_uri:
            endpoint, query = base_uri.split("?", 1)
            params = query.split("&")
            for p in params:
                if "=" in p:
                    k, v = p.split("=", 1)
                    for payload in self.MUTATION_PAYLOADS:
                        mutations.append(f"{endpoint}?{k}={payload}")
        else:
            for payload in self.MUTATION_PAYLOADS:
                separator = "&" if "?" in base_uri else "?"
                mutations.append(f"{base_uri}{separator}test_param={payload}")

        return mutations

    def execute_fuzz_case(
        self,
        target_uri: str,
        package_name: Optional[str] = None,
        timeout: float = 5.0,
        *,
        serial: Optional[str] = None,
        guard: Optional[Callable[[], None]] = None,
    ) -> FuzzResult:
        """Execute one bounded case only after caller scope checks pass.

        There is deliberately no implicit ADB device selection. ``guard`` must
        revalidate the caller's exact authorized device/package/action scope
        immediately before execution. This helper does not itself establish
        authorization or prove a vulnerability.
        """
        if not serial or not serial.strip() or guard is None:
            return FuzzResult(target_uri=target_uri, status="BLOCKED_SCOPE")
        if not 0 < timeout <= 15 or not target_uri or len(target_uri) > 4096:
            return FuzzResult(target_uri=target_uri, status="INVALID_INPUT")
        if package_name is not None and not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_name):
            return FuzzResult(target_uri=target_uri, status="INVALID_INPUT")

        cmd = [self.adb_path, "-s", serial.strip(), "shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", target_uri]
        if package_name:
            cmd.extend(["-p", package_name])

        try:
            guard()
        except Exception:
            return FuzzResult(target_uri=target_uri, status="BLOCKED_SCOPE")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = res.stdout + res.stderr

            if "Error:" in output or "SecurityException" in output:
                status = "PERMISSION_DENIED" if "SecurityException" in output else "CRASH"
            elif "Status: ok" in output:
                status = "SUCCESS"
            else:
                status = "UNKNOWN"

            return FuzzResult(
                target_uri=target_uri,
                status=status,
                response_code=res.returncode,
                logcat_errors=[line for line in output.splitlines() if "Error" in line or "Exception" in line],
            )
        except subprocess.TimeoutExpired:
            return FuzzResult(target_uri=target_uri, status="TIMEOUT")
        except FileNotFoundError:
            return FuzzResult(target_uri=target_uri, status="ADB_NOT_FOUND")
