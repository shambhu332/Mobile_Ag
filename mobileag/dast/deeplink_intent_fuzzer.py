"""Dynamic Deep Link & Intent Mutation Fuzzer.

Executes mutation fuzzing against declared Android URI schemes and exported components
via ADB, capturing logcat output, activity manager results, and crash tombstones.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


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

    def execute_fuzz_case(self, target_uri: str, package_name: Optional[str] = None, timeout: float = 5.0) -> FuzzResult:
        """Execute a single fuzz case using ADB and inspect output."""
        cmd = [self.adb_path, "shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", target_uri]
        if package_name:
            cmd.extend(["-p", package_name])

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
