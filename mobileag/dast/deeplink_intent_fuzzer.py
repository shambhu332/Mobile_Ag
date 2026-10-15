"""Dynamic Deep Link & Intent Mutation Fuzzer.

Executes mutation fuzzing against declared Android URI schemes and exported components
via ADB, capturing logcat output, activity manager results, and crash tombstones.
"""
from __future__ import annotations

import subprocess
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


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
    MAX_URI_LENGTH = 4096
    MAX_QUERY_FIELDS = 64
    MAX_MUTATIONS = 449  # base plus 64 fields times seven payloads

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    def generate_mutations(self, base_uri: str) -> List[str]:
        """Generate a bounded set of properly encoded query-value mutations."""
        if not isinstance(base_uri, str) or not base_uri or len(base_uri) > self.MAX_URI_LENGTH:
            return []
        try:
            parsed = urlsplit(base_uri)
            hostname, port = parsed.hostname, parsed.port
            query_params = parse_qsl(
                parsed.query, keep_blank_values=True, max_num_fields=self.MAX_QUERY_FIELDS
            )
        except (TypeError, ValueError):
            return []
        if parsed.scheme.lower() in {"http", "https"} and not hostname:
            return []

        mutations: List[str] = [base_uri]
        if not query_params:
            query_params = [("test_param", "")]
        for index, (name, old_value) in enumerate(query_params):
            for payload in self.MUTATION_PAYLOADS:
                changed = list(query_params)
                changed[index] = (name, payload)
                mutated = urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path,
                    urlencode(changed, doseq=True), parsed.fragment,
                ))
                if len(mutated) <= self.MAX_URI_LENGTH:
                    mutations.append(mutated)
        # The input query cap and fixed payload count provide this bound; keep
        # an explicit slice as a guard against future payload-suite growth.
        return list(dict.fromkeys(mutations))[:self.MAX_MUTATIONS]

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
        if (not 0 < timeout <= 15 or not target_uri or len(target_uri) > self.MAX_URI_LENGTH
                or "\x00" in target_uri):
            return FuzzResult(target_uri=target_uri, status="INVALID_INPUT")
        if package_name is not None and not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_name):
            return FuzzResult(target_uri=target_uri, status="INVALID_INPUT")

        remote_args = ["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", target_uri]
        if package_name:
            remote_args.extend(["-p", package_name])
        # adb shell transports a command string to the device shell. Quote each
        # remote argument so URI metacharacters remain data, not shell syntax.
        cmd = [self.adb_path, "-s", serial.strip(), "shell", shlex.join(remote_args)]

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
