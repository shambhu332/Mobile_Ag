"""Scoped, bounded deep-link launch probes via ADB.

The helper reports activity-manager command observations only. It does not
collect logcat, crash tombstones, or proof of vulnerability.
"""
from __future__ import annotations

import inspect
import subprocess
import re
import shlex
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from mobileag.analysis.api_endpoint_safety import safe_api_route


@dataclass
class FuzzResult:
    target_uri: str
    status: str  # command observation, not an exploitability verdict
    response_code: int = 0
    logcat_errors: List[str] = field(default_factory=list)
    output_bytes_observed: int = 0
    output_truncated: bool = False


class DeepLinkIntentFuzzer:
    """Runs researcher-scoped Android deep-link launch probes via ADB."""

    MUTATION_PAYLOADS = [
        "https://mobileag.invalid/redirect-review-marker",
        "javascript:void(0)",
        "content://mobileag.invalid/synthetic/canary",
        "file:///mobileag-synthetic-nonexistent.txt",
        "../../mobileag_synthetic_canary.txt",
        "' OR 'mobileag_synthetic_canary'='mobileag_synthetic_canary",
        '{"mobileag_canary": "synthetic"}',
    ]
    MAX_URI_LENGTH = 4096
    MAX_QUERY_FIELDS = 64
    MAX_MUTATIONS = 449  # base plus 64 fields times seven payloads
    MAX_RETAINED_OUTPUT_BYTES = 4096

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    @staticmethod
    def _safe_target_uri(value: object) -> str:
        """Retain only a report-safe URI locator, never path/query values."""
        if not isinstance(value, str) or not value or len(value) > DeepLinkIntentFuzzer.MAX_URI_LENGTH:
            return "[REDACTED URI]"
        try:
            parsed = urlsplit(value)
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,31}", parsed.scheme):
                return "[REDACTED URI]"
            if parsed.scheme.lower() in {"http", "https"}:
                safe = safe_api_route(value)
                return safe if safe != "[REDACTED URL]" else "[REDACTED URI]"
            if parsed.netloc:
                host, port = parsed.hostname, parsed.port
                if not host:
                    return "[REDACTED URI]"
                host = f"[{host}]" if ":" in host and not host.startswith("[") else host
                authority = host + (f":{port}" if port is not None else "")
                return f"{parsed.scheme.lower()}://{authority}"
            return f"{parsed.scheme.lower()}:[REDACTED]"
        except (TypeError, ValueError, UnicodeError):
            return "[REDACTED URI]"

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
        synthetic_data_confirmed: bool = False,
    ) -> FuzzResult:
        """Execute one bounded case only after caller scope checks pass.

        There is deliberately no implicit ADB device selection. ``guard`` must
        revalidate the caller's exact authorized device/package/action scope
        immediately before execution. This helper does not itself establish
        authorization or prove a vulnerability.
        """
        evidence_uri = self._safe_target_uri(target_uri)
        if not isinstance(serial, str) or not serial.strip() or not callable(guard):
            return FuzzResult(target_uri=evidence_uri, status="BLOCKED_SCOPE")
        if synthetic_data_confirmed is not True:
            return FuzzResult(target_uri=evidence_uri, status="BLOCKED_SYNTHETIC_SCOPE")
        if (not isinstance(target_uri, str) or not 0 < timeout <= 15 or not target_uri
                or len(target_uri) > self.MAX_URI_LENGTH
                or "\x00" in target_uri):
            return FuzzResult(target_uri=evidence_uri, status="INVALID_INPUT")
        if package_name is not None and (not isinstance(package_name, str) or
                not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_name)):
            return FuzzResult(target_uri=evidence_uri, status="INVALID_INPUT")

        remote_args = ["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", target_uri]
        if package_name:
            remote_args.extend(["-p", package_name])
        # adb shell transports a command string to the device shell. Quote each
        # remote argument so URI metacharacters remain data, not shell syntax.
        cmd = [self.adb_path, "-s", serial.strip(), "shell", shlex.join(remote_args)]

        try:
            approved = guard()
            if inspect.isawaitable(approved):
                close = getattr(approved, "close", None)
                if callable(close):
                    close()
                return FuzzResult(target_uri=evidence_uri, status="BLOCKED_SCOPE")
            if approved is False:
                return FuzzResult(target_uri=evidence_uri, status="BLOCKED_SCOPE")
        except Exception:
            return FuzzResult(target_uri=evidence_uri, status="BLOCKED_SCOPE")
        try:
            returncode, stdout, stderr, output_bytes, truncated, timed_out = self._run_bounded(cmd, timeout)
            output = stdout + stderr

            if timed_out:
                status = "TIMEOUT"
            elif "SecurityException" in output:
                status = "PERMISSION_DENIED"
            elif "Error:" in output:
                status = "ERROR_OBSERVED"
            elif "Status: ok" in output:
                status = "SUCCESS"
            else:
                status = "UNKNOWN"

            return FuzzResult(
                target_uri=evidence_uri,
                status=status,
                response_code=returncode,
                # The launcher does not capture logcat; never retain raw
                # activity-manager output, which may echo private URI data.
                logcat_errors=[],
                output_bytes_observed=output_bytes,
                output_truncated=truncated,
            )
        except subprocess.TimeoutExpired:
            return FuzzResult(target_uri=evidence_uri, status="TIMEOUT")
        except FileNotFoundError:
            return FuzzResult(target_uri=evidence_uri, status="ADB_NOT_FOUND")

    def _run_bounded(self, cmd: list[str], timeout: float):
        """Drain ADB output concurrently and retain at most a small prefix."""
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        retained = [bytearray(), bytearray()]
        observed = [[0], [0]]

        def drain(stream, output: bytearray, count: list[int]) -> None:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                count[0] += len(chunk)
                remaining = self.MAX_RETAINED_OUTPUT_BYTES - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])

        threads = [
            threading.Thread(target=drain, args=(process.stdout, retained[0], observed[0]), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, retained[1], observed[1]), daemon=True),
        ]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                process.kill()
            except ProcessLookupError:
                pass
            returncode = process.wait()
        for thread in threads:
            thread.join(timeout=1)
        total = sum(count[0] for count in observed)
        truncated = (any(count[0] > self.MAX_RETAINED_OUTPUT_BYTES for count in observed)
                     or any(thread.is_alive() for thread in threads))
        return (
            returncode,
            retained[0].decode("utf-8", errors="replace"),
            retained[1].decode("utf-8", errors="replace"),
            total,
            truncated,
            timed_out,
        )
