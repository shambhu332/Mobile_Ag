"""Bounded ContentProvider probes that report observations, not proof.

ADB read/query success and SQL parser errors are not by themselves evidence of
unauthorized disclosure or injection; classification requires comparison with
the provider contract and synthetic control data.
"""
from __future__ import annotations

import shutil
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from mobileag.reporting.finding import Finding


@dataclass
class ProviderFuzzResult:
    authority: str
    target_uri: str
    action: str  # query, read
    payload: str
    status: str  # OBSERVATION_* or ACCESS_DENIED/NOT_FOUND/ERROR; never a vulnerability verdict alone
    # Raw provider output can contain private rows; never include it in result records.
    output_snippet: str = ""
    error_message: Optional[str] = None


class ContentProviderFuzzer:
    """Dynamic fuzzer for exported ContentProviders using ADB commands."""

    TRAVERSAL_PAYLOADS = [
        "../../../../../../data/data/{pkg}/databases/{pkg}.db",
        "../../../../../../data/data/{pkg}/shared_prefs/{pkg}_preferences.xml",
        "../../../../../../etc/hosts",
    ]

    SQLI_PROBES = [
        "' OR '1'='1",
        "1 UNION SELECT 1, sqlite_version(), 3--",
    ]
    MAX_TIMEOUT_SECONDS = 15
    MAX_AUTHORITY_LENGTH = 255
    MAX_PACKAGE_LENGTH = 255

    def __init__(self, adb_path: Optional[str] = None):
        self.adb_path = adb_path or shutil.which("adb") or "/usr/bin/adb"

    def fuzz_provider_traversal(
        self, authority: str, package_name: str, timeout: float = 5.0, *,
        serial: Optional[str] = None, guard=None,
    ) -> List[ProviderFuzzResult]:
        """Test ContentProvider for path traversal leaks using `content read`."""
        results: List[ProviderFuzzResult] = []

        if not self._valid_probe_inputs(authority, timeout):
            return [ProviderFuzzResult(authority=str(authority)[:self.MAX_AUTHORITY_LENGTH],
                target_uri="", action="read", payload="", status="INVALID_INPUT")]
        if not self._has_explicit_scope(serial, guard):
            return [ProviderFuzzResult(authority=str(authority)[:self.MAX_AUTHORITY_LENGTH],
                target_uri="", action="read", payload="", status="BLOCKED_SCOPE")]
        if (not isinstance(package_name, str) or len(package_name) > self.MAX_PACKAGE_LENGTH
                or not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_name)):
            return [ProviderFuzzResult(authority=authority, target_uri="", action="read",
                payload="", status="INVALID_INPUT")]

        for template in self.TRAVERSAL_PAYLOADS:
            payload = template.format(pkg=package_name)
            uri = f"content://{authority}/{payload}"
            if not self._scope_allows(guard):
                results.append(ProviderFuzzResult(authority=authority, target_uri=uri,
                    action="read", payload=payload, status="BLOCKED_SCOPE"))
                continue
            cmd = self._adb_command(serial, ["content", "read", "--uri", uri])

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                output = proc.stdout.strip()
                err = proc.stderr.strip()

                if proc.returncode == 0 and len(output) > 0 and "SecurityException" not in err and "Permission Denial" not in err:
                    # Readability is an observation, not proof that the rows are
                    # sensitive, unauthorized, or outside the provider contract.
                    status = "OBSERVED_READABLE"
                elif "SecurityException" in err or "Permission Denial" in err:
                    status = "ACCESS_DENIED"
                elif "FileNotFoundException" in err or "does not exist" in err:
                    status = "NOT_FOUND"
                else:
                    status = "INCONCLUSIVE"

                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="read",
                    payload=payload,
                    status=status,
                    output_snippet="",
                    error_message="Provider command returned an error; raw output omitted." if err else None,
                ))
            except Exception as ex:
                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="read",
                    payload=payload,
                    status="TIMEOUT" if isinstance(ex, subprocess.TimeoutExpired) else "ERROR",
                    error_message=type(ex).__name__,
                ))

        return results

    def fuzz_provider_sqli(
        self, authority: str, projection_param: str = "", timeout: float = 5.0, *,
        serial: Optional[str] = None, guard=None,
    ) -> List[ProviderFuzzResult]:
        """Test ContentProvider projection/selection parameters for SQL injection using `content query`."""
        results: List[ProviderFuzzResult] = []

        if not self._valid_probe_inputs(authority, timeout):
            return [ProviderFuzzResult(authority=str(authority)[:self.MAX_AUTHORITY_LENGTH],
                target_uri="", action="query", payload="", status="INVALID_INPUT")]
        if not self._has_explicit_scope(serial, guard):
            return [ProviderFuzzResult(authority=str(authority)[:self.MAX_AUTHORITY_LENGTH],
                target_uri="", action="query", payload="", status="BLOCKED_SCOPE")]

        for probe in self.SQLI_PROBES:
            uri = f"content://{authority}"
            if not self._scope_allows(guard):
                results.append(ProviderFuzzResult(authority=authority, target_uri=uri,
                    action="query", payload=probe, status="BLOCKED_SCOPE"))
                continue
            cmd = self._adb_command(serial, ["content", "query", "--uri", uri, "--where", f"id={probe}"])

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                output = proc.stdout.strip()
                err = proc.stderr.strip()

                # If query succeeds or reflects SQL error syntax rather than SecurityException
                if "sqlite" in err.lower() or "syntax error" in err.lower():
                    status = "SQL_ERROR_OBSERVED"
                elif proc.returncode == 0 and "Row:" in output:
                    status = "QUERY_RESULT_OBSERVED"
                elif "SecurityException" in err or "Permission Denial" in err:
                    status = "ACCESS_DENIED"
                else:
                    status = "INCONCLUSIVE"

                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="query",
                    payload=probe,
                    status=status,
                    output_snippet="",
                    error_message="Provider command returned an error; raw output omitted." if err else None,
                ))
            except Exception as ex:
                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="query",
                    payload=probe,
                    status="TIMEOUT" if isinstance(ex, subprocess.TimeoutExpired) else "ERROR",
                    error_message=type(ex).__name__,
                ))

        return results

    @classmethod
    def _valid_probe_inputs(cls, authority, timeout) -> bool:
        return bool(
            isinstance(authority, str) and len(authority) <= cls.MAX_AUTHORITY_LENGTH
            and re.fullmatch(r"[A-Za-z0-9._-]+", authority)
            and isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
            and 0 < timeout <= cls.MAX_TIMEOUT_SECONDS
        )

    @staticmethod
    def _has_explicit_scope(serial, guard) -> bool:
        return bool(isinstance(serial, str) and serial.strip() and callable(guard))

    @staticmethod
    def _scope_allows(guard) -> bool:
        try:
            guard()
            return True
        except Exception:
            return False

    def _adb_command(self, serial: str, remote_args: list[str]) -> list[str]:
        """Bind ADB to the selected serial and quote each device-shell argument."""
        return [self.adb_path, "-s", serial.strip(), "shell", shlex.join(remote_args)]
