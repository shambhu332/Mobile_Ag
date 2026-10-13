"""ContentProvider Traversal and SQL Injection Dynamic Fuzzer.

Probes exported Android ContentProviders via ADB queries and reads to verify
arbitrary file access and SQL injection without relying on simulated guesses.
"""
from __future__ import annotations

import shutil
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
    status: str  # VULNERABLE, ACCESS_DENIED, NOT_FOUND, SAFE
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

    def __init__(self, adb_path: Optional[str] = None):
        self.adb_path = adb_path or shutil.which("adb") or "/usr/bin/adb"

    def fuzz_provider_traversal(self, authority: str, package_name: str, timeout: float = 5.0) -> List[ProviderFuzzResult]:
        """Test ContentProvider for path traversal leaks using `content read`."""
        results: List[ProviderFuzzResult] = []

        for template in self.TRAVERSAL_PAYLOADS:
            payload = template.format(pkg=package_name)
            uri = f"content://{authority}/{payload}"
            cmd = [self.adb_path, "shell", "content", "read", "--uri", uri]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                output = proc.stdout.strip()
                err = proc.stderr.strip()

                if proc.returncode == 0 and len(output) > 0 and "SecurityException" not in err and "Permission Denial" not in err:
                    status = "VULNERABLE"
                elif "SecurityException" in err or "Permission Denial" in err:
                    status = "ACCESS_DENIED"
                elif "FileNotFoundException" in err or "does not exist" in err:
                    status = "NOT_FOUND"
                else:
                    status = "SAFE"

                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="read",
                    payload=payload,
                    status=status,
                    output_snippet=output[:200] if output else err[:200],
                    error_message=err if err else None,
                ))
            except Exception as ex:
                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="read",
                    payload=payload,
                    status="TIMEOUT" if isinstance(ex, subprocess.TimeoutExpired) else "ERROR",
                    error_message=str(ex),
                ))

        return results

    def fuzz_provider_sqli(self, authority: str, projection_param: str = "", timeout: float = 5.0) -> List[ProviderFuzzResult]:
        """Test ContentProvider projection/selection parameters for SQL injection using `content query`."""
        results: List[ProviderFuzzResult] = []

        for probe in self.SQLI_PROBES:
            uri = f"content://{authority}"
            cmd = [self.adb_path, "shell", "content", "query", "--uri", uri, "--where", f"id={probe}"]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                output = proc.stdout.strip()
                err = proc.stderr.strip()

                # If query succeeds or reflects SQL error syntax rather than SecurityException
                if "sqlite" in err.lower() or "syntax error" in err.lower():
                    status = "VULNERABLE_SQL_SYNTAX"
                elif proc.returncode == 0 and "Row:" in output:
                    status = "VULNERABLE"
                elif "SecurityException" in err or "Permission Denial" in err:
                    status = "ACCESS_DENIED"
                else:
                    status = "SAFE"

                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="query",
                    payload=probe,
                    status=status,
                    output_snippet=output[:200] if output else err[:200],
                    error_message=err if err else None,
                ))
            except Exception as ex:
                results.append(ProviderFuzzResult(
                    authority=authority,
                    target_uri=uri,
                    action="query",
                    payload=probe,
                    status="TIMEOUT" if isinstance(ex, subprocess.TimeoutExpired) else "ERROR",
                    error_message=str(ex),
                ))

        return results
