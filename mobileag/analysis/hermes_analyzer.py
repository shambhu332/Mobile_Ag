"""React Native Hermes Bytecode (.hbc) Analyzer.

Inspects React Native bundles compiled into Hermes bytecode (index.android.bundle),
verifies the Hermes binary magic header (0x1F480120), extracts embedded string tables,
identifies API endpoints, hardcoded credentials, and function metadata.
"""
from __future__ import annotations

import os
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from mobileag.analysis.bounded_sources import explicit_scan_root
from mobileag.analysis.api_endpoint_safety import safe_api_route
from typing import Dict, List, Optional, Set


@dataclass
class HermesAnalysisResult:
    is_hermes: bool = False
    bytecode_version: Optional[int] = None
    file_size_bytes: int = 0
    string_count: int = 0
    # Function count is unknown until a real bytecode table parser is implemented.
    function_count: Optional[int] = None
    api_endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, object]] = field(default_factory=list)
    extracted_strings: List[str] = field(default_factory=list)
    scan_status: str = "not_started"
    bytes_scanned: int = 0
    scan_truncated: bool = False
    candidate_output_truncated: bool = False
    scan_errors: List[str] = field(default_factory=list)


class HermesBytecodeAnalyzer:
    """Parses Hermes bytecode (.hbc) headers and extracts embedded string literals."""

    HERMES_MAGIC = 0x1F480120  # Hermes 64-bit magic header in little endian
    MAX_BUNDLE_BYTES = 15 * 1024 * 1024
    MAX_PRINTABLE_STRINGS = 100_000
    MAX_EXTRACTED_STRINGS = 100
    MAX_API_ENDPOINTS = 100

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    SECRET_PATTERN = re.compile(
        r"(?:api_?key|auth_?token|bearer|secret|password|access_?token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']",
        re.IGNORECASE,
    )

    def analyze_bundle(self, bundle_path: str | Path) -> HermesAnalysisResult:
        """Parse a Hermes bundle file."""
        path = Path(bundle_path)
        result = HermesAnalysisResult()

        if path.is_symlink():
            result.scan_status = "invalid"
            result.scan_errors.append("symlink_bundle_skipped")
            return result
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                details = os.fstat(f.fileno())
                if not stat.S_ISREG(details.st_mode):
                    result.scan_status = "invalid"
                    result.scan_errors.append("non_regular_bundle_skipped")
                    return result
                result.file_size_bytes = details.st_size
                data = f.read(self.MAX_BUNDLE_BYTES + 1)
        except OSError:
            result.scan_status = "invalid"
            result.scan_errors.append("bundle_read_error")
            return result

        if len(data) > self.MAX_BUNDLE_BYTES:
            result.scan_truncated = True
            data = data[:self.MAX_BUNDLE_BYTES]
        result.bytes_scanned = len(data)
        result.scan_status = "partial" if result.scan_truncated else "complete"

        if len(data) < 12:
            return result

        # Check Hermes magic number (uint64)
        magic = struct.unpack("<Q", data[:8])[0]
        if magic != self.HERMES_MAGIC:
            return result

        result.is_hermes = True
        result.bytecode_version = struct.unpack("<I", data[8:12])[0]

        # This bounded printable-string pass is not a Hermes string-table parser.
        self._extract_strings_and_secrets(data, result)
        if result.candidate_output_truncated:
            result.scan_status = "partial"
        return result

    def _extract_strings_and_secrets(self, data: bytes, result: HermesAnalysisResult) -> None:
        """Extract string literals and identify sensitive patterns."""
        endpoints: Set[str] = set()
        strings_sample: List[str] = []
        secret_marker_added = False

        def mark_truncated(reason: str) -> None:
            result.candidate_output_truncated = True
            if reason not in result.scan_errors:
                result.scan_errors.append(reason)

        # Iterate rather than materializing every match from a potentially dense
        # binary. Keep retained outputs bounded independently of the input size.
        for match in re.finditer(b"[\x20-\x7E]{4,}", data):
            if result.string_count >= self.MAX_PRINTABLE_STRINGS:
                mark_truncated("printable_string_limit")
                break
            result.string_count += 1
            s = match.group().decode("utf-8", errors="ignore")

            for url in self.URL_PATTERN.findall(s):
                safe_url = safe_api_route(url)
                if (safe_url != "[REDACTED URL]"
                        and not safe_url.endswith((".png", ".jpg", ".svg", ".ttf", ".woff", ".webp"))):
                    if len(endpoints) < self.MAX_API_ENDPOINTS:
                        endpoints.add(safe_url)
                    elif safe_url not in endpoints:
                        mark_truncated("api_endpoint_limit")

            secret_match = self.SECRET_PATTERN.search(s)
            safe_string = s
            if secret_match:
                # A candidate is enough to trigger manual review. Do not leak
                # the matched token or surrounding credential-bearing text.
                safe_string = self.SECRET_PATTERN.sub(
                    lambda item: item.group(0).replace(item.group(1), "[REDACTED]"), s,
                )
                if not secret_marker_added:
                    result.secrets.append({"name": "embedded credential", "value_redacted": True})
                    secret_marker_added = True
            if len(strings_sample) < self.MAX_EXTRACTED_STRINGS:
                strings_sample.append(safe_string)
            else:
                mark_truncated("string_sample_limit")

        result.api_endpoints = sorted(endpoints)[:100]
        result.extracted_strings = strings_sample

    def audit_package_bundles(self, extracted_dir: str | Path) -> List[HermesAnalysisResult]:
        """Find and audit any React Native bundles inside an extracted APK."""
        results: List[HermesAnalysisResult] = []
        base = explicit_scan_root(extracted_dir)
        if base is None or base.is_symlink() or not base.is_dir():
            return []

        # Typical locations: assets/index.android.bundle
        candidate_files = [
            base / "assets" / "index.android.bundle",
            base / "assets" / "index.bundle",
        ]

        for cand in candidate_files:
            if cand.is_file():
                results.append(self.analyze_bundle(cand))

        return results
