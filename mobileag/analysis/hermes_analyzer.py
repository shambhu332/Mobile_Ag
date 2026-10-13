"""React Native Hermes Bytecode (.hbc) Analyzer.

Inspects React Native bundles compiled into Hermes bytecode (index.android.bundle),
verifies the Hermes binary magic header (0x1F480120), extracts embedded string tables,
identifies API endpoints, hardcoded credentials, and function metadata.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class HermesAnalysisResult:
    is_hermes: bool = False
    bytecode_version: Optional[int] = None
    file_size_bytes: int = 0
    string_count: int = 0
    function_count: int = 0
    api_endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    extracted_strings: List[str] = field(default_factory=list)


class HermesBytecodeAnalyzer:
    """Parses Hermes bytecode (.hbc) headers and extracts embedded string literals."""

    HERMES_MAGIC = 0x1F480120  # Hermes 64-bit magic header in little endian

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    SECRET_PATTERN = re.compile(
        r"(?:api_?key|auth_?token|bearer|secret|password|access_?token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']",
        re.IGNORECASE,
    )

    def analyze_bundle(self, bundle_path: str | Path) -> HermesAnalysisResult:
        """Parse a Hermes bundle file."""
        path = Path(bundle_path)
        result = HermesAnalysisResult()

        if not path.is_file():
            return result

        result.file_size_bytes = path.stat().st_size

        try:
            with open(path, "rb") as f:
                header = f.read(32)
        except OSError:
            return result

        if len(header) < 12:
            return result

        # Check Hermes magic number (uint64)
        magic = struct.unpack("<Q", header[:8])[0]
        if magic != self.HERMES_MAGIC:
            return result

        result.is_hermes = True
        result.bytecode_version = struct.unpack("<I", header[8:12])[0]

        # Extract ASCII and UTF-8 string tables from binary bundle
        self._extract_strings_and_secrets(path, result)
        return result

    def _extract_strings_and_secrets(self, path: Path, result: HermesAnalysisResult) -> None:
        """Extract string literals and identify sensitive patterns."""
        try:
            with open(path, "rb") as f:
                data = f.read(15 * 1024 * 1024)  # Read up to 15MB
        except OSError:
            return

        # Find printable ASCII/UTF-8 strings of 4+ characters
        raw_matches = re.findall(b"[\x20-\x7E]{4,}", data)
        result.string_count = len(raw_matches)

        endpoints: Set[str] = set()
        strings_sample: List[str] = []

        for m in raw_matches:
            try:
                s = m.decode("utf-8", errors="ignore")
            except Exception:
                continue

            if len(strings_sample) < 500:
                strings_sample.append(s)

            for url in self.URL_PATTERN.findall(s):
                if not url.endswith((".png", ".jpg", ".svg", ".ttf", ".woff", ".webp")):
                    endpoints.add(url)

            secret_match = self.SECRET_PATTERN.search(s)
            if secret_match:
                result.secrets.append({
                    "raw": s[:80],
                    "candidate": secret_match.group(1),
                })

        result.api_endpoints = sorted(endpoints)[:100]
        result.extracted_strings = strings_sample[:100]

    def audit_package_bundles(self, extracted_dir: str | Path) -> List[HermesAnalysisResult]:
        """Find and audit any React Native bundles inside an extracted APK."""
        results: List[HermesAnalysisResult] = []
        base = Path(extracted_dir)

        # Typical locations: assets/index.android.bundle
        candidate_files = [
            base / "assets" / "index.android.bundle",
            base / "assets" / "index.bundle",
        ]

        for cand in candidate_files:
            if cand.is_file():
                results.append(self.analyze_bundle(cand))

        return results
