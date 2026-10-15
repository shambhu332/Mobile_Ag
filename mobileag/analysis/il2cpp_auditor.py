"""Unity IL2CPP Metadata & Binary Reconstructor.

Analyzes Unity applications compiled with IL2CPP (libil2cpp.so and global-metadata.dat).
Validates the IL2CPP metadata signature (0xFAB11BAF), extracts string literal pools,
and reconstructs C# class/method signatures.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class Il2CppAnalysisResult:
    is_il2cpp: bool = False
    metadata_version: Optional[int] = None
    libil2cpp_present: bool = False
    global_metadata_present: bool = False
    string_literals_count: int = 0
    reconstructed_classes: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    potential_secrets: List[Dict[str, object]] = field(default_factory=list)


class Il2CppAuditor:
    """Parses Unity IL2CPP binaries and global-metadata.dat structures."""

    IL2CPP_METADATA_MAGIC = 0xFAB11BAF

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    SECRET_PATTERN = re.compile(
        r"(?:api_?key|auth_?token|bearer|secret|password)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']",
        re.IGNORECASE,
    )

    def audit_package(self, extracted_dir: str | Path) -> Il2CppAnalysisResult:
        """Scan extracted package for Unity IL2CPP assets and binaries."""
        base = Path(extracted_dir)
        result = Il2CppAnalysisResult()

        lib_dir = base / "lib"
        metadata_file = base / "assets" / "bin" / "Data" / "Managed" / "Metadata" / "global-metadata.dat"

        # Check for libil2cpp.so
        if lib_dir.is_dir():
            for root, _, files in os.walk(lib_dir):
                if "libil2cpp.so" in files:
                    result.libil2cpp_present = True
                    result.is_il2cpp = True
                    break

        # Check for global-metadata.dat
        if metadata_file.is_file():
            result.global_metadata_present = True
            result.is_il2cpp = True
            self._parse_metadata_file(metadata_file, result)

        return result

    def _parse_metadata_file(self, metadata_path: Path, result: Il2CppAnalysisResult) -> None:
        """Parse global-metadata.dat header and string literal pools."""
        try:
            with open(metadata_path, "rb") as f:
                header = f.read(64)
        except OSError:
            return

        if len(header) < 12:
            return

        magic, version = struct.unpack("<II", header[:8])
        if magic != self.IL2CPP_METADATA_MAGIC:
            return

        result.metadata_version = version

        # Scan string literal pool
        try:
            with open(metadata_path, "rb") as f:
                data = f.read(10 * 1024 * 1024)  # Read up to 10MB
        except OSError:
            return

        raw_strings = re.findall(b"[\x20-\x7E]{4,}", data)
        result.string_literals_count = len(raw_strings)

        endpoints: Set[str] = set()
        classes: Set[str] = set()

        for m in raw_strings:
            try:
                s = m.decode("utf-8", errors="ignore")
            except Exception:
                continue

            for url in self.URL_PATTERN.findall(s):
                if not url.endswith((".png", ".jpg", ".asset", ".unity")):
                    endpoints.add(url)

            secret_match = self.SECRET_PATTERN.search(s)
            if secret_match:
                # Retain only a review marker; do not persist credential bytes.
                result.potential_secrets.append({"name": "embedded credential", "value_redacted": True})

            # Detect class-like strings
            if re.match(r"^[A-Z][a-zA-Z0-9_]+Manager$|^[A-Z][a-zA-Z0-9_]+Controller$", s):
                classes.add(s)

        result.api_endpoints = sorted(endpoints)[:100]
        result.reconstructed_classes = sorted(classes)[:50]
