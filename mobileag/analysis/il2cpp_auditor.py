"""Unity IL2CPP Metadata & Binary Reconstructor.

Analyzes Unity applications compiled with IL2CPP (libil2cpp.so and global-metadata.dat).
Validates the IL2CPP metadata signature (0xFAB11BAF), extracts string literal pools,
and reconstructs C# class/method signatures.
"""
from __future__ import annotations

import os
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
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
    scan_status: str = "not_started"
    tree_entries_scanned: int = 0
    metadata_bytes_scanned: int = 0
    metadata_truncated: bool = False
    candidate_output_truncated: bool = False
    scan_errors: List[str] = field(default_factory=list)


class Il2CppAuditor:
    """Parses Unity IL2CPP binaries and global-metadata.dat structures."""

    IL2CPP_METADATA_MAGIC = 0xFAB11BAF
    MAX_TREE_ENTRIES = 50_000
    MAX_METADATA_BYTES = 10 * 1024 * 1024
    MAX_PRINTABLE_STRINGS = 100_000
    MAX_ENDPOINTS = 100
    MAX_CLASS_CANDIDATES = 50

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    SECRET_PATTERN = re.compile(
        r"(?:api_?key|auth_?token|bearer|secret|password)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']",
        re.IGNORECASE,
    )

    def audit_package(self, extracted_dir: str | Path) -> Il2CppAnalysisResult:
        """Scan extracted package for Unity IL2CPP assets and binaries."""
        base = explicit_scan_root(extracted_dir)
        result = Il2CppAnalysisResult()
        if base is None or base.is_symlink() or not base.is_dir():
            result.scan_status = "invalid"
            result.scan_errors.append("invalid_scan_root")
            return result

        lib_dir = base / "lib"
        metadata_file = base / "assets" / "bin" / "Data" / "Managed" / "Metadata" / "global-metadata.dat"

        # Check for libil2cpp.so
        inventory = SourceInventory(max_entries=self.MAX_TREE_ENTRIES, max_file_bytes=1,
                                    max_total_bytes=1)
        if lib_dir.is_symlink():
            result.scan_errors.append("symlink_library_directory_skipped")
        elif lib_dir.is_dir():
            for library in inventory.paths(lib_dir):
                if library.name == "libil2cpp.so":
                    result.libil2cpp_present = True
                    result.is_il2cpp = True

        result.tree_entries_scanned = inventory.coverage["entries_examined"]
        limited = inventory.coverage["limits_reached"]
        if limited:
            result.scan_errors.append("tree_entry_limit")
        if inventory.coverage["source_file_skip_reasons"].get("symlink_entry"):
            result.scan_errors.append("symlink_entry_skipped")
        if inventory.coverage["source_file_skip_reasons"].get("directory_read_error"):
            result.scan_errors.append("directory_scan_error")

        # Check for global-metadata.dat
        metadata_parent_symlink = False
        for parent in metadata_file.parents:
            if parent == base:
                break
            if parent.is_symlink():
                metadata_parent_symlink = True
                break
        if metadata_file.is_symlink() or metadata_parent_symlink:
            result.scan_errors.append("symlink_metadata_skipped")
        elif metadata_file.is_file():
            result.global_metadata_present = True
            result.is_il2cpp = True
            self._parse_metadata_file(metadata_file, result)

        result.scan_errors = sorted(set(result.scan_errors))
        result.scan_status = (
            "partial" if limited or result.scan_errors or result.metadata_truncated
            else "complete"
        )

        return result

    def _parse_metadata_file(self, metadata_path: Path, result: Il2CppAnalysisResult) -> None:
        """Parse global-metadata.dat header and string literal pools."""
        try:
            fd = os.open(metadata_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                details = os.fstat(f.fileno())
                if not stat.S_ISREG(details.st_mode):
                    result.scan_errors.append("non_regular_metadata_skipped")
                    return
                data = f.read(self.MAX_METADATA_BYTES + 1)
        except OSError:
            result.scan_errors.append("metadata_read_error")
            return

        if len(data) > self.MAX_METADATA_BYTES:
            result.metadata_truncated = True
            data = data[:self.MAX_METADATA_BYTES]
        result.metadata_bytes_scanned = len(data)

        if len(data) < 12:
            result.scan_errors.append("metadata_header_truncated")
            return

        magic, version = struct.unpack("<II", data[:8])
        if magic != self.IL2CPP_METADATA_MAGIC:
            result.scan_errors.append("metadata_magic_mismatch")
            return

        result.metadata_version = version
        # Printable strings are review candidates, not parsed IL2CPP tables.

        endpoints: Set[str] = set()
        classes: Set[str] = set()

        secret_marker_added = False
        def mark_truncated(reason: str) -> None:
            result.candidate_output_truncated = True
            if reason not in result.scan_errors:
                result.scan_errors.append(reason)

        for m in re.finditer(b"[\x20-\x7E]{4,}", data):
            if result.string_literals_count >= self.MAX_PRINTABLE_STRINGS:
                mark_truncated("printable_string_limit")
                break
            result.string_literals_count += 1
            s = m.group().decode("utf-8", errors="ignore")

            for url in self.URL_PATTERN.findall(s):
                if not url.endswith((".png", ".jpg", ".asset", ".unity")):
                    if len(endpoints) < self.MAX_ENDPOINTS:
                        endpoints.add(url)
                    elif url not in endpoints:
                        mark_truncated("api_endpoint_limit")

            secret_match = self.SECRET_PATTERN.search(s)
            if secret_match and not secret_marker_added:
                # Retain only a review marker; do not persist credential bytes.
                result.potential_secrets.append({"name": "embedded credential", "value_redacted": True})
                secret_marker_added = True

            # Detect class-like strings
            if re.match(r"^[A-Z][a-zA-Z0-9_]+Manager$|^[A-Z][a-zA-Z0-9_]+Controller$", s):
                if len(classes) < self.MAX_CLASS_CANDIDATES:
                    classes.add(s)
                elif s not in classes:
                    mark_truncated("class_candidate_limit")

        result.api_endpoints = sorted(endpoints)
        result.reconstructed_classes = sorted(classes)
