"""Bounded Unity IL2CPP metadata and binary indicators.

The current structured parser validates version-29 string-literal ranges. Other
versions use bounded printable-string heuristics; type/method reconstruction
is not implemented, and class-looking strings remain lexical candidates.
"""
from __future__ import annotations

import os
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
from typing import Callable, Dict, List, Optional, Set


@dataclass
class Il2CppAnalysisResult:
    is_il2cpp: bool = False
    metadata_version: Optional[int] = None
    metadata_tables_status: str = "not_attempted"
    metadata_string_literals_count: int = 0
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
    SUPPORTED_STRING_TABLE_VERSIONS = {29}
    V29_HEADER_MIN_BYTES = 256
    MAX_STRING_LITERAL_TABLE_BYTES = 4 * 1024 * 1024
    MAX_STRING_LITERAL_ITEMS = 50_000
    MAX_STRING_LITERAL_BYTES = 4 * 1024 * 1024
    MAX_STRING_LITERAL_LENGTH = 4096

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
                identity = (details.st_dev, details.st_ino, details.st_size,
                            details.st_mtime_ns, details.st_ctime_ns)
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
        endpoints: Set[str] = set()
        classes: Set[str] = set()
        secret_marker_added = [False]

        def mark_truncated(reason: str) -> None:
            result.candidate_output_truncated = True
            if reason not in result.scan_errors:
                result.scan_errors.append(reason)

        def collect_candidate(value: str) -> None:
            for url in self.URL_PATTERN.findall(value):
                if not url.endswith((".png", ".jpg", ".asset", ".unity")):
                    if len(endpoints) < self.MAX_ENDPOINTS:
                        endpoints.add(url)
                    elif url not in endpoints:
                        mark_truncated("api_endpoint_limit")
            if self.SECRET_PATTERN.search(value) and not secret_marker_added[0]:
                result.potential_secrets.append({"name": "embedded credential", "value_redacted": True})
                secret_marker_added[0] = True
            if re.match(r"^[A-Z][a-zA-Z0-9_]+Manager$|^[A-Z][a-zA-Z0-9_]+Controller$", value):
                if len(classes) < self.MAX_CLASS_CANDIDATES:
                    classes.add(value)
                elif value not in classes:
                    mark_truncated("class_candidate_limit")

        result.metadata_tables_status = self._parse_string_literal_table(
            metadata_path, result, identity, collect_candidate,
        )
        if result.metadata_tables_status == "partial":
            result.scan_errors.append("string_literal_table_partial")
        elif result.metadata_tables_status == "invalid":
            result.scan_errors.append("string_literal_table_invalid")

        if result.metadata_tables_status != "parsed":
            # Non-v29/invalid inputs retain the explicitly lexical fallback.
            for match in re.finditer(b"[\\x20-\\x7E]{4,}", data):
                if result.string_literals_count >= self.MAX_PRINTABLE_STRINGS:
                    mark_truncated("printable_string_limit")
                    break
                result.string_literals_count += 1
                collect_candidate(match.group().decode("utf-8", errors="ignore"))
        else:
            result.string_literals_count = result.metadata_string_literals_count

        result.api_endpoints = sorted(endpoints)
        result.reconstructed_classes = sorted(classes)

    def _parse_string_literal_table(
        self, metadata_path: Path, result: Il2CppAnalysisResult,
        expected_identity: tuple[int, ...], candidate_sink: Callable[[str], None],
    ) -> str:
        """Validate and count v29 string-literal records without retaining values.

        The first two offset/count pairs follow the v29 GlobalMetadata header.
        Other versions are deliberately left as unsupported rather than guessed.
        Layout reference: Unity 2021.3.40f1 GlobalMetadataFileInternals.h at
        https://github.com/xog1/il2cpp/blob/6a0ffab36733ff525dc9da2e657dd5c803c4d0f6/2021.3.40f1/libil2cpp/vm/GlobalMetadataFileInternals.h
        """
        if result.metadata_version not in self.SUPPORTED_STRING_TABLE_VERSIONS:
            return "unsupported_version"
        fd = -1
        try:
            fd = os.open(metadata_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            details = os.fstat(fd)
            if not stat.S_ISREG(details.st_mode):
                return "invalid"
            identity = (details.st_dev, details.st_ino, details.st_size,
                        details.st_mtime_ns, details.st_ctime_ns)
            if identity != expected_identity:
                return "partial"
            if details.st_size < 24:
                return "invalid"
            header = os.pread(fd, 24, 0)
            if len(header) != 24:
                return "partial"
            magic, version, table_offset, table_size, data_offset, data_size = struct.unpack("<6I", header)
            if magic != self.IL2CPP_METADATA_MAGIC or version != 29:
                return "invalid"
            if (table_offset < self.V29_HEADER_MIN_BYTES or table_size % 8 != 0
                    or table_size > self.MAX_STRING_LITERAL_TABLE_BYTES
                    or data_offset < self.V29_HEADER_MIN_BYTES or table_offset + table_size > details.st_size
                    or data_offset + data_size > details.st_size):
                return "invalid"
            table = os.pread(fd, table_size, table_offset)
            if len(table) != table_size:
                return "partial"
            if table_size // 8 > self.MAX_STRING_LITERAL_ITEMS:
                table = table[:self.MAX_STRING_LITERAL_ITEMS * 8]
                result.candidate_output_truncated = True
                partial = True
            else:
                partial = False
            total_literal_bytes = 0
            for entry_offset in range(0, len(table), 8):
                length, data_index = struct.unpack_from("<II", table, entry_offset)
                if length > self.MAX_STRING_LITERAL_LENGTH or data_index + length > data_size:
                    partial = True
                    continue
                total_literal_bytes += length
                if total_literal_bytes > self.MAX_STRING_LITERAL_BYTES:
                    result.candidate_output_truncated = True
                    partial = True
                    break
                value = os.pread(fd, length, data_offset + data_index)
                if len(value) != length:
                    partial = True
                    continue
                try:
                    value.decode("utf-8")
                except UnicodeDecodeError:
                    partial = True
                    continue
                result.metadata_string_literals_count += 1
                candidate_sink(value.decode("utf-8"))
            return "partial" if partial else "parsed"
        except OSError:
            return "partial"
        finally:
            if fd >= 0:
                os.close(fd)
