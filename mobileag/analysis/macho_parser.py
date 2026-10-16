"""iOS Mach-O & Swift Metadata Binary Parser.

Inspects iOS application binaries (Mach-O 64-bit / Universal Fat), parses segments and
load commands, inspects Swift 5 runtime sections, and extracts embedded URLs, cryptographic
primitives (CommonCrypto/CryptoKit), and custom URL schemes.
"""
from __future__ import annotations

import os
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from mobileag.analysis.bounded_sources import explicit_scan_root
from mobileag.analysis.api_endpoint_safety import safe_api_route, sanitize_candidate_text


@dataclass
class MachoAnalysisResult:
    is_macho: bool = False
    is_64bit: bool = True
    cpu_type: str = "ARM64"
    file_size_bytes: int = 0
    load_commands_count: int = 0
    imported_dylibs: List[str] = field(default_factory=list)
    swift_sections_detected: List[str] = field(default_factory=list)
    swift_section_name_candidates: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    crypto_frameworks: List[str] = field(default_factory=list)
    parse_status: str = "not_attempted"
    parse_errors: List[str] = field(default_factory=list)
    sections: List[Dict[str, object]] = field(default_factory=list)
    cstring_samples: List[str] = field(default_factory=list)
    architectures: List[str] = field(default_factory=list)
    slice_count: int = 0
    symbol_names: List[str] = field(default_factory=list)
    swift_type_name_candidates: List[str] = field(default_factory=list)
    swift_type_field_candidates: List[Dict[str, object]] = field(default_factory=list)
    swift_type_metadata_status: str = "not_attempted"
    swift_protocol_name_candidates: List[str] = field(default_factory=list)
    swift_protocol_metadata_status: str = "not_attempted"
    binary_truncated: bool = False
    candidate_output_truncated: bool = False


class MachoBinaryParser:
    """Parses Mach-O headers and metadata sections in iOS IPAs."""

    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE
    MH_MAGIC_32 = 0xFEEDFACE
    MH_CIGAM_32 = 0xCEFAEDFE
    FAT_MAGIC = 0xCAFEBABE
    FAT_MAGIC_64 = 0xCAFEBABF

    SWIFT5_SECTION_NAMES = [
        "__swift5_types",
        "__swift5_proto",
        "__swift5_fieldmd",
        "__swift5_assocty",
        "__swift5_protos",
    ]

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    MAX_BINARY_BYTES = 15 * 1024 * 1024
    MAX_URL_CANDIDATES = 100_000
    MAX_API_ENDPOINTS = 100
    LC_SEGMENT_64 = 0x19
    LC_SEGMENT_32 = 0x01
    LC_SYMTAB = 0x02
    DYLIB_COMMANDS = {
        0x0C, 0x0D, 0x18 | 0x80000000, 0x1F | 0x80000000,
        0x20, 0x23 | 0x80000000,
    }

    def parse_binary(self, binary_path: str | Path) -> MachoAnalysisResult:
        """Parse an iOS Mach-O binary file."""
        path = Path(binary_path)
        result = MachoAnalysisResult()
        try:
            details = path.lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
                result.parse_status = "rejected_input"
                result.parse_errors.append("Input must be a regular non-symlink file")
                return result
        except OSError as exc:
            result.parse_status = "read_error"
            result.parse_errors.append(type(exc).__name__)
            return result

        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (not stat.S_ISREG(opened.st_mode)
                        or (opened.st_dev, opened.st_ino) != (details.st_dev, details.st_ino)):
                    result.parse_status = "rejected_input"
                    result.parse_errors.append("File changed during safe open")
                    return result
                result.file_size_bytes = opened.st_size
                data = stream.read(self.MAX_BINARY_BYTES + 1)
        except OSError as exc:
            result.parse_status = "read_error"
            result.parse_errors.append(type(exc).__name__)
            return result

        if len(data) < 4:
            result.parse_status = "truncated"
            result.parse_errors.append("Mach-O magic is truncated")
            return result

        magic = struct.unpack(">I", data[:4])[0]
        magic_le = struct.unpack("<I", data[:4])[0]
        is_thin64 = magic_le == self.MH_MAGIC_64 or magic == self.MH_MAGIC_64
        is_thin32 = magic_le == self.MH_MAGIC_32 or magic == self.MH_MAGIC_32
        is_fat = (magic in {self.FAT_MAGIC, self.FAT_MAGIC_64}
                  or magic_le in {self.FAT_MAGIC, self.FAT_MAGIC_64})
        if not (is_thin64 or is_thin32 or is_fat):
            result.parse_status = "not_macho"
            return result
        result.is_macho = True
        if is_thin64:
            result.is_64bit = True
        elif is_thin32:
            result.is_64bit = False
        else:
            result.cpu_type = "Universal Fat Binary"

        truncated = len(data) > self.MAX_BINARY_BYTES
        data = data[:self.MAX_BINARY_BYTES]
        result.binary_truncated = truncated

        if is_thin64:
            self._parse_thin_64(data, result)
        elif is_thin32:
            self._parse_thin_32(data, result)
        else:
            self._parse_fat(data, result)
        if truncated:
            result.parse_errors.append("Binary exceeds bounded read limit; file-backed regions may be incomplete")
            result.parse_status = "partial"
        elif result.parse_status == "not_attempted":
            result.parse_status = "complete"

        # Keep legacy whole-file name matches explicitly separate from
        # sections resolved from LC_SEGMENT_64 section records.
        for sec in self.SWIFT5_SECTION_NAMES:
            if sec.encode() in data:
                result.swift_section_name_candidates.append(sec)

        # Check for crypto framework imports
        if b"CommonCrypto" in data:
            result.crypto_frameworks.append("CommonCrypto")
        if b"CryptoKit" in data:
            result.crypto_frameworks.append("CryptoKit")
        if b"Security.framework" in data:
            result.crypto_frameworks.append("Security.framework")

        # Extract URLs
        endpoints: Set[str] = set()
        url_pattern = re.compile(rb"https?://[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]+")
        url_candidates = 0
        for match in url_pattern.finditer(data):
            if url_candidates >= self.MAX_URL_CANDIDATES:
                result.candidate_output_truncated = True
                result.parse_errors.append("URL candidate scan limit reached")
                break
            url_candidates += 1
            try:
                u = match.group(0).decode("utf-8", errors="ignore")
                safe_url = safe_api_route(u)
                if (safe_url != "[REDACTED URL]"
                        and not safe_url.endswith((".png", ".jpg", ".svg", ".plist"))):
                    if safe_url not in endpoints and len(endpoints) >= self.MAX_API_ENDPOINTS:
                        result.candidate_output_truncated = True
                        if "API endpoint candidate limit reached" not in result.parse_errors:
                            result.parse_errors.append("API endpoint candidate limit reached")
                    else:
                        endpoints.add(safe_url)
            except Exception:
                continue

        result.api_endpoints = sorted(endpoints)
        if result.candidate_output_truncated:
            result.parse_status = "partial"
        return result

    def _parse_fat(self, data: bytes, result: MachoAnalysisResult) -> None:
        """Parse bounded FAT/FAT64 slice tables and aggregate supported thin slices."""
        if len(data) < 8:
            result.parse_status = "truncated"
            result.parse_errors.append("Truncated fat Mach-O header")
            return
        magic_be, magic_le = struct.unpack_from(">I", data, 0)[0], struct.unpack_from("<I", data, 0)[0]
        is_64 = magic_be == self.FAT_MAGIC_64 or magic_le == self.FAT_MAGIC_64
        endian = ">" if magic_be in {self.FAT_MAGIC, self.FAT_MAGIC_64} else "<"
        arch_count = struct.unpack_from(endian + "I", data, 4)[0]
        entry_size = 32 if is_64 else 20
        if arch_count == 0 or arch_count > 128 or 8 + arch_count * entry_size > len(data):
            result.parse_status = "partial"
            result.parse_errors.append("Fat architecture table exceeds bounded input or count limit")
            return

        result.slice_count = arch_count
        statuses: list[str] = []
        for index in range(arch_count):
            entry_offset = 8 + index * entry_size
            if is_64:
                cpu_type, _subtype, slice_offset, slice_size, _align, _reserved = struct.unpack_from(
                    endian + "iiQQII", data, entry_offset
                )
            else:
                cpu_type, _subtype, slice_offset, slice_size, _align = struct.unpack_from(
                    endian + "iiIII", data, entry_offset
                )
            arch_name = {0x0100000C: "ARM64", 0x01000007: "X86_64",
                         12: "ARM", 7: "X86"}.get(cpu_type, f"0x{cpu_type & 0xffffffff:08x}")
            result.architectures.append(arch_name)
            if slice_offset > len(data) or slice_size > len(data) - slice_offset or slice_size < 4:
                statuses.append("partial")
                result.parse_errors.append(f"Fat slice {index} has an invalid bounded file range")
                continue
            slice_data = data[slice_offset:slice_offset + slice_size]
            slice_magic = struct.unpack_from("<I", slice_data, 0)[0]
            if slice_magic not in {self.MH_MAGIC_64, self.MH_CIGAM_64,
                                   self.MH_MAGIC_32, self.MH_CIGAM_32}:
                statuses.append("unsupported")
                result.parse_errors.append(f"Fat slice {index} is not a supported thin Mach-O")
                continue
            slice_result = MachoAnalysisResult(is_macho=True)
            if slice_magic in {self.MH_MAGIC_64, self.MH_CIGAM_64}:
                self._parse_thin_64(slice_data, slice_result)
            else:
                slice_result.is_64bit = False
                self._parse_thin_32(slice_data, slice_result)
            if slice_result.cpu_type != arch_name:
                statuses.append("partial")
                result.parse_errors.append(
                    f"Fat slice {index} CPU type disagrees with its architecture-table entry"
                )
                continue
            statuses.append(slice_result.parse_status)
            result.load_commands_count += slice_result.load_commands_count
            result.sections.extend({**section, "architecture": arch_name}
                                   for section in slice_result.sections)
            for name in slice_result.imported_dylibs:
                if name not in result.imported_dylibs:
                    result.imported_dylibs.append(name)
            for name in slice_result.swift_sections_detected:
                if name not in result.swift_sections_detected:
                    result.swift_sections_detected.append(name)
            for sample in slice_result.cstring_samples:
                if sample not in result.cstring_samples and len(result.cstring_samples) < 1000:
                    result.cstring_samples.append(sample)
            for name in slice_result.symbol_names:
                if name not in result.symbol_names and len(result.symbol_names) < 2000:
                    result.symbol_names.append(name)
            for name in slice_result.swift_type_name_candidates:
                if name not in result.swift_type_name_candidates and len(result.swift_type_name_candidates) < 1000:
                    result.swift_type_name_candidates.append(name)
            for fields in slice_result.swift_type_field_candidates:
                if fields not in result.swift_type_field_candidates and len(result.swift_type_field_candidates) < 1000:
                    result.swift_type_field_candidates.append(fields)
            for name in slice_result.swift_protocol_name_candidates:
                if name not in result.swift_protocol_name_candidates and len(result.swift_protocol_name_candidates) < 1000:
                    result.swift_protocol_name_candidates.append(name)
            if slice_result.swift_protocol_metadata_status != "not_attempted":
                result.swift_protocol_metadata_status = "parsed" if result.swift_protocol_metadata_status in {"not_attempted", "parsed"} and slice_result.swift_protocol_metadata_status == "parsed" else "partial"
            if slice_result.swift_type_metadata_status != "not_attempted":
                result.swift_type_metadata_status = "parsed" if result.swift_type_metadata_status in {"not_attempted", "parsed"} and slice_result.swift_type_metadata_status == "parsed" else "partial"
            result.parse_errors.extend(f"slice {index}: {error}" for error in slice_result.parse_errors)
        result.parse_status = "complete" if statuses and all(status == "not_attempted" for status in statuses) else (
            "complete" if statuses and all(status == "complete" for status in statuses) else "partial"
        )

    def _parse_thin_32(self, data: bytes, result: MachoAnalysisResult) -> None:
        """Parse bounded 32-bit Mach-O load commands and section file ranges."""
        if len(data) < 28:
            result.parse_status = "truncated"
            result.parse_errors.append("Truncated 32-bit Mach-O header")
            return
        magic_bytes = data[:4]
        endian = "<" if magic_bytes == b"\xce\xfa\xed\xfe" else ">"
        try:
            _magic, cpu_type, _subtype, _filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(
                endian + "IiiIIII", data, 0
            )
        except struct.error:
            result.parse_status = "truncated"
            result.parse_errors.append("Malformed 32-bit Mach-O header")
            return
        result.cpu_type = {12: "ARM", 7: "X86"}.get(cpu_type, f"0x{cpu_type & 0xffffffff:08x}")
        if not result.architectures:
            result.architectures.append(result.cpu_type)
        if ncmds > 65536 or sizeofcmds > self.MAX_BINARY_BYTES or 28 + sizeofcmds > len(data):
            result.parse_status = "partial"
            result.parse_errors.append("32-bit load-command region exceeds available bounded input")
            return
        command_end = 28 + sizeofcmds
        cursor = 28
        symtab = None
        for _ in range(ncmds):
            if cursor + 8 > command_end:
                result.parse_errors.append("32-bit load-command header exceeds declared command region")
                result.parse_status = "partial"
                break
            command, command_size = struct.unpack_from(endian + "II", data, cursor)
            if command_size < 8 or cursor + command_size > command_end:
                result.parse_errors.append("Invalid 32-bit load-command size")
                result.parse_status = "partial"
                break
            if command == self.LC_SEGMENT_32:
                self._parse_segment_32(data, cursor, command_size, endian, result)
            if command == self.LC_SYMTAB:
                if command_size >= 24:
                    symtab = struct.unpack_from(endian + "IIII", data, cursor + 8)
                else:
                    result.parse_status = "partial"
                    result.parse_errors.append("Truncated LC_SYMTAB command")
            if command in self.DYLIB_COMMANDS and command_size >= 24:
                name_offset = struct.unpack_from(endian + "I", data, cursor + 8)[0]
                name_start = cursor + name_offset
                name_end = data.find(b"\0", name_start, cursor + command_size)
                if 24 <= name_offset < command_size and name_end >= 0:
                    name = data[name_start:name_end].decode("utf-8", errors="replace")
                    if name and name not in result.imported_dylibs:
                        result.imported_dylibs.append(name)
            cursor += command_size
        result.load_commands_count = ncmds
        if symtab:
            self._parse_symbol_table(data, symtab, endian, is_64bit=False, result=result)
        self._extract_section_contents(data, result)
        self._extract_swift_type_names(data, result, endian)
        self._extract_swift_protocol_names(data, result, endian)

    def _extract_swift_type_names(self, data: bytes, result: MachoAnalysisResult, endian: str) -> None:
        """Inventory bounded Swift nominal type names; this is not type reconstruction."""
        sections = [s for s in result.sections if s.get("name") == "__swift5_types"]
        if not sections:
            return
        result.swift_type_metadata_status = "parsed"
        examined = 0
        field_records_examined = 0
        for section in sections:
            offset, size = section.get("offset"), section.get("size")
            if not isinstance(offset, int) or not isinstance(size, int) or size % 4 or offset < 0 or size > 4 * 10000 or offset > len(data) or size > len(data) - offset:
                result.swift_type_metadata_status = "partial"
                continue
            for entry in range(offset, offset + size, 4):
                examined += 1
                if examined > 10000:
                    result.swift_type_metadata_status = "partial"
                    return
                relative = struct.unpack_from(endian + "i", data, entry)[0]
                # Relative-indirectable pointers use bit 0 as an indirection tag.
                # Do not dereference indirect pointers in this bounded inventory.
                if relative & 1:
                    result.swift_type_metadata_status = "partial"
                    continue
                descriptor = entry + relative
                if descriptor < 0 or descriptor > len(data) - 20:
                    result.swift_type_metadata_status = "partial"
                    continue
                flags = struct.unpack_from(endian + "I", data, descriptor)[0]
                if flags & 0x1f not in {16, 17, 18}:  # class, struct, enum context descriptors
                    continue
                name_relative = struct.unpack_from(endian + "i", data, descriptor + 8)[0]
                name_offset = descriptor + 8 + name_relative
                if name_offset < 0 or name_offset >= len(data):
                    result.swift_type_metadata_status = "partial"
                    continue
                end = data.find(b"\0", name_offset, min(len(data), name_offset + 256))
                if end < 0:
                    result.swift_type_metadata_status = "partial"
                    continue
                raw = data[name_offset:end]
                if not raw:
                    continue
                try:
                    candidate = raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    result.swift_type_metadata_status = "partial"
                    continue
                if any(ord(character) < 0x20 or ord(character) == 0x7f for character in candidate):
                    result.swift_type_metadata_status = "partial"
                    continue
                if candidate not in result.swift_type_name_candidates and len(result.swift_type_name_candidates) < 1000:
                    result.swift_type_name_candidates.append(candidate)
                fields_relative = struct.unpack_from(endian + "i", data, descriptor + 16)[0]
                if fields_relative == 0:
                    continue
                fields_pointer = descriptor + 16
                field_descriptor = fields_pointer + fields_relative
                field_sections = [s for s in result.sections if s.get("name") == "__swift5_fieldmd"]
                field_section = next((s for s in field_sections
                                      if isinstance(s.get("offset"), int) and isinstance(s.get("size"), int)
                                      and s["offset"] <= field_descriptor <= s["offset"] + s["size"] - 16), None)
                if field_section is None:
                    result.swift_type_metadata_status = "partial"
                    continue
                field_end = field_section["offset"] + field_section["size"]
                _mangled, _superclass, kind, record_size, field_count = struct.unpack_from(
                    endian + "iiHHI", data, field_descriptor
                )
                if kind not in {0, 1, 2, 3} or record_size != 12 or field_count > 1000:
                    result.swift_type_metadata_status = "partial"
                    continue
                records_start = field_descriptor + 16
                if records_start > field_end or field_count * record_size > field_end - records_start:
                    result.swift_type_metadata_status = "partial"
                    continue
                field_names: list[str] = []
                for field_index in range(field_count):
                    field_records_examined += 1
                    if field_records_examined > 10000:
                        result.swift_type_metadata_status = "partial"
                        break
                    record = records_start + field_index * record_size
                    name_pointer = record + 8
                    name_relative = struct.unpack_from(endian + "i", data, name_pointer)[0]
                    name_offset = name_pointer + name_relative
                    if name_relative == 0 or name_offset < 0 or name_offset >= len(data):
                        result.swift_type_metadata_status = "partial"
                        continue
                    name_end = data.find(b"\0", name_offset, min(len(data), name_offset + 256))
                    if name_end < 0:
                        result.swift_type_metadata_status = "partial"
                        continue
                    try:
                        field_name = data[name_offset:name_end].decode("utf-8", errors="strict")
                    except UnicodeDecodeError:
                        result.swift_type_metadata_status = "partial"
                        continue
                    if not field_name or any(ord(char) < 0x20 or ord(char) == 0x7f for char in field_name):
                        result.swift_type_metadata_status = "partial"
                        continue
                    field_names.append(field_name)
                if field_names and len(result.swift_type_field_candidates) < 1000:
                    result.swift_type_field_candidates.append({"type_name": candidate, "field_names": field_names})

    def _extract_swift_protocol_names(self, data: bytes, result: MachoAnalysisResult, endian: str) -> None:
        """Inventory names from direct Swift protocol descriptor pointers."""
        sections = [s for s in result.sections if s.get("name") == "__swift5_protos"]
        if not sections:
            return
        result.swift_protocol_metadata_status = "parsed"
        examined = 0
        for section in sections:
            offset, size = section.get("offset"), section.get("size")
            if not isinstance(offset, int) or not isinstance(size, int) or size % 4 or size > 4 * 10000 or offset < 0 or offset > len(data) or size > len(data) - offset:
                result.swift_protocol_metadata_status = "partial"
                continue
            for entry in range(offset, offset + size, 4):
                examined += 1
                if examined > 10000:
                    result.swift_protocol_metadata_status = "partial"
                    return
                relative = struct.unpack_from(endian + "i", data, entry)[0]
                # Avoid following relative-indirectable pointers: the referenced
                # pointer can be authenticated or require another address mapping.
                if relative & 1:
                    result.swift_protocol_metadata_status = "partial"
                    continue
                descriptor = entry + relative
                if descriptor < 0 or descriptor > len(data) - 24:
                    result.swift_protocol_metadata_status = "partial"
                    continue
                flags = struct.unpack_from(endian + "I", data, descriptor)[0]
                if flags & 0x1f != 3:  # Protocol context descriptor
                    continue
                name_relative = struct.unpack_from(endian + "i", data, descriptor + 8)[0]
                name_offset = descriptor + 8 + name_relative
                if name_offset < 0 or name_offset >= len(data):
                    result.swift_protocol_metadata_status = "partial"
                    continue
                end = data.find(b"\0", name_offset, min(len(data), name_offset + 256))
                if end < 0:
                    result.swift_protocol_metadata_status = "partial"
                    continue
                try:
                    name = data[name_offset:end].decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    result.swift_protocol_metadata_status = "partial"
                    continue
                if not name or any(ord(char) < 0x20 or ord(char) == 0x7f for char in name):
                    result.swift_protocol_metadata_status = "partial"
                    continue
                if name not in result.swift_protocol_name_candidates and len(result.swift_protocol_name_candidates) < 1000:
                    result.swift_protocol_name_candidates.append(name)

    def _parse_segment_32(self, data: bytes, cursor: int, command_size: int,
                          endian: str, result: MachoAnalysisResult) -> None:
        if command_size < 56:
            result.parse_errors.append("Truncated LC_SEGMENT command")
            result.parse_status = "partial"
            return
        segment_name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii", errors="replace")
        section_count = struct.unpack_from(endian + "I", data, cursor + 48)[0]
        if section_count > 4096 or 56 + section_count * 68 > command_size:
            result.parse_errors.append("LC_SEGMENT section table exceeds command bounds")
            result.parse_status = "partial"
            return
        section_cursor = cursor + 56
        for _ in range(section_count):
            raw = struct.unpack_from(endian + "16s16sIIIIIIIII", data, section_cursor)
            section_name = raw[0].split(b"\0", 1)[0].decode("ascii", errors="replace")
            owner = raw[1].split(b"\0", 1)[0].decode("ascii", errors="replace")
            section_size, file_offset = raw[3], raw[4]
            result.sections.append({"segment": owner or segment_name, "name": section_name,
                                    "size": section_size, "offset": file_offset})
            section_cursor += 68

    def _extract_section_contents(self, data: bytes, result: MachoAnalysisResult) -> None:
        swift_names = set(self.SWIFT5_SECTION_NAMES)
        for section in result.sections:
            if section["name"] in swift_names and section["name"] not in result.swift_sections_detected:
                result.swift_sections_detected.append(str(section["name"]))
            if section["name"] != "__cstring":
                continue
            offset, size = int(section["offset"]), int(section["size"])
            if offset > len(data) or size > len(data) - offset:
                result.parse_errors.append("__cstring file range exceeds bounded input")
                result.parse_status = "partial"
                continue
            raw = data[offset:offset + size]
            for value in re.findall(rb"[\x20-\x7e]{4,}", raw):
                sample = sanitize_candidate_text(value.decode("ascii", errors="replace"))
                if sample not in result.cstring_samples:
                    result.cstring_samples.append(sample)
                    if len(result.cstring_samples) >= 1000:
                        result.parse_errors.append("C-string sample limit reached")
                        result.parse_status = "partial"
                        break

    def _parse_symbol_table(self, data: bytes, symtab: tuple[int, int, int, int],
                            endian: str, *, is_64bit: bool, result: MachoAnalysisResult) -> None:
        symbol_offset, symbol_count, string_offset, string_size = symtab
        entry_size = 16 if is_64bit else 12
        if symbol_count > 100_000 or string_size > 8 * 1024 * 1024:
            result.parse_status = "partial"
            result.parse_errors.append("Symbol/string table exceeds bounded count or size")
            return
        symbol_bytes = symbol_count * entry_size
        if (symbol_offset > len(data) or symbol_bytes > len(data) - symbol_offset
                or string_offset > len(data) or string_size > len(data) - string_offset):
            result.parse_status = "partial"
            result.parse_errors.append("Symbol/string table range exceeds bounded input")
            return
        strings = data[string_offset:string_offset + string_size]
        for index in range(symbol_count):
            offset = symbol_offset + index * entry_size
            if is_64bit:
                name_index, _symbol_type, _section, _description, _value = struct.unpack_from(
                    endian + "IBBHQ", data, offset
                )
            else:
                name_index, _symbol_type, _section, _description, _value = struct.unpack_from(
                    endian + "IBBHI", data, offset
                )
            if name_index == 0 or name_index >= len(strings):
                continue
            end = strings.find(b"\0", name_index)
            if end < 0 or end - name_index > 4096:
                continue
            name = strings[name_index:end].decode("utf-8", errors="replace")
            if name and name not in result.symbol_names:
                result.symbol_names.append(name)
                if len(result.symbol_names) >= 2000:
                    result.parse_status = "partial"
                    result.parse_errors.append("Symbol name sample limit reached")
                    break

    def _parse_thin_64(self, data: bytes, result: MachoAnalysisResult) -> None:
        """Parse bounded 64-bit Mach-O load commands and section file ranges."""
        if len(data) < 32:
            result.parse_status = "truncated"
            result.parse_errors.append("Truncated 64-bit Mach-O header")
            return
        magic_bytes = data[:4]
        endian = "<" if magic_bytes == b"\xcf\xfa\xed\xfe" else ">"
        try:
            _magic, cpu_type, _subtype, _filetype, ncmds, sizeofcmds, _flags, _reserved = struct.unpack_from(
                endian + "IiiIIIII", data, 0
            )
        except struct.error:
            result.parse_status = "truncated"
            result.parse_errors.append("Malformed 64-bit Mach-O header")
            return
        result.cpu_type = {0x0100000C: "ARM64", 0x01000007: "X86_64"}.get(cpu_type, f"0x{cpu_type & 0xffffffff:08x}")
        if not result.architectures:
            result.architectures.append(result.cpu_type)
        if ncmds > 65536 or sizeofcmds > self.MAX_BINARY_BYTES or 32 + sizeofcmds > len(data):
            result.parse_status = "partial"
            result.parse_errors.append("Load-command region exceeds available bounded input")
            return

        command_end = 32 + sizeofcmds
        cursor = 32
        symtab = None
        for _ in range(ncmds):
            if cursor + 8 > command_end:
                result.parse_errors.append("Load-command header exceeds declared command region")
                result.parse_status = "partial"
                break
            command, command_size = struct.unpack_from(endian + "II", data, cursor)
            if command_size < 8 or cursor + command_size > command_end:
                result.parse_errors.append("Invalid load-command size")
                result.parse_status = "partial"
                break
            if command == self.LC_SEGMENT_64:
                self._parse_segment_64(data, cursor, command_size, endian, result)
            if command == self.LC_SYMTAB:
                if command_size >= 24:
                    symtab = struct.unpack_from(endian + "IIII", data, cursor + 8)
                else:
                    result.parse_status = "partial"
                    result.parse_errors.append("Truncated LC_SYMTAB command")
            if command in self.DYLIB_COMMANDS:
                if command_size >= 24:
                    name_offset = struct.unpack_from(endian + "I", data, cursor + 8)[0]
                    name_start = cursor + name_offset
                    name_end = data.find(b"\0", name_start, cursor + command_size)
                    if 24 <= name_offset < command_size and name_end >= 0:
                        name = data[name_start:name_end].decode("utf-8", errors="replace")
                        if name and name not in result.imported_dylibs:
                            result.imported_dylibs.append(name)
            cursor += command_size
        result.load_commands_count = ncmds
        if symtab:
            self._parse_symbol_table(data, symtab, endian, is_64bit=True, result=result)
        self._extract_section_contents(data, result)
        self._extract_swift_type_names(data, result, endian)
        self._extract_swift_protocol_names(data, result, endian)

    def _parse_segment_64(self, data: bytes, cursor: int, command_size: int,
                          endian: str, result: MachoAnalysisResult) -> None:
        if command_size < 72:
            result.parse_errors.append("Truncated LC_SEGMENT_64 command")
            result.parse_status = "partial"
            return
        segment_name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii", errors="replace")
        section_count = struct.unpack_from(endian + "I", data, cursor + 64)[0]
        if section_count > 4096 or 72 + section_count * 80 > command_size:
            result.parse_errors.append("LC_SEGMENT_64 section table exceeds command bounds")
            result.parse_status = "partial"
            return
        section_cursor = cursor + 72
        for _ in range(section_count):
            raw = struct.unpack_from(endian + "16s16sQQIIIIIIII", data, section_cursor)
            section_name = raw[0].split(b"\0", 1)[0].decode("ascii", errors="replace")
            owner = raw[1].split(b"\0", 1)[0].decode("ascii", errors="replace")
            section_size, file_offset = raw[3], raw[4]
            result.sections.append({"segment": owner or segment_name, "name": section_name,
                                    "size": section_size, "offset": file_offset})
            section_cursor += 80

    def audit_app_bundle(self, app_dir: str | Path) -> Optional[MachoAnalysisResult]:
        """Audit the main Mach-O executable in an extracted .app directory."""
        path = explicit_scan_root(app_dir)
        if path is None or path.is_symlink() or not path.is_dir():
            return None

        # Look for the primary executable (matching .app folder name or Info.plist CFBundleExecutable)
        app_name = path.name.replace(".app", "")
        main_binary = path / app_name

        if main_binary.is_file():
            return self.parse_binary(main_binary)

        # Scan for any Mach-O files in top level of .app
        for item in path.iterdir():
            if item.is_file() and not item.name.endswith((".plist", ".nib", ".car", ".png", ".lproj")):
                res = self.parse_binary(item)
                if res.is_macho:
                    return res

        return None
