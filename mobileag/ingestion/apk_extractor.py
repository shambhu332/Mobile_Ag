import asyncio
import hashlib
import logging
import os
import sys
from importlib.metadata import PackageNotFoundError, version as package_version
import shutil
import re
import stat
import struct
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict

from config.settings import Settings

logger = logging.getLogger(__name__)

_TOOL_DIAGNOSTIC_MARKERS = {
    "warning": re.compile(r"^(?:\s*(?:WARN(?:ING)?\b|W\s*:|\[WARN(?:ING)?\b))", re.I),
    "error": re.compile(r"^(?:\s*(?:ERROR\b|E\s*:|\[ERROR\b|FATAL\b))", re.I),
    "unsupported": re.compile(r"\b(?:unsupported|not supported|cannot decode|can't decode|failed to decompil)\b", re.I),
    "skip_or_omission": re.compile(r"\b(?:skip(?:ping|ped)?|omitted|failed to process)\b", re.I),
}
_MAX_TOOL_LOG_SCAN_BYTES = 4 * 1024 * 1024
_MAX_TOOL_LOG_LINE_BYTES = 64 * 1024
_MAX_SMALI_WALK_ENTRIES = 100_000
_MAX_DEX_CLASS_DESCRIPTORS = 100_000
_MAX_TOTAL_DEX_CLASS_DESCRIPTORS = 200_000
_MAX_DEX_DESCRIPTOR_BYTES = 4096
_MAX_PACKAGE_MANIFEST_BYTES = 8 * 1024 * 1024

class APKExtractor:
    """
    Extracts and decompiles an APK using APKTool and JADX.
    """

    def __init__(self, settings: Settings) -> None:
        """
        Initializes the APKExtractor.

        Args:
            settings: Configuration settings containing tool paths.
        """
        self.settings = settings
        configured_jadx = getattr(settings, "JADX_PATH", None)
        if configured_jadx and Path(configured_jadx).exists():
            self.jadx_path = configured_jadx
        else:
            self.jadx_path = shutil.which("jadx") or "jadx"

        configured_apktool = getattr(settings, "APKTOOL_PATH", None)
        if configured_apktool and Path(configured_apktool).exists():
            self.apktool_path = configured_apktool
        else:
            self.apktool_path = shutil.which("apktool") or "apktool"

    @staticmethod
    def _sha256(path: Path) -> str:
        """Hash the input artifact without changing it; fail rather than record a partial digest."""
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _count_smali_files(root: Path) -> dict[str, Any]:
        """Count materialized regular Smali files under one Apktool DEX tree.

        This inventories outputs only. A count cannot establish that the
        decompiler represented every class or that the analyzer consumed it.
        Symlinks are never followed and traversal is capped.
        """
        if root.is_symlink() or not root.is_dir():
            return {"status": "unavailable", "count": None}
        count = entries = 0
        try:
            for current, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
                entries += len(dirs) + len(files)
                if entries > _MAX_SMALI_WALK_ENTRIES:
                    return {"status": "capped", "count": count}
                for name in files:
                    candidate = Path(current) / name
                    if name.endswith(".smali") and not candidate.is_symlink() and candidate.is_file():
                        count += 1
            return {"status": "measured_output_inventory", "count": count}
        except OSError:
            return {"status": "incomplete", "count": count}

    @staticmethod
    def _read_smali_class_descriptors(root: Path) -> dict[str, Any]:
        """Read only bounded .class directives from regular Apktool outputs."""
        if root.is_symlink() or not root.is_dir():
            return {"status": "unavailable", "count": None, "descriptors": None}
        descriptors = set(); entries = files_seen = 0
        directive = re.compile(rb"(?m)^\s*\.class\s+(?:[^\r\n]*\s)?(L[^.;\[\r\n]+;)\s*(?:#.*)?$")
        try:
            for current, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
                entries += len(dirs) + len(files)
                if entries > _MAX_SMALI_WALK_ENTRIES:
                    return {"status": "capped", "count": len(descriptors), "descriptors": None}
                for name in files:
                    candidate = Path(current) / name
                    if not name.endswith(".smali") or candidate.is_symlink() or not candidate.is_file():
                        continue
                    files_seen += 1
                    with candidate.open("rb") as stream:
                        prefix = stream.read(64 * 1024)
                    matches = directive.findall(prefix)
                    if len(matches) != 1:
                        return {"status": "incomplete_class_directive_inventory",
                                "count": files_seen, "descriptors": None}
                    try:
                        descriptor = matches[0].decode("utf-8", errors="strict")
                    except UnicodeDecodeError:
                        return {"status": "unsupported_smali_class_encoding",
                                "count": files_seen, "descriptors": None}
                    if not APKExtractor._valid_class_descriptor(descriptor):
                        return {"status": "invalid_smali_class_descriptor",
                                "count": files_seen, "descriptors": None}
                    if descriptor in descriptors:
                        return {"status": "duplicate_smali_class_descriptor",
                                "count": files_seen, "descriptors": None}
                    descriptors.add(descriptor)
            return {"status": "measured_smali_class_descriptors", "count": files_seen,
                    "descriptors": descriptors}
        except (OSError, UnicodeDecodeError):
            return {"status": "incomplete", "count": files_seen, "descriptors": None}

    @staticmethod
    def _read_dex_class_descriptors(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> dict[str, Any]:
        """Parse bounded DEX class-def/type/string tables for exact descriptors."""
        try:
            with archive.open(member) as stream:
                data = stream.read(128 * 1024 * 1024 + 1)
            if len(data) > 128 * 1024 * 1024:
                return {"status": "dex_member_size_limit", "count": None, "descriptors": None}
            header = data[:112]
            if (len(header) != 112 or not re.fullmatch(rb"dex\n0[0-9]{2}\x00", header[:8])
                    or struct.unpack_from("<I", header, 32)[0] != member.file_size
                    or len(data) != member.file_size
                    or struct.unpack_from("<I", header, 36)[0] != 112
                    or struct.unpack_from("<I", header, 40)[0] != 0x12345678):
                return {"status": "invalid_or_unsupported_dex_header", "count": None, "descriptors": None}
            string_count, string_off = struct.unpack_from("<II", header, 56)
            type_count, type_off = struct.unpack_from("<II", header, 64)
            class_count, class_off = struct.unpack_from("<II", header, 96)

            def bounded_table(offset: int, count: int, width: int) -> bool:
                if count == 0:
                    return offset == 0 or 112 <= offset <= len(data)
                return offset >= 112 and offset + count * width <= len(data)

            if class_count > _MAX_DEX_CLASS_DESCRIPTORS:
                return {"status": "dex_class_count_limit", "count": class_count, "descriptors": None}
            if (not bounded_table(string_off, string_count, 4)
                    or not bounded_table(type_off, type_count, 4)
                    or not bounded_table(class_off, class_count, 32)):
                return {"status": "invalid_dex_table_bounds", "count": None, "descriptors": None}
            if class_count == 0:
                return {"status": "measured_class_descriptors", "count": 0, "descriptors": set()}
            if string_count > len(data) // 4 or type_count > len(data) // 4:
                return {"status": "invalid_dex_table_count", "count": None, "descriptors": None}

            def mutf8_units(raw: bytes) -> list[int] | None:
                """Decode bounded DEX Modified UTF-8 into UTF-16 code units."""
                units = []
                cursor = 0
                while cursor < len(raw):
                    first = raw[cursor]
                    cursor += 1
                    if first <= 0x7f:
                        if first == 0:
                            return None
                        unit = first
                    elif 0xc0 <= first <= 0xdf:
                        if cursor >= len(raw):
                            return None
                        second = raw[cursor]
                        cursor += 1
                        if second & 0xc0 != 0x80:
                            return None
                        unit = ((first & 0x1f) << 6) | (second & 0x3f)
                        if unit == 0:
                            if first != 0xc0 or second != 0x80:
                                return None
                        elif unit < 0x80:
                            return None
                    elif 0xe0 <= first <= 0xef:
                        if cursor + 1 >= len(raw):
                            return None
                        second, third = raw[cursor], raw[cursor + 1]
                        cursor += 2
                        if second & 0xc0 != 0x80 or third & 0xc0 != 0x80:
                            return None
                        unit = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f)
                        if unit < 0x800:
                            return None
                    else:
                        # MUTF-8 encodes supplementary code points as UTF-16
                        # surrogate pairs; four-byte UTF-8 sequences are invalid.
                        return None
                    units.append(unit)
                    if len(units) > _MAX_DEX_DESCRIPTOR_BYTES:
                        return None
                return units

            def string_at(index: int) -> str | None:
                if index >= string_count:
                    return None
                item_off = struct.unpack_from("<I", data, string_off + index * 4)[0]
                if item_off >= len(data):
                    return None
                # UTF-16 length is a ULEB128 prefix; inspect at most five bytes.
                cursor = item_off
                utf16_length = shift = 0
                for _ in range(5):
                    if cursor >= len(data):
                        return None
                    byte = data[cursor]; cursor += 1
                    utf16_length |= (byte & 0x7f) << shift
                    if not byte & 0x80:
                        break
                    shift += 7
                else:
                    return None
                if utf16_length > _MAX_DEX_DESCRIPTOR_BYTES:
                    return None
                end_limit = min(len(data), cursor + _MAX_DEX_DESCRIPTOR_BYTES * 3 + 1)
                end = data.find(b"\x00", cursor, end_limit)
                if end < 0:
                    return None
                raw = data[cursor:end]
                units = mutf8_units(raw)
                if units is None or len(units) != utf16_length:
                    return None
                try:
                    return bytes(unit_byte for unit in units
                                 for unit_byte in (unit >> 8, unit & 0xff)).decode("utf-16-be")
                except UnicodeDecodeError:
                    return None

            descriptors = set()
            for index in range(class_count):
                class_idx = struct.unpack_from("<I", data, class_off + index * 32)[0]
                if class_idx >= type_count:
                    return {"status": "invalid_dex_class_index", "count": None, "descriptors": None}
                descriptor_idx = struct.unpack_from("<I", data, type_off + class_idx * 4)[0]
                descriptor = string_at(descriptor_idx)
                if (descriptor is None or not APKExtractor._valid_class_descriptor(descriptor)
                        or descriptor in descriptors):
                    return {"status": "unsupported_or_invalid_class_descriptor", "count": None,
                            "descriptors": None}
                descriptors.add(descriptor)
            return {"status": "measured_class_descriptors", "count": class_count,
                    "descriptors": descriptors}
        except (OSError, zipfile.BadZipFile, RuntimeError, struct.error):
            return {"status": "unreadable_dex_tables", "count": None, "descriptors": None}

    @staticmethod
    def _valid_class_descriptor(descriptor: str) -> bool:
        """Validate a DEX/Smali object descriptor without ASCII-only assumptions."""
        if (not isinstance(descriptor, str) or len(descriptor) < 3
                or descriptor[0] != "L" or descriptor[-1] != ";"):
            return False
        body = descriptor[1:-1]
        return bool(body and not body.startswith("/") and not body.endswith("/")
                    and "//" not in body
                    and all(char not in ".;[\\" and not (0xd800 <= ord(char) <= 0xdfff)
                            and not char.isspace() and ord(char) >= 0x20 for char in body))

    @staticmethod
    def _dex_class_definition_count(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> dict[str, Any]:
        """Read only the bounded DEX header and class_defs table extent."""
        try:
            with archive.open(member) as stream:
                header = stream.read(112)
            if (len(header) != 112 or not re.fullmatch(rb"dex\n0[0-9]{2}\x00", header[:8])
                    or struct.unpack_from("<I", header, 32)[0] != member.file_size
                    or struct.unpack_from("<I", header, 36)[0] != 112
                    or struct.unpack_from("<I", header, 40)[0] != 0x12345678):
                return {"status": "invalid_or_unsupported_dex_header", "count": None}
            count, offset = struct.unpack_from("<II", header, 96)
            if ((count == 0 and offset != 0)
                    or (count > 0 and (offset < 112 or offset + count * 32 > member.file_size))):
                return {"status": "invalid_dex_class_defs_bounds", "count": None}
            if count > _MAX_DEX_CLASS_DESCRIPTORS:
                return {"status": "dex_class_count_limit", "count": count}
            return {"status": "measured_dex_header", "count": count}
        except (OSError, zipfile.BadZipFile, RuntimeError, struct.error):
            return {"status": "unreadable_dex_header", "count": None}

    @staticmethod
    def _archive_inventory(apk_path: Path, apktool_dir: Path | None = None) -> dict[str, Any]:
        """Count bounded APK inputs and compare root DEX members with Apktool output.

        This is ingestion accounting only: a matched directory does not establish
        that all bytecode was decoded or analyzed, and a mismatch is not a finding.
        """
        result: dict[str, Any] = {
            "status": "not_measured", "zip_member_count": None,
            "expanded_bytes": None, "dex_members": 0,
            "root_dex_members": 0, "nested_dex_members": 0,
            "native_library_members": 0, "dex_smali_dirs_expected": 0,
            "dex_smali_dirs_found": 0, "dex_extraction_status": "not_measured",
            "dex_class_definitions": {"status": "not_measured", "count": None},
            "dex_class_definitions_by_member": {},
            "dex_class_output_comparison": {"status": "not_measured", "count_delta": None,
                                             "per_member": {}},
            "dex_class_descriptor_comparison": {"status": "not_measured", "missing_from_smali_count": None,
                                                "extra_smali_count": None, "per_member": {}},
            "smali_output_files": {"status": "not_measured", "count": None},
            "smali_output_by_dex": {},
            "unsupported_constructs": {"status": "not_measured", "count": None},
        }
        try:
            with zipfile.ZipFile(apk_path) as archive:
                members = archive.infolist()
                # validate_archive enforces MAX_MEMBERS before this helper is called;
                # retain a local fail-closed guard for standalone/test use too.
                from mobileag.security.archives import MAX_MEMBERS
                if not members or len(members) > MAX_MEMBERS:
                    result["status"] = "incomplete"
                    return result
                result["status"] = "measured_input_inventory"
                result["zip_member_count"] = len(members)
                result["expanded_bytes"] = sum(member.file_size for member in members)
                dex_members = [member.filename for member in members
                               if member.filename.lower().endswith(".dex")]
                root_dex = [name for name in dex_members if "/" not in name]
                result["dex_members"] = len(dex_members)
                result["root_dex_members"] = len(root_dex)
                result["nested_dex_members"] = len(dex_members) - len(root_dex)
                duplicate_dex_members = len(root_dex) != len(set(root_dex))
                result["native_library_members"] = sum(
                    member.filename.lower().endswith(".so") for member in members
                )
                expected_dirs = []
                directory_by_member = {}
                invalid_dex_mapping = False
                for name in root_dex:
                    match = re.fullmatch(r"classes(?:(\d+))?\.dex", name)
                    if match:
                        suffix = match.group(1)
                        index = int(suffix) if suffix else 1
                        if (suffix is not None and (index < 2 or str(index) != suffix)):
                            invalid_dex_mapping = True
                            continue
                        directory = "smali" if index == 1 else f"smali_classes{index}"
                        expected_dirs.append(directory)
                        directory_by_member[name] = directory
                    else:
                        invalid_dex_mapping = True
                # ZIP permits duplicate filenames; getinfo() resolves one occurrence,
                # so never report an exact comparison for ambiguous input members.
                if duplicate_dex_members:
                    invalid_dex_mapping = True
                if len(directory_by_member) != len(set(directory_by_member.values())):
                    invalid_dex_mapping = True
                result["dex_smali_dirs_expected"] = len(expected_dirs)
                dex_counts = ({name: {"status": "duplicate_dex_member_name", "count": None}
                               for name in dict.fromkeys(root_dex)} if duplicate_dex_members else
                              {name: APKExtractor._dex_class_definition_count(archive, archive.getinfo(name))
                               for name in root_dex})
                declared_class_total = (sum(item["count"] for item in dex_counts.values())
                                        if root_dex and all(item["status"] == "measured_dex_header"
                                                            for item in dex_counts.values()) else None)
                if declared_class_total is not None and declared_class_total <= _MAX_TOTAL_DEX_CLASS_DESCRIPTORS:
                    dex_parsed = {name: APKExtractor._read_dex_class_descriptors(archive, archive.getinfo(name))
                                  for name in root_dex}
                else:
                    dex_parsed = {name: {"status": "descriptor_set_budget_exceeded", "count": item.get("count"),
                                         "descriptors": None}
                                  for name, item in dex_counts.items()}
                result["dex_class_definitions_by_member"] = dex_counts
                if root_dex and all(item["status"] == "measured_dex_header" for item in dex_counts.values()):
                    result["dex_class_definitions"] = {
                        "status": "measured_dex_header_counts",
                        "count": sum(item["count"] for item in dex_counts.values()),
                    }
                elif root_dex:
                    result["dex_class_definitions"] = {"status": "incomplete", "count": None}
                elif not dex_members:
                    result["dex_class_definitions"] = {"status": "not_applicable", "count": None}
                if apktool_dir is not None and expected_dirs:
                    found = sum((apktool_dir / directory).is_dir() for directory in expected_dirs)
                    result["dex_smali_dirs_found"] = found
                    result["dex_extraction_status"] = (
                        "incomplete_or_ambiguous_mapping" if invalid_dex_mapping else
                        "matched" if found == len(expected_dirs) else "mismatch")
                    per_dex = {directory: APKExtractor._count_smali_files(apktool_dir / directory)
                               for directory in expected_dirs}
                    smali_descriptors = {}
                    smali_total = 0
                    for directory in dict.fromkeys(expected_dirs):
                        if declared_class_total is None or declared_class_total > _MAX_TOTAL_DEX_CLASS_DESCRIPTORS:
                            smali_descriptors[directory] = {"status": "descriptor_set_budget_exceeded",
                                                            "count": None, "descriptors": None}
                            continue
                        parsed_smali = APKExtractor._read_smali_class_descriptors(apktool_dir / directory)
                        if (parsed_smali.get("status") == "measured_smali_class_descriptors"
                                and smali_total + parsed_smali["count"] > _MAX_TOTAL_DEX_CLASS_DESCRIPTORS):
                            parsed_smali = {"status": "descriptor_set_budget_exceeded", "count": None,
                                            "descriptors": None}
                        elif parsed_smali.get("status") == "measured_smali_class_descriptors":
                            smali_total += parsed_smali["count"]
                        smali_descriptors[directory] = parsed_smali
                    result["smali_output_by_dex"] = per_dex
                    statuses = {item["status"] for item in per_dex.values()}
                    result["smali_output_files"] = {
                        "status": ("measured_output_inventory" if statuses == {"measured_output_inventory"}
                                   else "incomplete"),
                        "count": (sum(item["count"] for item in per_dex.values()
                                      if type(item.get("count")) is int)
                                  if statuses == {"measured_output_inventory"} else None),
                    }
                    comparable = not invalid_dex_mapping and all(name in directory_by_member
                                     and dex_counts[name]["status"] == "measured_dex_header"
                                     and per_dex.get(directory_by_member[name], {}).get("count") is not None
                                     for name in root_dex)
                    if comparable:
                        per_member = {}
                        for name in root_dex:
                            dex_count = dex_counts[name]["count"]
                            smali_count = per_dex[directory_by_member[name]]["count"]
                            delta = smali_count - dex_count
                            per_member[name] = {
                                "declared_class_count": dex_count,
                                "smali_output_file_count": smali_count,
                                "count_delta": delta,
                                "status": "count_match" if delta == 0 else "count_mismatch",
                            }
                        delta = sum(item["count_delta"] for item in per_member.values())
                        all_match = all(item["status"] == "count_match" for item in per_member.values())
                        result["dex_class_output_comparison"] = {
                            "status": "declared_class_count_matches_smali_file_count" if all_match else "class_count_mismatch",
                            "count_delta": delta,
                            "per_member": per_member,
                        }
                    else:
                        result["dex_class_output_comparison"] = {"status": "incomplete", "count_delta": None,
                                                                 "per_member": {}}
                    descriptor_comparable = (
                        not invalid_dex_mapping
                        and len(directory_by_member) == len(root_dex)
                        and all(dex_parsed[name]["status"] == "measured_class_descriptors"
                                and smali_descriptors.get(directory_by_member[name], {}).get("status") == "measured_smali_class_descriptors"
                                for name in root_dex)
                    )
                    if descriptor_comparable:
                        per_member = {}
                        for name in root_dex:
                            declared = dex_parsed[name]["descriptors"]
                            extracted = smali_descriptors[directory_by_member[name]]["descriptors"]
                            missing = len(declared - extracted)
                            extra = len(extracted - declared)
                            per_member[name] = {
                                "status": "exact_descriptor_set_match" if not missing and not extra else "descriptor_set_mismatch",
                                "dex_class_count": len(declared), "smali_class_count": len(extracted),
                                "missing_from_smali_count": missing, "extra_smali_count": extra,
                            }
                        total_missing = sum(row["missing_from_smali_count"] for row in per_member.values())
                        total_extra = sum(row["extra_smali_count"] for row in per_member.values())
                        all_match = all(row["status"] == "exact_descriptor_set_match" for row in per_member.values())
                        result["dex_class_descriptor_comparison"] = {
                            "status": "exact_descriptor_set_match" if all_match else "descriptor_set_mismatch",
                            "missing_from_smali_count": total_missing, "extra_smali_count": total_extra,
                            "per_member": per_member,
                        }
                    else:
                        result["dex_class_descriptor_comparison"] = {
                            "status": "incomplete_or_unsupported", "missing_from_smali_count": None,
                            "extra_smali_count": None, "per_member": {},
                        }
                elif apktool_dir is not None and root_dex:
                    result["dex_extraction_status"] = "incomplete_or_ambiguous_mapping"
                    result["dex_class_output_comparison"] = {
                        "status": "incomplete", "count_delta": None, "per_member": {}}
                    result["dex_class_descriptor_comparison"] = {
                        "status": "incomplete_or_unsupported", "missing_from_smali_count": None,
                        "extra_smali_count": None, "per_member": {}}
                elif apktool_dir is not None and not root_dex:
                    result["dex_extraction_status"] = "not_applicable"
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
            result["status"] = "incomplete"
        return result

    @staticmethod
    async def _tool_version(executable: str, args: tuple[str, ...]) -> dict[str, Any]:
        """Collect a bounded, best-effort version string using argv (never a shell)."""
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                executable, *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            output, _ = await asyncio.wait_for(process.communicate(), timeout=5)
            version = output.decode("utf-8", errors="replace").strip()[:500]
            return {"executable": Path(executable).name, "version": version or None,
                    "version_exit_code": process.returncode}
        except (OSError, asyncio.TimeoutError) as exc:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            return {"executable": Path(executable).name, "version": None,
                    "version_error": type(exc).__name__}

    @staticmethod
    def _classify_tool_log_line(line: bytes, counts: dict[str, int]) -> None:
        """Count diagnostic markers only; never persist tool-provided text."""
        decoded = line.decode("utf-8", errors="replace").strip()
        if not decoded:
            return
        for label, pattern in _TOOL_DIAGNOSTIC_MARKERS.items():
            if pattern.search(decoded):
                counts[label] += 1

    @staticmethod
    def _summarize_decompiler_diagnostics(tool_runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Expose bounded decompiler-log marker counts without retaining log text.

        These are diagnostic line counts, not exact omitted-file or unsupported
        construct counts. Only a positive error/unsupported/omission marker, or
        incomplete log observation, downgrades the decompilation review state.
        """
        marker_names = tuple(_TOOL_DIAGNOSTIC_MARKERS)
        per_tool: dict[str, Any] = {}
        total = {name: 0 for name in marker_names}
        complete = True
        for tool_name in ("apktool", "jadx"):
            execution = tool_runs.get(tool_name, {})
            observation = execution.get("log_observation") if isinstance(execution, dict) else None
            if not isinstance(observation, dict):
                complete = False
                per_tool[tool_name] = {"status": "not_recorded", "marker_line_counts": None}
                continue
            counts = observation.get("marker_line_counts")
            if not isinstance(counts, dict) or any(type(counts.get(name)) is not int or counts[name] < 0
                                                   for name in marker_names):
                complete = False
                safe_counts = None
            else:
                safe_counts = {name: counts[name] for name in marker_names}
                for name in marker_names:
                    total[name] += counts[name]
            tool_complete = (observation.get("status") == "bounded_text_classification"
                             and observation.get("classification_truncated") is False
                             and safe_counts is not None)
            complete = complete and tool_complete
            per_tool[tool_name] = {
                "status": "bounded_text_classification" if tool_complete else "incomplete",
                "marker_line_counts": safe_counts,
                "classified_bytes": observation.get("classified_bytes")
                    if type(observation.get("classified_bytes")) is int else None,
                "classification_truncated": observation.get("classification_truncated") is True,
                "raw_log_retained": False,
            }
        concerning = total["error"] + total["unsupported"] + total["skip_or_omission"]
        return {
            "status": "bounded_diagnostics_complete" if complete else "bounded_diagnostics_incomplete",
            "per_tool": per_tool,
            "marker_line_counts": total if complete else None,
            "review_state": "partial" if not complete or concerning else "completed",
            "unsupported_construct_count": None,
            "omitted_file_count": None,
            "limitations": [
                "Marker lines are tool-log diagnostics, not exact unsupported-construct or omitted-file counts.",
                "Marker categories may overlap on a line and are not deduplicated across tool logs.",
                "No diagnostic marker does not prove decompiler completeness.",
                "Raw decompiler output is not retained.",
            ],
        }

    @classmethod
    async def _drain_tool_log(cls, reader) -> dict[str, Any]:
        """Drain the pipe while classifying a bounded prefix, without storing logs."""
        counts = {key: 0 for key in _TOOL_DIAGNOSTIC_MARKERS}
        output_bytes = scanned_bytes = truncated_lines = 0
        buffer = bytearray()
        truncated = False

        async def process_complete_lines(final: bool = False) -> None:
            nonlocal truncated_lines
            while True:
                newline = buffer.find(b"\n")
                if newline < 0 and not final and len(buffer) <= _MAX_TOOL_LOG_LINE_BYTES:
                    return
                if newline >= 0:
                    end = newline + 1
                else:
                    end = min(len(buffer), _MAX_TOOL_LOG_LINE_BYTES)
                    if not final and len(buffer) > _MAX_TOOL_LOG_LINE_BYTES:
                        truncated_lines += 1
                line = bytes(buffer[:end])
                del buffer[:end]
                cls._classify_tool_log_line(line, counts)
                if not buffer or (newline < 0 and not final and len(buffer) <= _MAX_TOOL_LOG_LINE_BYTES):
                    return

        while True:
            chunk = await reader.read(64 * 1024)
            if not chunk:
                break
            output_bytes += len(chunk)
            remaining = _MAX_TOOL_LOG_SCAN_BYTES - scanned_bytes
            if remaining > 0:
                prefix = chunk[:remaining]
                scanned_bytes += len(prefix)
                buffer.extend(prefix)
                await process_complete_lines()
            if len(chunk) > max(remaining, 0):
                truncated = True
        if output_bytes > scanned_bytes:
            truncated = True
        if buffer:
            await process_complete_lines(final=True)
        return {
            "status": "bounded_text_classification",
            "output_bytes": output_bytes,
            "classified_bytes": scanned_bytes,
            "classification_truncated": truncated,
            "overlong_line_chunks_truncated": truncated_lines,
            "marker_line_counts": counts,
            "raw_log_retained": False,
            "omitted_file_count": None,
            "unsupported_construct_count": None,
        }

    async def extract(self, apk_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Extracts resources and Java source code from the APK.

        Args:
            apk_path: The path to the APK file.
            output_dir: The directory where the extracted files will be saved.

        Returns:
            A dictionary containing paths to the extracted directories, the manifest,
            and the parsed package name.
        """
        apk_p = Path(apk_path)
        out_p = Path(output_dir)

        if not apk_p.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        if not apk_p.is_file():
            raise ValueError("APK path must identify a regular file")

        artifact_sha256 = self._sha256(apk_p)

        out_p.mkdir(parents=True, exist_ok=True)
        
        apktool_dir = out_p / "apktool_out"
        jadx_dir = out_p / "jadx_out"

        from mobileag.security.archives import validate_archive
        if validate_archive(apk_p) != "android":
            raise ValueError("Expected an Android APK archive")

        async def run_tool(command, timeout):
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            drain_task = asyncio.create_task(self._drain_tool_log(process.stdout))
            try:
                code = await asyncio.wait_for(process.wait(), timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                process.kill()
                await process.wait()
                try:
                    await asyncio.wait_for(drain_task, timeout=2)
                except asyncio.TimeoutError:
                    drain_task.cancel()
                    await asyncio.gather(drain_task, return_exceptions=True)
                raise
            try:
                log_observation = await asyncio.wait_for(drain_task, timeout=2)
            except asyncio.TimeoutError:
                drain_task.cancel()
                await asyncio.gather(drain_task, return_exceptions=True)
                log_observation = {"status": "incomplete_pipe_drain", "output_bytes": None,
                                   "classified_bytes": None, "classification_truncated": True,
                                   "marker_line_counts": None, "raw_log_retained": False,
                                   "omitted_file_count": None, "unsupported_construct_count": None}
            if code != 0:
                raise RuntimeError(f"{Path(command[0]).name} failed (exit {code}); scan is incomplete")
            return {"exit_code": code, "log_observation": log_observation}

        apktool_run = await run_tool([self.apktool_path, "d", str(apk_p), "-o", str(apktool_dir), "-f"], 120)
        jadx_run = await run_tool([self.jadx_path, str(apk_p), "-d", str(jadx_dir), "--no-res", "--show-bad-code", "-j", "4"], 120)
        if self._sha256(apk_p) != artifact_sha256:
            raise RuntimeError("Input APK changed during extraction; refusing to bind scan evidence to a moving artifact")
        if not jadx_dir.is_dir() or not (apktool_dir / "AndroidManifest.xml").is_file():
            raise RuntimeError("Decompilation output is incomplete")

        archive_inventory = self._archive_inventory(apk_p, apktool_dir)
        decompiler_diagnostics = self._summarize_decompiler_diagnostics({
            "apktool": apktool_run, "jadx": jadx_run,
        })
        archive_inventory["decompiler_diagnostics"] = decompiler_diagnostics
        if self._sha256(apk_p) != artifact_sha256:
            raise RuntimeError("Input APK changed while recording archive inventory; refusing to bind scan evidence to a moving artifact")

        manifest_path = apktool_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            candidates = [
                jadx_dir / "resources" / "AndroidManifest.xml",
                out_p / "AndroidManifest.xml",
            ]
            for c in candidates:
                if c.exists():
                    manifest_path = c
                    break

        package_name = self._parse_package_name(manifest_path)

        return {
            "apktool_dir": str(apktool_dir) if apktool_dir.exists() else "",
            "jadx_dir": str(jadx_dir) if jadx_dir.exists() else "",
            "manifest_path": str(manifest_path) if manifest_path.exists() else "",
            "package_name": package_name,
            "artifact_provenance": {
                "sha256": artifact_sha256,
                "size_bytes": apk_p.stat().st_size,
                "filename": apk_p.name,
                "mobileag_version": self._mobileag_version(),
                "python_version": sys.version.split()[0],
                "tools": {
                    "apktool": {**await self._tool_version(self.apktool_path, ("--version",)),
                                "execution": apktool_run},
                    "jadx": {**await self._tool_version(self.jadx_path, ("--version",)),
                             "execution": jadx_run},
                },
                "archive_inventory": archive_inventory,
                "decompiler_diagnostics": decompiler_diagnostics,
            },
        }

    @staticmethod
    def _mobileag_version() -> str:
        try:
            return package_version("mobileag")
        except PackageNotFoundError:
            return "source-checkout"

    def _parse_package_name(self, manifest_path: Path) -> str:
        """Parses the package name from the AndroidManifest.xml."""
        try:
            fd = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                details = os.fstat(stream.fileno())
                if (not stat.S_ISREG(details.st_mode)
                        or details.st_size > _MAX_PACKAGE_MANIFEST_BYTES):
                    raise ValueError("Manifest is not a regular file or exceeds the size limit")
                raw = stream.read(_MAX_PACKAGE_MANIFEST_BYTES + 1)
            if len(raw) > _MAX_PACKAGE_MANIFEST_BYTES:
                raise ValueError("Manifest exceeds the size limit")
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ValueError("Manifest DTD/entity declarations are unsupported")
            root = ET.fromstring(raw)
            return root.attrib.get("package", "unknown")
        except Exception as e:
            logger.warning("Manifest package name was not safely parsed: %s", type(e).__name__)
            return "unknown"
