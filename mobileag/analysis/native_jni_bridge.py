"""Native JNI Cross-Boundary Analyzer (inspired by REA).

Inspects native shared libraries (.so) in mobile packages, maps exported JNI entry points
(Java_<package>_<class>_<method>), and audits imported libc and OS calls to uncover
hidden native execution sinks (system, popen, strcpy, sqlite3_exec).
"""
from __future__ import annotations

import os
import re
import stat
import struct
from io import BytesIO
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.analysis.bounded_sources import explicit_scan_root

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover - dependency is pinned for normal installs
    ELFFile = None


@dataclass
class JniExportedFunction:
    mangled_name: str
    java_class: str
    java_method: str
    library_name: str
    # Deprecated compatibility field. Binary-wide string co-occurrence cannot
    # establish that a JNI method reaches or calls a native symbol.
    dangerous_calls_referenced: List[str] = field(default_factory=list)


@dataclass
class NativeLibraryAuditResult:
    library_name: str
    architecture: str
    scan_status: str = "not_analyzed"
    bytes_scanned: int = 0
    scan_truncated: bool = False
    scan_errors: List[str] = field(default_factory=list)
    exported_jni_functions: List[JniExportedFunction] = field(default_factory=list)
    jni_export_name_candidates: List[str] = field(default_factory=list)
    dangerous_symbol_string_candidates: List[str] = field(default_factory=list)
    imported_dangerous_symbols: List[str] = field(default_factory=list)
    elf_parse_status: str = "not_attempted"
    dynamic_symbols_seen: int = 0
    findings: List[Finding] = field(default_factory=list)


class NativeJniAnalyzer:
    """Collects bounded printable-string and JNI-name candidates from ELF files."""

    DANGEROUS_LIBC_SINKS = {
        "system": ("CWE-78", Severity.HIGH, "Native Command Injection sink 'system()' imported"),
        "popen": ("CWE-78", Severity.HIGH, "Native Command Injection sink 'popen()' imported"),
        "execve": ("CWE-78", Severity.HIGH, "Process execution sink 'execve()' imported"),
        "strcpy": ("CWE-120", Severity.MEDIUM, "Unbounded memory copy sink 'strcpy()' imported (Buffer Overflow risk)"),
        "sprintf": ("CWE-120", Severity.MEDIUM, "Unbounded format sink 'sprintf()' imported"),
        "sqlite3_exec": ("CWE-89", Severity.HIGH, "Raw SQL execution sink 'sqlite3_exec()' imported in native library"),
    }

    def demangle_jni_name(self, symbol: str) -> Optional[tuple[str, str]]:
        """Decode the JNI long-name prefix into a class and method name.

        Overload signatures are omitted from the returned method name. This is
        a name decoder only; it does not resolve Java declarations or prove use.
        """
        if not symbol.startswith("Java_"):
            return None
        body = symbol[5:]
        overload = body.find("__")
        if overload >= 0:
            body = body[:overload]

        delimiter = None
        index = len(body) - 1
        while index >= 0:
            if body[index] != "_":
                index -= 1
                continue
            if index + 1 < len(body) and body[index + 1] in "123":
                index -= 1
                continue
            if (index + 5 < len(body) and body[index + 1] == "0"
                    and re.fullmatch(r"[0-9a-fA-F]{4}", body[index + 2:index + 6])):
                index -= 1
                continue
            delimiter = index
            break
        if delimiter is None or delimiter == 0 or delimiter == len(body) - 1:
            return None

        def decode(component: str, *, class_name: bool) -> str:
            output: list[str] = []
            cursor = 0
            while cursor < len(component):
                char = component[cursor]
                if char == "_" and cursor + 1 < len(component):
                    marker = component[cursor + 1]
                    replacements = {"1": "_", "2": ";", "3": "["}
                    if marker in replacements:
                        output.append(replacements[marker])
                        cursor += 2
                        continue
                    if (marker == "0" and cursor + 5 < len(component)
                            and re.fullmatch(r"[0-9a-fA-F]{4}", component[cursor + 2:cursor + 6])):
                        output.append(chr(int(component[cursor + 2:cursor + 6], 16)))
                        cursor += 6
                        continue
                    output.append("." if class_name else "_")
                else:
                    output.append(char)
                cursor += 1
            return "".join(output)

        class_name = decode(body[:delimiter], class_name=True)
        method_name = decode(body[delimiter + 1:], class_name=False)
        if not class_name or not method_name:
            return None
        return class_name, method_name

    def audit_library(self, so_path: str | Path) -> NativeLibraryAuditResult:
        """Audit an individual .so ELF library."""
        path = Path(so_path)
        lib_name = path.name
        arch = path.parent.name if path.parent.name in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64") else "unknown"

        result = NativeLibraryAuditResult(library_name=lib_name, architecture=arch)

        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    result.scan_status = "invalid"
                    result.scan_errors.append("non_regular_library")
                    return result
                file_size = os.fstat(f.fileno()).st_size
                data = f.read(5 * 1024 * 1024 + 1)
                result.scan_truncated = file_size > 5 * 1024 * 1024 or len(data) > 5 * 1024 * 1024
                if len(data) > 5 * 1024 * 1024:
                    data = data[:5 * 1024 * 1024]
        except OSError:
            result.scan_status = "invalid"
            result.scan_errors.append("library_read_error")
            return result
        result.bytes_scanned = len(data)
        if result.scan_truncated:
            result.scan_status = "partial"
            result.scan_errors.append("library_byte_limit")
        else:
            result.scan_status = "analyzed_heuristically"

        # Basic ELF Magic verification (0x7F, 'E', 'L', 'F')
        if not data.startswith(b"\x7fELF"):
            result.scan_status = "invalid"
            result.scan_errors.append("invalid_elf_header")
            return result

        # Extract printable strings as candidates; these are not ELF imports.
        raw_strings = re.findall(b"[a-zA-Z0-9_]{3,}", data)
        strings_set: Set[str] = {s.decode("ascii", errors="ignore") for s in raw_strings}

        for sink in self.DANGEROUS_LIBC_SINKS:
            if sink in strings_set:
                result.dangerous_symbol_string_candidates.append(sink)

        # Parse dynamic symbols separately from byte-string heuristics. Imports
        # still do not prove a call site or JNI reachability.
        if ELFFile is None:
            result.elf_parse_status = "unsupported"
            result.scan_errors.append("elf_parser_unavailable")
        elif result.scan_truncated:
            result.elf_parse_status = "partial"
            result.scan_errors.append("elf_table_may_be_truncated")
        else:
            try:
                elf = ELFFile(BytesIO(data))
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym is None:
                    result.elf_parse_status = "not_present"
                    result.scan_status = "partial"
                    result.scan_errors.append("dynamic_symbol_table_missing")
                else:
                    result.elf_parse_status = "parsed"
                    for index, symbol in enumerate(dynsym.iter_symbols()):
                        if index >= 5000:
                            result.elf_parse_status = "partial"
                            result.scan_errors.append("dynamic_symbol_limit")
                            break
                        result.dynamic_symbols_seen += 1
                        name = symbol.name
                        if not name or len(name) > 256 or symbol.entry.st_info.type != "STT_FUNC":
                            continue
                        if symbol.entry.st_shndx == "SHN_UNDEF":
                            if name in self.DANGEROUS_LIBC_SINKS:
                                result.imported_dangerous_symbols.append(name)
                        elif name.startswith("Java_"):
                            demangled = self.demangle_jni_name(name)
                            if demangled:
                                cls_name, method_name = demangled
                                result.exported_jni_functions.append(JniExportedFunction(
                                    mangled_name=name, java_class=cls_name,
                                    java_method=method_name, library_name=lib_name,
                                ))
            except Exception:
                result.elf_parse_status = "partial"
                result.scan_status = "partial"
                result.scan_errors.append("elf_symbol_parse_error")

        if result.elf_parse_status in {"partial", "unsupported", "not_present"}:
            result.scan_status = "partial"

        # Identify JNI-looking strings for review, but do not promote them to
        # verified exports unless the dynamic symbol table says so.
        for s in strings_set:
            if s.startswith("Java_"):
                demangled = self.demangle_jni_name(s)
                if demangled:
                    result.jni_export_name_candidates.append(s)

        # Imports or symbol-like strings are review leads, never exploit claims.
        for sink in sorted(set(result.imported_dangerous_symbols) |
                           set(result.dangerous_symbol_string_candidates)):
            is_import = sink in result.imported_dangerous_symbols
            result.findings.append(
                Finding(
                    id=f"NATIVE_LIBC_SINK_{lib_name}_{sink}",
                    title=(f"Review native ELF import in {lib_name}: {sink}" if is_import else
                           f"Review native symbol-like string candidate in {lib_name}: {sink}"),
                    description=((f"The ELF dynamic symbol table lists undefined function import '{sink}' in '{lib_name}' ({arch}). "
                                  "This does not establish a call site, execution, attacker-controlled arguments, or JNI reachability.")
                                 if is_import else
                                 (f"The bounded printable-string scan found '{sink}' in '{lib_name}' ({arch}). "
                                  "This does not establish an ELF dynamic import, call site, execution, "
                                  "tainted arguments, or reachability from an exported JNI method.")),
                    severity=Severity.INFO,
                    status=FindingStatus.UNVERIFIED,
                    cwe_id="CWE-Unknown",
                    file_path=str(path),
                    metadata={
                        "library": lib_name,
                        "architecture": arch,
                        "symbol_string_candidate": not is_import,
                        "analysis_kind": "elf_dynamic_symbol_import" if is_import else "byte_string_inventory",
                        "exported_jni_symbols_co_located": [f.mangled_name for f in result.exported_jni_functions],
                        "call_reachability": "not_analyzed",
                        "scan_status": result.scan_status,
                        "elf_parse_status": result.elf_parse_status,
                        "bytes_scanned": result.bytes_scanned,
                        "scan_truncated": result.scan_truncated,
                        "dynamic_symbols_seen": result.dynamic_symbols_seen,
                    },
                )
            )

        return result

    def audit_package_libraries(self, extracted_dir: str | Path) -> List[NativeLibraryAuditResult]:
        """Audit all native libraries in extracted APK."""
        results: List[NativeLibraryAuditResult] = []
        root = explicit_scan_root(extracted_dir)
        if root is None or root.is_symlink() or not root.is_dir():
            return results
        lib_dir = root / "lib"
        if lib_dir.is_symlink() or not lib_dir.is_dir():
            return results

        for current, dirs, files in os.walk(lib_dir, followlinks=False):
            dirs[:] = sorted(name for name in dirs if not (Path(current) / name).is_symlink())
            for file in files:
                candidate = Path(current) / file
                if file.endswith(".so") and not candidate.is_symlink() and candidate.is_file():
                    results.append(self.audit_library(candidate))
        return results
