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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.analysis.bounded_sources import explicit_scan_root


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
    dangerous_symbol_string_candidates: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def imported_dangerous_symbols(self) -> List[str]:
        """Deprecated compatibility alias; values are printable-string candidates."""
        return self.dangerous_symbol_string_candidates


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
        """Convert Java_com_example_app_NativeClass_methodName to (FQCN, method)."""
        if not symbol.startswith("Java_"):
            return None

        # JNI name encoding replaces '_' with '/' or package separators
        # Java_com_example_app_NativeClass_nativeMethod
        parts = symbol.split("_")
        if len(parts) >= 3:
            # parts[0] is 'Java'
            # middle parts form package + class
            method = parts[-1]
            pkg_class = ".".join(parts[1:-1])
            return pkg_class, method
        return None

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

        # Extract printable strings
        raw_strings = re.findall(b"[a-zA-Z0-9_]{3,}", data)
        strings_set: Set[str] = {s.decode("ascii", errors="ignore") for s in raw_strings}

        # This intentionally does not parse ELF dynamic symbols: strings in a
        # binary are only candidates and can be unrelated data or debug text.
        for sink in self.DANGEROUS_LIBC_SINKS:
            if sink in strings_set:
                result.dangerous_symbol_string_candidates.append(sink)

        # Identify exported JNI functions
        for s in strings_set:
            if s.startswith("Java_"):
                demangled = self.demangle_jni_name(s)
                if demangled:
                    cls_name, method_name = demangled
                    jni_func = JniExportedFunction(
                        mangled_name=s,
                        java_class=cls_name,
                        java_method=method_name,
                        library_name=lib_name,
                    )
                    result.exported_jni_functions.append(jni_func)

        # Co-presence of strings and JNI-style names does not prove a call edge.
        for sink in result.dangerous_symbol_string_candidates:
            result.findings.append(
                Finding(
                    id=f"NATIVE_LIBC_SINK_{lib_name}_{sink}",
                    title=f"Review native symbol-like string candidate in {lib_name}: {sink}",
                    description=(f"The bounded printable-string scan found '{sink}' in '{lib_name}' ({arch}). "
                                 "This does not establish an ELF dynamic import, call site, execution, "
                                 "tainted arguments, or reachability from an exported JNI method."),
                    severity=Severity.INFO,
                    status=FindingStatus.UNVERIFIED,
                    cwe_id="CWE-Unknown",
                    file_path=str(path),
                    metadata={
                        "library": lib_name,
                        "architecture": arch,
                        "symbol_string_candidate": sink,
                        "exported_jni_symbols_co_located": [f.mangled_name for f in result.exported_jni_functions],
                        "call_reachability": "not_analyzed",
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
