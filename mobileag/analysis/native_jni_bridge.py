"""Native JNI Cross-Boundary Analyzer (inspired by REA).

Inspects native shared libraries (.so) in mobile packages, maps exported JNI entry points
(Java_<package>_<class>_<method>), and audits imported libc and OS calls to uncover
hidden native execution sinks (system, popen, strcpy, sqlite3_exec).
"""
from __future__ import annotations

import os
import re
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
    dangerous_calls_referenced: List[str] = field(default_factory=list)


@dataclass
class NativeLibraryAuditResult:
    library_name: str
    architecture: str
    exported_jni_functions: List[JniExportedFunction] = field(default_factory=list)
    imported_dangerous_symbols: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class NativeJniAnalyzer:
    """Disassembles and audits ELF dynamic symbols and JNI exported functions."""

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
            with open(path, "rb") as f:
                data = f.read(5 * 1024 * 1024)  # Read up to 5MB
        except OSError:
            return result

        # Basic ELF Magic verification (0x7F, 'E', 'L', 'F')
        if not data.startswith(b"\x7fELF"):
            return result

        # Extract printable strings
        raw_strings = re.findall(b"[a-zA-Z0-9_]{3,}", data)
        strings_set: Set[str] = {s.decode("ascii", errors="ignore") for s in raw_strings}

        # Identify dangerous imported sinks
        for sink, (cwe, sev, desc) in self.DANGEROUS_LIBC_SINKS.items():
            if sink in strings_set:
                result.imported_dangerous_symbols.append(sink)

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
                        dangerous_calls_referenced=[d for d in result.imported_dangerous_symbols],
                    )
                    result.exported_jni_functions.append(jni_func)

        # Generate findings for high-risk native configurations
        for sink in result.imported_dangerous_symbols:
            cwe, sev, desc = self.DANGEROUS_LIBC_SINKS[sink]
            matching_jni = [f.java_class + "." + f.java_method for f in result.exported_jni_functions]
            jni_ctx = f" Exposed via JNI endpoints: {', '.join(matching_jni[:3])}." if matching_jni else ""

            result.findings.append(
                Finding(
                    id=f"NATIVE_LIBC_SINK_{lib_name}_{sink}",
                    title=f"Native Dangerous Execution Sink in {lib_name}: {sink}()",
                    description=f"{desc} inside shared library '{lib_name}' ({arch}).{jni_ctx}",
                    severity=sev,
                    status=FindingStatus.UNVERIFIED,
                    cwe_id=cwe,
                    file_path=str(path),
                    metadata={
                        "library": lib_name,
                        "architecture": arch,
                        "sink": sink,
                        "exported_jni_methods": [f.mangled_name for f in result.exported_jni_functions],
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
