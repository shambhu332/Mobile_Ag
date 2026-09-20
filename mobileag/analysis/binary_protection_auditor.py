"""Binary protection auditor for Android native shared libraries (.so files).

Uses pyelftools to parse ELF headers and check for compile-time hardening controls:
- Stack Canaries (__stack_chk_fail)
- Non-Executable Stack (NX / DEP via PT_GNU_STACK)
- Relocation Read-Only (RELRO via PT_GNU_RELRO, Full vs Partial)
- Position Independent Executable / Shared Object (PIE via ET_DYN)
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    ELFFile = None
    DynamicSection = None

from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)


class BinaryProtectionAuditor:
    """Audits compiled native libraries (.so) for defensive ELF security mitigations."""

    def __init__(self) -> None:
        if ELFFile is None:
            logger.warning("pyelftools is not installed. Native binary protection auditing will be limited.")

    def find_native_libraries(self, decompiled_dir: str | Path) -> list[Path]:
        """Locate all .so files under lib/ or root directories."""
        root = Path(decompiled_dir)
        so_files = list(root.rglob("lib/**/*.so"))
        if not so_files:
            so_files = list(root.rglob("*.so"))
        return sorted(so_files)

    def audit_library_file(self, so_path: Path, base_dir: Optional[Path] = None) -> list[dict[str, Any]]:
        """Parse ELF headers of a single shared library and evaluate binary protections.

        Args:
            so_path: Path to the .so shared library.
            base_dir: Optional base directory to compute relative file path.

        Returns:
            List of findings as standardized dictionaries.
        """
        if ELFFile is None:
            return []

        rel_path = str(so_path.relative_to(base_dir)) if base_dir and so_path.is_relative_to(base_dir) else str(so_path)
        lib_name = so_path.name

        try:
            with so_path.open("rb") as f:
                elf = ELFFile(f)

                # 1. Check PIE / ET_DYN
                is_pie = elf.header.get("e_type") == "ET_DYN"

                # 2. Check Stack Canary
                has_canary = False
                for section_name in [".dynsym", ".symtab"]:
                    sec = elf.get_section_by_name(section_name)
                    if sec:
                        for sym in sec.iter_symbols():
                            if sym.name in ("__stack_chk_fail", "__intel_security_cookie"):
                                has_canary = True
                                break
                    if has_canary:
                        break

                # 3. Check NX (PT_GNU_STACK)
                has_nx = False
                gnu_stack_found = False
                for seg in elf.iter_segments():
                    if seg["p_type"] == "PT_GNU_STACK":
                        gnu_stack_found = True
                        # PF_X is 0x1. If (flags & 1) == 0, stack is non-executable
                        if (seg["p_flags"] & 0x1) == 0:
                            has_nx = True
                        break

                # 4. Check RELRO
                has_relro = False
                full_relro = False
                for seg in elf.iter_segments():
                    if seg["p_type"] == "PT_GNU_RELRO":
                        has_relro = True
                        break

                if has_relro:
                    dyn_sec = elf.get_section_by_name(".dynamic")
                    if dyn_sec and isinstance(dyn_sec, DynamicSection):
                        for tag in dyn_sec.iter_tags():
                            d_tag = tag.entry.d_tag
                            d_val = getattr(tag.entry, "d_val", 0)
                            if d_tag == "DT_BIND_NOW":
                                full_relro = True
                                break
                            elif d_tag == "DT_FLAGS" and (d_val & 0x8):  # DF_BIND_NOW = 0x8
                                full_relro = True
                                break
                            elif d_tag == "DT_FLAGS_1" and (d_val & 0x1):  # DF_1_NOW = 0x1
                                full_relro = True
                                break

        except Exception as e:
            logger.debug(f"Failed to parse ELF file {so_path}: {e}")
            return []

        findings: list[dict[str, Any]] = []

        # Evaluate Stack Canary
        if not has_canary:
            findings.append({
                "issue_id": "BIN-NO-STACK-CANARY",
                "cwe": "CWE-119",
                "severity": "Medium",
                "title": f"Missing Stack Canary Protection in {lib_name}",
                "description": (
                    f"The native library '{lib_name}' was compiled without stack canary instrumentation "
                    f"(__stack_chk_fail not present in symbol tables). Stack-based buffer overflows can directly "
                    f"overwrite the function return pointer."
                ),
                "file_path": rel_path,
                "remediation": "Recompile with '-fstack-protector-all' or '-fstack-protector-strong' compiler flags."
            })

        # Evaluate NX Stack
        if not has_nx:
            findings.append({
                "issue_id": "BIN-EXECUTABLE-STACK",
                "cwe": "CWE-119",
                "severity": "High",
                "title": f"Executable Stack (Missing NX / DEP) in {lib_name}",
                "description": (
                    f"The native library '{lib_name}' does not enforce non-executable stack protection "
                    f"(PT_GNU_STACK segment is missing or marked executable). An attacker can execute shellcode "
                    f"injected directly into stack memory."
                ),
                "file_path": rel_path,
                "remediation": "Recompile with '-z noexecstack' linker option."
            })

        # Evaluate RELRO
        if not has_relro:
            findings.append({
                "issue_id": "BIN-NO-RELRO",
                "cwe": "CWE-732",
                "severity": "Medium",
                "title": f"No RELRO (Relocation Read-Only) in {lib_name}",
                "description": (
                    f"The native library '{lib_name}' lacks a PT_GNU_RELRO segment. The Global Offset Table (GOT) "
                    f"remains completely writable during runtime, facilitating GOT overwrite exploitation."
                ),
                "file_path": rel_path,
                "remediation": "Recompile using '-Wl,-z,relro -Wl,-z,now' for Full RELRO protection."
            })
        elif not full_relro:
            findings.append({
                "issue_id": "BIN-PARTIAL-RELRO",
                "cwe": "CWE-732",
                "severity": "Low",
                "title": f"Partial RELRO Detected in {lib_name}",
                "description": (
                    f"The native library '{lib_name}' uses Partial RELRO instead of Full RELRO. The GOT is located "
                    f"before the BSS, but lazy binding allows GOT entries to remain writable."
                ),
                "file_path": rel_path,
                "remediation": "Add '-Wl,-z,now' linker flag to enforce immediate symbol binding (Full RELRO)."
            })

        # Evaluate PIE
        if not is_pie:
            findings.append({
                "issue_id": "BIN-NO-PIE",
                "cwe": "CWE-119",
                "severity": "Medium",
                "title": f"Position Independent Code (PIE) Missing in {lib_name}",
                "description": (
                    f"The binary '{lib_name}' was not compiled as a position-independent shared object (ET_DYN). "
                    f"Without PIE, the binary cannot take full advantage of Address Space Layout Randomization (ASLR)."
                ),
                "file_path": rel_path,
                "remediation": "Compile with '-fPIC' and link with '-pie'."
            })

        return findings

    def audit_directory(self, decompiled_dir: str | Path) -> list[dict[str, Any]]:
        """Synchronously audit all discovered .so libraries under a directory."""
        root = Path(decompiled_dir)
        so_files = self.find_native_libraries(root)
        all_findings = []
        for so_file in so_files:
            all_findings.extend(self.audit_library_file(so_file, base_dir=root))
        return all_findings

    async def audit_directory_async(self, decompiled_dir: str | Path) -> list[Finding]:
        """Asynchronously audit native libraries and return Finding objects."""
        raw_findings = await asyncio.to_thread(self.audit_directory, decompiled_dir)
        findings: list[Finding] = []

        for item in raw_findings:
            cwe = item["cwe"]
            score, vector = get_default_cvss_for_cwe(cwe)
            sev_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
            }
            severity = sev_map.get(item["severity"], Severity.MEDIUM)

            findings.append(Finding(
                title=item["title"],
                description=item["description"],
                severity=severity,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component=Path(item["file_path"]).name,
                detection_method="BinaryProtectionAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation=item["remediation"],
                file_path=item["file_path"],
            ))

        return findings
