"""Binary protection auditor for Android native shared libraries (.so files).

Uses pyelftools to parse ELF headers and check for compile-time hardening controls:
- Stack Canaries (__stack_chk_fail)
- Non-Executable Stack (NX / DEP via PT_GNU_STACK)
- Relocation Read-Only (RELRO via PT_GNU_RELRO, Full vs Partial)
- Position Independent Executable / Shared Object (PIE via ET_DYN)
"""

import asyncio
import io
import logging
import os
import stat
from pathlib import Path
from typing import Any, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    ELFFile = None
    DynamicSection = None

from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)


class BinaryProtectionAuditor:
    """Audits compiled native libraries (.so) for defensive ELF security mitigations."""

    def __init__(self) -> None:
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}
        if ELFFile is None:
            logger.warning("pyelftools is not installed. Native binary protection auditing will be limited.")

    def find_native_libraries(self, decompiled_dir: str | Path) -> list[Path]:
        """Locate all .so files under lib/ or root directories."""
        root = Path(decompiled_dir)
        inventory = SourceInventory(max_entries=5000, max_file_bytes=64*1024*1024,
                                    max_total_bytes=256*1024*1024)
        return sorted(path for path, _ in inventory.read(root, {".so"}))

    def audit_library_file(self, so_path: Path, base_dir: Optional[Path] = None,
                           data: Optional[bytes] = None) -> list[dict[str, Any]]:
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
            if data is None:
                fd = os.open(so_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    details = os.fstat(stream.fileno())
                    if not stat.S_ISREG(details.st_mode) or details.st_size > 64*1024*1024:
                        return []
                    data = stream.read(64*1024*1024 + 1)
                if len(data) > 64*1024*1024:
                    return []
            elf = ELFFile(io.BytesIO(data))

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
                    f"No stack-canary symbol was observed in '{lib_name}'. This is a hardening indicator, not evidence of a reachable memory corruption flaw or exploit."
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
                    f"The ELF does not expose a confirmed non-executable GNU stack marker for '{lib_name}'. Verify toolchain/platform defaults and actual load behavior; no code-execution path is established."
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
                    f"No PT_GNU_RELRO segment was observed in '{lib_name}'. This is a hardening observation and does not prove a writable GOT overwrite path or exploitable corruption."
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
                    f"The ELF appears to use partial RELRO. Confirm dynamic tags and runtime loader behavior; no GOT overwrite primitive or impact is demonstrated."
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
                    f"The ELF type does not appear to be ET_DYN for '{lib_name}'. Confirm the artifact type and Android loader behavior; this is a hardening/configuration signal, not exploit proof."
                ),
                "file_path": rel_path,
                "remediation": "Compile with '-fPIC' and link with '-pie'."
            })

        return findings

    def audit_directory(self, decompiled_dir: str | Path) -> list[dict[str, Any]]:
        """Synchronously audit all discovered .so libraries under a directory."""
        root = Path(decompiled_dir)
        all_findings = []
        if ELFFile is None:
            self.coverage = {"static_status": "unsupported", "runtime_status": "not_tested",
                             "proof_status": "not_proven", "exhaustive": False,
                             "limitations": ["pyelftools is unavailable; ELF protections were not analyzed"]}
            return all_findings
        inventory = SourceInventory(max_entries=5000, max_file_bytes=64*1024*1024,
                                    max_total_bytes=256*1024*1024)
        for so_file, data in inventory.read(root, {".so"}):
            all_findings.extend(self.audit_library_file(so_file, base_dir=root, data=data))
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             candidate_count=len(all_findings))
        return all_findings

    async def audit_directory_async(self, decompiled_dir: str | Path) -> list[Finding]:
        """Asynchronously audit native libraries and return Finding objects."""
        raw_findings = await asyncio.to_thread(self.audit_directory, decompiled_dir)
        findings: list[Finding] = []

        for item in raw_findings:
            cwe = item["cwe"]
            findings.append(Finding(
                title=item["title"],
                description=item["description"],
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component=Path(item["file_path"]).name,
                detection_method="BinaryProtectionAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation=item["remediation"],
                file_path=item["file_path"],
                metadata={"proof_state": "not_proven", "analysis_kind": "ELF_hardening_signal",
                          "limitations": ["not a vulnerability exploitability test", "runtime loader behavior not tested"]},
            ))

        return findings
