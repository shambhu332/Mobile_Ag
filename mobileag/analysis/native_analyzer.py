import asyncio
import hashlib
from io import BytesIO
import logging
from pathlib import Path

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)
_MAX_NATIVE_IMPORT_NAME_SAMPLES = 2048
_MAX_NATIVE_IMPORT_NAMES_PER_LIBRARY = 64


class NativeAnalyzer:
    """Agent for analyzing native (.so) libraries for security vulnerabilities."""

    def __init__(self, router: LLMRouter, ghidra_path: str = '/opt/ghidra'):
        """Initialize the native analyzer with an LLM router and Ghidra path."""
        self.router = router
        self.ghidra_path = ghidra_path
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}
        self.unsafe_functions = {
            b"strcpy": ("CWE-120", "Unsafe string copy without bounds check"),
            b"sprintf": ("CWE-120", "Unsafe string formatting without bounds check"),
            b"gets": ("CWE-120", "Insecure gets function prone to stack buffer overflow"),
            b"strcat": ("CWE-120", "Unsafe string concatenation"),
            b"system": ("CWE-78", "Direct system command execution"),
            b"popen": ("CWE-78", "Process execution via shell pipe"),
            b"execve": ("CWE-78", "Process replacement command execution"),
            b"ptrace": ("CWE-489", "Anti-debugging ptrace hook detection"),
        }

    @staticmethod
    def _elf_import_inventory(raw_data: bytes) -> dict:
        """Return bounded ELF identity/import metadata without inferring calls."""
        result = {"is_elf": False, "elf_magic": False, "parse_error": False, "elf_class": None,
                  "machine": None, "soname": None, "build_id": None,
                  "needed_libraries": [], "needed_libraries_seen": 0,
                  "imported_functions": set(),
                  "dynamic_functions_seen": 0, "symbol_limit_reached": False,
                  "dynamic_tag_limit_reached": False}
        if not raw_data.startswith(b"\x7fELF"):
            return result
        result["elf_magic"] = True
        try:
            from elftools.elf.elffile import ELFFile
            elf = ELFFile(BytesIO(raw_data))
            result.update(is_elf=True, elf_class=elf.elfclass,
                          machine=elf.header.get("e_machine"))
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for index, tag in enumerate(dynamic.iter_tags()):
                    if index >= 1000:
                        result["dynamic_tag_limit_reached"] = True
                        break
                    if tag.entry.d_tag == "DT_SONAME":
                        name = getattr(tag, "soname", "")
                        if isinstance(name, str) and name and len(name) <= 256:
                            result["soname"] = name
                    elif tag.entry.d_tag == "DT_NEEDED":
                        result["needed_libraries_seen"] += 1
                        if len(result["needed_libraries"]) < 8:
                            name = getattr(tag, "needed", "")
                            if isinstance(name, str) and name and len(name) <= 96:
                                result["needed_libraries"].append(name)
            build_id_section = elf.get_section_by_name(".note.gnu.build-id")
            if build_id_section is not None:
                for index, note in enumerate(build_id_section.iter_notes()):
                    if index >= 32:
                        break
                    if note.get("n_name") == "GNU" and note.get("n_type") == "NT_GNU_BUILD_ID":
                        build_id = note.get("n_desc")
                        if isinstance(build_id, str) and len(build_id) <= 128 and all(
                                char in "0123456789abcdefABCDEF" for char in build_id):
                            result["build_id"] = build_id.lower()
                            break
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym is not None:
                for index, symbol in enumerate(dynsym.iter_symbols()):
                    if index >= 5000:
                        result["symbol_limit_reached"] = True
                        break
                    if symbol.entry.st_shndx == "SHN_UNDEF" and symbol.entry.st_info.type == "STT_FUNC":
                        result["dynamic_functions_seen"] += 1
                        name = symbol.name
                        if name and len(name) <= 256:
                            result["imported_functions"].add(name)
        except Exception:
            # Malformed/truncated ELF is an incomplete inventory, not a clean result.
            result["parse_error"] = True
        return result

    def _inspect_so_binary(self, so_file: Path, base_path: Path, raw_data: bytes) -> tuple[list[Finding], dict]:
        """Inspect bounded ELF metadata and byte strings; neither proves execution."""
        findings: list[Finding] = []
        elf_info = self._elf_import_inventory(raw_data)
        try:
            rel_path = str(so_file.relative_to(base_path)) if so_file.is_relative_to(base_path) else str(so_file)
            lib_name = so_file.name

            for func_bytes, (cwe, desc) in self.unsafe_functions.items():
                if func_bytes in raw_data:
                    func_name = func_bytes.decode("utf-8", errors="ignore")
                    is_import = func_name in elf_info["imported_functions"]
                    analysis_kind = "elf_dynamic_symbol_import" if is_import else "byte_string_inventory"
                    evidence = (f"ELF dynamic symbol table lists an undefined function symbol '{func_name}' in '{lib_name}'. This does not establish a call site, attacker-controlled arguments, reachability or vulnerability."
                                if is_import else
                                f"Byte sequence '{func_name}' was observed in '{lib_name}'. This does not establish an ELF import, executable call, attacker-controlled argument, memory corruption or command injection.")
                    findings.append(Finding(
                        title=f"Review native byte-string candidate: {func_name}",
                        description=evidence + " Ghidra/disassembly and runtime validation were not performed; ptrace can be expected anti-debug behavior.",
                        severity=Severity.INFO,
                        cwe_id=cwe,
                        cvss_score=0.0,
                        cvss_vector="",
                        affected_component=lib_name,
                        detection_method="NativeAnalyzer",
                        status=FindingStatus.UNVERIFIED,
                        remediation=f"Inspect whether '{func_name}' is an actual reachable call, its argument bounds and trust boundary. Change code only for a demonstrated unsafe usage; the byte string alone needs no remediation.",
                        file_path=rel_path,
                        metadata={"proof_state": "not_proven", "analysis_kind": analysis_kind,
                                  "ghidra_executed": False, "function_call_observed": False,
                                  "elf_parse_error": elf_info["parse_error"],
                                  "elf_class": elf_info["elf_class"], "elf_machine": elf_info["machine"],
                                  "elf_soname": elf_info["soname"], "elf_build_id": elf_info["build_id"],
                                  "needed_libraries_seen": elf_info["needed_libraries_seen"],
                                  "needed_libraries_truncated": elf_info["needed_libraries_seen"] > len(elf_info["needed_libraries"]),
                                  "needed_libraries": elf_info["needed_libraries"]}
                    ))

        except Exception as e:
            logger.warning(f"Error inspecting native binary {so_file}: {e}")

        return findings, elf_info

    def _sync_analyze(self, base_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        inventory = SourceInventory(max_entries=5000, max_file_bytes=64*1024*1024, max_total_bytes=256*1024*1024)
        elf_counts = {"elf_files_parsed": 0, "non_elf_shared_object_files": 0,
                      "elf_parse_failures": 0, "elf_dynamic_functions_seen": 0,
                      "elf_symbol_limits_reached": 0, "elf_dynamic_tag_limits_reached": 0,
                      "libraries": []}
        remaining_import_name_samples = _MAX_NATIVE_IMPORT_NAME_SAMPLES
        for path, data in inventory.read(base_path, {".so"}):
            file_findings, elf_info = self._inspect_so_binary(path, base_path, data)
            findings.extend(file_findings)
            elf_counts["elf_files_parsed"] += int(elf_info["is_elf"] and not elf_info["parse_error"])
            elf_counts["non_elf_shared_object_files"] += int(not elf_info["elf_magic"])
            elf_counts["elf_parse_failures"] += int(elf_info["parse_error"])
            elf_counts["elf_dynamic_functions_seen"] += elf_info["dynamic_functions_seen"]
            elf_counts["elf_symbol_limits_reached"] += int(elf_info["symbol_limit_reached"])
            elf_counts["elf_dynamic_tag_limits_reached"] += int(elf_info["dynamic_tag_limit_reached"])
            try:
                relative_path = str(path.relative_to(base_path))[:256]
            except ValueError:
                relative_path = path.name[:256]
            import_names = sorted(elf_info["imported_functions"])
            sample_count = min(_MAX_NATIVE_IMPORT_NAMES_PER_LIBRARY,
                               remaining_import_name_samples, len(import_names))
            import_sample = import_names[:sample_count]
            remaining_import_name_samples -= sample_count
            elf_counts["libraries"].append({
                "relative_path": relative_path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "is_elf": elf_info["is_elf"],
                "parse_error": elf_info["parse_error"],
                "elf_class": elf_info["elf_class"],
                "machine": elf_info["machine"],
                "soname": elf_info["soname"],
                "build_id": elf_info["build_id"],
                "needed_library_count": elf_info["needed_libraries_seen"],
                "needed_libraries": elf_info["needed_libraries"],
                "undefined_function_import_count": elf_info["dynamic_functions_seen"],
                "undefined_function_import_names": import_sample,
                "undefined_function_import_names_truncated": (
                    len(import_names) > sample_count or elf_info["symbol_limit_reached"]),
            })
            if len(findings) >= 1000:
                findings = findings[:1000]
                inventory.record_limit('native_candidate_count')
                break
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             candidate_count=len(findings), native_inventory=elf_counts,
                             limits={**inventory.coverage['limits'], 'findings':1000,
                                     'elf_dynamic_symbols_per_file':5000,
                                     'elf_import_name_samples_total':_MAX_NATIVE_IMPORT_NAME_SAMPLES,
                                     'elf_import_names_per_library':_MAX_NATIVE_IMPORT_NAMES_PER_LIBRARY})
        return findings

    async def analyze(self, decompiled_path: str) -> list[Finding]:
        """Analyze bounded native-library bytes from a decompiled application."""
        logger.info("Starting native analysis in: %s", decompiled_path)
        findings = await asyncio.to_thread(self._sync_analyze, Path(decompiled_path))
        logger.info("Native analysis completed: %d findings.", len(findings))
        return findings
