import asyncio
import logging
from pathlib import Path

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)


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

    def _inspect_so_binary(self, so_file: Path, base_path: Path, raw_data: bytes) -> list[Finding]:
        """Inspect bounded bytes from one .so using a conservative string inventory."""
        findings: list[Finding] = []
        try:
            rel_path = str(so_file.relative_to(base_path)) if so_file.is_relative_to(base_path) else str(so_file)
            lib_name = so_file.name

            for func_bytes, (cwe, desc) in self.unsafe_functions.items():
                if func_bytes in raw_data:
                    func_name = func_bytes.decode("utf-8", errors="ignore")
                    findings.append(Finding(
                        title=f"Review native byte-string candidate: {func_name}",
                        description=(f"Byte sequence '{func_name}' was observed in '{lib_name}'. This does not establish an ELF import, executable call, attacker-controlled argument, memory corruption or command injection. Ghidra/disassembly and runtime validation were not performed; ptrace can be expected anti-debug behavior."),
                        severity=Severity.INFO,
                        cwe_id=cwe,
                        cvss_score=0.0,
                        cvss_vector="",
                        affected_component=lib_name,
                        detection_method="NativeAnalyzer",
                        status=FindingStatus.UNVERIFIED,
                        remediation=f"Inspect whether '{func_name}' is an actual reachable call, its argument bounds and trust boundary. Change code only for a demonstrated unsafe usage; the byte string alone needs no remediation.",
                        file_path=rel_path,
                        metadata={"proof_state": "not_proven", "analysis_kind": "byte_string_inventory", "ghidra_executed": False}
                    ))

        except Exception as e:
            logger.warning(f"Error inspecting native binary {so_file}: {e}")

        return findings

    def _sync_analyze(self, base_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        inventory = SourceInventory(max_entries=5000, max_file_bytes=64*1024*1024, max_total_bytes=256*1024*1024)
        for path, data in inventory.read(base_path, {".so"}):
            findings.extend(self._inspect_so_binary(path, base_path, data))
            if len(findings) >= 1000:
                findings = findings[:1000]
                inventory.coverage['limits_reached'] = True
                break
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             candidate_count=len(findings), limits={**inventory.coverage['limits'], 'findings':1000})
        return findings

    async def analyze(self, decompiled_path: str) -> list[Finding]:
        """Analyze bounded native-library bytes from a decompiled application."""
        logger.info("Starting native analysis in: %s", decompiled_path)
        findings = await asyncio.to_thread(self._sync_analyze, Path(decompiled_path))
        logger.info("Native analysis completed: %d findings.", len(findings))
        return findings
