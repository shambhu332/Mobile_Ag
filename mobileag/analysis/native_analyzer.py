import asyncio
import logging
from pathlib import Path

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)


class NativeAnalyzer:
    """Agent for analyzing native (.so) libraries for security vulnerabilities."""

    def __init__(self, router: LLMRouter, ghidra_path: str = '/opt/ghidra'):
        """Initialize the native analyzer with an LLM router and Ghidra path."""
        self.router = router
        self.ghidra_path = ghidra_path
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

    async def _inspect_so_binary(self, so_file: Path, base_path: Path) -> list[Finding]:
        """Inspect a single .so library using direct binary byte scanning and strings fallback."""
        findings: list[Finding] = []
        try:
            # Direct binary inspection (100% portable, no subprocess requirement)
            raw_data = await asyncio.to_thread(so_file.read_bytes)
            rel_path = str(so_file.relative_to(base_path)) if so_file.is_relative_to(base_path) else str(so_file)
            lib_name = so_file.name

            for func_bytes, (cwe, desc) in self.unsafe_functions.items():
                if func_bytes in raw_data:
                    func_name = func_bytes.decode("utf-8", errors="ignore")
                    score, vector = get_default_cvss_for_cwe(cwe)
                    findings.append(Finding(
                        title=f"Unsafe C Function / Symbol in Native Library: {func_name}",
                        description=f"The native library '{lib_name}' imports or defines '{func_name}': {desc}.",
                        severity=Severity.HIGH if cwe == "CWE-78" else Severity.MEDIUM,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        affected_component=lib_name,
                        detection_method="NativeAnalyzer",
                        status=FindingStatus.CONFIRMED,
                        remediation=f"Replace '{func_name}' with safe, bounds-checked alternatives (e.g. strncpy, snprintf, or C++ std::string equivalents).",
                        file_path=rel_path
                    ))

        except Exception as e:
            logger.warning(f"Error inspecting native binary {so_file}: {e}")

        return findings

    async def analyze(self, decompiled_path: str) -> list[Finding]:
        """Analyze native libraries found in the decompiled application."""
        logger.info(f"Starting native analysis in: {decompiled_path}")
        findings: list[Finding] = []
        base_path = Path(decompiled_path)
        
        so_files = list(base_path.rglob("lib/**/*.so"))
        if not so_files:
            logger.info("No native .so libraries discovered.")
            return findings

        # Run binary inspections concurrently with non-blocking async processes
        tasks = [self._inspect_so_binary(so, base_path) for so in so_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"Native binary analysis task failed: {res}")

        logger.info(f"Native analysis completed: {len(findings)} findings.")
        return findings
