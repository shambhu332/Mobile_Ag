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
        self.unsafe_functions = {b"strcpy", b"sprintf", b"gets", b"strcat", b"system"}

    async def _inspect_so_binary(self, so_file: Path, base_path: Path) -> list[Finding]:
        """Inspect a single .so library using async subprocess."""
        findings: list[Finding] = []
        try:
            cmd = ["strings", str(so_file)]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=20.0)
            
            if process.returncode == 0 and stdout:
                rel_path = str(so_file.relative_to(base_path))
                lib_name = so_file.name

                for func in self.unsafe_functions:
                    if func in stdout:
                        func_name = func.decode("utf-8", errors="ignore")
                        cwe = "CWE-120"
                        score, vector = get_default_cvss_for_cwe(cwe)
                        findings.append(Finding(
                            title=f"Unsafe C Function Used in Native Library: {func_name}",
                            description=f"The native library '{lib_name}' imports or defines the unsafe function '{func_name}', presenting potential buffer overflow hazards.",
                            severity=Severity.MEDIUM,
                            cwe_id=cwe,
                            cvss_score=score,
                            cvss_vector=vector,
                            affected_component=lib_name,
                            detection_method="NativeAnalyzer",
                            status=FindingStatus.UNVERIFIED,
                            remediation=f"Replace '{func_name}' with safe, bounds-checked alternatives such as strncpy, snprintf, or C++ std::string equivalents.",
                            file_path=rel_path
                        ))

        except (asyncio.TimeoutError, FileNotFoundError) as e:
            logger.debug(f"Strings command timeout or unavailable on {so_file}: {e}")
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
