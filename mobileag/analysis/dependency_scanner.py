import asyncio
import logging
import re
from pathlib import Path
import httpx

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)


class DependencyScanner:
    """Agent for scanning dependencies for known CVEs via OSV."""

    def __init__(self, router: LLMRouter):
        """Initialize the dependency scanner with an LLM router."""
        self.router = router
        self.dep_pattern = re.compile(r"(?:implementation|api|compile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]")

    def _sync_find_gradle_dependencies(self, base_path: Path) -> list[tuple[str, str, str, str]]:
        """Synchronously scan build.gradle files and META-INF pom.properties for maven coordinates."""
        dependencies = []
        # 1. Gradle files
        for file_path in base_path.rglob("build.gradle*"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                for group, artifact, version in self.dep_pattern.findall(content):
                    dependencies.append((group, artifact, version, rel_path))
            except Exception as e:
                logger.error(f"Error reading gradle file {file_path}: {e}")

        # 2. Embedded APK pom.properties (META-INF/maven/**/pom.properties)
        for pom_prop in base_path.rglob("pom.properties"):
            try:
                content = pom_prop.read_text(encoding="utf-8", errors="ignore")
                group, artifact, version = "", "", ""
                for line in content.splitlines():
                    clean = line.strip()
                    if clean.startswith("groupId="):
                        group = clean.split("=", 1)[1].strip()
                    elif clean.startswith("artifactId="):
                        artifact = clean.split("=", 1)[1].strip()
                    elif clean.startswith("version="):
                        version = clean.split("=", 1)[1].strip()
                if group and artifact and version:
                    rel_path = str(pom_prop.relative_to(base_path))
                    dependencies.append((group, artifact, version, rel_path))
            except Exception as e:
                logger.debug(f"Error reading pom.properties {pom_prop}: {e}")

        return dependencies

    async def _query_osv_package(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        group: str,
        artifact: str,
        version: str,
        file_path: str
    ) -> list[Finding]:
        """Query OSV API for a single dependency with concurrency limiting."""
        pkg_name = f"{group}:{artifact}"
        query = {
            "package": {"name": pkg_name, "ecosystem": "Maven"},
            "version": version
        }
        findings: list[Finding] = []

        async with semaphore:
            try:
                response = await client.post("https://api.osv.dev/v1/query", json=query, timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get("vulns", []):
                        cve_id = vuln.get("aliases", [vuln.get("id", "CVE-Unknown")])[0]
                        summary = vuln.get("summary", "Known vulnerability identified in third-party library dependency.")
                        
                        cwe = "CWE-1104"
                        score, vector = get_default_cvss_for_cwe(cwe)
                        findings.append(Finding(
                            title=f"Vulnerable Dependency: {pkg_name} ({version})",
                            description=f"{summary} (Advisory/CVE: {cve_id})",
                            severity=Severity.HIGH,
                            cwe_id=cwe,
                            cvss_score=score,
                            cvss_vector=vector,
                            affected_component=pkg_name,
                            detection_method="DependencyScanner",
                            status=FindingStatus.UNVERIFIED,
                            remediation=f"Upgrade {pkg_name} to a secure version that resolves {cve_id}.",
                            file_path=file_path
                        ))
            except Exception as e:
                logger.debug(f"OSV lookup failed for {pkg_name}:{version} - {e}")

        return findings

    async def scan(self, decompiled_path: str) -> list[Finding]:
        """Parse build files and query OSV for known CVEs in dependencies."""
        logger.info(f"Starting dependency scan in: {decompiled_path}")
        findings: list[Finding] = []
        base_path = Path(decompiled_path)
        
        dependencies = await asyncio.to_thread(self._sync_find_gradle_dependencies, base_path)
        if not dependencies:
            logger.info("No Gradle dependencies identified.")
            return findings

        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient() as client:
            tasks = [
                self._query_osv_package(client, semaphore, grp, art, ver, fp)
                for grp, art, ver, fp in dependencies
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"Dependency scan task error: {res}")

        logger.info(f"Dependency scan completed: {len(findings)} findings.")
        return findings
