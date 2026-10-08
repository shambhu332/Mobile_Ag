import asyncio
import logging
import re
from pathlib import Path
import httpx

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)


class DependencyScanner:
    """Agent for scanning dependencies for known CVEs via OSV."""

    def __init__(self, router: LLMRouter):
        """Initialize the dependency scanner with an LLM router."""
        self.router = router
        self.dep_pattern = re.compile(r"(?:implementation|api|compile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]")
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}

    def _sync_find_gradle_dependencies(self, base_path: Path) -> list[tuple[str, str, str, str]]:
        """Synchronously scan build.gradle files and META-INF pom.properties for maven coordinates."""
        dependencies = []
        seen = set()
        inventory = SourceInventory(max_entries=5000, max_file_bytes=1024*1024, max_total_bytes=16*1024*1024)
        for file_path, data in inventory.read(base_path, names={"pom.properties"}, suffixes={"build.gradle", "build.gradle.kts"}):
            try:
                content = data.decode("utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                parsed = []
                if file_path.name.startswith("build.gradle"):
                    parsed = [(g,a,v,rel_path) for g,a,v in self.dep_pattern.findall(content)]
                else:
                    values = {}
                    for line in content.splitlines():
                        clean = line.strip()
                        if clean.startswith(("groupId=", "artifactId=", "version=")):
                            key, value = clean.split("=", 1)
                            values[key] = value.strip()
                    if all(values.get(key) for key in ("groupId", "artifactId", "version")):
                        parsed = [(values["groupId"], values["artifactId"], values["version"], rel_path)]
                for dep in parsed:
                    identity = dep[:3]
                    if identity not in seen:
                        seen.add(identity)
                        dependencies.append(dep)
                    if len(dependencies) >= 500:
                        inventory.coverage['limits_reached'] = True
                        break
                if len(dependencies) >= 500:
                    break
            except (OSError, UnicodeError) as e:
                logger.debug("Error reading dependency metadata %s: %s", file_path, e)
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             dependency_count=len(dependencies), limits={**inventory.coverage['limits'], 'dependencies':500})
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
        if getattr(self.router, "_settings", None) and self.router._settings.offline is True:
            self.coverage = {"static_status": "skipped_offline", "runtime_status": "not_tested",
                             "proof_status": "not_proven", "exhaustive": False,
                             "limitations": ["OSV lookup disabled by offline mode"]}
            return []
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
