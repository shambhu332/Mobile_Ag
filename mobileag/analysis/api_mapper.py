import asyncio
import logging
import re
from pathlib import Path

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)


class APIMapper:
    """Agent for extracting API endpoints and identifying associated security issues."""

    def __init__(self, router: LLMRouter):
        """Initialize the API mapper with an LLM router."""
        self.router = router
        self.retrofit_pattern = re.compile(r'@(GET|POST|PUT|DELETE|PATCH)\(\s*"([^"]+)"\s*\)')
        self.url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9._/?%&=-]*)?')
        self.graphql_pattern = re.compile(r'query\s*\{|mutation\s*\{')

    def _sync_map_apis(self, base_path: Path) -> tuple[list[dict], list[dict]]:
        """Synchronously scan source files for API definitions and URL references."""
        endpoints: list[dict] = []
        raw_findings: list[dict] = []

        for file_path in base_path.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in {".java", ".kt"}:
                continue
                
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                stem = file_path.stem
                
                # Extract Retrofit annotations
                for method, path in self.retrofit_pattern.findall(content):
                    endpoints.append({
                        "method": method,
                        "url": path,
                        "class_name": stem,
                        "requires_auth": "Authorization" in content
                    })
                    
                    if "admin" in path.lower() or "privilege" in path.lower():
                        raw_findings.append({
                            "type": "privileged_endpoint",
                            "path": path,
                            "component": stem,
                            "file_path": rel_path
                        })

                # Extract hardcoded URLs
                for url in self.url_pattern.findall(content):
                    lower_url = url.lower()
                    if "dev" in lower_url or "staging" in lower_url or "test." in lower_url:
                        raw_findings.append({
                            "type": "staging_url",
                            "url": url,
                            "component": stem,
                            "file_path": rel_path
                        })
                    elif lower_url.startswith("http://") and not lower_url.startswith("http://localhost") and not lower_url.startswith("http://127.0.0.1"):
                        raw_findings.append({
                            "type": "cleartext_url",
                            "url": url,
                            "component": stem,
                            "file_path": rel_path
                        })

            except Exception as e:
                logger.debug(f"Could not read file {file_path}: {e}")
                continue

        return endpoints, raw_findings

    async def map_apis(self, decompiled_path: str) -> tuple[list[dict], list[Finding]]:
        """Map API endpoints and identify API-related vulnerabilities."""
        logger.info(f"Starting API mapping in: {decompiled_path}")
        findings: list[Finding] = []
        base_path = Path(decompiled_path)
        
        endpoints, raw_findings = await asyncio.to_thread(self._sync_map_apis, base_path)

        for item in raw_findings:
            if item["type"] == "privileged_endpoint":
                cwe = "CWE-285"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Privileged Endpoint Referenced in Client Code: {item['path']}",
                    description=f"Client application references administrative or privileged endpoint '{item['path']}'.",
                    severity=Severity.HIGH,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=item["component"],
                    detection_method="APIMapper",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Ensure privileged endpoints enforce robust server-side RBAC and avoid hardcoding administrative routes in client binaries.",
                    file_path=item["file_path"]
                ))
            elif item["type"] == "staging_url":
                cwe = "CWE-489"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Non-Production Staging/Dev Environment URL: {item['url']}",
                    description=f"Decompiled code references development/staging endpoint: {item['url']}.",
                    severity=Severity.MEDIUM,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=item["component"],
                    detection_method="APIMapper",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Configure build variants (buildConfigField) to ensure non-production URLs are excluded from release packages.",
                    file_path=item["file_path"]
                ))
            elif item["type"] == "cleartext_url":
                cwe = "CWE-319"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Hardcoded Cleartext HTTP URL: {item['url']}",
                    description=f"Code references unencrypted HTTP URL: {item['url']}.",
                    severity=Severity.MEDIUM,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=item["component"],
                    detection_method="APIMapper",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Migrate all network endpoints to HTTPS with modern TLS configurations.",
                    file_path=item["file_path"]
                ))

        logger.info(f"API mapping complete: {len(endpoints)} endpoints, {len(findings)} findings.")
        return endpoints, findings
