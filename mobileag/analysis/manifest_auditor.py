import logging
from typing import Any

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)


class ManifestAuditor:
    """Agent for auditing Android manifest files for security vulnerabilities."""

    def __init__(self, router: LLMRouter):
        """Initialize the manifest auditor with an LLM router."""
        self.router = router

    async def audit(self, manifest_data: dict[str, Any], package_name: str) -> list[Finding]:
        """Audit the provided manifest data for security misconfigurations."""
        logger.info(f"Starting manifest audit for package: {package_name}")
        findings: list[Finding] = []

        # Application level checks
        app_data = manifest_data.get("application", {})
        
        # Check allowBackup (True by default on older Android)
        if app_data.get("allowBackup") is True:
            cwe = "CWE-530"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title="Application Data Backup Allowed",
                description="The app has android:allowBackup set to true, allowing extraction of private app data via ADB backup.",
                severity=Severity.MEDIUM,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component="AndroidManifest.xml/application",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Set android:allowBackup='false' in AndroidManifest.xml unless specifically required.",
                file_path="AndroidManifest.xml"
            ))

        # Check debuggable
        if app_data.get("debuggable") is True:
            cwe = "CWE-489"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title="Application is Debuggable",
                description="The app has android:debuggable set to true. Attackers can attach debuggers to inspect memory and inject code.",
                severity=Severity.HIGH,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component="AndroidManifest.xml/application",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Ensure android:debuggable is false in all production build variants.",
                file_path="AndroidManifest.xml"
            ))

        # Check cleartext traffic
        if app_data.get("usesCleartextTraffic") is True:
            cwe = "CWE-319"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title="Cleartext Traffic Enabled",
                description="The app permits unencrypted cleartext HTTP traffic, risking interception and tampering via MitM attacks.",
                severity=Severity.HIGH,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component="AndroidManifest.xml/application",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Set android:usesCleartextTraffic='false' and configure a strict Network Security Configuration.",
                file_path="AndroidManifest.xml"
            ))

        # Component level checks
        components = manifest_data.get("components") or (
            app_data.get("activities", []) + 
            app_data.get("services", []) + 
            app_data.get("receivers", []) +
            app_data.get("providers", [])
        )

        for comp in components:
            exported = comp.get("exported", False)
            permission = comp.get("permission")
            name = comp.get("name", "UnknownComponent")
            comp_type = comp.get("type", "component").capitalize()

            if exported and not permission:
                cwe = "CWE-926"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Exported {comp_type} Without Permission: {name}",
                    description=f"{comp_type} '{name}' is exported to other apps without any permission restrictions.",
                    severity=Severity.HIGH,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=name,
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation=f"Explicitly set android:exported='false' if external access is not needed, or guard with a custom signature permission.",
                    file_path="AndroidManifest.xml"
                ))

            task_affinity = comp.get("taskAffinity")
            if task_affinity and exported:
                cwe = "CWE-1021"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Task Affinity Hijacking Risk: {name}",
                    description=f"Exported activity '{name}' defines a custom taskAffinity ('{task_affinity}'), creating susceptibility to StrandHogg / task hijacking.",
                    severity=Severity.MEDIUM,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=name,
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Avoid custom taskAffinity on exported activities unless strictly required, and configure launchMode properly.",
                    file_path="AndroidManifest.xml"
                ))

        logger.info(f"Manifest audit completed: {len(findings)} findings.")
        return findings
