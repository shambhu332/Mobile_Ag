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

            # FileProvider misconfiguration check
            if "FileProvider" in name or (comp.get("meta_data") and "android.support.FILE_PROVIDER_PATHS" in comp.get("meta_data", {})):
                if exported:
                    cwe = "CWE-22"
                    score, vector = get_default_cvss_for_cwe(cwe)
                    findings.append(Finding(
                        title=f"Exported FileProvider with Arbitrary File Access Risk: {name}",
                        description=f"FileProvider '{name}' is set to android:exported='true'. FileProviders must never be exported directly.",
                        severity=Severity.CRITICAL,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        affected_component=name,
                        detection_method="ManifestAuditor",
                        status=FindingStatus.CONFIRMED,
                        remediation="Set android:exported='false' on all FileProvider declarations and rely on temporary FLAG_GRANT_READ_URI_PERMISSION.",
                        file_path="AndroidManifest.xml"
                    ))

        # Check custom declared permissions for weak protectionLevel (CWE-276)
        declared_perms = manifest_data.get("declared_permissions", [])
        for dperm in declared_perms:
            p_name = dperm.get("name", "")
            prot = (dperm.get("protectionLevel") or "").lower()
            if prot in ("normal", "", "none"):
                cwe = "CWE-276"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Insecure Custom Permission with Normal Protection Level: {p_name}",
                    description=(
                        f"Custom permission '{p_name}' defines protectionLevel='{prot or 'normal'}'. "
                        "Any third-party app installed on the device can request and automatically obtain this permission "
                        "without user prompting or signature verification, defeating component access control."
                    ),
                    severity=Severity.HIGH,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"AndroidManifest.xml/permission/{p_name}",
                    detection_method="ManifestAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Elevate custom permissions guarding sensitive components to android:protectionLevel='signature'.",
                    file_path="AndroidManifest.xml"
                ))

        # Check dangerous system permissions requested
        requested_perms = manifest_data.get("permissions", [])
        if "android.permission.SYSTEM_ALERT_WINDOW" in requested_perms:
            cwe = "CWE-1021"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title="Dangerous Permission Requested: SYSTEM_ALERT_WINDOW (Overlay / Tapjacking)",
                description="The app requests SYSTEM_ALERT_WINDOW, allowing drawing overlays on top of other apps, exposing users to tapjacking and UI spoofing.",
                severity=Severity.MEDIUM,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component="AndroidManifest.xml/uses-permission",
                detection_method="ManifestAuditor",
                status=FindingStatus.CONFIRMED,
                remediation="Only request SYSTEM_ALERT_WINDOW if background floating UI is indispensable. Enforce FLAG_SECURE on sensitive activities.",
                file_path="AndroidManifest.xml"
            ))

        if "android.permission.REQUEST_INSTALL_PACKAGES" in requested_perms:
            cwe = "CWE-250"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title="Excessive Privilege: REQUEST_INSTALL_PACKAGES Requested",
                description="The app requests REQUEST_INSTALL_PACKAGES, enabling sideloading and prompt-based APK installation, facilitating drive-by malware delivery if compromised.",
                severity=Severity.HIGH,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component="AndroidManifest.xml/uses-permission",
                detection_method="ManifestAuditor",
                status=FindingStatus.CONFIRMED,
                remediation="Remove REQUEST_INSTALL_PACKAGES and direct users to official app stores instead of in-app self-updating APKs.",
                file_path="AndroidManifest.xml"
            ))

        logger.info(f"Manifest audit completed: {len(findings)} findings.")
        return findings
