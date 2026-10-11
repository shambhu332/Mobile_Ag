import logging
from typing import Any

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus

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
            findings.append(Finding(
                title="Application Data Backup Allowed",
                description="The manifest declares android:allowBackup=true. This alone does not establish that sensitive data is included or retrievable on the target Android version; review backup rules, target OS behavior and the data actually stored.",
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component="AndroidManifest.xml/application",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Set android:allowBackup='false' in AndroidManifest.xml unless specifically required.",
                file_path="AndroidManifest.xml"
            ))

        # Check debuggable
        if app_data.get("debuggable") is True:
            cwe = "CWE-489"
            findings.append(Finding(
                title="Application is Debuggable",
                description="The manifest declares android:debuggable=true. Confirm the effective installed release build and ordinary-app/debug authorization conditions; this static flag alone does not demonstrate an exploitable production package.",
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component="AndroidManifest.xml/application",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Ensure android:debuggable is false in all production build variants.",
                file_path="AndroidManifest.xml"
            ))

        # Check cleartext traffic
        if app_data.get("usesCleartextTraffic") is True:
            cwe = "CWE-319"
            findings.append(Finding(
                title="Cleartext Traffic Enabled",
                description="The manifest declares android:usesCleartextTraffic=true. Effective behavior can depend on target SDK and Network Security Config; verify a sensitive request actually uses cleartext before claiming interception impact.",
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
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

            # Android 12+ rejects target-31+ APK components with intent filters
            # that omit android:exported. This is a build/installability lead,
            # not a claim of external reachability or vulnerability.
            target_sdk = str(manifest_data.get("target_sdk", ""))
            if (exported is None and not comp.get("exported_explicit")
                    and comp.get("intent_filters") and target_sdk.isdecimal()
                    and int(target_sdk) >= 31):
                findings.append(Finding(
                    title=f"Missing android:exported on {comp_type}: {name}",
                    description=(f"Target SDK {target_sdk} and an intent filter are present, but the component omits "
                                 "android:exported. Android 12+ requires this value for target-31+ apps; the APK may "
                                 "fail installation rather than expose this component. Confirm the merged release manifest."),
                    severity=Severity.INFO, cwe_id="CWE-Unknown", cvss_score=0.0,
                    affected_component=name, detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Set android:exported explicitly to the intended value in the merged release manifest.",
                    file_path="AndroidManifest.xml",
                    metadata={"analysis_kind": "manifest_installability", "proof_state": "not_proven",
                              "target_sdk": target_sdk},
                ))

            if exported and not permission:
                # Exposure is an attack-surface observation, not proof of a
                # missing authorization check. Launcher/public components may
                # intentionally accept callers and require no permission.
                findings.append(Finding(
                    title=f"Review Exported {comp_type}: {name}",
                    description=f"{comp_type} '{name}' accepts external callers without a manifest permission. "
                                "This may be intentional (for example a launcher activity). Trace caller-controlled "
                                "inputs to sensitive operations and verify runtime authorization before claiming a vulnerability.",
                    severity=Severity.INFO,
                    cwe_id="CWE-Unknown",
                    affected_component=name,
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Keep intentionally public entrypoints usable. For private operations, disable export "
                                "or enforce caller authorization before processing inputs; do not disable launcher access blindly.",
                    file_path="AndroidManifest.xml"
                ))

            task_affinity = comp.get("taskAffinity")
            if task_affinity and exported:
                cwe = "CWE-1021"
                findings.append(Finding(
                    title=f"Task Affinity Hijacking Risk: {name}",
                    description=f"Exported activity '{name}' declares taskAffinity '{task_affinity}'. This configuration alone does not demonstrate task hijacking; review launch mode, task behavior, platform version and a reproducible victim-flow impact.",
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=name,
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Avoid custom taskAffinity on exported activities unless strictly required, and configure launchMode properly.",
                    file_path="AndroidManifest.xml"
                ))

            # FileProvider misconfiguration check
            if "FileProvider" in name or (comp.get("meta_data") and "android.support.FILE_PROVIDER_PATHS" in comp.get("meta_data", {})):
                if exported and not permission:
                    cwe = "CWE-22"
                    findings.append(Finding(
                        title=f"Exported FileProvider with Arbitrary File Access Risk: {name}",
                        description=f"A provider identified as FileProvider is declared exported. Inspect the resolved provider implementation, URI grant configuration, paths and effective installed manifest; this lexical manifest signal alone does not prove arbitrary file access.",
                        severity=Severity.INFO,
                        cwe_id=cwe,
                        cvss_score=0.0,
                        cvss_vector="",
                        affected_component=name,
                        detection_method="ManifestAuditor",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Set android:exported='false' on all FileProvider declarations and rely on temporary FLAG_GRANT_READ_URI_PERMISSION.",
                        file_path="AndroidManifest.xml"
                    ))

        # A weak custom permission is relevant here only when an exported
        # component actually uses it. An unused declaration alone protects
        # nothing and is not a security finding.
        declared_perms = manifest_data.get("declared_permissions", [])
        used_exported_permissions = {
            comp.get("permission") for comp in components
            if comp.get("exported") is True and comp.get("permission")
        }
        for dperm in declared_perms:
            p_name = dperm.get("name", "")
            prot = (dperm.get("protectionLevel") or "").lower()
            if p_name in used_exported_permissions and prot in ("normal", "", "none"):
                cwe = "CWE-276"
                findings.append(Finding(
                    title=f"Exported Component Uses Normal-Protection Custom Permission: {p_name}",
                    description=(
                        f"An exported component uses custom permission '{p_name}' with protectionLevel='{prot or 'normal'}'. "
                        "Normal-level permissions are generally grantable to ordinary installed apps; verify the effective merged manifest, component sensitivity, and runtime authorization before assessing impact."
                    ),
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=f"AndroidManifest.xml/permission/{p_name}",
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Elevate custom permissions guarding sensitive components to android:protectionLevel='signature'.",
                    file_path="AndroidManifest.xml"
                ))

        # Check dangerous system permissions requested
        requested_perms = manifest_data.get("permissions", [])
        if "android.permission.SYSTEM_ALERT_WINDOW" in requested_perms:
            cwe = "CWE-1021"
            findings.append(Finding(
                title="Dangerous Permission Requested: SYSTEM_ALERT_WINDOW (Overlay / Tapjacking)",
                description="The manifest requests SYSTEM_ALERT_WINDOW. Runtime user authorization and actual overlay behavior are separate; the request alone does not establish that the app can draw overlays or cause tapjacking.",
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component="AndroidManifest.xml/uses-permission",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Only request SYSTEM_ALERT_WINDOW if background floating UI is indispensable. Enforce FLAG_SECURE on sensitive activities.",
                file_path="AndroidManifest.xml"
            ))

        if "android.permission.REQUEST_INSTALL_PACKAGES" in requested_perms:
            cwe = "CWE-250"
            findings.append(Finding(
                title="Excessive Privilege: REQUEST_INSTALL_PACKAGES Requested",
                description="The manifest requests REQUEST_INSTALL_PACKAGES. OS/user authorization gates and an actual installation flow determine behavior; this request alone does not prove arbitrary installation or harmful impact.",
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component="AndroidManifest.xml/uses-permission",
                detection_method="ManifestAuditor",
                status=FindingStatus.UNVERIFIED,
                remediation="Remove REQUEST_INSTALL_PACKAGES and direct users to official app stores instead of in-app self-updating APKs.",
                file_path="AndroidManifest.xml"
            ))

        logger.info(f"Manifest audit completed: {len(findings)} findings.")
        return findings
