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
                file_path="AndroidManifest.xml",
                metadata={"check_id": "manifest_allow_backup", "proof_state": "not_proven"}
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
            access_policy = comp.get("declared_access_permissions")
            if not isinstance(access_policy, dict):
                access_policy = ({"read": permission or None, "write": permission or None}
                                 if comp.get("type") == "provider"
                                 else {"interaction": permission or None})
            unguarded_provider_access = ([direction for direction in ("read", "write")
                                          if not access_policy.get(direction)]
                                         if comp.get("type") == "provider" else [])
            missing_permission = (bool(unguarded_provider_access) if comp.get("type") == "provider"
                                  else not permission)
            permission_resolution = comp.get("permission_resolution", {})
            unresolved_permission_access = [
                direction for direction, resolution in permission_resolution.items()
                if isinstance(resolution, dict)
                and resolution.get("status") == "unresolved_resource_reference"
            ] if isinstance(permission_resolution, dict) else []
            unresolved_path_permissions = []
            if comp.get("type") == "provider":
                for index, path_permission in enumerate(comp.get("path_permissions", [])[:128]):
                    if not isinstance(path_permission, dict):
                        continue
                    path_resolution = path_permission.get("permission_resolution", {})
                    if not isinstance(path_resolution, dict):
                        continue
                    for direction, resolution in path_resolution.items():
                        if (isinstance(resolution, dict)
                                and resolution.get("status") == "unresolved_resource_reference"):
                            unresolved_path_permissions.append(f"path_permission[{index}].{direction}")
            unresolved_permission_access.extend(unresolved_path_permissions)

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

            if exported and missing_permission:
                # Exposure is an attack-surface observation, not proof of a
                # missing authorization check. Launcher/public components may
                # intentionally accept callers and require no permission.
                findings.append(Finding(
                    title=f"Review Exported {comp_type}: {name}",
                    description=(f"{comp_type} '{name}' has no declared permission for "
                                 f"{', '.join(unguarded_provider_access) if unguarded_provider_access else 'component interaction'}. "
                                "This may be intentional (for example a launcher activity). Trace caller-controlled "
                                "inputs to sensitive operations and verify the merged manifest and runtime authorization before claiming a vulnerability."),
                    severity=Severity.INFO,
                    cwe_id="CWE-Unknown",
                    affected_component=name,
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Keep intentionally public entrypoints usable. For private operations, disable export "
                                "or enforce caller authorization before processing inputs; do not disable launcher access blindly.",
                    file_path="AndroidManifest.xml",
                    metadata={"declared_access_permissions": access_policy,
                              "unguarded_provider_access": unguarded_provider_access,
                              "proof_state": "not_proven"},
                ))

            if exported and unresolved_permission_access:
                findings.append(Finding(
                    title=f"Review Unresolved Exported Component Permission: {name}",
                    description=(f"Permission configuration for exported {comp_type.lower()} '{name}' contains a resource reference that this bounded manifest pass did not resolve for: "
                                 f"{', '.join(sorted(unresolved_permission_access))}. Do not treat the reference as a verified authorization boundary or as proof that access is unrestricted; inspect the resource table and merged release manifest."),
                    severity=Severity.INFO, cwe_id="CWE-284", cvss_score=0.0,
                    affected_component=name, detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Resolve permission resource references against the built artifact and verify the effective caller authorization before drawing a security conclusion.",
                    file_path="AndroidManifest.xml",
                    metadata={"analysis_kind": "unresolved_component_permission",
                              "permission_resolution": permission_resolution,
                              "unresolved_path_permissions": unresolved_path_permissions,
                              "path_permissions_truncated": bool(comp.get("path_permissions_truncated")),
                              "unresolved_access_directions": sorted(unresolved_permission_access),
                              "proof_status": "not_proven"},
                ))

            task_affinity = comp.get("taskAffinity")
            task_affinity_origin = comp.get("taskAffinityOrigin", "unknown")
            launch_mode = comp.get("launchMode", "unknown")
            # An absent component attribute normally inherits app/package affinity;
            # only an observed non-default literal is a task-affinity review lead.
            task_affinity_is_literal = (
                isinstance(task_affinity, str) and bool(task_affinity)
                and not task_affinity.startswith(("@", "?"))
            )
            non_default_task_affinity = (
                task_affinity_is_literal and bool(package_name)
                and task_affinity != package_name
            )
            if (non_default_task_affinity and exported and comp_type.lower() == "activity"
                    and not comp.get("alias_target")):
                cwe = "CWE-1021"
                findings.append(Finding(
                    title=f"Review Non-default Task Affinity: {name}",
                    description=(f"Exported activity '{name}' has effective taskAffinity '{task_affinity}' "
                                 f"(source: {task_affinity_origin}) and launchMode '{launch_mode}'. "
                                 "This configuration alone does not demonstrate task hijacking. Inspect the "
                                 "merged manifest, task/intent flags, reparenting behavior, platform version "
                                 "and a reproducible victim-flow impact; launchMode by itself is not a security verdict."),
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=name,
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Avoid unnecessary cross-application task affinity. Preserve required task behavior and validate it on supported Android builds; do not change launchMode as a substitute for authorization or input validation.",
                    file_path="AndroidManifest.xml",
                    metadata={"analysis_kind": "exported_non_default_task_affinity",
                              "proof_state": "not_proven",
                              "task_affinity": task_affinity,
                              "task_affinity_origin": task_affinity_origin,
                              "launch_mode": launch_mode,
                              "launch_mode_explicit": comp.get("launchModeExplicit", False)},
                ))

            # FileProvider misconfiguration check
            if "FileProvider" in name or (comp.get("meta_data") and "android.support.FILE_PROVIDER_PATHS" in comp.get("meta_data", {})):
                if exported and missing_permission:
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

        # Broad configured roots are a review lead only. A provider must still
        # issue a URI grant, and its implementation/runtime behavior determines
        # the actual caller-visible data boundary.
        path_inventory = manifest_data.get("provider_path_inventory", {})
        for provider in path_inventory.get("providers", []):
            if provider.get("status") != "parsed":
                continue
            provider_name = provider.get("provider", "unknown")
            provider_component = next((component for component in components
                                       if component.get("name") == provider_name
                                       and component.get("type") == "provider"), {})
            for entry in provider.get("entries", []):
                configured_path = str(entry.get("path", "")).strip()
                if entry.get("type") != "root-path" and configured_path not in ("", ".", "/"):
                    continue
                findings.append(Finding(
                    title=f"Review Broad FileProvider Path Configuration: {provider_name}",
                    description=(f"FileProvider XML maps a broad '{entry.get('type', 'unknown')}' root with path "
                                 f"'{configured_path}'. This is a configuration review lead only: a third party "
                                 f"still needs an issued URI grant (manifest grantUriPermissions="
                                 f"{provider_component.get('grant_uri_permissions', 'not_recorded')}), and provider code, "
                                 "URI construction, effective installed configuration, and the files actually exposed "
                                 "are not established."),
                    severity=Severity.INFO, cwe_id="CWE-Unknown", cvss_score=0.0,
                    affected_component=str(provider_name),
                    detection_method="ManifestAuditor", status=FindingStatus.UNVERIFIED,
                    remediation=("Restrict FileProvider roots to the smallest required subdirectory, issue temporary "
                                 "URI grants only for intended files, and validate provider path and caller behavior."),
                    file_path=str(provider.get("resource", "AndroidManifest.xml")),
                    metadata={"analysis_kind": "provider_path_configuration", "proof_state": "not_proven",
                              "provider_path_type": entry.get("type"), "external_uri_grant_verified": False,
                              "provider_exported": provider_component.get("exported"),
                              "grant_uri_permissions": provider_component.get("grant_uri_permissions"),
                              "declared_grant_path_count": len(provider_component.get("grant_uri_permissions_paths", [])),
                              "declared_path_permission_count": len(provider_component.get("path_permissions", []))},
                ))

        # A weak custom permission is relevant here only when an exported
        # component actually uses it. An unused declaration alone protects
        # nothing and is not a security finding.
        declared_perms = manifest_data.get("declared_permissions", [])
        used_exported_permissions: dict[str, list[dict[str, str]]] = {}
        for comp in components:
            if comp.get("exported") is not True:
                continue
            access = comp.get("declared_access_permissions")
            if not isinstance(access, dict):
                access = ({"read": comp.get("permission"), "write": comp.get("permission")}
                          if comp.get("type") == "provider" else
                          {"interaction": comp.get("permission")})
            resolution = comp.get("permission_resolution", {})
            if not isinstance(resolution, dict):
                resolution = {}
            directions = ("read", "write") if comp.get("type") == "provider" else ("interaction",)
            for direction in directions:
                direction_resolution = resolution.get(direction, {})
                if ("permission_resolution" in comp and
                        (not isinstance(direction_resolution, dict)
                        or direction_resolution.get("status") not in {
                            "literal_name", "resolved_simple_string_resource"})):
                    continue
                perm_name = access.get(direction)
                if isinstance(perm_name, str) and perm_name:
                    used_exported_permissions.setdefault(perm_name, []).append({
                        "component": str(comp.get("name", "UnknownComponent"))[:256],
                        "access": direction,
                    })
            if comp.get("type") == "provider":
                for index, path_permission in enumerate(comp.get("path_permissions", [])[:128]):
                    if not isinstance(path_permission, dict):
                        continue
                    path_access = path_permission.get("declared_access_permissions", {})
                    path_resolution = path_permission.get("permission_resolution", {})
                    if not isinstance(path_access, dict) or not isinstance(path_resolution, dict):
                        continue
                    path_label = next((f"{key}={str(path_permission[key])[:128]}"
                                       for key in ("path", "pathPrefix", "pathPattern")
                                       if path_permission.get(key)), f"path_permission[{index}]")
                    for direction in ("read", "write"):
                        resolution_row = path_resolution.get(direction, {})
                        if (not isinstance(resolution_row, dict)
                                or resolution_row.get("status") not in {
                                    "literal_name", "resolved_simple_string_resource"}):
                            continue
                        perm_name = path_access.get(direction)
                        if isinstance(perm_name, str) and perm_name:
                            used_exported_permissions.setdefault(perm_name, []).append({
                                "component": f"{str(comp.get('name', 'UnknownComponent'))[:180]} ({path_label})",
                                "access": direction,
                            })
        for dperm in declared_perms:
            if not isinstance(dperm, dict):
                continue
            name_resolution = dperm.get("name_resolution", {})
            if (isinstance(name_resolution, dict) and name_resolution
                    and name_resolution.get("status") not in {
                        "literal_name", "resolved_simple_string_resource"}):
                continue
            p_name = dperm.get("name", "")
            if not isinstance(p_name, str) or not p_name:
                continue
            raw_protection = dperm.get("protectionLevel") or "normal"
            if not isinstance(raw_protection, str):
                continue
            prot = raw_protection.lower()
            base_protection = prot.split("|", 1)[0].strip() or "normal"
            use_sites = used_exported_permissions.get(p_name, [])
            if use_sites and base_protection in {"normal", "dangerous", "none"}:
                cwe = "CWE-276"
                use_summary = ", ".join(sorted({f"{site['component']} ({site['access']})"
                                                 for site in use_sites}))[:1000]
                findings.append(Finding(
                    title=f"Review Broad Custom Permission on Exported Component: {p_name}",
                    description=(
                        f"Exported component access uses custom permission '{p_name}' with protectionLevel='{prot}'. "
                        f"Recorded use sites: {use_summary}. A normal permission is generally available to ordinary installed apps; dangerous permissions are user-mediated. Verify the merged manifest, component sensitivity, and runtime authorization before assessing impact."
                    ),
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=f"AndroidManifest.xml/permission/{p_name}",
                    detection_method="ManifestAuditor",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Elevate custom permissions guarding sensitive components to android:protectionLevel='signature'.",
                    file_path="AndroidManifest.xml",
                    metadata={"analysis_kind": "custom_permission_protection",
                              "protection_level": prot, "base_protection_level": base_protection,
                              "exported_use_sites": use_sites, "proof_status": "not_proven"},
                ))

        # Check dangerous system permissions requested
        requested_perms = manifest_data.get("permissions", [])
        request_details: dict[str, list[dict[str, Any]]] = {}
        for request in manifest_data.get("permission_requests", []):
            if not isinstance(request, dict) or not isinstance(request.get("name"), str):
                continue
            request_details.setdefault(request["name"], []).append({
                "request_element": request.get("request_element"),
                "max_sdk_version": request.get("max_sdk_version"),
                "uses_permission_flags": request.get("uses_permission_flags"),
                "name_resolution_status": request.get("name_resolution", {}).get("status")
                if isinstance(request.get("name_resolution"), dict) else "not_recorded",
            })
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
                file_path="AndroidManifest.xml",
                metadata={"permission_request_declarations": request_details.get(
                    "android.permission.SYSTEM_ALERT_WINDOW", []), "proof_status": "not_proven"},
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
                file_path="AndroidManifest.xml",
                metadata={"permission_request_declarations": request_details.get(
                    "android.permission.REQUEST_INSTALL_PACKAGES", []), "proof_status": "not_proven"},
            ))

        logger.info(f"Manifest audit completed: {len(findings)} findings.")
        return findings
