import json
import pytest
import tempfile
from pathlib import Path
from mobileag.ingestion.manifest_parser import ManifestParser
from mobileag.reporting.finding import FindingStatus

@pytest.fixture
def dummy_manifest():
    """Creates a temporary dummy AndroidManifest.xml file for testing."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
        <uses-permission android:name="android.permission.INTERNET" />
        <application android:allowBackup="true" android:debuggable="true"
                     android:fullBackupContent="@xml/backup_rules"
                     android:dataExtractionRules="@xml/extraction_rules">
            <activity android:name=".MainActivity" android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.MAIN" />
                    <category android:name="android.intent.category.LAUNCHER" />
                </intent-filter>
            </activity>
            <service android:name=".HiddenService" android:exported="false" />
            <provider android:name=".DataProvider" android:exported="true" android:authorities="com.test.app.provider" />
        </application>
    </manifest>"""
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".xml") as f:
        f.write(xml_content)
        path = f.name
        
    yield path
    Path(path).unlink()

def test_manifest_parser(dummy_manifest):
    """Test parsing logic for AndroidManifest.xml."""
    parser = ManifestParser()
    data = parser.parse(dummy_manifest)
    
    # Check basic attributes
    assert data["package"] == "com.test.app"
    assert "android.permission.INTERNET" in data["permissions"]
    
    # Check application flags
    assert data["application"]["allowBackup"] is True
    assert data["application"]["debuggable"] is True
    assert data["application"]["backup_rule_references"] == {
        "legacy_rules": {"status": "reference_observed", "reference": "@xml/backup_rules"},
        "data_extraction_rules": {"status": "reference_observed", "reference": "@xml/extraction_rules"},
    }
    
    # Check extracted components
    components = data.get("components", [])
    assert len(components) == 3
    
    # Verify specific components
    main_activity = next(c for c in components if c["name"] == ".MainActivity")
    assert main_activity["exported"] is True
    assert main_activity["type"] == "activity"
    
    hidden_service = next(c for c in components if c["name"] == ".HiddenService")
    assert hidden_service["exported"] is False
    assert hidden_service["type"] == "service"
    
    provider = next(c for c in components if c["name"] == ".DataProvider")
    assert provider["exported"] is True
    assert provider["type"] == "provider"
    assert data["split_metadata"] == {
        "status": "attribute_absent", "split_name": None,
        "is_split_manifest": False, "split_set_completeness": "not_measured",
    }


def test_backup_rule_xml_inventory_is_bounded_and_does_not_publish_paths(tmp_path):
    res = tmp_path / "res" / "xml"
    res.mkdir(parents=True)
    (res / "legacy.xml").write_text(
        '<full-backup-content><include domain="sharedpref" path="private.xml"/>'
        '<exclude domain="database" path="cache.db"/></full-backup-content>')
    (res / "modern.xml").write_text(
        '<data-extraction-rules><cloud-backup><exclude domain="file" path="secrets/"/>'
        '</cloud-backup><device-transfer><include domain="database" path="."/>'
        '</device-transfer></data-extraction-rules>')
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">
      <application android:fullBackupContent="@xml/legacy" android:dataExtractionRules="@xml/modern"/>
    </manifest>''')

    result = ManifestParser().parse(str(manifest))["application"]["backup_rules_inventory"]
    assert result["status"] == "completed"
    by_kind = {item["kind"]: item for item in result["rules"]}
    legacy, modern = by_kind["legacy_rules"], by_kind["data_extraction_rules"]
    assert (legacy["kind"], legacy["root"], legacy["include_count"], legacy["exclude_count"]) == (
        "legacy_rules", "full-backup-content", 1, 1)
    assert legacy["domains"] == ["database", "sharedpref"]
    assert (modern["kind"], modern["root"], modern["include_count"], modern["exclude_count"]) == (
        "data_extraction_rules", "data-extraction-rules", 1, 1)
    assert "private.xml" not in json.dumps(result)
    assert result["runtime_status"] == "not_tested"
    assert result["proof_status"] == "not_proven"


def test_backup_rule_inventory_fails_closed_on_missing_resource(tmp_path):
    (tmp_path / "res" / "xml").mkdir(parents=True)
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">
      <application android:fullBackupContent="@xml/missing"/>
    </manifest>''')
    result = ManifestParser().parse(str(manifest))["application"]["backup_rules_inventory"]
    assert result["status"] == "incomplete"
    legacy = next(item for item in result["rules"] if item["kind"] == "legacy_rules")
    assert legacy["status"] == "unavailable_or_invalid"
    assert legacy["include_count"] is None


@pytest.mark.parametrize("payload", [
    '<!DOCTYPE x [<!ENTITY leak "expanded">]><full-backup-content>&leak;</full-backup-content>',
    '<full-backup-content><include domain="file" path="x"></full-backup-content>',
])
def test_backup_rule_inventory_rejects_doctype_and_malformed_xml(tmp_path, payload):
    resource_dir = tmp_path / "res" / "xml"
    resource_dir.mkdir(parents=True)
    (resource_dir / "rules.xml").write_text(payload)
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">
      <application android:fullBackupContent="@xml/rules"/>
    </manifest>''')
    result = ManifestParser().parse(str(manifest))["application"]["backup_rules_inventory"]
    assert result["status"] == "incomplete"
    legacy = next(item for item in result["rules"] if item["kind"] == "legacy_rules")
    assert legacy["status"] == "unavailable_or_invalid"
    assert legacy["include_count"] is None


def test_backup_rule_inventory_marks_literal_configuration_unresolved(tmp_path):
    (tmp_path / "res" / "xml").mkdir(parents=True)
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app">
      <application android:fullBackupContent="true"/>
    </manifest>''')
    result = ManifestParser().parse(str(manifest))["application"]["backup_rules_inventory"]
    assert result["status"] == "incomplete"
    legacy = next(item for item in result["rules"] if item["kind"] == "legacy_rules")
    assert legacy["status"] == "non_resource_value"
    assert legacy["include_count"] is None

def test_manifest_records_split_name_without_claiming_split_set_completeness(tmp_path):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text('<manifest package="org.example" split="config.arm64_v8a"><application/></manifest>')
    parsed = ManifestParser().parse(str(path))
    assert parsed["split_metadata"] == {
        "status": "manifest_attribute_observed", "split_name": "config.arm64_v8a",
        "is_split_manifest": True, "split_set_completeness": "not_measured",
    }

def test_split_capability_inventory_does_not_infer_complete_set():
    from mobileag.reporting.capability_inventory import capability_inventory
    row = capability_inventory({"split_manifest": {
        "status": "manifest_attribute_observed", "split_name": "config.arm64_v8a",
        "is_split_manifest": True, "split_set_completeness": "not_measured",
    }})["formats"]["split_apk_aab"]
    assert row["execution_state"] == "single_apk_split_attribute_observed"
    assert row["evidence_state"] == "not_tested"
    assert row["proof_status"] == "not_proven"


def test_component_permissions_resolve_application_defaults_and_provider_overrides(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    path = tmp_path / "AndroidManifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <permission android:name="org.example.SIG" android:protectionLevel="signature"/>
      <application android:permission="org.example.SIG">
        <activity android:name=".Defaulted" android:exported="true"/>
        <provider android:name=".Provider" android:exported="true" android:readPermission="org.example.SIG"/>
        <provider android:name=".PublicProvider" android:exported="true" android:permission=""/>
      </application></manifest>''')
    parsed = ManifestParser().parse(str(path))
    activity, provider, public_provider = parsed["components"]
    assert activity["permission"] == "org.example.SIG"
    assert activity["permission_origin"] == "application_inherited"
    assert provider["declared_access_permissions"] == {
        "read": "org.example.SIG", "read_origin": "readPermission",
        "write": "org.example.SIG", "write_origin": "application_inherited",
    }
    assert public_provider["declared_access_permissions"]["read"] == "org.example.SIG"

    # A generic provider permission protects read and write unless an explicit
    # per-direction override changes it; it is not enough to inspect `permission` alone.
    parsed["application"]["allowBackup"] = False
    findings = __import__('asyncio').run(ManifestAuditor(None).audit(parsed, parsed['package_name']))
    assert not any("Exported Provider" in f.title for f in findings)


def test_task_affinity_inventory_resolves_inheritance_launch_mode_and_review_lead(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    path = tmp_path / "AndroidManifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <application android:taskAffinity="org.shared.task">
        <activity android:name=".Inherited" android:exported="true" android:launchMode="singleTask"/>
        <activity android:name=".Explicit" android:exported="true" android:taskAffinity="org.partner.task" android:launchMode="standard"/>
        <activity android:name=".Default" android:exported="true"/>
        <activity android:name=".NoAffinity" android:exported="true" android:taskAffinity=""/>
        <activity-alias android:name=".Alias" android:targetActivity=".Explicit" android:exported="true" android:taskAffinity="org.alias.task"/>
      </application></manifest>''')

    parsed = ManifestParser().parse(str(path))
    inherited, explicit, defaulted, no_affinity = parsed["components"][:4]
    assert (inherited["taskAffinity"], inherited["taskAffinityOrigin"]) == ("org.shared.task", "application")
    assert inherited["launchMode"] == "singleTask"
    assert (explicit["taskAffinity"], explicit["taskAffinityOrigin"]) == ("org.partner.task", "component")
    assert explicit["launchMode"] == "standard"
    assert (defaulted["taskAffinity"], defaulted["taskAffinityOrigin"]) == ("org.shared.task", "application")
    assert no_affinity["taskAffinity"] == ""
    assert no_affinity["taskAffinityOrigin"] == "component"
    alias = parsed["components"][-1]
    assert alias["alias_target"] == ".Explicit"

    findings = __import__('asyncio').run(ManifestAuditor(None).audit(parsed, parsed["package_name"]))
    leads = [item for item in findings if item.metadata.get("analysis_kind") == "exported_non_default_task_affinity"]
    assert len(leads) == 3
    assert {item.affected_component for item in leads} == {".Inherited", ".Explicit", ".Default"}
    assert all(item.status == FindingStatus.UNVERIFIED and item.cvss_score == 0 for item in leads)
    explicit_lead = next(item for item in leads if item.affected_component == ".Explicit")
    assert explicit_lead.metadata["launch_mode"] == "standard"
    assert explicit_lead.metadata["task_affinity_origin"] == "component"
    assert "does not demonstrate task hijacking" in explicit_lead.description
    assert not any(item.affected_component == ".Alias" for item in leads)

    default_manifest = tmp_path / "DefaultAffinity.xml"
    default_manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <application><activity android:name=".Default" android:exported="true"/></application></manifest>''')
    package_default = ManifestParser().parse(str(default_manifest))["components"][0]
    assert (package_default["taskAffinity"], package_default["taskAffinityOrigin"]) == (
        "org.example", "package_default",
    )
    default_data = ManifestParser().parse(str(default_manifest))
    default_findings = __import__('asyncio').run(
        ManifestAuditor(None).audit(default_data, default_data["package_name"]),
    )
    assert not any(item.metadata.get("analysis_kind") == "exported_non_default_task_affinity"
                   for item in default_findings)


@pytest.mark.asyncio
async def test_exported_permission_resource_references_remain_unresolved_review_leads(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    path = tmp_path / "AndroidManifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <application android:permission="@string/default_guard">
        <activity android:name=".DeepLink" android:exported="true"/>
        <provider android:name=".Files" android:exported="true" android:readPermission="@string/read_guard"/>
      </application></manifest>''')
    parsed = ManifestParser().parse(str(path))
    activity, provider = parsed["components"]
    assert activity["permission_resolution"]["interaction"]["status"] == "unresolved_resource_reference"
    assert provider["permission_resolution"]["read"]["status"] == "unresolved_resource_reference"
    assert provider["permission_resolution"]["write"]["status"] == "unresolved_resource_reference"

    findings = await ManifestAuditor(None).audit(parsed, parsed["package_name"])
    unresolved = [item for item in findings if item.metadata.get("analysis_kind") == "unresolved_component_permission"]
    assert {item.metadata["unresolved_access_directions"][0] for item in unresolved} == {"interaction", "read"}
    assert all(item.status == FindingStatus.UNVERIFIED and item.cvss_score == 0 for item in unresolved)
    assert not any("Review Exported" in item.title for item in findings)


@pytest.mark.asyncio
async def test_unique_plain_permission_string_resources_resolve_and_drive_custom_permission_review(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text('''<resources>
      <string name="app_guard">org.example.APP_GUARD</string>
      <string name="provider_read">org.example.READ_GUARD</string>
      <string name="declared_read">org.example.READ_GUARD</string>
    </resources>''')
    path = tmp_path / "AndroidManifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <permission android:name="@string/declared_read" android:protectionLevel="normal"/>
      <application android:permission="@string/app_guard">
        <activity android:name=".Home" android:exported="true"/>
        <provider android:name=".Provider" android:exported="true" android:readPermission="@string/provider_read"/>
      </application></manifest>''')

    parsed = ManifestParser().parse(str(path))
    activity, provider = parsed["components"]
    assert activity["permission"] == "org.example.APP_GUARD"
    assert activity["permission_resolution"]["interaction"]["status"] == "resolved_simple_string_resource"
    assert provider["declared_access_permissions"]["read"] == "org.example.READ_GUARD"
    assert provider["declared_access_permissions"]["write"] == "org.example.APP_GUARD"
    assert parsed["declared_permissions"][0]["name"] == "org.example.READ_GUARD"
    assert parsed["permission_resource_inventory"]["status"] == "measured_bounded_values"
    assert "org.example.READ_GUARD" not in json.dumps(parsed["permission_resource_inventory"])

    findings = await ManifestAuditor(None).audit(parsed, parsed["package_name"])
    weak = [item for item in findings if item.metadata.get("analysis_kind") == "custom_permission_protection"]
    assert len(weak) == 1
    assert {site["access"] for site in weak[0].metadata["exported_use_sites"]} == {"read"}
    assert weak[0].status == FindingStatus.UNVERIFIED and weak[0].cvss_score == 0


def test_conflicting_permission_string_variants_are_not_resolved(tmp_path):
    (tmp_path / "res" / "values").mkdir(parents=True)
    (tmp_path / "res" / "values-fr").mkdir()
    (tmp_path / "res" / "values" / "strings.xml").write_text(
        '<resources><string name="guard">org.example.GUARD</string></resources>')
    (tmp_path / "res" / "values-fr" / "strings.xml").write_text(
        '<resources><string name="guard">org.example.OPEN</string></resources>')
    path = tmp_path / "AndroidManifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <application android:permission="@string/guard"><activity android:name=".Entry" android:exported="true"/></application>
    </manifest>''')

    parsed = ManifestParser().parse(str(path))

    activity = parsed["components"][0]
    assert activity["permission"] == "@string/guard"
    assert activity["permission_resolution"]["interaction"]["status"] == "unresolved_resource_reference"
    assert parsed["permission_resource_inventory"]["ambiguous_names"] == 1


@pytest.mark.asyncio
async def test_permission_request_variants_retain_sdk_gate_and_max_sdk_context(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    path = tmp_path / "AndroidManifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="32"/>
      <uses-permission-sdk-23 android:name="android.permission.SYSTEM_ALERT_WINDOW" android:maxSdkVersion="35"/>
      <application/>
    </manifest>''')

    parsed = ManifestParser().parse(str(path))

    assert parsed["permissions"] == ["android.permission.CAMERA", "android.permission.SYSTEM_ALERT_WINDOW"]
    assert parsed["permission_request_inventory"] == {
        "status": "measured_declarations", "count": 2, "truncated": False,
        "runtime_grant_state": "not_tested", "proof_status": "not_proven",
    }
    assert parsed["permission_requests"][0]["request_element"] == "uses-permission"
    assert parsed["permission_requests"][0]["max_sdk_version"] == "32"
    assert parsed["permission_requests"][1]["request_element"] == "uses-permission-sdk-23"
    assert parsed["permission_requests"][1]["max_sdk_version"] == "35"

    findings = await ManifestAuditor(None).audit(parsed, parsed["package_name"])
    overlay = next(item for item in findings if "SYSTEM_ALERT_WINDOW" in item.title)
    assert overlay.metadata["permission_request_declarations"] == [{
        "request_element": "uses-permission-sdk-23", "max_sdk_version": "35",
        "uses_permission_flags": None, "name_resolution_status": "literal_name",
    }]
    assert overlay.status == FindingStatus.UNVERIFIED and overlay.cvss_score == 0


@pytest.mark.asyncio
async def test_exported_provider_permission_candidate_names_unguarded_direction():
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    parsed = {"application": {"allowBackup": False}, "target_sdk": "35",
              "components": [{"name": ".Provider", "type": "provider", "exported": True,
                              "permission": "org.example.READ", "declared_access_permissions": {
                                  "read": "org.example.READ", "write": None}}]}
    findings = await ManifestAuditor(None).audit(parsed, "org.example")
    lead = next(f for f in findings if "Exported" in f.title)
    assert lead.severity.value == "INFO"
    assert lead.metadata["unguarded_provider_access"] == ["write"]


@pytest.mark.asyncio
async def test_exported_provider_weak_permission_checks_read_write_overrides_and_flags():
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    weak = {"application": {"allowBackup": False}, "declared_permissions": [
        {"name": "org.example.READ", "protectionLevel": "normal|appop"},
        {"name": "org.example.SIGNATURE", "protectionLevel": "signature|privileged"}],
        "components": [
            {"name": ".Provider", "type": "provider", "exported": True,
             "declared_access_permissions": {"read": "org.example.READ", "write": "org.example.READ"}},
            {"name": ".Internal", "type": "service", "exported": True,
             "permission": "org.example.SIGNATURE"},
        ]}
    findings = await ManifestAuditor(None).audit(weak, "org.example")
    candidates = [f for f in findings if f.cwe_id == "CWE-276"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.severity.value == "INFO" and candidate.status.value == "UNVERIFIED"
    assert candidate.metadata["base_protection_level"] == "normal"
    assert {site["access"] for site in candidate.metadata["exported_use_sites"]} == {"read", "write"}
    assert not candidate.metadata["proof_status"] == "proven"


@pytest.mark.asyncio
async def test_exported_provider_path_permissions_are_checked_by_access_direction(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    path = tmp_path / "provider-path-permission-manifest.xml"
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example">
      <permission android:name="org.example.PUBLIC_PATH" android:protectionLevel="normal"/>
      <permission android:name="org.example.SIGNATURE_PATH" android:protectionLevel="signature"/>
      <application><provider android:name=".Files" android:exported="true" android:permission="org.example.SIGNATURE_PATH">
        <path-permission android:pathPrefix="/public" android:readPermission="org.example.PUBLIC_PATH" android:writePermission="org.example.SIGNATURE_PATH"/>
      </provider></application>
    </manifest>''')

    parsed = ManifestParser().parse(str(path))
    path_permission = parsed["providers"][0]["path_permissions"][0]
    assert path_permission["declared_access_permissions"] == {
        "read": "org.example.PUBLIC_PATH", "write": "org.example.SIGNATURE_PATH"}
    assert path_permission["permission_resolution"]["read"]["status"] == "literal_name"

    findings = await ManifestAuditor(None).audit(parsed, "org.example")
    candidates = [item for item in findings if item.metadata.get("analysis_kind") == "custom_permission_protection"]
    assert len(candidates) == 1
    assert candidates[0].metadata["protection_level"] == "normal"
    assert candidates[0].metadata["exported_use_sites"] == [{
        "component": ".Files (pathPrefix=/public)", "access": "read"}]
    assert candidates[0].status == FindingStatus.UNVERIFIED and candidates[0].cvss_score == 0

def test_apktool_sdk_version_metadata(tmp_path):
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text('<manifest package="org.example.fixture"><application/></manifest>')
    (tmp_path / 'apktool.yml').write_text('sdkInfo:\n  minSdkVersion: 23\n  targetSdkVersion: 35\nversionInfo:\n  versionCode: 1\n  versionName: "1.0-synthetic"\n')
    parsed = ManifestParser().parse(str(path))
    assert (parsed['version_name'], parsed['version_code'], parsed['min_sdk'], parsed['target_sdk']) == ('1.0-synthetic', '1', '23', '35')
    (tmp_path / 'apktool.yml').write_text('versionInfo:\n  versionName: !!python/object/apply:os.system [bad]\n  versionCode: &alias 7\n')
    assert ManifestParser().parse(str(path))['version_name'] is None


def test_provider_paths_and_uri_grant_declarations_are_bounded_inventory(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor
    from mobileag.reporting.finding import FindingStatus, Severity

    manifest_path = tmp_path / 'AndroidManifest.xml'
    xml_dir = tmp_path / 'res' / 'xml'
    xml_dir.mkdir(parents=True)
    (xml_dir / 'provider_paths.xml').write_text(
        '<paths><files-path name="broad" path=""/><cache-path name="exports" path="exports/"/></paths>')
    manifest_path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.synthetic">
      <application><provider android:name=".Files" android:exported="false" android:grantUriPermissions="true">
        <grant-uri-permission android:pathPrefix="/public"/>
        <path-permission android:path="/private" android:readPermission="org.example.SIG"/>
        <meta-data android:name="androidx.core.content.FILE_PROVIDER_PATHS" android:resource="@xml/provider_paths"/>
      </provider></application></manifest>''')
    parsed = ManifestParser().parse(str(manifest_path))
    provider = parsed['providers'][0]
    inventory = parsed['provider_path_inventory']
    assert inventory['static_status'] == 'completed'
    assert inventory['providers'][0]['entries'] == [
        {'type': 'files-path', 'name': 'broad', 'path': ''},
        {'type': 'cache-path', 'name': 'exports', 'path': 'exports/'},
    ]
    assert provider['grant_uri_permissions'] is True
    assert provider['grant_uri_permissions_paths'][0]['pathPrefix'] == '/public'
    assert provider['path_permissions'][0]['readPermission'] == 'org.example.SIG'

    findings = __import__('asyncio').run(ManifestAuditor(None).audit(parsed, parsed['package_name']))
    broad = next(f for f in findings if 'Broad FileProvider Path Configuration' in f.title)
    assert broad.severity == Severity.INFO and broad.status == FindingStatus.UNVERIFIED
    assert broad.metadata['external_uri_grant_verified'] is False
    assert 'still needs an issued URI grant' in broad.description
    assert not any(f.metadata.get('provider_path_type') == 'cache-path' for f in findings)


def test_provider_path_resource_traversal_or_symlink_fails_incomplete(tmp_path):
    manifest_path = tmp_path / 'AndroidManifest.xml'
    xml_dir = tmp_path / 'res' / 'xml'
    xml_dir.mkdir(parents=True)
    outside = tmp_path / 'outside.xml'
    outside.write_text('<paths><root-path name="root" path=""/></paths>')
    (xml_dir / 'unsafe.xml').symlink_to(outside)
    manifest_path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <application><provider android:name=".Files" android:exported="false">
        <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/unsafe"/>
      </provider><provider android:name=".Traversal" android:exported="false">
        <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/../../outside"/>
      </provider></application></manifest>''')
    parsed = ManifestParser().parse(str(manifest_path))
    assert parsed['provider_path_inventory']['static_status'] == 'incomplete'
    assert parsed['provider_path_inventory']['unresolved_count'] == 2
    assert all(provider['entries'] == [] for provider in parsed['provider_path_inventory']['providers'])


@pytest.mark.asyncio
async def test_exported_component_is_review_not_proven_vulnerability():
    from mobileag.analysis.manifest_auditor import ManifestAuditor
    from mobileag.reporting.finding import Severity, FindingStatus
    auditor = ManifestAuditor(None)
    findings = await auditor.audit({'application': {'allowBackup': False}, 'components': [{'name': '.Main', 'type': 'activity', 'exported': True}]}, 'org.example.fixture')
    exposure = next(f for f in findings if 'Exported' in f.title)
    assert exposure.severity == Severity.INFO and exposure.status == FindingStatus.UNVERIFIED
    assert exposure.cvss_score == 0 and not exposure.cvss_vector

@pytest.mark.parametrize('target,exported,cleartext', [('16', True, True), ('27', False, True), ('35', False, False), ('', None, None)])
def test_android_sdk_defaults_and_inherited_permissions(tmp_path, target, exported, cleartext):
    path = tmp_path/'AndroidManifest.xml'
    sdk = f'<uses-sdk android:targetSdkVersion="{target}"/>' if target else ''
    path.write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android">{sdk}<application android:permission="org.example.GUARD"><provider android:name=".Provider"/></application></manifest>')
    parsed = ManifestParser().parse(str(path))
    assert parsed['providers'][0]['exported'] is exported
    assert parsed['providers'][0]['permission'] == 'org.example.GUARD'
    assert parsed['application']['usesCleartextTraffic'] is cleartext


@pytest.mark.asyncio
async def test_target_31_missing_exported_with_filter_is_not_reported_as_reachable(tmp_path):
    from mobileag.analysis.manifest_auditor import ManifestAuditor

    path = tmp_path / 'AndroidManifest.xml'
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="35"/><application>
        <activity android:name=".MissingExported"><intent-filter>
          <action android:name="org.example.ACTION"/>
        </intent-filter></activity>
      </application></manifest>''')
    parsed = ManifestParser().parse(str(path))
    component = parsed['components'][0]
    assert component['exported'] is None
    assert parsed['target_sdk'] == '35'
    findings = await ManifestAuditor(None).audit(parsed, parsed['package_name'])
    assert any('Missing android:exported' in finding.title for finding in findings)
    assert not any('Review Exported' in finding.title for finding in findings)
