import pytest
import tempfile
from pathlib import Path
from mobileag.ingestion.manifest_parser import ManifestParser

@pytest.fixture
def dummy_manifest():
    """Creates a temporary dummy AndroidManifest.xml file for testing."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
        <uses-permission android:name="android.permission.INTERNET" />
        <application android:allowBackup="true" android:debuggable="true">
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

def test_apktool_sdk_version_metadata(tmp_path):
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text('<manifest package="org.example.fixture"><application/></manifest>')
    (tmp_path / 'apktool.yml').write_text('sdkInfo:\n  minSdkVersion: 23\n  targetSdkVersion: 35\nversionInfo:\n  versionCode: 1\n  versionName: "1.0-synthetic"\n')
    parsed = ManifestParser().parse(str(path))
    assert (parsed['version_name'], parsed['version_code'], parsed['min_sdk'], parsed['target_sdk']) == ('1.0-synthetic', '1', '23', '35')
    (tmp_path / 'apktool.yml').write_text('versionInfo:\n  versionName: !!python/object/apply:os.system [bad]\n  versionCode: &alias 7\n')
    assert ManifestParser().parse(str(path))['version_name'] is None


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
