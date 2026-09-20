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
