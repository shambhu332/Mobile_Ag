"""Test FastAPI DAST endpoints in MobileAg web application."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_dast_devices_endpoint(client):
    response = client.get("/api/dast/devices")
    assert response.status_code == 200
    data = response.json()
    assert "adb_available" in data
    assert "device_count" in data
    assert isinstance(data["devices"], list)


def test_dast_connect_endpoint(client):
    response = client.post("/api/dast/connect", json={"host_port": "127.0.0.1:5555"})
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_dast_root_endpoint(client):
    response = client.post("/api/dast/root", json={"serial": "emulator-5554"})
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_dast_logcat_endpoint(client):
    response = client.get("/api/dast/logcat?serial=emulator-5554&lines=50")
    assert response.status_code == 200
    data = response.json()
    assert "lines" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_dast_fuzz_trigger_endpoint(client):
    with patch("mobileag.web.app.intent_fuzzer.fuzz_activity_intents") as mock_fuzz:
        mock_fuzz.return_value = ([], [
            Finding(
                title="CWE-755: Unhandled Crash During Intent Fuzz",
                description="Activity crashed with NullPointerException",
                severity=Severity.HIGH,
                cwe_id="CWE-755",
            )
        ])
        response = client.post("/api/dast/fuzz", json={
            "serial": "emulator-5554",
            "package_name": "com.target.testapp",
            "activities": ["com.target.testapp.MainActivity"],
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "initiated"
        assert data["device"] == "emulator-5554"


def test_dast_storage_endpoint(client):
    with patch("mobileag.web.app.storage_auditor.audit_all_storage") as mock_storage:
        mock_storage.return_value = {
            "package_name": "com.target.testapp",
            "device_serial": "emulator-5554",
            "total_storage_findings": 1,
            "shared_prefs_findings": 1,
            "database_findings": 0,
            "cache_findings": 0,
            "findings": [{
                "id": "find-storage-01",
                "title": "Cleartext Secret in SharedPreferences: session.xml [auth_token]",
                "severity": "HIGH",
                "cwe_id": "CWE-312",
            }],
        }
        response = client.post("/api/dast/storage", json={
            "serial": "emulator-5554",
            "package_name": "com.target.testapp",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["report"]["total_storage_findings"] == 1


def test_dast_providers_endpoint(client):
    with patch("mobileag.web.app.provider_auditor.audit_providers") as mock_prov:
        mock_prov.return_value = (
            [{"authority": "com.target.testapp.provider", "uri": "content://com.target.testapp.provider", "findings_count": 1}],
            [Finding(
                title="Exported Content Provider Leak: content://com.target.testapp.provider",
                description="Leaked query data",
                severity=Severity.HIGH,
                cwe_id="CWE-926",
            )]
        )
        response = client.post("/api/dast/providers", json={
            "serial": "emulator-5554",
            "package_name": "com.target.testapp",
            "authorities": ["com.target.testapp.provider"],
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert len(data["results"]) == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["cwe_id"] == "CWE-926"


def test_apk_upload_endpoint(client):
    apk_content = b"PK\x03\x04MockAPKFileContentForTesting"
    response = client.post(
        "/api/upload/apk",
        files={"file": ("test_upload_sample.apk", apk_content, "application/vnd.android.package-archive")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["filename"] == "test_upload_sample.apk"
    assert "file_path" in data


def test_apk_upload_invalid_extension(client):
    response = client.post(
        "/api/upload/apk",
        files={"file": ("payload.exe", b"MZNotAnApk", "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Only .apk, .ipa, or .zip" in response.json()["detail"]


def test_scan_run_autonomous_endpoint(client):
    response = client.post(
        "/api/scans/run",
        json={
            "apk_path": "/tmp/test_target.apk",
            "auto_dast": True,
            "auto_taint": True,
            "bypass_root": True,
            "bypass_ssl": True,
            "serial": "emulator-5554"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "initiated"
    assert data["auto_dast"] is True
    assert data["auto_taint"] is True
    assert data["bypass_root"] is True
    assert data["bypass_ssl"] is True
    assert "scan_id" in data


def test_dast_traffic_audit_endpoint(client):
    response = client.post(
        "/api/dast/traffic/audit",
        json={
            "transactions": [
                {
                    "url": "https://api.example.com/v1/accounts/98765/transactions",
                    "method": "GET",
                    "response_status": 200,
                    "response_headers": {"Strict-Transport-Security": "max-age=31536000"},
                }
            ]
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["findings_count"] >= 1
    assert any(f["cwe_id"] == "CWE-639" for f in data["findings"])


def test_dast_frida_unified_endpoint(client):
    response = client.post(
        "/api/dast/frida",
        json={
            "serial": "emulator-5554",
            "package_name": "com.target.app",
            "script_type": "unified",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "Unified Enterprise Runtime" in data["script"]



