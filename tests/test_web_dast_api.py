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
