"""Tests for Loupe DAST diagnostic endpoints: Sockets, Inspector, Settings, and Proxy."""

import importlib
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

web = importlib.import_module("mobileag.web.app")


@pytest.fixture
def client():
    return TestClient(web.app, headers={"Authorization": "Bearer " + web.app.state.auth_token})


def fixture_scan(sid="scan_sig"):
    return {
        "scan_id": sid,
        "package_name": "org.example.synthetic",
        "status": "completed",
        "version": "1.0",
        "artifact_sha256": "b" * 64,
        "revision": 0,
        "created_at": "2026-10-19",
        "stats": {"total": 1},
        "signature_analysis": {
            "signing_block_found": True,
            "schemes": {"v1": True, "v2": True, "v3": False, "v3.1": False},
            "certificates": [
                {
                    "subject": "CN=Test App,O=Test Corp",
                    "issuer": "CN=Test App,O=Test Corp",
                    "serial_number": "ABCD",
                    "signature_algorithm": "SHA256",
                    "key_type": "RSA",
                    "key_size": 2048,
                    "not_valid_before": "2024-01-01T00:00:00",
                    "not_valid_after": "2049-01-01T00:00:00",
                    "sha256_fingerprint": "11223344",
                    "sha1_fingerprint": "55667788",
                    "is_debug": False,
                    "is_expired": False,
                }
            ],
            "vulnerabilities": [],
            "janus_vulnerable": False,
        },
        "findings": [],
    }


def test_signature_endpoint_returns_signature_analysis(client):
    repo = web.repository()
    repo.save(fixture_scan("scan_sig_test"))

    res = client.get("/api/scans/scan_sig_test/signature")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == "scan_sig_test"
    sig = data["signature"]
    assert sig["signing_block_found"] is True
    assert sig["schemes"]["v1"] is True
    assert sig["schemes"]["v2"] is True
    assert sig["janus_vulnerable"] is False
    assert len(sig["certificates"]) == 1
    assert "Test Corp" in sig["certificates"][0]["subject"]


def test_sockets_endpoint_enforces_scope_and_returns_data(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    monkeypatch.setenv("MOBILEAG_ALLOWED_ORIGINS", "http://localhost:8080")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["sockets", "inspector", "settings", "proxy"],
    })

    mock_sockets = [
        {"proto": "tcp", "state": "LISTEN", "local": "0.0.0.0:8080", "peer": "*:*", "proc": "uid:1000", "uid": 1000, "inode": "1234"},
        {"proto": "tcp", "state": "ESTAB", "local": "127.0.0.1:45678", "peer": "93.184.216.34:443", "proc": "uid:10123", "uid": 10123, "inode": "5678"},
    ]
    with patch.object(web.adb_manager, "get_sockets", AsyncMock(return_value=mock_sockets)):
        res = client.get("/api/dast/sockets?serial=emulator-5554")
        assert res.status_code == 200
        data = res.json()
        assert data["count"] == 2
        assert data["sockets"][0]["state"] == "LISTEN"
        assert data["sockets"][1]["peer"] == "93.184.216.34:443"

    # Unauthorized device
    res_unauth = client.get("/api/dast/sockets?serial=unauthorized-device")
    assert res_unauth.status_code == 403


def test_inspector_endpoint_enforces_scope_and_returns_nodes(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    monkeypatch.setenv("MOBILEAG_ALLOWED_ORIGINS", "http://localhost:8080")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["sockets", "inspector", "settings", "proxy"],
    })

    mock_nodes = [
        {"id": "node_0", "cls": "FrameLayout", "fullClass": "android.widget.FrameLayout", "rid": "", "text": "", "desc": "", "bounds": "[0,0][1080,2400]", "depth": 0},
        {"id": "node_1", "cls": "TextView", "fullClass": "android.widget.TextView", "rid": "org.example:id/title", "text": "Welcome", "desc": "", "bounds": "[50,100][500,200]", "depth": 1},
    ]
    with patch.object(web.adb_manager, "dump_view_hierarchy", AsyncMock(return_value={"nodes": mock_nodes, "count": 2, "status": "success"})):
        res = client.post("/api/dast/inspector", json={"serial": "emulator-5554"})
        assert res.status_code == 200
        data = res.json()
        assert data["count"] == 2
        assert data["nodes"][1]["text"] == "Welcome"


def test_settings_and_proxy_endpoints(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    monkeypatch.setenv("MOBILEAG_ALLOWED_ORIGINS", "http://localhost:8080")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["sockets", "inspector", "settings", "proxy"],
    })

    # 1. GET settings
    mock_settings = [{"k": "http_proxy", "v": ":0"}, {"k": "animator_duration_scale", "v": "1.0"}]
    with patch.object(web.adb_manager, "get_settings", AsyncMock(return_value=mock_settings)):
        res = client.get("/api/dast/settings?serial=emulator-5554&namespace=global")
        assert res.status_code == 200
        assert res.json()["count"] == 2

    # 2. POST setting
    with patch.object(web.adb_manager, "put_setting", AsyncMock(return_value={"status": "success", "namespace": "global", "key": "http_proxy", "value": "127.0.0.1:8080"})):
        res = client.post("/api/dast/settings", json={"serial": "emulator-5554", "namespace": "global", "key": "http_proxy", "value": "127.0.0.1:8080"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"

    # 3. Configure proxy
    with patch.object(web.adb_manager, "configure_proxy", AsyncMock(return_value={"status": "success", "proxy": "127.0.0.1:8080"})):
        res = client.post("/api/dast/proxy/setup", json={"serial": "emulator-5554", "host": "127.0.0.1", "port": 8080})
        assert res.status_code == 200
        assert res.json()["proxy"] == "127.0.0.1:8080"

    # 4. Clear proxy
    with patch.object(web.adb_manager, "clear_proxy", AsyncMock(return_value={"status": "success", "proxy": "cleared"})):
        res = client.post("/api/dast/proxy/clear", json={"serial": "emulator-5554"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"


def test_binaries_endpoint_returns_hardening_data(client):
    scan = fixture_scan("scan_bin_test")
    scan["native_binaries"] = {
        "libraries": [
            {
                "name": "libnative.so",
                "arch": "arm64-v8a",
                "canary": True,
                "nx": True,
                "pie": True,
                "relro": "Full",
                "hardening_score": 100,
            }
        ],
        "total_libraries": 1,
        "hardening_score": 100,
        "summary": {"missing_canary": 0, "missing_nx": 0, "missing_relro": 0, "missing_pie": 0},
    }
    web.repository().save(scan)

    res = client.get("/api/scans/scan_bin_test/binaries")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == "scan_bin_test"
    assert data["native_binaries"]["total_libraries"] == 1
    assert data["native_binaries"]["libraries"][0]["canary"] is True


def test_nsc_endpoint_returns_trust_tree(client):
    scan = fixture_scan("scan_nsc_test")
    scan["nsc_analysis"] = {
        "has_custom_config": True,
        "config_file": "network_security_config.xml",
        "risk_posture": "CRITICAL",
        "base_config": {"cleartext_permitted": True, "trust_anchors": ["system", "user"]},
        "domain_configs": [],
        "pin_sets": [],
        "debug_overrides": {"present": True, "trust_user_certs": True},
        "findings": [{"title": "Cleartext HTTP Allowed", "severity": "High", "cwe": "CWE-319"}],
    }
    web.repository().save(scan)

    res = client.get("/api/scans/scan_nsc_test/nsc")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == "scan_nsc_test"
    assert data["nsc"]["risk_posture"] == "CRITICAL"
    assert data["nsc"]["base_config"]["cleartext_permitted"] is True


def test_compliance_endpoint_computes_masvs_radar(client):
    scan = fixture_scan("scan_comp_test")
    scan["findings"] = [
        {"id": "F1", "title": "Insecure Storage", "severity": "CRITICAL", "cwe_id": "CWE-312"},
        {"id": "F2", "title": "Weak Cipher", "severity": "HIGH", "cwe_id": "CWE-327"},
    ]
    web.repository().save(scan)

    res = client.get("/api/scans/scan_comp_test/compliance")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == "scan_comp_test"
    assert "radar" in data
    assert len(data["radar"]["labels"]) == 8
    assert len(data["radar"]["scores"]) == 8
    storage_idx = data["radar"]["labels"].index("Storage")
    assert data["radar"]["scores"][storage_idx] < 100
    assert data["overall_posture_percentage"] < 100

