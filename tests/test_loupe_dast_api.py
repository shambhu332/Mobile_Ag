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


def test_packages_endpoints(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["packages", "fs", "clipboard"],
    })

    # 1. GET packages list
    mock_pkgs = [{"package": "org.example.synthetic", "apk_path": "/data/app/org.example.synthetic-1/base.apk"}]
    with patch("mobileag.dast.file_manager.DeviceFileManager.list_packages", AsyncMock(return_value=mock_pkgs)):
        res = client.get("/api/dast/packages?serial=emulator-5554")
        assert res.status_code == 200
        data = res.json()
        assert data["count"] == 1
        assert data["packages"][0]["package"] == "org.example.synthetic"

    # 2. GET package info
    mock_info = {
        "package_name": "org.example.synthetic",
        "version_name": "1.0.0",
        "version_code": "100",
        "target_sdk": "34",
        "min_sdk": "26",
        "data_dir": "/data/user/0/org.example.synthetic",
        "code_path": "/data/app/org.example.synthetic",
        "requested_permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
        "granted_permissions": ["android.permission.INTERNET"],
        "dangerous_count": 1,
    }
    with patch.object(web.adb_manager, "get_package_info", AsyncMock(return_value=mock_info)):
        res = client.get("/api/dast/packages/info?serial=emulator-5554&package_name=org.example.synthetic")
        assert res.status_code == 200
        assert res.json()["version_name"] == "1.0.0"
        assert res.json()["dangerous_count"] == 1

    # 3. POST package action
    with patch.object(web.adb_manager, "execute_package_action", AsyncMock(return_value={"status": "success", "action": "force_stop", "package_name": "org.example.synthetic", "output": "Done"})):
        res = client.post("/api/dast/packages/action", json={"serial": "emulator-5554", "package_name": "org.example.synthetic", "action": "force_stop"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"

    # 4. POST package pull
    with patch("mobileag.dast.file_manager.DeviceFileManager.pull_apk", AsyncMock(return_value={"status": "success", "local_path": "/tmp/test.apk", "package": "org.example.synthetic"})):
        res = client.post("/api/dast/packages/pull", json={"serial": "emulator-5554", "package_name": "org.example.synthetic"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"


def test_fs_and_clipboard_endpoints(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["packages", "fs", "clipboard"],
    })

    # 1. GET fs ls
    mock_ls = {"path": "/sdcard", "entries": [{"name": "Download", "type": "dir", "size": 4096, "permissions": "rwxrwx---", "modified": "2026-10-19"}]}
    with patch("mobileag.dast.file_manager.DeviceFileManager.list_directory", AsyncMock(return_value=mock_ls)):
        res = client.get("/api/dast/fs/ls?serial=emulator-5554&path=/sdcard")
        assert res.status_code == 200
        assert len(res.json()["entries"]) == 1

    # 2. GET clipboard
    with patch.object(web.adb_manager, "get_clipboard", AsyncMock(return_value={"status": "success", "text": "secret_token_123"})):
        res = client.get("/api/dast/clipboard?serial=emulator-5554")
        assert res.status_code == 200
        assert res.json()["text"] == "secret_token_123"

    # 3. POST clipboard
    with patch.object(web.adb_manager, "set_clipboard", AsyncMock(return_value={"status": "success", "output": ""})):
        res = client.post("/api/dast/clipboard", json={"serial": "emulator-5554", "text": "test_payload"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"


def test_device_posture_and_memory_endpoints(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["device_posture", "memory"],
    })

    # 1. Device Posture
    mock_posture = {
        "serial": "emulator-5554",
        "model": "Pixel 7 Pro",
        "manufacturer": "Google",
        "android_version": "14",
        "sdk_level": "34",
        "abi": "x86_64",
        "security_patch": "2024-06-01",
        "build_type": "userdebug",
        "build_tags": "release-keys",
        "debuggable": False,
        "selinux": "Enforcing",
        "is_rooted": False,
        "is_permissive": False,
        "posture_score": 95,
        "findings": [],
    }
    with patch.object(web.adb_manager, "get_device_posture", AsyncMock(return_value=mock_posture)):
        res = client.get("/api/dast/device/posture?serial=emulator-5554")
        assert res.status_code == 200
        assert res.json()["model"] == "Pixel 7 Pro"
        assert res.json()["posture_score"] == 95

    # 2. Package Memory & Procs
    mock_mem = {
        "package_name": "org.example.synthetic",
        "pid": 4321,
        "total_pss_kb": 54200,
        "native_heap_kb": 18200,
        "java_heap_kb": 12400,
        "code_kb": 8900,
        "stack_kb": 1200,
        "graphics_kb": 4500,
        "private_dirty_kb": 32000,
        "active_processes": [{"pid": "4321", "name": "org.example.synthetic"}],
        "is_running": True,
    }
    with patch.object(web.adb_manager, "get_package_memory_and_procs", AsyncMock(return_value=mock_mem)):
        res = client.get("/api/dast/memory?serial=emulator-5554&package_name=org.example.synthetic")
        assert res.status_code == 200
        assert res.json()["pid"] == 4321
        assert res.json()["total_pss_kb"] == 54200


def test_wireless_and_cert_endpoints(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    repo = web.repository()
    repo.save_policy({
        "devices": ["emulator-5554"],
        "packages": ["org.example.synthetic"],
        "origins": ["http://localhost:8080"],
        "methods": ["GET", "POST"],
        "actions": ["wireless", "cert"],
    })

    # 1. Wireless mDNS
    with patch.object(web.adb_manager, "wireless_mdns_services", AsyncMock(return_value={"status": "success", "services": [{"name": "test-dev", "type": "_adb._tcp", "addr": "192.168.1.50:5555"}]})):
        res = client.get("/api/dast/wireless/mdns")
        assert res.status_code == 200
        assert len(res.json()["services"]) == 1

    # 2. Wireless pair
    with patch.object(web.adb_manager, "wireless_pair", AsyncMock(return_value={"status": "success", "output": "Successfully paired"})):
        res = client.post("/api/dast/wireless/pair", json={"addr": "192.168.1.50:37000", "code": "123456"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"

    # 3. Wireless connect
    with patch.object(web.adb_manager, "wireless_connect", AsyncMock(return_value={"status": "success", "output": "Connected to 192.168.1.50:5555"})):
        res = client.post("/api/dast/wireless/connect", json={"addr": "192.168.1.50:5555"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"

    # 4. Cert prepare
    mock_prepared = {
        "hash": "7af03122",
        "android_filename": "7af03122.0",
        "subject": "CN=Test CA",
        "issuer": "CN=Test CA",
        "dates": "notBefore=2024\nnotAfter=2034",
        "pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
    }
    with patch.object(web.adb_manager, "prepare_ca_certificate", return_value=mock_prepared):
        res = client.post("/api/dast/cert/prepare", json={"cert_data": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"})
        assert res.status_code == 200
        assert res.json()["android_filename"] == "7af03122.0"

    # 5. Cert install
    mock_install = {
        "status": "staged",
        "serial": "emulator-5554",
        "target_path": "/data/local/tmp/7af03122.0",
        "filename": "7af03122.0",
        "instructions": {"user_install": "am start..."},
    }
    with patch.object(web.adb_manager, "install_ca_certificate", AsyncMock(return_value=mock_install)):
        res = client.post("/api/dast/cert/install", json={"serial": "emulator-5554", "cert_pem": "...", "filename": "7af03122.0"})
        assert res.status_code == 200
        assert res.json()["status"] == "staged"



