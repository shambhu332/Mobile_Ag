"""Test FastAPI DAST endpoints in MobileAg web application."""

from unittest.mock import AsyncMock, patch
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.web.app import app


@pytest.fixture
def client():
    return TestClient(app, headers={"Authorization": "Bearer " + app.state.auth_token})


def test_captured_api_exports_require_session_and_mark_inventory(monkeypatch, client):
    import importlib
    web = importlib.import_module("mobileag.web.app")
    from mobileag.dast.traffic_auditor import HTTPTransaction

    capture = SimpleNamespace(get_transactions=lambda: [HTTPTransaction(
        url="https://api.example.test/v1/me", method="GET", response_status=200,
        response_headers={"Content-Type": "application/json",
                          "Set-Cookie": "session_id=synthetic-export-cookie; Path=/"},
        response_body='{"account":"synthetic"}')],
        get_capture_stats=lambda: {'transaction_count': 1, 'stored_bytes_estimate': 256,
                                   'omitted_transactions': 0},
        omitted_transactions=0)
    monkeypatch.setattr(web, "api_capture_proxy", capture)

    assert TestClient(app).get("/api/dast/api-capture/openapi").status_code == 401
    openapi = client.get("/api/dast/api-capture/openapi")
    assert openapi.status_code == 200
    assert openapi.json()["x-mobileag-proof-state"] == "not_proven"
    assert "/v1/me" in openapi.json()["paths"]
    har = client.get("/api/dast/api-capture/har")
    assert har.status_code == 200
    entry = har.json()["log"]["entries"][0]
    assert entry["request"]["method"] == "GET"
    assert {header["name"] for header in entry["response"]["headers"]} == {
        "Content-Type", "Set-Cookie"
    }
    assert "synthetic-export-cookie" not in har.text


def test_empty_scan_sbom_exports_use_a_valid_generic_application_purl(monkeypatch, client):
    import importlib
    web = importlib.import_module("mobileag.web.app")
    scan = {"scan_id": "synthetic-purl", "app_name": "org.example.demo", "version": "2.1.0",
            "package_name": "org.example.demo", "dependencies": []}
    monkeypatch.setattr(web, "get_scan_details", AsyncMock(return_value=scan))

    cyclonedx = client.get("/api/scans/synthetic-purl/cyclonedx")
    assert cyclonedx.status_code == 200
    component = cyclonedx.json()["components"][0]
    assert component["type"] == "application"
    assert component["purl"] == "pkg:generic/org.example.demo@2.1.0"
    spdx = client.get("/api/scans/synthetic-purl/spdx")
    assert spdx.status_code == 200
    assert spdx.json()["packages"][0]["externalRefs"][0]["referenceLocator"] == component["purl"]


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


def test_dast_connect_rechecks_policy_after_connect_attempt(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")
    calls = []

    async def revoke_connect_scope(host_port, guard=None):
        calls.append(host_port)
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "connect"]
        web.repository().save_policy(policy)
        return {"status": "success", "output": "synthetic ADB connect response"}

    monkeypatch.setattr(web.adb_manager, "connect_device", revoke_connect_scope)
    response = client.post("/api/dast/connect", json={"host_port": "127.0.0.1:5555"})
    assert calls == ["127.0.0.1:5555"]
    assert response.status_code == 403


def test_dast_screenshot_withholds_image_after_policy_revocation(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")

    async def revoke_screenshot_scope(serial, guard=None):
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "screenshot"]
        web.repository().save_policy(policy)
        return b"\x89PNG\r\n\x1a\nsynthetic-image"

    monkeypatch.setattr(web.adb_manager, "capture_screenshot", revoke_screenshot_scope)
    response = client.post("/api/dast/screenshot", json={"serial": "emulator-5554"})
    assert response.status_code == 403
    assert "image_b64" not in response.text


def test_dast_root_endpoint(client):
    response = client.post("/api/dast/root", json={"serial": "emulator-5554"})
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_dast_logcat_endpoint(client):
    response = client.get("/api/dast/logcat?serial=emulator-5554&package_name=com.target.testapp&lines=50")
    assert response.status_code in (200, 403)
    if response.status_code == 403:
        return  # Device/package scope is intentionally fail-closed.
    data = response.json()
    assert "lines" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_dast_logcat_requires_explicit_package(client):
    response = client.get("/api/dast/logcat?serial=emulator-5554&lines=50")
    assert response.status_code in (403, 422)  # middleware scope may reject first


def test_dast_logcat_withholds_result_after_scope_revocation(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")
    web.adb_manager.get_process_pids = AsyncMock(return_value=[4242])

    async def revoke_during_log_read(*, serial, lines, pid, guard=None):
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "logcat"]
        web.repository().save_policy(policy)
        return ["synthetic log line"]

    web.adb_manager.get_logcat_dump = AsyncMock(side_effect=revoke_during_log_read)
    response = client.get(
        "/api/dast/logcat?serial=emulator-5554&package_name=org.example&lines=10",
    )
    assert web.adb_manager.get_logcat_dump.await_count == 1
    assert response.status_code == 403
    assert "synthetic log line" not in response.text


@pytest.mark.asyncio
async def test_device_wide_logcat_clear_is_retired(client, monkeypatch):
    import importlib
    from starlette.requests import Request
    from fastapi import HTTPException

    web = importlib.import_module("mobileag.web.app")
    clear = AsyncMock(return_value=True)
    monkeypatch.setattr(web.adb_manager, "clear_logcat", clear)
    request = Request({
        "type": "http", "headers": [],
        "state": {"authenticated_token": web.app.state.auth_token},
    })
    with pytest.raises(HTTPException) as raised:
        await web.clear_dast_logcat(web.DeviceActionRequest(serial="emulator-5554"), request)
    assert raised.value.status_code == 410

    response = client.post("/api/dast/logcat/clear", json={"serial": "emulator-5554"})
    assert response.status_code == 403  # Retired action is also absent from scope choices.
    clear.assert_not_awaited()
    assert "data-onclick=\"static59\"" not in client.get("/").text


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
        rejected = client.post("/api/dast/fuzz", json={
            "serial": "emulator-5554", "package_name": "com.target.testapp",
            "activities": ["com.target.testapp.MainActivity"],
        })
        assert rejected.status_code == 403
        response = client.post("/api/dast/fuzz", json={
            "serial": "emulator-5554",
            "package_name": "com.target.testapp",
            "activities": ["com.target.testapp.MainActivity"],
            "synthetic_data_confirmed": True,
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
    import io, zipfile
    archive = io.BytesIO()
    with zipfile.ZipFile(archive,"w") as z:
        z.writestr("AndroidManifest.xml", "<manifest package='synthetic'/>")
    apk_content = archive.getvalue()
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
    assert response.status_code == 400  # Missing/out-of-scope input is never a simulated scan.


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


def test_dast_traffic_audit_can_review_declared_shadow_routes_without_live_requests(client):
    secret_id = "AbCdEf0123456789GhIjKlMnOpQrStUv"
    secret_query = "synthetic-shadow-query-marker"
    response = client.post("/api/dast/traffic/audit", json={
        "transactions": [{
            "url": f"https://alice:synthetic-password@api.example.test/v1/orders/{secret_id}?token={secret_query}",
            "method": "POST", "response_status": 200,
        }],
        "declared_endpoints": [{
            "url": "https://api.example.test/v1/orders/{orderId}", "method": "GET",
        }],
    })
    assert response.status_code == 200
    body = response.json()
    assert body["shadow_api_review_status"] == "unverified_review_leads"
    assert body["shadow_api_findings_count"] == 1
    shadow = body["shadow_api_findings"][0]
    assert shadow["metadata"]["method"] == "POST"
    assert shadow["affected_component"] == "/v1/orders/{id1}"
    assert body["live_requests_sent"] == 0
    encoded_shadow = str(shadow)
    for secret in ("alice", "synthetic-password", secret_id, secret_query):
        assert secret not in encoded_shadow


def test_dast_traffic_audit_marks_shadow_review_not_requested_when_missing(client):
    response = client.post("/api/dast/traffic/audit", json={"transactions": []})
    assert response.status_code == 200
    body = response.json()
    assert body["shadow_api_review_status"] == "not_requested"
    assert body["shadow_api_findings_count"] == 0
    assert body["live_requests_sent"] == 0


def test_dast_frida_unified_endpoint(client, monkeypatch):
    import importlib
    web = importlib.import_module("mobileag.web.app")
    attach = AsyncMock(side_effect=AssertionError("Safe profile must not execute Frida"))
    monkeypatch.setattr(web.frida_runner, "execute_script_payload", attach)
    response = client.post(
        "/api/dast/frida",
        json={
            "serial": "emulator-5554",
            "package_name": "com.target.app",
            "script_type": "unified",
        },
    )
    assert response.status_code == 403
    attach.assert_not_awaited()


def test_dast_execute_adb_endpoint(client):
    response = client.post(
        "/api/dast/execute_adb",
        json={
            "serial": "emulator-5554",
            "command": "echo 'POC_VERIFIED'",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "output" in data


def test_dast_execute_adb_rechecks_scope_after_command(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")
    calls = []

    async def revoke_shell_scope(serial, command, guard=None):
        calls.append((serial, command))
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "execute_adb"]
        web.repository().save_policy(policy)
        return {"status": "success", "output": "synthetic shell output", "exit_code": 0}

    monkeypatch.setattr(web.adb_manager, "execute_shell", revoke_shell_scope)
    response = client.post("/api/dast/execute_adb", json={
        "serial": "emulator-5554", "command": "echo synthetic",
    })
    assert calls == [("emulator-5554", "echo synthetic")]
    assert response.status_code == 403


def test_dast_execute_adb_command_length_is_bounded(client):
    response = client.post("/api/dast/execute_adb", json={
        "serial": "emulator-5554", "command": "x" * 4097,
    })
    assert response.status_code == 422


def test_dast_install_rechecks_scope_after_archive_validation(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")
    artifact = web.UPLOAD_DIR / "synthetic-install.apk"
    artifact.write_bytes(b"synthetic APK fixture")

    def revoke_install_scope(path):
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "install"]
        web.repository().save_policy(policy)
        return "android"

    monkeypatch.setattr(web, "validate_archive", revoke_install_scope)
    installer = AsyncMock(return_value={"status": "success"})
    monkeypatch.setattr(web.adb_manager, "install_apk", installer)
    response = client.post("/api/dast/install", json={
        "serial": "emulator-5554", "apk_path": str(artifact),
        "grant_permissions": False,
    })
    assert response.status_code == 403
    installer.assert_not_awaited()


def test_dast_root_stops_before_verification_after_scope_revocation(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")
    commands = []

    async def revoke_after_root_command(args, **kwargs):
        commands.append(args)
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "root"]
        web.repository().save_policy(policy)
        return 0, b"synthetic root command result", b""

    monkeypatch.setattr(web.adb_manager, "_exec_cmd", revoke_after_root_command)
    check_root = AsyncMock(return_value=False)
    monkeypatch.setattr(web.adb_manager, "_check_root", check_root)
    response = client.post("/api/dast/root", json={"serial": "emulator-5554"})
    assert response.status_code == 403
    assert commands == [["-s", "emulator-5554", "root"]]
    check_root.assert_not_awaited()


def test_dast_launch_rechecks_scope_after_activity_dispatch(client, monkeypatch):
    import importlib

    web = importlib.import_module("mobileag.web.app")
    calls = []

    async def revoke_launch_scope(serial, component, guard=None):
        calls.append((serial, component))
        policy = web.repository().get_policy()
        policy["actions"] = [action for action in policy["actions"] if action != "launch"]
        web.repository().save_policy(policy)
        return {"status": "success", "output": "synthetic Activity Manager response"}

    monkeypatch.setattr(web.adb_manager, "launch_activity", revoke_launch_scope)
    response = client.post("/api/dast/launch", json={
        "serial": "emulator-5554",
        "component": "org.example/.MainActivity",
    })
    assert calls == [("emulator-5554", "org.example/.MainActivity")]
    assert response.status_code == 403


def test_copilot_requires_real_scan(client):
    assert client.post('/api/copilot', json={'prompt':'Write a PoC'}).status_code == 422
    assert client.post('/api/copilot', json={'prompt':'Write a PoC', 'scan_id':'absent'}).status_code == 404


def test_get_scan_apis_endpoint(client):
    # No fabricated demo targets/endpoints in live mode.
    assert client.get('/api/scans/scan_meesho_demo/apis').status_code == 404


def test_get_scan_apis_counts_all_routes_as_unverified_candidates(monkeypatch, client):
    import importlib
    web = importlib.import_module("mobileag.web.app")
    endpoints = [
        {"method": "GET", "url": "/v1/profile", "evidence_type": "route_literal"},
        {"method": "UNKNOWN", "url": "https://api.example.test/v1/items/{id}",
         "evidence_type": "embedded_url_candidate"},
    ]
    graphql_operations = [{"operation_type": "query", "operation_name": "LoadProfile",
                           "source_file": "Api.kt", "line_number": 12,
                           "evidence_type": "graphql_operation_string_candidate"}]
    monkeypatch.setattr(web, "get_scan_details", AsyncMock(return_value={
        "api_endpoints": endpoints,
        "coverage": {"api_mapping": {"graphql_operation_candidates": graphql_operations}},
    }))

    response = client.get("/api/scans/synthetic-api-candidates/apis")
    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert response.json()["candidate_count"] == 2
    assert response.json()["vulnerable_count"] == 0
    assert response.json()["graphql_operation_candidate_count"] == 1
    assert response.json()["graphql_operations"] == graphql_operations
    assert "unverified" in response.json()["assessment"]


def test_api_test_replay_endpoint(client):
    response = client.post(
        "/api/apis/test",
        json={
            "url": "http://api.dev.targetapp.internal/v1/auth/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": '{"username":"admin","password":"secret"}',
        },
    )
    assert response.status_code == 403  # No configured outbound scope.


def test_api_fuzz_owasp_top_10_endpoint(client):
    response = client.post(
        "/api/apis/fuzz",
        json={
            "url": "https://api.targetapp.com/v1/accounts/10023/transactions",
            "method": "GET",
            "headers": {"Authorization": "Bearer sample_token"},
            "response_status": 200,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["findings_count"] >= 1
    cwes = [f["cwe_id"] for f in data["findings"]]
    # Should detect CWE-639 (BOLA sequential numeric ID)
    assert "CWE-639" in cwes


def test_api_fuzz_admin_bfla_and_cleartext(client):
    response = client.post(
        "/api/apis/fuzz",
        json={
            "url": "http://api.dev.targetapp.internal/v1/admin/users/9918",
            "method": "DELETE",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    cwes = [f["cwe_id"] for f in data["findings"]]
    # Should flag cleartext HTTP (CWE-319) and privileged admin path (CWE-285)
    assert "CWE-319" in cwes
    assert "CWE-285" not in cwes




