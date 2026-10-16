"""Unit tests for MobileAg DAST modules: ADBManager, LogcatAuditor, TrafficAuditor, IntentFuzzer."""

from unittest.mock import AsyncMock, patch

import pytest
from mobileag.dast.adb_manager import ADBManager, ConnectedDevice
from mobileag.dast.frida_runner import FridaRunner
from mobileag.dast.intent_fuzzer import IntentFuzzer
from mobileag.dast.logcat_auditor import LogcatAuditor
from mobileag.dast.mitm_proxy import AsyncMITMProxy
from mobileag.dast.provider_auditor import ProviderAuditor
from mobileag.dast.storage_auditor import StorageAuditor
from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor


@pytest.mark.asyncio
async def test_adb_manager_availability():
    mgr = ADBManager()
    mgr._exec_cmd = AsyncMock(return_value=(0,b"Android Debug Bridge version 1.0.41",b""))
    is_avail = await mgr.is_adb_available()
    assert is_avail is True


@pytest.mark.asyncio
async def test_adb_manager_device_enumeration():
    mgr = ADBManager()
    devices = await mgr.list_devices()
    assert isinstance(devices, list)


def test_logcat_auditor_sensitive_token_leak():
    auditor = LogcatAuditor()
    log_sample = [
        "09-21 10:00:01.123 1234 1234 I ActivityManager: Process: com.test.app, PID: 1234",
        "09-21 10:00:01.124 1234 1234 D ApiClient: Sending request with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0",
        "09-21 10:00:02.456 1234 1234 I MainActivity: Initialized",
    ]
    findings = auditor.audit_lines(log_sample, package_name="com.test.app")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-532"
    assert "Bearer" in findings[0].title


def test_logcat_auditor_crash_detection():
    auditor = LogcatAuditor()
    log_sample = [
        "09-21 10:05:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main",
        "09-21 10:05:00.001 1234 1234 E AndroidRuntime: Process: com.test.app, PID: 1234",
        "java.lang.NullPointerException: Attempt to invoke virtual method on a null object reference",
    ]
    findings = auditor.audit_lines(log_sample, package_name="com.test.app")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-755"
    assert "Crash" in findings[0].title


def test_traffic_auditor_cleartext_and_query_leak():
    auditor = TrafficAuditor()
    transactions = [
        HTTPTransaction(
            url="http://api.insecure-service.com/v1/user?token=secret12345",
            method="GET",
            response_status=200,
            response_headers={"Content-Type": "application/json"}
        ),
        HTTPTransaction(
            url="https://api.secure-service.com/auth/login",
            method="POST",
            response_status=200,
            response_headers={"Content-Type": "application/json"}  # Missing Cache-Control: no-store
        ),
    ]
    findings = auditor.audit_transactions(transactions)
    assert len(findings) >= 2
    cwes = [f.cwe_id for f in findings]
    assert "CWE-319" in cwes  # Cleartext HTTP
    assert "CWE-598" in cwes  # Sensitive token in GET query
    assert "CWE-524" in cwes  # Missing Cache-Control on sensitive endpoint


@pytest.mark.asyncio
async def test_intent_fuzzer_crash_capture():
    mock_adb = ADBManager()
    mock_adb.clear_logcat = AsyncMock(return_value=True)
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"Starting: Intent { cmp=com.target.app/.VulnActivity }\n", b""))
    mock_adb.get_logcat_dump = AsyncMock(side_effect=[[], [
        "09-21 10:10:00.000 5678 5678 E AndroidRuntime: FATAL EXCEPTION: main",
        "Process: com.target.app, PID: 5678",
        "java.lang.NullPointerException: Null intent parameter in onCreate",
    ]])

    fuzzer = IntentFuzzer(adb=mock_adb)
    res = await fuzzer.exercise_component(
        serial="emulator-5554",
        package_name="com.target.app",
        component_name="com.target.app.VulnActivity",
    )

    assert res["crashed"] is True
    assert len(res["findings"]) == 1
    assert res["findings"][0].cwe_id == "CWE-755"
    assert "com.target.app.VulnActivity" in res["findings"][0].affected_component


@pytest.mark.asyncio
async def test_storage_auditor_shared_preferences():
    mock_adb = ADBManager()
    auditor = StorageAuditor(adb=mock_adb)

    async def mock_run_su(serial, cmd, guard=None):
        if "ls -1" in cmd:
            return "user_session.xml\nsettings.xml"
        if "cat /data/data/com.test.app/shared_prefs/user_session.xml" in cmd:
            return '<map><string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDc</string></map>'
        if "cat /data/data/com.test.app/shared_prefs/settings.xml" in cmd:
            return '<map><boolean name="dark_mode" value="true" /></map>'
        return ""

    auditor._run_su_cmd = mock_run_su
    findings = await auditor.audit_shared_preferences(serial="emulator-5554", package_name="com.test.app")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-312"
    assert "user_session.xml" in findings[0].title


@pytest.mark.asyncio
async def test_storage_auditor_honors_scope_denial_before_shell(monkeypatch):
    mock_adb = ADBManager()
    calls = []

    async def forbidden_exec(*args, **kwargs):
        calls.append(True)
        raise AssertionError("denied storage audit must not invoke shell")

    mock_adb._exec_cmd = forbidden_exec
    auditor = StorageAuditor(adb=mock_adb)
    with pytest.raises(PermissionError):
        await auditor._run_su_cmd("synthetic-device", "ls -1 /synthetic", guard=lambda: False)
    assert calls == []


@pytest.mark.asyncio
async def test_storage_auditor_revocation_prevents_unprivileged_fallback():
    mock_adb = ADBManager()
    calls = []

    async def denied_su(*args, **kwargs):
        calls.append(args[0])
        return 1, b"", b""

    mock_adb._exec_cmd = denied_su
    approvals = iter((True, False))
    auditor = StorageAuditor(adb=mock_adb)
    with pytest.raises(PermissionError):
        await auditor._run_su_cmd(
            "synthetic-device", "ls -1 /synthetic", guard=lambda: next(approvals),
        )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_storage_auditor_sqlite_databases():
    mock_adb = ADBManager()
    auditor = StorageAuditor(adb=mock_adb)

    async def mock_run_su(serial, cmd, guard=None):
        if "ls -1" in cmd:
            return "app_accounts.db"
        if "head -c 16" in cmd:
            return "SQLite format 3\x00"
        if "sqlite3" in cmd:
            return "users\ncredentials"
        return ""

    auditor._run_su_cmd = mock_run_su
    findings = await auditor.audit_sqlite_databases(serial="emulator-5554", package_name="com.test.app")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-312"
    assert "app_accounts.db" in findings[0].title
    assert "users, credentials" in findings[0].description


@pytest.mark.asyncio
async def test_storage_auditor_cache_and_audit_all():
    mock_adb = ADBManager()
    auditor = StorageAuditor(adb=mock_adb)

    async def mock_run_su(serial, cmd, guard=None):
        if "grep" in cmd:
            return "/data/data/com.test.app/cache/req1: Authorization: Bearer token123"
        return ""

    auditor._run_su_cmd = mock_run_su
    findings = await auditor.audit_cache_leakage(serial="emulator-5554", package_name="com.test.app")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-524"

    res = await auditor.audit_all_storage(serial="emulator-5554", package_name="com.test.app")
    assert res["total_storage_findings"] == 1
    assert res["cache_findings"] == 1


@pytest.mark.asyncio
async def test_provider_auditor_scoped_shell_observation(monkeypatch):
    import json
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")
    monkeypatch.setenv("MOBILEAG_PROVIDER_FIXTURES", json.dumps([{
        "package_name": "com.test.app", "uri": "content://com.test.app.provider/fixtures/synthetic"}]))
    mock_adb = ADBManager()

    async def mock_exec(cmd, timeout=4.0):
        if "--where" in cmd:
            return (0, b"", b"android.database.sqlite.SQLiteException: syntax error near '1=1'")
        return (0, b"Row: 0 _id=1, username=admin, token=sec123\n", b"")

    mock_adb._exec_cmd = mock_exec
    auditor = ProviderAuditor(adb=mock_adb)

    results, findings = await auditor.audit_providers(
        serial="emulator-5554",
        package_name="com.test.app",
        authorities=["com.test.app.provider"],
        guard=lambda: None,
    )

    assert len(results) == 1
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-926"
    assert findings[0].cvss_score == 0
    assert "sec123" not in str(findings[0].to_dict())


@pytest.mark.asyncio
async def test_provider_auditor_requires_synchronous_scope_guard(monkeypatch):
    import json
    from unittest.mock import AsyncMock
    from mobileag.dast.provider_auditor import ProviderAuditor

    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "synthetic-device")
    uri = "content://com.test.app.provider/fixtures/synthetic"
    monkeypatch.setenv("MOBILEAG_PROVIDER_FIXTURES", json.dumps([{
        "package_name": "com.test.app", "uri": uri,
    }]))
    adb = ADBManager()
    adb._exec_cmd = AsyncMock(side_effect=AssertionError("Unapproved provider query"))
    auditor = ProviderAuditor(adb=adb)

    with pytest.raises(PermissionError, match="required"):
        await auditor.audit_provider_uri("synthetic-device", "com.test.app", uri)

    async def async_guard():
        return False

    with pytest.raises(PermissionError, match="synchronous"):
        await auditor.audit_provider_uri(
            "synthetic-device", "com.test.app", uri, guard=async_guard,
        )
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_provider_auditor_honors_boolean_scope_denial_before_adb(monkeypatch):
    import json
    from mobileag.dast.provider_auditor import ProviderAuditor

    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "synthetic-device")
    uri = "content://com.test.app.provider/fixtures/synthetic"
    monkeypatch.setenv("MOBILEAG_PROVIDER_FIXTURES", json.dumps([{
        "package_name": "com.test.app", "uri": uri,
    }]))
    called = []

    async def forbidden_exec(*args, **kwargs):
        called.append(True)
        raise AssertionError("denied provider diagnostic must not invoke ADB")

    auditor = ProviderAuditor(adb=ADBManager())
    auditor.adb._exec_cmd = forbidden_exec
    with pytest.raises(PermissionError):
        await auditor.audit_provider_uri(
            "synthetic-device", "com.test.app", uri, guard=lambda: False,
        )
    assert called == []


@pytest.mark.asyncio
async def test_provider_auditor_honors_scope_revocation_after_adb(monkeypatch):
    import json
    from mobileag.dast.provider_auditor import ProviderAuditor

    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "synthetic-device")
    uri = "content://com.test.app.provider/fixtures/synthetic"
    monkeypatch.setenv("MOBILEAG_PROVIDER_FIXTURES", json.dumps([{
        "package_name": "com.test.app", "uri": uri,
    }]))
    calls = []

    async def mock_exec(*args, **kwargs):
        calls.append(True)
        return 0, b"Row: synthetic controlled fixture", b""

    auditor = ProviderAuditor(adb=ADBManager())
    auditor.adb._exec_cmd = mock_exec
    approvals = iter((True, False))
    with pytest.raises(PermissionError):
        await auditor.audit_provider_uri(
            "synthetic-device", "com.test.app", uri,
            guard=lambda: next(approvals),
        )
    assert calls == [True]


def test_traffic_auditor_owasp_api_top10():
    auditor = TrafficAuditor()
    transactions = [
        # BOLA / IDOR check
        HTTPTransaction(
            url="https://api.example.com/v1/users/45123/profile",
            method="GET",
            response_status=200,
            response_headers={"Strict-Transport-Security": "max-age=31536000"},
        ),
        # PII exposure in response payload
        HTTPTransaction(
            url="https://api.example.com/v1/checkout",
            method="POST",
            response_status=200,
            response_headers={"Strict-Transport-Security": "max-age=31536000"},
            response_body='{"status":"ok", "ssn":"123-45-6789", "user_password":"plainSecret123"}',
        ),
        # Missing HSTS & Permissive CORS with credentials
        HTTPTransaction(
            url="https://api.example.com/v1/public-data",
            method="GET",
            response_status=200,
            response_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        ),
    ]

    findings = auditor.audit_transactions(transactions)
    cwes = {f.cwe_id for f in findings}

    assert "CWE-639" in cwes  # BOLA / IDOR
    assert "CWE-359" in cwes  # Sensitive PII exposure
    assert "CWE-16" in cwes   # Missing HSTS
    assert "CWE-942" in cwes  # Permissive CORS with credentials


@pytest.mark.asyncio
async def test_async_mitm_proxy_lifecycle_and_interception(monkeypatch):
    monkeypatch.setenv("MOBILEAG_PROXY_TOKEN", "synthetic-test-token")
    proxy = AsyncMITMProxy(host="127.0.0.1", port=0)
    assert proxy.is_running is False
    await proxy.start()
    assert proxy.is_running is True

    # Record simulated transactions
    proxy.record_transaction(
        HTTPTransaction(
            url="http://api.insecure.com/api/v1/data",
            method="GET",
            response_status=200,
        )
    )
    assert len(proxy.get_transactions()) == 1

    findings = proxy.audit_captured_traffic()
    assert len(findings) >= 1
    assert any(f.cwe_id == "CWE-319" for f in findings)

    await proxy.stop()
    assert proxy.is_running is False


def test_proxy_capture_storage_is_bounded_and_reports_omissions():
    proxy = AsyncMITMProxy(max_capture_bytes=400)
    proxy.record_transaction(HTTPTransaction(url="http://api.test/a", request_body="a" * 200))
    proxy.record_transaction(HTTPTransaction(url="http://api.test/b", request_body="b" * 200))
    stats = proxy.get_capture_stats()
    assert stats["transaction_count"] == 1
    assert stats["stored_bytes_estimate"] <= stats["max_capture_bytes"]
    assert proxy.get_transactions()[0].url.endswith("/b")

    proxy.record_transaction(HTTPTransaction(
        url="http://api.test/oversize", response_body="x" * (proxy.MAX_TRANSACTION_BYTES + 1)))
    assert proxy.get_capture_stats()["omitted_transactions"] == 1
    proxy.clear_transactions()
    assert proxy.get_capture_stats()["stored_bytes_estimate"] == 0
    assert proxy.get_capture_stats()["omitted_transactions"] == 0


def test_frida_runner_unified_agent_and_session():
    runner = FridaRunner()
    assert not hasattr(runner, "generate_all_in_one_agent_script")

    # Test attach_and_instrument_session fallback behavior
    result = runner.attach_and_instrument_session(
        package_name="com.test.app",
        script_code="console.log('test');",
    )
    assert isinstance(result, dict) and result["status"] == "disabled"
    assert "package_name" in result
    assert result["package_name"] == "com.test.app"

