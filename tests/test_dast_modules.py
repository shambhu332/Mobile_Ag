"""Unit tests for MobileAg DAST modules: ADBManager, LogcatAuditor, TrafficAuditor, IntentFuzzer."""

from unittest.mock import AsyncMock, patch

import pytest
from mobileag.dast.adb_manager import ADBManager, ConnectedDevice
from mobileag.dast.intent_fuzzer import IntentFuzzer
from mobileag.dast.logcat_auditor import LogcatAuditor
from mobileag.dast.provider_auditor import ProviderAuditor
from mobileag.dast.storage_auditor import StorageAuditor
from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor


@pytest.mark.asyncio
async def test_adb_manager_availability():
    mgr = ADBManager()
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
        "09-21 10:00:01.123 1234 1234 D ApiClient: Sending request with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0",
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
        "Process: com.test.app, PID: 1234",
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
    mock_adb.get_logcat_dump = AsyncMock(return_value=[
        "09-21 10:10:00.000 5678 5678 E AndroidRuntime: FATAL EXCEPTION: main",
        "Process: com.target.app, PID: 5678",
        "java.lang.NullPointerException: Null intent parameter in onCreate",
    ])

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

    async def mock_run_su(serial, cmd):
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
async def test_storage_auditor_sqlite_databases():
    mock_adb = ADBManager()
    auditor = StorageAuditor(adb=mock_adb)

    async def mock_run_su(serial, cmd):
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

    async def mock_run_su(serial, cmd):
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
async def test_provider_auditor_leak_and_sqli():
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
    )

    assert len(results) == 1
    assert len(findings) == 2
    cwes = [f.cwe_id for f in findings]
    assert "CWE-926" in cwes  # Exported Content Provider leak
    assert "CWE-89" in cwes   # SQL syntax error leakage


