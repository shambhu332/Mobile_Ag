"""Unit tests for MobileAg DAST modules: ADBManager, LogcatAuditor, TrafficAuditor, IntentFuzzer."""

from unittest.mock import AsyncMock, patch

import pytest
from mobileag.dast.adb_manager import ADBManager, ConnectedDevice
from mobileag.dast.intent_fuzzer import IntentFuzzer
from mobileag.dast.logcat_auditor import LogcatAuditor
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

