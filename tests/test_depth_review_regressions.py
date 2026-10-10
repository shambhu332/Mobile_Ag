"""Synthetic reproductions of evidence attribution, privacy and scope defects."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from mobileag.security.privacy import redact
from mobileag.dast.intent_fuzzer import IntentFuzzer
from mobileag.dast.provider_auditor import ProviderAuditor
from mobileag.dast.mitm_proxy import AsyncMITMProxy
from mobileag.dast.traffic_auditor import HTTPTransaction
from mobileag.dast.logcat_auditor import LogcatAuditor
from mobileag.dast.storage_auditor import StorageAuditor

FATAL = '10-08 12:00:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main'
TARGET = '10-08 12:00:00.001 1234 1234 E AndroidRuntime: Process: org.example.fixture, PID: 1234'


def test_proxy_capture_does_not_retain_url_credentials():
    proxy = AsyncMITMProxy()
    tx = HTTPTransaction(url='https://fixture.invalid/item?token=syntheticOpaqueCredential', method='GET')
    proxy.record_transaction(tx)
    assert 'syntheticOpaqueCredential' not in proxy.get_transactions()[0].url


def test_proxy_auth_header_is_redacted_from_evidence():
    proxy = AsyncMITMProxy()
    tx = HTTPTransaction(url='https://fixture.invalid/', method='GET',
                         request_headers={'Proxy-Authorization': 'Bearer syntheticProxySecret'})
    proxy.record_transaction(tx)
    assert 'syntheticProxySecret' not in repr(proxy.get_transactions()[0].request_headers)


def test_logcat_auditor_does_not_scan_shared_buffer_without_target_process():
    lines = [FATAL, TARGET.replace('org.example.fixture', 'org.other.fixture'),
             '10-08 12:00:00.002 1234 1234 E App: password=syntheticSecret']
    assert LogcatAuditor().audit_lines(lines, package_name='org.example.fixture') == []
    assert LogcatAuditor().audit_lines(lines, package_name='') == []


def test_storage_file_listing_rejects_shell_metacharacter_entries():
    assert StorageAuditor._listed_files('ok.xml\n$(id).xml\n`touch pwned`.xml\n../escape.xml', ('.xml',)) == ['ok.xml']


def test_storage_auditor_rejects_package_path_injection():
    with pytest.raises(ValueError):
        StorageAuditor._package_path('org.example;id')


@pytest.mark.asyncio
async def test_adb_logcat_requests_attributable_threadtime_format():
    from mobileag.dast.adb_manager import ADBManager
    adb = ADBManager()
    adb._exec_cmd = AsyncMock(return_value=(0, b'10-08 12:00:00.000 1234 1234 E App: safe', b''))
    await adb.get_logcat_dump('emulator-5554', filter_pkg='org.example.fixture', lines=7)
    command = adb._exec_cmd.await_args.args[0]
    assert command[command.index('logcat') + 1:command.index('logcat') + 3] == ['-v', 'threadtime']


@pytest.mark.asyncio
async def test_adb_install_defaults_are_non_granting_and_non_replacing(tmp_path):
    from mobileag.dast.adb_manager import ADBManager
    apk = tmp_path / 'fixture.apk'
    apk.write_bytes(b'synthetic')
    adb = ADBManager()
    adb._exec_cmd = AsyncMock(return_value=(0, b'Success', b''))
    await adb.install_apk('emulator-5554', apk)
    command = adb._exec_cmd.await_args.args[0]
    assert command[:3] == ['-s', 'emulator-5554', 'install']
    assert '-g' not in command and '-r' not in command


@pytest.mark.asyncio
async def test_adb_target_logcat_uses_validated_exact_pid():
    from mobileag.dast.adb_manager import ADBManager
    adb = ADBManager()
    adb._exec_cmd = AsyncMock(return_value=(0, b'10-08 12:00:00.000 1234 1234 E App: safe', b''))
    await adb.get_logcat_dump('emulator-5554', pid=1234)
    assert '--pid=1234' in adb._exec_cmd.await_args.args[0]
    with pytest.raises(ValueError):
        await adb.get_logcat_dump('emulator-5554', pid=-1)


@pytest.mark.asyncio
async def test_process_pid_lookup_is_exact_and_bounded():
    from mobileag.dast.adb_manager import ADBManager
    adb = ADBManager()
    adb._exec_cmd = AsyncMock(return_value=(0, b'1234 2345 1234 invalid', b''))
    assert await adb.get_process_pids('emulator-5554', 'org.example.fixture') == [1234, 2345]
    with pytest.raises(ValueError):
        await adb.get_process_pids('emulator-5554', 'org.example;id')


def test_escaped_json_credential_redaction_preserves_json():
    source = json.dumps({'access_token': 'first"syntheticOpaqueCredential', 'public': 'keep'})
    result = redact(source)
    assert 'syntheticOpaqueCredential' not in result
    assert json.loads(result)['access_token'] == '[REDACTED]'


def test_provider_key_format_redaction():
    key = 'gsk_' + 'A' * 52
    assert key not in redact('Synthetic key: ' + key)


def test_traffic_patterns_are_candidates_not_confirmed_risk_scores():
    from mobileag.dast.traffic_auditor import TrafficAuditor
    items = TrafficAuditor().audit_transactions([
        HTTPTransaction(url='https://api.fixture.invalid/users/123', response_headers={}),
        HTTPTransaction(url='https://api.fixture.invalid/', response_headers={
            'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'})])
    assert items
    assert all(f.status.value == 'UNVERIFIED' and f.cvss_score == 0 for f in items)
    bola = next(f for f in items if 'Numeric Resource Identifier' in f.title)
    assert 'does not demonstrate' in bola.description
    cors = next(f for f in items if 'CORS Wildcard' in f.title)
    assert 'not proof' in cors.description


def test_dynamic_cookie_review_flags_only_likely_session_cookies_and_redacts_values():
    from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor
    risky = TrafficAuditor().audit_transactions([HTTPTransaction(
        url='https://api.fixture.invalid/account', response_headers={
            'Set-Cookie': 'session_id=syntheticCookieSecret; Path=/',
            'Cache-Control': 'no-store',
            'Strict-Transport-Security': 'max-age=31536000'})])
    cookie_findings = [f for f in risky if f.title.startswith('Session Cookie Attribute Review:')]
    assert len(cookie_findings) == 1
    finding = cookie_findings[0]
    assert finding.status.value == 'UNVERIFIED' and finding.cvss_score == 0
    assert 'Secure' in finding.description and 'HttpOnly' in finding.description
    assert 'syntheticCookieSecret' not in repr(finding.to_dict())

    safe = TrafficAuditor().audit_transactions([HTTPTransaction(
        url='https://api.fixture.invalid/account', response_headers={
            'Set-Cookie': 'session_id=synthetic; Path=/; Secure; HttpOnly; SameSite=Lax',
            'Cache-Control': 'no-store',
            'Strict-Transport-Security': 'max-age=31536000'})])
    assert safe == []


@pytest.mark.asyncio
@pytest.mark.parametrize('scenario', ['stale', 'other_process', 'launch_failed', 'new_target'])
async def test_intent_crash_requires_fresh_target_evidence(monkeypatch, scenario):
    import mobileag.dast.intent_fuzzer as module
    monkeypatch.setattr(module, 'asyncio', SimpleNamespace(sleep=AsyncMock()))
    before = [FATAL, TARGET] if scenario == 'stale' else []
    after = [FATAL, TARGET.replace('org.example.fixture', 'org.other.fixture')] if scenario == 'other_process' else [FATAL, TARGET]
    adb = SimpleNamespace(_exec_cmd=AsyncMock(return_value=(1 if scenario == 'launch_failed' else 0, b'synthetic launch', b'')),
                          get_logcat_dump=AsyncMock(side_effect=[before, after]))
    result = await IntentFuzzer(adb=adb).exercise_component('synthetic', 'org.example.fixture', '.Entry')
    assert result['crashed'] is (scenario == 'new_target')
    if result['findings']:
        assert all(f.cvss_score == 0 and f.status.value == 'UNVERIFIED' for f in result['findings'])


@pytest.mark.asyncio
async def test_intent_revocation_during_baseline_blocks_launch(monkeypatch):
    valid = True
    async def baseline(*args, **kwargs):
        nonlocal valid
        valid = False
        return []
    def guard():
        if not valid:
            raise PermissionError('Synthetic revocation')
    adb = SimpleNamespace(_exec_cmd=AsyncMock(), get_logcat_dump=AsyncMock(side_effect=baseline))
    with pytest.raises(PermissionError):
        await IntentFuzzer(adb=adb).exercise_component('synthetic', 'org.example.fixture', '.Entry', guard=guard)
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_provider_approval_does_not_authorize_arbitrary_authority():
    adb = SimpleNamespace(_exec_cmd=AsyncMock(return_value=(0, b'Row: synthetic data', b'')))
    with pytest.raises(PermissionError):
        await ProviderAuditor(adb).audit_providers('emulator-5554', 'com.example', ['org.other.provider'])
    adb._exec_cmd.assert_not_awaited()
