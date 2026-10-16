"""Synthetic runtime observations; no device commands or exploit claims."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
import importlib
from urllib.parse import urlsplit,parse_qs
import pytest
from mobileag.dast.runtime_evidence import new_lines,attributed_crashes
from mobileag.dast.deeplink_fuzzer import DeepLinkFuzzer
from mobileag.reporting.finding import FindingStatus

FATAL='10-07 12:00:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main'
TARGET='10-07 12:00:00.001 1234 1234 E AndroidRuntime: Process: org.example.fixture, PID: 1234'


def test_only_new_matching_target_pid_is_attributed():
    assert attributed_crashes([FATAL,TARGET],'org.example.fixture')==[FATAL]
    assert attributed_crashes([FATAL,TARGET.replace('org.example.fixture','org.example.fixtureevil')],'org.example.fixture')==[]
    assert attributed_crashes([FATAL,TARGET.replace('1234','4321')],'org.example.fixture')==[]
    assert attributed_crashes(['AndroidRuntime normal message',TARGET],'org.example.fixture')==[]
    assert new_lines([FATAL,TARGET],[FATAL,TARGET])==[]
    assert new_lines(['x'],['x','x'])==['x']


def test_synthetic_payloads_preserve_approved_route_no_external_callback_or_real_secrets():
    payloads=DeepLinkFuzzer().generate_fuzz_payloads('fixture://route/profile?existing=synthetic#section','org.example.fixture')
    assert len(payloads)==5
    for payload in payloads:
        parsed=urlsplit(payload['uri'])
        assert parsed.scheme=='fixture' and parsed.netloc=='route' and parsed.path=='/profile' and parsed.fragment=='section'
        assert parse_qs(parsed.query)['existing']==['synthetic']
        assert all(value not in payload['uri'] for value in ('attacker.evil','user_session','is_admin','role=admin','alert('))
    with pytest.raises(ValueError):DeepLinkFuzzer().generate_fuzz_payloads('no-scheme','org.example.fixture')


@pytest.mark.parametrize('scenario',['new_target','stale_target','other_process','string_only','launch_failed'])
@pytest.mark.asyncio
async def test_link_diagnostics_do_not_invent_proof(monkeypatch,scenario):
    module=importlib.import_module('mobileag.dast.deeplink_fuzzer')
    monkeypatch.setattr(module,'asyncio',SimpleNamespace(sleep=AsyncMock()))
    after=[FATAL,TARGET]
    before=[]
    if scenario=='stale_target':before=after
    elif scenario=='other_process':after=[FATAL,TARGET.replace('org.example.fixture','org.other.fixture')]
    elif scenario=='string_only':after=['WebView saw javascript: marker','file:// shared_prefs marker']
    adb=SimpleNamespace(_exec_cmd=AsyncMock(return_value=(1 if scenario=='launch_failed' else 0,b'synthetic launch',b'')),get_logcat_dump=AsyncMock(side_effect=[before,after]))
    fuzzer=DeepLinkFuzzer(adb)
    monkeypatch.setattr(fuzzer,'generate_fuzz_payloads',lambda *args:[{'uri':'fixture://route?token=synthetic-private','category':'fixture','cwe':'CWE-755'}])
    rows,findings=await fuzzer.fuzz_deep_links(
        'synthetic-serial','org.example.fixture',['fixture://route?token=synthetic-private'],guard=lambda: None,
    )
    assert rows[0]['proof_state']=='not_proven' and rows[0]['attacker_context']=='adb_shell_diagnostic'
    assert 'synthetic-private' not in str(rows)+str(findings)
    assert bool(findings)==(scenario=='new_target')
    if findings:assert findings[0].status==FindingStatus.UNVERIFIED and findings[0].cvss_score==0
    assert not any('logcat' in call.args[0] and '-c' in call.args[0] for call in adb._exec_cmd.await_args_list)


@pytest.mark.asyncio
async def test_revocation_during_baseline_blocks_launch(monkeypatch):
    adb=SimpleNamespace(_exec_cmd=AsyncMock(),get_logcat_dump=AsyncMock(return_value=[]))
    valid=True
    async def revoke(*args,**kwargs):
        nonlocal valid
        valid=False
        return []
    adb.get_logcat_dump.side_effect=revoke
    def guard():
        if not valid:raise PermissionError('synthetic revoked')
    with pytest.raises(PermissionError):await DeepLinkFuzzer(adb).exercise_deep_link('synthetic','org.example.fixture','fixture://route',guard=guard)
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_false_scope_guard_blocks_before_baseline():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    adb = SimpleNamespace(_exec_cmd=AsyncMock(), get_logcat_dump=AsyncMock())
    with pytest.raises(PermissionError):
        await DeepLinkFuzzer(adb).exercise_deep_link(
            'synthetic-serial', 'org.example.fixture', 'fixture://route',
            guard=lambda: False,
        )
    adb.get_logcat_dump.assert_not_awaited()
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_denial_after_baseline_blocks_deep_link_launch():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    adb = SimpleNamespace(
        _exec_cmd=AsyncMock(), get_logcat_dump=AsyncMock(return_value=[]),
    )
    checks = 0

    def revoke_after_baseline():
        nonlocal checks
        checks += 1
        return checks < 2

    with pytest.raises(PermissionError):
        await DeepLinkFuzzer(adb).exercise_deep_link(
            'synthetic-serial', 'org.example.fixture', 'fixture://route',
            guard=revoke_after_baseline,
        )
    adb.get_logcat_dump.assert_awaited_once()
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_ui_hierarchy_explicit_denial_prevents_device_commands():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from mobileag.dast.ui_crawler import UICrawler

    adb = SimpleNamespace(_exec_cmd=AsyncMock())
    with pytest.raises(PermissionError):
        await UICrawler(adb).dump_ui_hierarchy('synthetic-serial', guard=lambda: False)
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_ui_hierarchy_revocation_stops_read_and_cleanup_commands():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from mobileag.dast.ui_crawler import UICrawler

    adb = SimpleNamespace(_exec_cmd=AsyncMock(return_value=(0, b'', b'')))
    checks = 0

    def revoke_after_dump():
        nonlocal checks
        checks += 1
        return checks < 2

    with pytest.raises(PermissionError):
        await UICrawler(adb).dump_ui_hierarchy(
            'synthetic-serial', guard=revoke_after_dump,
        )
    adb._exec_cmd.assert_awaited_once()
    assert adb._exec_cmd.await_args.args[0][3:5] == ['uiautomator', 'dump']


@pytest.mark.asyncio
async def test_ui_crawl_reports_explicit_scope_denial_without_adb():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from mobileag.dast.ui_crawler import UICrawler

    adb = SimpleNamespace(_exec_cmd=AsyncMock())
    report = await UICrawler(adb).crawl_app(
        'synthetic-serial', 'org.example.fixture', guard=lambda: False,
    )
    assert report['status'] == 'blocked'
    adb._exec_cmd.assert_not_awaited()
