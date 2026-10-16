"""Synthetic-only auto-preflight and status-route boundary regressions."""
import importlib
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from mobileag.dast.adb_manager import ADBManager, ConnectedDevice

web = importlib.import_module('mobileag.web.app')


@pytest.fixture
def client():
    return TestClient(web.app, headers={'Authorization': 'Bearer ' + web.app.state.auth_token})


@pytest.mark.asyncio
async def test_discovery_never_probes_or_selects_device(monkeypatch):
    manager = ADBManager()
    execute = AsyncMock(return_value=(0, b'List of devices attached\nemulator-5554 device model:Synthetic\nother unauthorized\noffline-id offline\n', b''))
    monkeypatch.setattr(manager, '_exec_cmd', execute)
    details = AsyncMock(side_effect=AssertionError('Device shell must not be used'))
    monkeypatch.setattr(manager, '_get_device_details', details)
    devices = await manager.discover_devices()
    assert [(device.serial, device.status) for device in devices] == [('emulator-5554', 'device'), ('other', 'unauthorized'), ('offline-id', 'offline')]
    assert devices[0].model == 'Synthetic'
    assert all(not device.is_rooted and device.android_version == 'Unknown' for device in devices)
    execute.assert_awaited_once_with(['devices', '-l'], timeout=3.0, output_limit=65536)
    details.assert_not_called()


@pytest.mark.asyncio
async def test_discovery_bounded_deduplicated_and_failed_unknown(monkeypatch):
    manager = ADBManager()
    execute = AsyncMock(return_value=(0, ('List of devices attached\n-s device\n' + ''.join(f'd{i} device\nd{i} device\n' for i in range(150))).encode(), b''))
    monkeypatch.setattr(manager, '_exec_cmd', execute)
    devices = await manager.discover_devices()
    assert len(devices) == 100 and all(device.serial != '-s' for device in devices)
    execute.return_value = (-1, b'', b'private diagnostic text')
    with pytest.raises(ValueError, match='^ADB inventory unavailable$'):
        await manager.discover_devices()


def mock_preflight(monkeypatch):
    host = AsyncMock(return_value={'sandbox_probe': True, 'android_tools': {'jadx': True, 'apktool': True}})
    monkeypatch.setattr(web, 'get_readiness', host)
    monkeypatch.setattr(web.adb_manager, 'is_adb_available', AsyncMock(return_value=True))
    inventory = AsyncMock(return_value=[ConnectedDevice('emulator-5554', 'device'), ConnectedDevice('outside-scope', 'device'), ConnectedDevice('offline-id', 'offline')])
    monkeypatch.setattr(web.adb_manager, 'discover_devices', inventory)
    return host, inventory


def test_preflight_is_authenticated_local_only_no_mutations(client, monkeypatch):
    host, inventory = mock_preflight(monkeypatch)
    shell = web.adb_manager._exec_cmd
    policy = web.repository().get_policy()
    jobs = dict(web.ACTIVE_SCANS)
    response = client.get('/api/preflight')
    assert response.status_code == 200
    data = response.json()
    assert data['host']['sandbox_probe'] and data['devices']['inventory_state'] == 'checked'
    assert data['device_selection'] == 'explicit_only'
    assert data['target_testing_started'] is False and data['model_contacted'] is False
    assert data['devices']['devices'][0]['root_checked'] is False
    assert data['devices']['devices'][1]['allowed'] is False
    assert all('api_key' not in provider for provider in data['providers']['providers'])
    assert web.repository().get_policy() == policy and web.ACTIVE_SCANS == jobs
    shell.assert_not_awaited()
    host.assert_awaited_once(); inventory.assert_awaited_once()
    host.reset_mock(); inventory.reset_mock()
    assert TestClient(web.app).get('/api/preflight').status_code == 401
    host.assert_not_awaited(); inventory.assert_not_awaited()


def test_preflight_rechecks_session_after_await(client, monkeypatch):
    mock_preflight(monkeypatch)
    async def revoke():
        monkeypatch.setattr(web.app.state, 'auth_token', 'synthetic-replacement')
        return {'sandbox_probe': True}
    monkeypatch.setattr(web, 'get_readiness', revoke)
    assert client.get('/api/preflight').status_code == 401


def test_inventory_error_not_empty_success(client, monkeypatch):
    monkeypatch.setattr(web.adb_manager, 'is_adb_available', AsyncMock(return_value=True))
    monkeypatch.setattr(web.adb_manager, 'discover_devices', AsyncMock(side_effect=ValueError('private failure')))
    data = client.get('/api/dast/devices').json()
    assert data['inventory_state'] == 'unknown' and data['devices'] == []
    assert 'private failure' not in str(data)


@pytest.mark.parametrize('code,output,state', [(0,b'USER PID NAME\nshell 23 frida-server\n','observed'),(0,b'shell 23 not-frida-server\n','not_observed'),(-1,b'','unknown')])
def test_frida_status_read_only_not_attachment(client, monkeypatch, code, output, state):
    execute = AsyncMock(return_value=(code, output, b'private stderr'))
    monkeypatch.setattr(ADBManager, '_exec_cmd', execute)
    attach = AsyncMock(side_effect=AssertionError('No attach permitted'))
    monkeypatch.setattr(web.frida_runner, 'execute_script_payload', attach)
    response = client.get('/api/dast/frida/status?serial=emulator-5554')
    assert response.status_code == 200
    data = response.json()
    assert data['process_state'] == state and not data['attach_verified']
    assert data['compatibility'] == 'not_checked' and not data['native_dependency']
    assert 'private stderr' not in response.text
    execute.assert_awaited_once_with(['-s','emulator-5554','shell','ps','-A'],timeout=4.0,output_limit=65536)
    attach.assert_not_awaited()


@pytest.mark.parametrize('condition', ['outside-device','action-not-approved','serial-option','unauthenticated'])
def test_frida_status_denies_before_commands(client, monkeypatch, condition):
    serial = 'emulator-5554'
    if condition == 'outside-device': serial = 'outside-scope'
    if condition == 'serial-option':
        serial = '-s'
        monkeypatch.setenv('MOBILEAG_ALLOWED_DEVICES','-s')
        web.repository().save_policy({'devices':['-s'],'packages':[], 'origins':[], 'methods':[], 'actions':['frida_status']})
    if condition == 'action-not-approved':
        policy = web.repository().get_policy(); policy['actions'] = []
        web.repository().save_policy(policy)
    if condition == 'unauthenticated': client = TestClient(web.app)
    assert client.get('/api/dast/frida/status', params={'serial':serial}).status_code in {401,403,422}
    web.adb_manager._exec_cmd.assert_not_awaited()


@pytest.mark.parametrize('revocation', ['session','scope','environment'])
def test_frida_status_rechecks_revocation_after_await(client, monkeypatch, revocation):
    async def revoke(*args, **kwargs):
        if revocation == 'session': monkeypatch.setattr(web.app.state,'auth_token','synthetic-replacement')
        elif revocation == 'scope': web.repository().save_policy({'devices':[], 'packages':[], 'origins':[], 'methods':[], 'actions':[]})
        else: monkeypatch.setenv('MOBILEAG_ALLOWED_DEVICES','')
        return 0,b'shell 3 frida-server\n',b''
    monkeypatch.setattr(ADBManager, '_exec_cmd', revoke)
    assert client.get('/api/dast/frida/status?serial=emulator-5554').status_code == (401 if revocation == 'session' else 403)


def test_frida_status_failure_sanitized(client, monkeypatch):
    monkeypatch.setattr(ADBManager,'_exec_cmd',AsyncMock(side_effect=RuntimeError('private synthetic marker')))
    response=client.get('/api/dast/frida/status?serial=emulator-5554')
    assert response.status_code==200 and response.json()['process_state']=='unknown'
    assert 'private synthetic marker' not in response.text


@pytest.mark.parametrize('preset', ['crypto','root_bypass','unpinning'])
def test_frida_preset_preview_is_disabled(client, monkeypatch, preset):
    attach=AsyncMock(side_effect=AssertionError('Disabled preview must not attach'))
    monkeypatch.setattr(web.frida_runner,'execute_script_payload',attach)
    response=client.get('/api/frida/presets/'+preset)
    assert response.status_code==410 and 'script' not in response.json()
    attach.assert_not_awaited(); web.adb_manager._exec_cmd.assert_not_awaited()
    assert client.get('/api/frida/presets/arbitrary').status_code==422
    assert TestClient(web.app).get('/api/frida/presets/'+preset).status_code==401


def test_inventory_rechecks_session_before_discovery(client, monkeypatch):
    inventory=AsyncMock()
    monkeypatch.setattr(web.adb_manager,'discover_devices',inventory)
    async def revoke():
        monkeypatch.setattr(web.app.state,'auth_token','synthetic-replacement')
        return True
    monkeypatch.setattr(web.adb_manager,'is_adb_available',revoke)
    assert client.get('/api/dast/devices').status_code==401
    inventory.assert_not_awaited()


def test_frida_status_without_saved_policy_denied(client):
    web.repository().save_policy({'devices':[], 'packages':[], 'origins':[], 'methods':[], 'actions':[]})
    assert client.get('/api/dast/frida/status?serial=emulator-5554').status_code==403
    web.adb_manager._exec_cmd.assert_not_awaited()
