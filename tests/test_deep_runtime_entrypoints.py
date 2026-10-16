"""Mock-only negative controls for the legacy DAST orchestration entrypoint."""
import importlib
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient

web = importlib.import_module('mobileag.web.app')


def runtime_mocks(monkeypatch):
    devices = AsyncMock(return_value=[])
    discover = AsyncMock(return_value=[])
    fuzz = AsyncMock(return_value=([], []))
    monkeypatch.setattr(web.adb_manager, 'list_devices', devices)
    monkeypatch.setattr(web.adb_manager, 'discover_devices', discover)
    monkeypatch.setattr(web.intent_fuzzer, 'fuzz_activity_intents', fuzz)
    monkeypatch.setattr(web.storage_auditor, 'audit_all_storage', AsyncMock(return_value={'findings': []}))
    monkeypatch.setattr(web.memory_auditor, 'run_memory_audit', AsyncMock(return_value={'findings': []}))
    return devices, discover, fuzz


def test_legacy_dast_revocation_before_background_stops_device_work(monkeypatch):
    devices, discover, fuzz = runtime_mocks(monkeypatch)
    token = web.app.state.auth_token
    rotated = False

    async def broadcast(_):
        nonlocal rotated
        if not rotated:
            rotated = True
            web.app.state.auth_token = 'synthetic-rotated-token'

    monkeypatch.setattr(web.manager, 'broadcast', broadcast)
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + token})
    response = client.post('/api/dast/fuzz', json={
        'serial': 'emulator-5554', 'package_name': 'com.example',
        'audit_storage': False, 'audit_memory': False,
        'synthetic_data_confirmed': True,
    })
    assert response.status_code == 200
    devices.assert_not_awaited()
    discover.assert_not_awaited()
    fuzz.assert_not_awaited()


def test_legacy_dast_fuzz_permission_does_not_grant_storage_memory(monkeypatch):
    _, _, fuzz = runtime_mocks(monkeypatch)
    policy = web.repository().get_policy()
    policy['actions'] = ['fuzz']
    web.repository().save_policy(policy)
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + web.app.state.auth_token})
    response = client.post('/api/dast/fuzz', json={
        'serial': 'emulator-5554', 'package_name': 'com.example',
        'audit_storage': True, 'audit_memory': True,
    })
    assert response.status_code == 403
    fuzz.assert_not_awaited()
