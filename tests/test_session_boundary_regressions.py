"""Synthetic request/validation suspension points; no target/device/provider calls."""
import asyncio
import importlib
import json
import zipfile
from unittest.mock import AsyncMock

import httpx
import pytest

from mobileag.assessments.models import Assessment
from mobileag.assessments.service import AssessmentService
from mobileag.llm.broker import LLMBroker

web = importlib.import_module('mobileag.web.app')
PKG = 'org.example.synthetic'


def fixture_service(monkeypatch):
    apk = web.UPLOAD_DIR / 'session-fixture.apk'
    with zipfile.ZipFile(apk, 'w') as archive:
        archive.writestr('AndroidManifest.xml', f'<manifest package="{PKG}"/>')
    request = Assessment(
        apk_path=str(apk), package_name=PKG,
        scope={'devices': [], 'packages': [PKG], 'origins': [], 'methods': ['GET'], 'actions': []},
        authorized=True, scope_change_confirmed=True, confirmation='START SCOPED TESTS',
    )
    static = AsyncMock(return_value={'scan_id': 'synthetic', 'status': 'completed', 'package_name': PKG})
    service = AssessmentService(
        lambda: web.OUTPUT_DIR, lambda: web.UPLOAD_DIR, web.repository,
        lambda token: token == web.app.state.auth_token,
        static, lambda: None, web.adb_manager, LLMBroker(AsyncMock()), web.hash_file,
    )
    monkeypatch.setattr(web.app.state, 'assessment_service', service, raising=False)
    return service, request


@pytest.mark.parametrize('path', ['/api/scope', '/api/assessments', '/api/automation/runs', '/api/dast/launch'])
@pytest.mark.parametrize('revocation', ['rotate', 'expire'])
@pytest.mark.asyncio
async def test_body_delivered_after_rotation_cannot_mutate_or_start(path, revocation, monkeypatch):
    service, request = fixture_service(monkeypatch)
    before = web.repository().get_policy()
    old_token = web.app.state.auth_token
    monkeypatch.setattr(web.app.state, 'session_deadline', web.app.state.session_deadline)
    payload = request.model_dump(mode='json') if path == '/api/assessments' else (
        {'serial': 'emulator-5554', 'package_name': PKG, 'component': PKG + '/.Main',
         'environment': 'synthetic', 'dedicated_device_confirmed': True, 'dedicated_account_confirmed': True}
        if path == '/api/automation/runs' else
        {'serial': 'emulator-5554', 'component': PKG + '/.Main'} if path == '/api/dast/launch' else request.scope.model_dump()
    )
    automation = AsyncMock()
    automation.create.return_value = {}
    monkeypatch.setattr(web.app.state, 'automation_service', automation, raising=False)

    async def delayed_body():
        # Headers have already passed middleware authentication when ASGI asks
        # the transport for this body. Rotate through the actual auth route.
        if revocation == 'rotate':
            monkeypatch.setattr(web.app.state, 'auth_token', 'synthetic-rotated-token')
        else:
            monkeypatch.setattr(web.app.state, 'session_deadline', 0)
        yield json.dumps(payload).encode()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=web.app), base_url='http://testserver') as client:
        response = await client.post(path, headers={'Authorization': 'Bearer ' + old_token, 'Content-Type': 'application/json'}, content=delayed_body())
    # Drain any pre-fix task before asserting so failed probes leave no work.
    if service.tasks:
        await asyncio.gather(*list(service.tasks.values()))
    assert response.status_code == 401
    assert web.repository().get_policy() == before
    assert service.store().list() == []
    service.static_runner.assert_not_called()
    automation.create.assert_not_called()
    web.adb_manager._exec_cmd.assert_not_called()


@pytest.mark.asyncio
async def test_rotation_during_create_hash_cannot_save_policy(monkeypatch):
    service, request = fixture_service(monkeypatch)
    before = web.repository().get_policy()
    token = web.app.state.auth_token
    original = asyncio.to_thread

    async def rotate_at_hash(fn, *args, **kwargs):
        if fn is service.hash_file:
            monkeypatch.setattr(web.app.state, 'auth_token', 'synthetic-rotated-token')
        return await original(fn, *args, **kwargs)

    monkeypatch.setattr(asyncio, 'to_thread', rotate_at_hash)
    try:
        with pytest.raises(PermissionError):
            await service.create(request, token)
    finally:
        if service.tasks:
            await asyncio.gather(*list(service.tasks.values()))
    assert web.repository().get_policy() == before
    assert service.store().list() == []
    service.static_runner.assert_not_called()


@pytest.mark.parametrize('boundary', ['cancel', 'rotate'])
@pytest.mark.parametrize('phase', ['pre_static', 'post_static'])
@pytest.mark.asyncio
async def test_cancel_or_rotation_during_pre_static_hash_blocks_worker(boundary, phase, monkeypatch):
    service, request = fixture_service(monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()
    original = asyncio.to_thread
    hash_calls = 0

    async def pause_run_hash(fn, *args, **kwargs):
        nonlocal hash_calls
        if fn is service.hash_file:
            hash_calls += 1
            if hash_calls == (2 if phase == 'pre_static' else 3):
                entered.set()
                await release.wait()
        return await original(fn, *args, **kwargs)

    monkeypatch.setattr(asyncio, 'to_thread', pause_run_hash)
    doc = await service.create(request, web.app.state.auth_token)
    task = service.tasks[doc['id']]
    await asyncio.wait_for(entered.wait(), 5)
    if boundary == 'cancel':
        service.cancel(doc['id'])
    else:
        monkeypatch.setattr(web.app.state, 'auth_token', 'synthetic-rotated-token')
    release.set()
    await task
    result = service.store().get(doc['id'])
    assert result['status'] == ('cancelled' if boundary == 'cancel' else 'paused')
    if phase == 'pre_static':
        service.static_runner.assert_not_called()
        assert result['stages']['sast']['status'] == 'not_executed'
    else:
        service.static_runner.assert_awaited_once()
        assert result['stages']['sast']['status'] == 'completed'


@pytest.mark.asyncio
async def test_current_token_streamed_scope_save_remains_supported():
    payload = {'devices': [], 'packages': [PKG], 'origins': [], 'methods': ['GET'], 'actions': []}
    body = json.dumps(payload).encode()
    async def chunks():
        yield body[:10]
        await asyncio.sleep(0)
        yield body[10:]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=web.app), base_url='http://testserver') as client:
        response = await client.post('/api/scope', headers={'Authorization': 'Bearer ' + web.app.state.auth_token,
                                    'Content-Type': 'application/json'}, content=chunks())
    assert response.status_code == 200
    assert web.repository().get_policy() == payload
