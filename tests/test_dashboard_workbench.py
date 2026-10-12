"""Dashboard read workbench, mocked self-transport and synthetic session only."""
import importlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from mobileag.dashboard.client import DashboardError
from mobileag.dashboard.routes import server_origin

web = importlib.import_module('mobileag.web.app')


def client():
    return TestClient(web.app, base_url='http://127.0.0.1:8099',
                      headers={'Authorization': 'Bearer ' + web.app.state.auth_token})


@pytest.mark.parametrize('server,expected', [(('127.0.0.1',8099),'http://127.0.0.1:8099'),
    (('0.0.0.0',8080),'http://127.0.0.1:8080'),(('::',8080),'http://[::1]:8080')])
def test_listening_socket_not_host_selects_self_origin(server, expected):
    request = Request({'type':'http','scheme':'http','server':server,
                       'headers':[(b'host',b'127.0.0.1:9999')]})
    assert server_origin(request) == expected


@pytest.mark.parametrize('server', [None, ('example.invalid',80), ('127.0.0.1',0), ('127.0.0.1',True)])
def test_ambiguous_nonlocal_socket_rejected(server):
    with pytest.raises(DashboardError):
        server_origin(Request({'type':'http','scheme':'http','server':server,'headers':[]}))


@pytest.mark.parametrize('transport', ['httpx','curl'])
def test_workbench_uses_current_token_trusted_port_and_allowlisted_get(transport):
    with patch('mobileag.dashboard.routes.DashboardClient') as factory:
        factory.return_value.get.return_value={'path':'/api/status','status_code':200,'transport':transport,'data':{'status':'online'}}
        response = client().post('/api/dashboard/read', json={'path':'/api/status','transport':transport},
                                 headers={'Host':'127.0.0.1:9001'})
    assert response.status_code == 200
    factory.assert_called_once_with('http://127.0.0.1:8099',web.app.state.auth_token)
    factory.return_value.get.assert_called_once_with('/api/status',transport)
    assert response.json()['writes_authorized'] is False
    assert web.app.state.auth_token not in response.text


@pytest.mark.parametrize('path', ['https://example.invalid', '/api/dast/logcat?serial=test',
    '/api/session/logout', '/api/scans/run', '/api/dashboard/read'])
def test_workbench_cannot_execute_generic_urls_shell_or_device_paths(path):
    with patch('mobileag.dashboard.routes.DashboardClient') as factory:
        response=client().post('/api/dashboard/read',json={'path':path,'transport':'curl'})
    assert response.status_code == 422
    factory.assert_not_called()


def test_invalid_payload_and_raw_transport_errors_do_not_echo_secrets():
    secret='synthetic-private-not-to-echo'
    response=client().post('/api/dashboard/read',json={'path':'/api/status','command':secret})
    assert response.status_code == 422 and secret not in response.text
    with patch('mobileag.dashboard.routes.DashboardClient') as factory:
        factory.return_value.get.side_effect=DashboardError(secret)
        response=client().post('/api/dashboard/read',json={'path':'/api/status'})
    assert response.status_code == 422 and secret not in response.text


def test_rotated_session_cannot_return_cached_read_data(monkeypatch):
    def rotate(*args):
        monkeypatch.setattr(web.app.state,'auth_token','synthetic-replacement-token')
        return {'status_code':200,'data':{'private':'synthetic-private-not-to-return'}}
    with patch('mobileag.dashboard.routes.DashboardClient') as factory:
        factory.return_value.get.side_effect=rotate
        response=client().post('/api/dashboard/read',json={'path':'/api/status'})
    assert response.status_code == 401
    assert 'synthetic-private-not-to-return' not in response.text


def test_capabilities_require_auth_and_do_not_execute_transport():
    with patch('mobileag.dashboard.routes.DashboardClient') as factory:
        response=client().get('/api/dashboard/capabilities')
    assert response.status_code == 200 and response.json()['read_only']
    factory.assert_not_called()
    assert TestClient(web.app).get('/api/dashboard/capabilities').status_code == 401


@pytest.mark.asyncio
async def test_cancelled_caller_does_not_free_live_worker_capacity():
    import asyncio
    import threading
    import httpx
    release=threading.Event()
    calls=[]
    def blocked(*args):
        calls.append('issued')
        release.wait(timeout=5)
        return {'status_code':200,'transport':'httpx','data':{'status':'online'}}
    headers={'Authorization':'Bearer '+web.app.state.auth_token}
    with patch('mobileag.dashboard.routes.DashboardClient') as factory:
        factory.return_value.get.side_effect=blocked
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=web.app),base_url='http://127.0.0.1:8099',headers=headers) as http:
            first=asyncio.create_task(http.post('/api/dashboard/read',json={'path':'/api/status'}))
            second=asyncio.create_task(http.post('/api/dashboard/read',json={'path':'/api/status'}))
            try:
                for _ in range(100):
                    if len(calls)==2:break
                    await asyncio.sleep(.01)
                assert len(calls)==2
                assert (await http.post('/api/dashboard/read',json={'path':'/api/status'})).status_code==409
                first.cancel()
                with pytest.raises(asyncio.CancelledError):await first
                assert (await http.post('/api/dashboard/read',json={'path':'/api/status'})).status_code==409
                assert len(calls)==2
            finally:
                release.set()
                if not first.done():first.cancel()
                await asyncio.gather(first,second,return_exceptions=True)
                # Shielded workers release their slots in the owner loop.
                await asyncio.sleep(.05)
