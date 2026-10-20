"""Opt-in UI shell must never exempt data, uploads, origin, or host authorization."""
import importlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from mobileag.studio import enable_studio, PUBLIC_FILES


@pytest.fixture
def studio(monkeypatch):
    web = importlib.import_module('mobileag.web.app')
    monkeypatch.setattr(web.app.state, 'studio_enabled', False, raising=False)
    enable_studio(web.app)
    return TestClient(web.app, base_url='http://127.0.0.1'), web


@pytest.mark.parametrize('path', list(PUBLIC_FILES))
def test_only_fixed_assets_are_public(studio, path):
    client, web = studio
    response = client.get(path)
    assert response.status_code == 200
    assert web.app.state.auth_token not in response.text
    assert response.headers['x-frame-options'] == 'DENY'
    assert "script-src 'self'" in response.headers['content-security-policy']
    assert 'no-store' in response.headers['cache-control']
    assert 'set-cookie' not in response.headers
    assert client.head(path).status_code == 200
    assert client.post(path).status_code == 405


@pytest.mark.parametrize('path', ['/api/status','/api/scans','/api/scope','/api/settings',
                                  '/ui/unknown','/ui/assets/../../api/status'])
def test_ui_does_not_open_other_paths(studio,path):
    client, _ = studio
    assert client.get(path).status_code == 401


def test_root_and_legacy_static_are_not_the_old_demo_ui(studio):
    client, _ = studio
    root = client.get('/', follow_redirects=False)
    assert root.status_code == 307 and root.headers['location'] == '/ui'
    assert client.get('/static/app.js').status_code == 404


def test_ui_origin_and_host_checks(studio):
    client, _ = studio
    assert client.get('/ui',headers={'Host':'evil.example'}).status_code == 403
    assert client.get('/ui/app.js',headers={'Origin':'https://evil.example'}).status_code == 403
    assert client.post('/api/upload/apk').status_code == 401


def test_studio_disabled_preserves_api_only(studio):
    client, web = studio
    web.app.state.studio_enabled=False
    assert client.get('/ui').status_code == 404
    assert client.get('/ui',headers={'Authorization':'Bearer '+web.app.state.auth_token}).status_code == 404


def test_browser_no_persistent_secrets_or_html_injection():
    code=(Path(__file__).parents[1]/'mobileag/studio/assets/app.js').read_text()
    for forbidden in ('innerHTML','outerHTML','insertAdjacentHTML','localStorage','sessionStorage','eval('):
        assert forbidden not in code
    assert "credentials:'omit'" in code
    assert "auto_dast:false" in code
    assert 'state.epoch' in code and 'state.selection' in code


def test_expired_session_does_not_close_shell_or_open_api(studio, monkeypatch):
    client, web = studio
    monkeypatch.setattr(web.app.state, 'session_deadline', 0)
    assert client.get('/ui').status_code == 200
    assert client.get('/api/status', headers={'Authorization':'Bearer '+web.app.state.auth_token}).status_code == 401


def test_repeated_enable_does_not_duplicate_routes(studio):
    client, web = studio
    before = len(web.app.routes)
    enable_studio(web.app)
    assert len(web.app.routes) == before
