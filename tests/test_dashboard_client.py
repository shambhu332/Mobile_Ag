"""Local dashboard access, mocked transports; no mobile/device actions."""
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner

from mobileag.dashboard.client import DashboardClient, DashboardError, local_origin, safe_endpoint
from mobileag.dashboard.commands import dashboard
from mobileag.dashboard.navigator import permitted_request

TOKEN = 'synthetic-dashboard-token-only'


@pytest.mark.parametrize('url', ['https://example.invalid', 'http://127.0.0.2', 'http://127.0.0.1@evil.invalid',
    'http://token@127.0.0.1', 'http://127.0.0.1/path', 'http://127.0.0.1/?token=secret',
    'http://127.0.0.1/#token', 'file:///tmp/local', 'http://127.0.0.1:bad'])
def test_remote_ambiguous_or_credential_origins_rejected(url):
    with pytest.raises(DashboardError): local_origin(url)


def test_localhost_is_numeric_pinned_and_ipv6_is_explicit():
    assert local_origin('http://localhost:8080/') == 'http://127.0.0.1:8080'
    assert local_origin('http://[::1]:8080') == 'http://[::1]:8080'


@pytest.mark.parametrize('path', ['/api/dast/logcat', '/api/dast/frida/status?serial=test',
    '/api/apis/test', '/api/scans/run', '/api/settings?token=secret', '//evil.invalid/api/status',
    '/api/../status', '/api/%73tatus', '/api/status#token', '/api/status?anything=x',
    '/api/scans?limit=101', '/api/scans?limit=1&limit=2', '/api/status\n'])
def test_device_write_sensitive_or_ambiguous_endpoints_rejected(path):
    assert not safe_endpoint(path)


def test_bounded_http_read_removes_reflected_token_and_secret_fields():
    def handler(request):
        assert request.url.host == '127.0.0.1'
        assert request.headers['Authorization'] == 'Bearer ' + TOKEN
        return httpx.Response(200, json={'note': TOKEN, 'access_token': 'another-secret', 'data': [TOKEN]})
    result = DashboardClient('http://localhost:8080', TOKEN, httpx.MockTransport(handler)).get()
    assert TOKEN not in json.dumps(result)
    assert 'another-secret' not in json.dumps(result)


@pytest.mark.parametrize('status', [302, 307, 401, 403, 500])
def test_no_redirect_or_error_body_echo(status):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(status, headers={'Location': 'https://evil.invalid'}, json={'detail': TOKEN})
    with pytest.raises(DashboardError) as error:
        DashboardClient('http://127.0.0.1:8080', TOKEN, httpx.MockTransport(handler)).get()
    assert TOKEN not in str(error.value)
    assert len(requests) == 1


def test_http_response_budget_fails_closed():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b'x'*1048577))
    with pytest.raises(DashboardError, match='budget'):
        DashboardClient('http://127.0.0.1:8080', TOKEN, transport).get()


def test_curl_uses_stdin_not_argv_shell_files_or_environment():
    def fake_run(argv, **kwargs):
        assert 'curl' == argv[0] and argv[1] == '--disable'
        assert TOKEN not in ' '.join(argv)
        assert kwargs['input'].count(TOKEN) == 1
        assert TOKEN not in json.dumps(kwargs['env'])
        assert not kwargs.get('shell')
        assert '--noproxy' in argv and '--max-redirs' in argv
        return SimpleNamespace(returncode=0, stdout=json.dumps({'note': TOKEN})+'\n200')
    with patch('mobileag.dashboard.client.subprocess.run', side_effect=fake_run):
        result = DashboardClient('http://127.0.0.1:8080', TOKEN).get(backend='curl')
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize('failure', [FileNotFoundError(TOKEN), subprocess.TimeoutExpired('curl', 12)])
def test_curl_failures_do_not_echo_sensitive_raw_exception(failure):
    with patch('mobileag.dashboard.client.subprocess.run', side_effect=failure):
        with pytest.raises(DashboardError) as error:
            DashboardClient('http://127.0.0.1:8080', TOKEN).get(backend='curl')
    assert TOKEN not in str(error.value)


def test_browser_policy_blocks_external_writes_and_device_gets():
    origin = 'http://127.0.0.1:8080'
    assert permitted_request(origin, origin+'/api/scans?limit=1&summaries=true', 'GET')
    assert permitted_request(origin, origin+'/static/workspace.js', 'GET')
    assert permitted_request(origin, origin+'/api/scans/scan_synthetic/resilience', 'GET')
    assert permitted_request(origin, origin+'/api/scans/scan_synthetic/test-plan', 'GET')
    assert permitted_request(origin, origin+'/api/scans/scan_synthetic/findings/synthetic-finding/poc', 'GET')
    for url, method in [(origin+'/api/scans/run', 'POST'), (origin+'/api/settings', 'PUT'),
                        ('https://evil.invalid/', 'GET'), (origin+'/api/dast/logcat?serial=test', 'GET'),
                        (origin+'/api/scans/scan_synthetic/findings/synthetic-finding/feedback', 'GET')]:
        assert not permitted_request(origin, url, method)


def test_cli_environment_connection_never_echoes_token(monkeypatch):
    monkeypatch.setenv('MOBILEAG_API_TOKEN', TOKEN)
    with patch.object(DashboardClient, 'get', return_value={'status_code': 200, 'data': {'status': 'ok'}}):
        result = CliRunner().invoke(dashboard, ['api'])
    assert result.exit_code == 0 and TOKEN not in result.output
    assert json.loads(result.output)['status_code'] == 200


def test_cli_private_prompt_used_when_no_environment_token(monkeypatch):
    monkeypatch.delenv('MOBILEAG_API_TOKEN', raising=False)
    with patch.object(DashboardClient, 'get', return_value={'status_code': 200}):
        result = CliRunner().invoke(dashboard, ['api'], input=TOKEN+'\n')
    assert result.exit_code == 0 and TOKEN not in result.output


def test_browser_redirect_rejected_before_following_chain():
    from mobileag.dashboard.navigator import read_only_route
    from unittest.mock import Mock
    route = Mock()
    route.request.url = 'http://127.0.0.1:8080/api/status'
    route.request.method = 'GET'
    response = route.fetch.return_value
    response.status = 302
    blocked = []
    read_only_route('http://127.0.0.1:8080', blocked, route)
    route.fetch.assert_called_once_with(max_redirects=0, timeout=10000)
    route.abort.assert_called_once()
    route.fulfill.assert_not_called()
    response.dispose.assert_called_once()
    assert blocked == [{'kind': 'redirect', 'method': 'GET'}]


def test_browser_write_blocked_before_transport():
    from mobileag.dashboard.navigator import read_only_route
    from unittest.mock import Mock
    route = Mock()
    route.request.url = 'http://127.0.0.1:8080/api/scans/run'
    route.request.method = 'POST'
    blocked = []
    read_only_route('http://127.0.0.1:8080', blocked, route)
    route.fetch.assert_not_called()
    route.abort.assert_called_once()
