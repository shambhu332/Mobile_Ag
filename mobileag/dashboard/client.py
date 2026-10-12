"""Authenticated, read-only local dashboard HTTP/curl client.

No shell commands, redirects, proxy credentials, token URLs or durable session
state. These endpoints inspect dashboard state, not mobile targets. Preflight
can perform harmless local host/tool checks; it does not authorize execution.
"""
import json
import re
import subprocess
from urllib.parse import urlsplit, parse_qsl

import httpx

from mobileag.security.privacy import redact

MAX_RESPONSE = 1024 * 1024
SAFE_ENDPOINTS = frozenset({
    '/api/status', '/api/readiness', '/api/preflight', '/api/scope', '/api/dashboard/capabilities',
    '/api/settings', '/api/graph/status', '/api/agents', '/api/scans',
    '/api/assessments', '/api/assessments/providers', '/api/automation/capabilities',
    '/api/automation/runs', '/api/dast/devices',
})


class DashboardError(ValueError):
    """Deliberately bounded errors, never raw response/credential details."""


def local_origin(url):
    try:
        parsed = urlsplit(url)
        port = parsed.port
        if (parsed.scheme not in {'http', 'https'} or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {'', '/'} or parsed.query or parsed.fragment):
            raise ValueError()
        host = '[::1]' if parsed.hostname == '::1' else '127.0.0.1'
        # Pin localhost to a numeric loopback address; never resolve user DNS.
        return f'{parsed.scheme}://{host}' + (f':{port}' if port is not None else '')
    except (TypeError, ValueError):
        raise DashboardError('Use a loopback dashboard origin without credentials, path, query or fragment') from None


def safe_endpoint(path):
    if not isinstance(path, str) or len(path) > 2048 or '%' in path or '\\' in path or any(ord(c) <= 32 or ord(c) > 126 for c in path):
        return False
    try:
        parsed = urlsplit(path)
    except ValueError:
        return False
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    known = parsed.path in SAFE_ENDPOINTS or bool(re.fullmatch(
        r'/api/scans/scan_[A-Za-z0-9_-]+(?:/(?:graph|apis|sarif|decisions|retention))?', parsed.path))
    if not known:
        return False
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if parsed.query and parsed.path != '/api/scans':
        return False
    if len({key for key, _ in query}) != len(query):
        return False
    for key, value in query:
        if key == 'summaries' and value in {'true', 'false'}:
            continue
        if key not in {'offset', 'limit'} or not re.fullmatch(r'\d{1,4}', value):
            return False
        if key == 'limit' and not 1 <= int(value) <= 100:
            return False
    return True


class DashboardClient:
    def __init__(self, url, token, transport=None):
        self.origin = local_origin(url)
        if not isinstance(token, str) or not re.fullmatch(r'[!-~]{8,4096}', token):
            raise DashboardError('A bounded session token is required through the environment or private prompt')
        self._token = token
        self._transport = transport

    def get(self, path='/api/status', backend='httpx'):
        if not safe_endpoint(path):
            raise DashboardError('Only approved read-only dashboard endpoints are available')
        if backend not in {'httpx', 'curl'}:
            raise DashboardError('Unsupported transport')
        url = self.origin + path
        try:
            if backend == 'curl':
                # Token is sent through stdin, never argv, a config file or URL.
                config = 'url = ' + json.dumps(url) + '\nheader = ' + json.dumps('Authorization: Bearer ' + self._token) + '\n'
                completed = subprocess.run([
                    'curl', '--disable', '--config', '-', '--silent', '--show-error',
                    '--noproxy', '*', '--proto', '=http,https', '--max-redirs', '0',
                    '--max-time', '10', '--connect-timeout', '3', '--max-filesize', str(MAX_RESPONSE),
                    '--request', 'GET', '--write-out', '\n%{http_code}',
                ], input=config, text=True, capture_output=True, timeout=12,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
                if completed.returncode:
                    raise DashboardError('Curl unavailable, response too large, or connection failed')
                body, status = completed.stdout.rsplit('\n', 1)
                status = int(status)
            else:
                with httpx.Client(transport=self._transport, timeout=10, trust_env=False, follow_redirects=False) as client:
                    with client.stream('GET', url, headers={'Authorization': 'Bearer ' + self._token}) as response:
                        status = response.status_code
                        content = bytearray()
                        for chunk in response.iter_bytes():
                            content.extend(chunk)
                            if len(content) > MAX_RESPONSE:
                                raise DashboardError('Dashboard response exceeds the client budget')
                        body = content.decode('utf-8')
            if len(body.encode()) > MAX_RESPONSE:
                raise DashboardError('Dashboard response exceeds the client budget')
            if status == 401:
                raise DashboardError('Dashboard session invalid or expired; provide a current token')
            if not 200 <= status < 300:
                raise DashboardError(f'Dashboard request rejected (HTTP {status}); redirects are not followed')
            # Remove even a raw reflected token before decoding/presentation.
            value = json.loads(body)
            def scrub(item):
                if isinstance(item, str): return item.replace(self._token, '[REDACTED]')
                if isinstance(item, list): return [scrub(entry) for entry in item]
                if isinstance(item, dict): return {scrub(key): scrub(entry) for key, entry in item.items()}
                return item
            return {'status_code': status, 'path': path, 'transport': backend, 'data': redact(scrub(value))}
        except DashboardError:
            raise
        except (OSError, subprocess.SubprocessError, httpx.HTTPError, ValueError, UnicodeError, RecursionError):
            raise DashboardError('Dashboard transport failed or returned invalid bounded JSON') from None
