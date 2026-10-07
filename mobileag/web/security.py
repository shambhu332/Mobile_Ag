"""Fail-closed dashboard authentication, origin checks and device scope."""
import hmac
import os
import re
import time
from urllib.parse import urlsplit
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.exceptions import HTTPException
from mobileag.security.archives import MAX_UPLOAD


def configured_list(name):
    return {x.strip() for x in os.environ.get(name, '').split(',') if x.strip()}


def origin_allowed(origin: str | None, host: str) -> bool:
    if not origin:
        return True  # Non-browser clients still require a bearer token.
    return origin in {f'http://{host}', f'https://{host}'}


def authorized(token, expected):
    return isinstance(token, str) and bool(token) and hmac.compare_digest(token, expected)


def check_device(serial):
    return isinstance(serial, str) and bool(serial) and serial in configured_list('MOBILEAG_ALLOWED_DEVICES')


class SecurityMiddleware:
    def __init__(self, app, owner):
        self.app, self.owner = app, owner

    async def __call__(self, scope, receive, send):
        if scope['type'] not in ('http', 'websocket'):
            return await self.app(scope, receive, send)
        if scope['type'] == 'http':
            original_send = send
            async def secure_send(message):
                if message['type'] == 'http.response.start':
                    message = dict(message)
                    message['headers'] = list(message.get('headers', [])) + [
                        (b'x-content-type-options', b'nosniff'),
                        (b'x-frame-options', b'DENY'),
                        (b'referrer-policy', b'no-referrer'),
                        (b'cache-control', b'no-store'),
                        (b'content-security-policy',
                         b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:* ws://localhost:*; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")]
                await original_send(message)
            send = secure_send
        headers = dict((k.decode().lower(), v.decode()) for k,v in scope['headers'])
        host = headers.get('host', '')
        hostname = urlsplit('http://' + host).hostname
        allowed = {'127.0.0.1', 'localhost', '::1'} | configured_list('MOBILEAG_ALLOWED_HOSTS')
        error = None
        status = 403
        if hostname not in allowed or not origin_allowed(headers.get('origin'), host):
            error = 'Host or Origin not allowed'
        elif scope['type'] == 'http' and scope['path'] != '/' and not scope['path'].startswith('/static/'):
            if time.monotonic() >= getattr(self.owner.state,'session_deadline',float('inf')) or not authorized(headers.get('authorization', '').removeprefix('Bearer '), self.owner.state.auth_token):
                error, status = 'Bearer authentication required', 401
        if error:
            if scope['type'] == 'websocket':
                return await send({'type':'websocket.close', 'code':1008})
            return await JSONResponse({'detail':error}, status_code=status)(scope, receive, send)
        if scope['type'] == 'websocket':
            return await self.app(scope, receive, send)
        path = scope['path']
        protected = path != '/' and not path.startswith('/static/')
        request_token = headers.get('authorization', '').removeprefix('Bearer ')
        # Bind downstream tasks to the credential actually authenticated, never
        # to the server's replacement token after logout/rotation.
        if protected:
            scope.setdefault('state', {})['authenticated_token'] = request_token

        def check_session():
            if protected and (time.monotonic() >= getattr(self.owner.state, 'session_deadline', float('inf'))
                              or not authorized(request_token, self.owner.state.auth_token)):
                raise HTTPException(401, 'Bearer authentication required')

        upload = path == '/api/upload/apk'
        limit = MAX_UPLOAD + 65536 if upload else 1024 * 1024
        try:
            length = int(headers.get('content-length', '0'))
        except ValueError:
            length = limit + 1
        if length < 0 or length > limit or (upload and not length):
            return await JSONResponse({'detail':'Request size limit exceeded or missing upload length'}, status_code=413)(scope, receive, send)
        # Bound every body before parsing; JSON requests are small, uploads spool to disk downstream.
        consumed = 0
        async def limited_receive():
            nonlocal consumed
            check_session()
            message = await receive()
            # A suspended/streaming body must not resurrect revoked authority.
            check_session()
            consumed += len(message.get('body', b''))
            if consumed > limit:
                raise HTTPException(413, 'Request size limit exceeded')
            return message
        if path.startswith('/api/dast/') and path not in {'/api/dast/devices', '/api/dast/traffic/audit'}:
            import json
            req = Request(scope, limited_receive)
            try:
                data = await req.json() if scope['method'] == 'POST' else dict(req.query_params)
                if not isinstance(data, dict):
                    raise ValueError('Invalid body')
                if path.endswith('/connect'):
                    permitted = data.get('host_port') in configured_list('MOBILEAG_ALLOWED_CONNECT')
                else:
                    permitted = check_device(data.get('serial'))
                if not permitted:
                    return await JSONResponse({'detail':'Device is outside configured scope'}, status_code=403)(scope, receive, send)
                from mobileag.web.policy import check_action
                policy = self.owner.state.scope_repository().get_policy()
                action = path.removeprefix('/api/dast/')
                if action == 'frida/status':
                    action = 'frida_status'
                if not check_action(policy, action, data):
                    return await JSONResponse({'detail':'Device action is not approved in the UI scope policy'}, status_code=403)(scope, receive, send)
                package = data.get('package_name')
                if package and not re.fullmatch(r'[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+', package):
                    raise ValueError('Invalid package name')
            except HTTPException as exc:
                return await JSONResponse({'detail': exc.detail}, status_code=exc.status_code)(scope, receive, send)
            except (ValueError, TypeError):
                return await JSONResponse({'detail':'Invalid request'}, status_code=400)(scope, receive, send)
            body = await req.body() if scope['method'] == 'POST' else b''
            delivered = False
            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {'type':'http.request','body':body,'more_body':False}
                return await receive()
            return await self.app(scope, replay, send)
        await self.app(scope, limited_receive, send)
