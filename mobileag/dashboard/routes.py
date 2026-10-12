"""Explicit read-only dashboard workbench, never a generic shell/URL proxy."""
import asyncio
import shutil
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from mobileag.dashboard.client import DashboardClient, DashboardError, SAFE_ENDPOINTS, local_origin, safe_endpoint
from mobileag.automation.routes import PrivateValidationRoute


class ReadDashboard(BaseModel):
    model_config = ConfigDict(extra='forbid')
    path: str = Field(default='/api/status', max_length=2048)
    transport: Literal['httpx', 'curl'] = 'httpx'


def server_origin(request):
    """Use the trusted listening socket, never client Host/Origin/URL inputs."""
    server = request.scope.get('server')
    if not server or len(server) != 2 or not isinstance(server[1], int) or isinstance(server[1], bool) or not 1 <= server[1] <= 65535:
        raise DashboardError('Dashboard workbench needs a local listening socket')
    if server[0] in {'127.0.0.1', 'localhost', '0.0.0.0'}:
        host = '127.0.0.1'
    elif server[0] in {'::1', '::'}:
        host = '[::1]'
    else:
        raise DashboardError('Dashboard workbench is limited to a loopback-capable local server')
    scheme = request.scope.get('scheme', 'http')
    return local_origin(f'{scheme}://{host}:{server[1]}')


def build_router(require_session):
    router = APIRouter(prefix='/api/dashboard', tags=['Read-only dashboard tools'], route_class=PrivateValidationRoute)
    active = set()

    @router.get('/capabilities')
    async def capabilities(request: Request):
        try:
            server_origin(request)
            local = True
        except DashboardError:
            local = False
        return {'read_only': True, 'writes_authorized': False, 'local_socket_available': local,
                'curl_installed': bool(shutil.which('curl', path='/usr/bin:/bin')),
                'endpoints': sorted(SAFE_ENDPOINTS), 'max_response_bytes': 1048576,
                'credential_storage': 'page/process_memory_only', 'redirects_followed': False}

    @router.post('/read')
    async def read(req: ReadDashboard, request: Request):
        require_session(request)
        if not safe_endpoint(req.path):
            raise HTTPException(422, 'Only allowlisted read-only dashboard paths are available')
        if len(active) >= 2:
            raise HTTPException(409, 'Dashboard read capacity reached; wait for the current request')
        try:
            origin = server_origin(request)
        except DashboardError:
            raise HTTPException(409, 'Read-only workbench requires a local listening socket') from None
        marker = object(); active.add(marker)
        task = None
        try:
            client = DashboardClient(origin, request.state.authenticated_token)
            task = asyncio.create_task(asyncio.to_thread(client.get, req.path, req.transport))
            # Keep the slot until the bounded worker actually ends, even if the
            # HTTP caller disconnects/cancels while curl is still running.
            def finished(done):
                active.discard(marker)
                if not done.cancelled():
                    done.exception()  # Consume bounded errors after caller cancellation.
            task.add_done_callback(finished)
            result = await asyncio.shield(task)
            require_session(request)
            return {**result, 'target': 'this_dashboard_only', 'writes_authorized': False}
        except DashboardError:
            raise HTTPException(422, 'Dashboard read failed; check session, local server, curl installation or response budget') from None
        finally:
            if task is None or task.done():
                active.discard(marker)

    return router
