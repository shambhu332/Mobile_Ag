"""Opt-in, offline browser client. No credentials or scan data in public assets."""
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse

ASSETS = Path(__file__).parent / 'assets'
PUBLIC_FILES = {'/ui': 'index.html', '/ui/': 'index.html',
                '/ui/app.js': 'app.js', '/ui/advanced.js': 'advanced.js', '/ui/style.css': 'style.css'}


def enable_studio(app):
    app.state.studio_enabled = True
    if getattr(app.state, 'studio_registered', False):
        return
    async def asset(request: Request):
        if not getattr(app.state, 'studio_enabled', False):
            raise HTTPException(404)
        return FileResponse(ASSETS / PUBLIC_FILES[request.url.path])
    for path in PUBLIC_FILES:
        app.add_api_route(path, asset, methods=['GET', 'HEAD'], include_in_schema=False)
    from mobileag.studio.routes import build_router
    app.include_router(build_router(app))
    app.openapi_schema = None
    app.state.studio_registered = True
