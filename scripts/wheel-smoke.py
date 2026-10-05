"""Check an installed wheel outside the source checkout. No devices/cloud calls."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import tempfile

async def check(target):
    import mobileag
    assert Path(mobileag.__file__).resolve().is_relative_to(target), 'Source checkout contaminated wheel smoke'
    import httpx
    from mobileag.web.app import app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
        response = await client.get('/')
        assert response.status_code == 200
        scripts = re.findall(r'<script[^>]+src=["\'](/static/[^"\']+)["\']', response.text)
        assert len(scripts) >= 12
        for script in scripts:
            assert (await client.get(script)).status_code == 200, script
        assert (await client.get('/api/scans')).status_code == 401
    print(json.dumps({'installed_wheel_import':True,'version':mobileag.__version__,'shipped_script_count':len(scripts),'unauthenticated_api_denied':True}))

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--target',required=True);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='mobileag-wheel-smoke-') as data:
        os.environ.update(MOBILEAG_DATA_DIR=data, MOBILEAG_API_TOKEN='synthetic-wheel-smoke-only', OFFLINE='true', APPROVED_LLM_PROVIDERS='[]')
        asyncio.run(check(Path(args.target).resolve()))
