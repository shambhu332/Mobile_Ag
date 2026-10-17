"""Check an installed wheel outside the source checkout. No devices/cloud calls."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import tempfile
from importlib import resources

async def check(target):
    import mobileag
    assert Path(mobileag.__file__).resolve().is_relative_to(target), 'Source checkout contaminated wheel smoke'
    import httpx
    from mobileag.automation.engine import AutomationService
    from mobileag.automation.models import CreateRun
    from mobileag.assessments.models import Assessment
    from mobileag.llm.broker import LLMBroker
    from mobileag.reporting.sarif_importer import import_sarif
    from mobileag.web.app import app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
        headers={'Authorization':'Bearer synthetic-wheel-smoke-only'}
        assert (await client.get('/', headers=headers)).status_code == 404
        assert (await client.get('/static/interface.js', headers=headers)).status_code == 404
        assert (await client.get('/workbench', headers=headers)).status_code == 404
        assert (await client.get('/api/scans')).status_code == 401
        assert (await client.get('/api/automation/runs')).status_code == 401
        assert (await client.get('/api/assessments')).status_code == 401
        assert (await client.get('/api/automation/capabilities',headers={'Authorization':'Bearer synthetic-wheel-smoke-only'})).json()['platforms']==['android']
        from mobileag.studio import enable_studio, PUBLIC_FILES
        enable_studio(app)
        for path in PUBLIC_FILES:
            response = await client.get(path)
            assert response.status_code == 200, f'Missing wheel UI asset: {path}'
            assert 'synthetic-wheel-smoke-only' not in response.text
        assert (await client.get('/api/scans')).status_code == 401
        assert (await client.get('/api/studio/catalog')).status_code == 401
        catalog=(await client.get('/api/studio/catalog',headers=headers)).json()
        assert any(op['path']=='/api/studio/taint/source-archive' for op in catalog['operations'])
        from mobileag.studio import jobs, worker
        assert callable(jobs.local_tool) and callable(worker.execute)
    schema = resources.files('mobileag').joinpath('data', 'sarif-schema-2.1.0.json')
    assert schema.is_file(), 'Full SARIF schema missing from installed wheel'
    imported = import_sarif({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'wheel-smoke'}},
        'results':[{'ruleId':'R1','message':{'text':'synthetic candidate'}}]}]})
    assert imported['imported_candidates'] == 1
    assert imported['findings'][0]['status'] == 'UNVERIFIED'
    print(json.dumps({'installed_wheel_import':True,'version':mobileag.__version__,'api_only_default':True,'opt_in_studio_assets_served':True,'unauthenticated_api_denied':True,'full_sarif_schema_shipped_and_offline_imported':True}))

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--target',required=True);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='mobileag-wheel-smoke-') as data:
        os.environ.update(MOBILEAG_DATA_DIR=data, MOBILEAG_API_TOKEN='synthetic-wheel-smoke-only', OFFLINE='true', APPROVED_LLM_PROVIDERS='[]')
        asyncio.run(check(Path(args.target).resolve()))
