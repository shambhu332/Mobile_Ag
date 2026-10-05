"""Synthetic local-only review. No devices, databases or remote providers are used.
Run with project deps; writes evidence beside this script and temporary fixtures.
"""
import asyncio, importlib, json, os, tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
OUT=Path(__file__).resolve().parent
ROOT=Path(tempfile.mkdtemp(prefix='mobileag-product-review-'))
os.environ.update(MOBILEAG_DATA_DIR=str(ROOT),MOBILEAG_API_TOKEN='synthetic-review-only',OFFLINE='true',MOBILEAG_ALLOWED_DEVICES='',MOBILEAG_ALLOWED_ORIGINS='',MOBILEAG_ALLOWED_CONNECT='')
from mobileag.analysis.secret_scanner import SecretScanner
from config.settings import Settings
from mobileag.llm.router import LLMRouter
from mobileag.filters.pipeline import FilterPipeline
from fastapi.testclient import TestClient
async def fixtures():
 src=ROOT/'source'; src.mkdir()
 # Valid Java line containing an inert string; browser handler interprets it as JS.
 line='class Example { String marker = "\'-window.auditXssProbe(1)-\'"; Object c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }'
 (src/'Example.java').write_text(line)
 settings=Settings(_env_file=None,offline=True,enable_reachability_filter=False,enable_consensus_voting=False,confidence_threshold=0.0)
 router=LLMRouter(settings)
 findings=await SecretScanner(router).scan(str(src))
 finding=findings[0].model_dump(mode='json')
 finding['id']='synthetic-finding'
 # Persistence/rendering boundary fixture: no claim of full APK decompilation/filter coverage.
 scan={'scan_id':'scan_synthetic_review','app_name':'Synthetic review fixture','package_name':'org.example.review','status':'completed','version':'test','framework':'Synthetic source fixture','findings':[finding], 'stats':{'total':1,'high':1,'critical':0,'medium':0,'low':0},'components':[],'api_endpoints':[],'agent_telemetry':[],'attack_surface_graph':{'nodes':[],'edges':[]}}
 folder=ROOT/'output'/scan['scan_id'];folder.mkdir(parents=True)
 (folder/'dashboard.json').write_text(json.dumps(scan))
 # Actual secret-scanner to provider boundary, mock transport only.
 secret_src=ROOT/'secret-source';secret_src.mkdir()
 dummy='AKIA'+'Z'*16
 (secret_src/'Dummy.java').write_text('String example = "'+dummy+'";')
 capture=SimpleNamespace(route=AsyncMock(return_value=SimpleNamespace(success=True,content='DUMMY')))
 await SecretScanner(capture).scan(str(secret_src))
 return scan, {'candidate_secret_in_provider_prompt':dummy in capture.route.call_args.kwargs['user_prompt'],'provider_call_count':capture.route.await_count,'real_network_calls':0}
scan,privacy=asyncio.run(fixtures())
m=importlib.import_module('mobileag.web.app')
m.attack_graph.verify_connection=AsyncMock(return_value=False)
m.adb_manager.list_devices=AsyncMock(return_value=[])
# Refuse any device subprocess even if future UI code tries it.
m.adb_manager._exec_cmd=AsyncMock(side_effect=RuntimeError('Device operations disabled in review'))
client=TestClient(m.app,base_url='http://127.0.0.1',raise_server_exceptions=False);headers={'Authorization':'Bearer synthetic-review-only'}
results={'fixture_root':str(ROOT),'privacy':privacy}
results['controls']={
 'anonymous_status':client.get('/api/status').status_code,
 'authenticated_status':client.get('/api/status',headers=headers).status_code,
 'foreign_origin':client.get('/api/status',headers={**headers,'Origin':'https://example.invalid'}).status_code,
 'outside_device_scope':client.post('/api/dast/root',headers=headers,json={'serial':'not-allowed'}).status_code,
 'outside_url_scope':client.post('/api/apis/test',headers=headers,json={'url':'https://example.invalid'}).status_code,
 'dashboard_security_headers':{k:v for k,v in client.get('/').headers.items() if k in ['content-security-policy','cache-control','x-frame-options','referrer-policy','x-content-type-options']}}
r=client.post('/api/findings/synthetic-finding/feedback',headers=headers,json={'verdict':'CONFIRMED','notes':'Synthetic controlled validation only'})
results['persisted_feedback']={'post_code':r.status_code,'post':r.json(),'get_status':client.get('/api/scans/scan_synthetic_review',headers=headers).json()['findings'][0]['status']}
r=client.post('/api/findings/nonexistent/feedback',headers=headers,json={'verdict':'FALSE_POSITIVE'})
results['unknown_feedback']={'status_code':r.status_code,'result':r.json()}
r=client.post('/api/copilot',headers=headers,json={'prompt':'Write a bounty report','scan_id':'does-not-exist'})
results['copilot']={'status_code':r.status_code,'response':r.json()}
results['agents']=client.get('/api/agents',headers=headers).json()
(OUT/'local-results.json').write_text(json.dumps(results,indent=2))
(OUT/'synthetic-finding.json').write_text(json.dumps(scan['findings'][0],indent=2))
# External server process for actual browser rendering, same authorization and route handlers.
(ROOT/'runner.py').write_text('''import os,importlib\nfrom unittest.mock import AsyncMock\nimport uvicorn\nm=importlib.import_module("mobileag.web.app")\nm.attack_graph.verify_connection=AsyncMock(return_value=False)\nm.adb_manager.list_devices=AsyncMock(return_value=[])\nm.adb_manager._exec_cmd=AsyncMock(side_effect=RuntimeError("No device testing"))\nuvicorn.run(m.app,host="127.0.0.1",port=18764,log_level="warning")\n''')
Path('/tmp/mobileag-product-review-path').write_text(str(ROOT))
print(json.dumps({k:v for k,v in results.items() if k not in {'agents','copilot'}},indent=2))
