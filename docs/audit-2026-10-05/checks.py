import asyncio, importlib, json, tempfile, zipfile, plistlib
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from click.testing import CliRunner
from config.settings import Settings
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer
from mobileag.core.orchestrator import Orchestrator
from mobileag.core.state import create_initial_state
from mobileag.dast.frida_runner import FridaRunner
from mobileag.dast.adb_manager import ADBManager
web = importlib.import_module('mobileag.web.app')
cli = importlib.import_module('mobileag.cli')
results = {}
with tempfile.TemporaryDirectory() as td:
    root=Path(td); uploads=root/'uploads'; uploads.mkdir()
    with patch.object(web,'UPLOAD_DIR',uploads):
        client=TestClient(web.app)
        r=client.post('/api/upload/apk',files={'file':('../outside.apk', b'SYNTHETIC', 'application/octet-stream')})
        results['upload_traversal']={'http':r.status_code,'outside_created':(root/'outside.apk').read_bytes()==b'SYNTHETIC'}
    with patch.object(web.adb_manager,'execute_shell',new=AsyncMock(return_value={'status':'success'})) as shell:
        r=client.post('/api/dast/execute_adb',json={'serial':'synthetic','command':'echo synthetic'},headers={'Origin':'https://untrusted.example'})
        results['unauthenticated_device_dispatch']={'http':r.status_code,'dispatched':shell.await_count,'cors_origin':r.headers.get('access-control-allow-origin')}
    r=client.post('/api/scans/run',json={'apk_path':str(root/'missing.apk'),'auto_dast':False})
    scan=client.get('/api/scans/'+r.json()['scan_id']).json()
    results['missing_apk_simulation']={'status':scan['status'],'findings':len(scan['findings'])}
    r=client.post('/api/apis/fuzz',json={'url':'https://synthetic.invalid/admin/users','response_status':403,'response_body':'Forbidden'})
    results['forbidden_api_confirmed']=[{'cwe':f['cwe_id'],'status':f['status']} for f in r.json()['findings']]
    apk=root/'synthetic.apk'; apk.write_bytes(b'x'*101)
    fake=MagicMock(); fake.scan=AsyncMock(return_value={})
    settings=Settings(_env_file=None,OPENAI_API_KEY='synthetic-not-a-real-key')
    with patch.object(cli,'get_settings',return_value=settings),patch.object(cli,'Orchestrator',return_value=fake) as ctor:
        r=CliRunner().invoke(cli.main,['scan','--apk',str(apk),'--offline'])
        results['offline_provider_retained']={'exit':r.exit_code,'providers':ctor.call_args.args[0].enabled_providers}
    out=root/'out';out.mkdir()
    state=create_initial_state('synthetic',str(apk),str(out))
    asyncio.run(Orchestrator._save_outputs(object(),state))
    results['report_generation']={'files':[p.name for p in out.iterdir()],'report_path':state.get('report_path')}
    # Verify raw preview is retained, while the final filtered-only result is never ingested.
    async def fake_scan(**kw):
        await kw['progress_callback']('Finding Discovered','raw',78,{'id':'raw','title':'Rejected raw lead','severity':'HIGH'})
        return {'package_name':'synthetic','filtered_findings':[{'id':'final','title':'Final-only finding'}]}
    with patch.object(web,'Orchestrator') as ctor:
        ctor.return_value.scan=AsyncMock(side_effect=fake_scan)
        r=client.post('/api/scans/run',json={'apk_path':str(apk),'auto_dast':False})
        scan=client.get('/api/scans/'+r.json()['scan_id']).json()
        results['dashboard_final_filter_ignored']=[f['id'] for f in scan['findings']]
    # IPA executable name is declared independently from bundle directory name.
    ipa=root/'sample.ipa'
    with zipfile.ZipFile(ipa,'w') as z:
        z.writestr('Payload/Display.app/Info.plist',plistlib.dumps({'CFBundleExecutable':'RealExecutable'}))
        z.writestr('Payload/Display.app/RealExecutable',b'synthetic')
    extracted=IOSSecurityAnalyzer().extract_ipa(ipa,root/'ios')
    results['ipa_executable_missed']=extracted['binary_path'] is None
engine=TaintEngine()
results['taint_inline_missed']=len(engine.analyze_source_content('web.loadUrl(getIntent().getStringExtra("url"));'))
results['taint_overwrite_false_positive']=len(engine.analyze_source_content('String url = getIntent().getStringExtra("url");\nurl = "https://safe.invalid";\nweb.loadUrl(url);'))
adb=ADBManager(); adb._exec_cmd=AsyncMock(return_value=(0,b'frida-server 1234',b''))
res=asyncio.run(FridaRunner(adb=adb).execute_script_payload('synthetic','synthetic.app','console.log("test");'))
results['frida_claim_without_attachment']={'status':res['status'],'commands':[c.args[0] for c in adb._exec_cmd.await_args_list]}
print(json.dumps(results,indent=2))
