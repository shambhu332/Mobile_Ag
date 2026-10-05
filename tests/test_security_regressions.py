"""Negative controls and integration contracts from the 2026-10-05 review."""
import asyncio
import importlib
import io
import json
import plistlib
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from config.settings import Settings
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer
from mobileag.core.orchestrator import Orchestrator
from mobileag.core.state import create_initial_state
from mobileag.llm.router import LLMRouter
from mobileag.llm.consensus import ConsensusVoter
from mobileag.reporting.finding import Finding, FindingStatus
from mobileag.security.archives import validate_archive

web = importlib.import_module('mobileag.web.app')

def apk_bytes():
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        z.writestr('AndroidManifest.xml','<manifest package="synthetic"/>')
    return stream.getvalue()

@pytest.fixture
def client():
    return TestClient(web.app, headers={'Authorization':'Bearer '+web.app.state.auth_token})

@pytest.mark.parametrize('path,method,payload',[
    ('/api/settings','get',None),('/api/dast/execute_adb','post',{'serial':'emulator-5554','command':'echo test'}),
    ('/api/scans','get',None),('/api/apis/test','post',{'url':'http://127.0.0.1/'})])
def test_unauthenticated_denied(path,method,payload):
    r=TestClient(web.app).request(method,path,**({'json':payload} if payload else {}))
    assert r.status_code == 401

@pytest.mark.parametrize('headers',[{'Origin':'https://foreign.invalid'},{'Host':'foreign.invalid'}])
def test_browser_boundary(client,headers):
    assert client.get('/api/scans',headers=headers).status_code == 403

@pytest.mark.parametrize('filename',['../outside.apk','/tmp/outside.apk','..\\outside.apk'])
def test_traversal_rejected(client,filename):
    assert client.post('/api/upload/apk',files={'file':(filename,apk_bytes())}).status_code == 400

def test_upload_unique_validated(client):
    a=client.post('/api/upload/apk',files={'file':('sample.apk',apk_bytes())}).json()
    b=client.post('/api/upload/apk',files={'file':('sample.apk',apk_bytes())}).json()
    assert a['file_path'] != b['file_path']
    assert Path(a['file_path']).is_relative_to(web.UPLOAD_DIR)
    assert client.post('/api/upload/apk',files={'file':('bad.apk',b'PKbad')}).status_code == 400
    assert len(list(web.UPLOAD_DIR.iterdir())) == 2

def test_websocket_auth(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/ws/telemetry') as ws:
            ws.send_json({'token':'wrong'})
            ws.receive_json()
    with client.websocket_connect('/ws/telemetry') as ws:
        ws.send_json({'token':web.app.state.auth_token})
        assert ws.receive_json()['type'] == 'connection_established'

def test_device_scope(client):
    assert client.post('/api/dast/root',json={'serial':'unscoped'}).status_code == 403

def test_offline_enforced(monkeypatch):
    with patch('mobileag.llm.router.get_provider_configs') as configs:
        router=LLMRouter(Settings(_env_file=None,offline=True,OPENAI_API_KEY='synthetic'))
        assert router.get_available_providers() == []
        configs.assert_not_called()

@pytest.mark.asyncio
async def test_offline_osv_skipped(tmp_path):
    from mobileag.analysis.dependency_scanner import DependencyScanner
    router=LLMRouter(Settings(_env_file=None,offline=True))
    scanner=DependencyScanner(router)
    (tmp_path/'build.gradle').write_text('implementation "test:test:1"')
    with patch('httpx.AsyncClient') as client:
        assert await scanner.scan(str(tmp_path)) == []
        client.assert_not_called()

def test_missing_scan_never_demo(client):
    r=client.post('/api/scans/run',json={'apk_path':str(web.UPLOAD_DIR/'absent.apk')})
    assert r.status_code == 400
    assert web.ACTIVE_SCANS == {}
    assert client.get('/api/scans/not-real').status_code == 404

def test_final_results_replace_previews(client):
    file=web.UPLOAD_DIR/'real.apk';file.write_bytes(apk_bytes())
    async def scan(*args,**kw):
        await kw['progress_callback']('Preview','raw lead',50,{'id':'raw','title':'Rejected'})
        return {'filtered_findings':[{'id':'final','title':'Final','description':'Synthetic','affected_component':'synthetic','severity':'LOW','status':'UNVERIFIED','cwe_id':'CWE-22'}]}
    with patch.object(web,'Orchestrator') as ctor:
        ctor.return_value.scan=AsyncMock(side_effect=scan)
        r=client.post('/api/scans/run',json={'apk_path':str(file),'auto_taint':False})
        assert r.status_code == 200
        sid=r.json()['scan_id']
        result=client.get('/api/scans/'+sid).json()
        assert [f['id'] for f in result['findings']] == ['final']
        assert ctor.call_args.args[0].enable_deep_taint is False
        assert Path(ctor.return_value.scan.call_args.kwargs['output_dir']) == web.OUTPUT_DIR
        web.ACTIVE_SCANS.clear()
        assert client.get('/api/scans/'+sid).json()['status'] == 'completed'

def test_scan_errors_not_success(client):
    file=web.UPLOAD_DIR/'real.apk';file.write_bytes(apk_bytes())
    with patch.object(web,'Orchestrator') as ctor:
        ctor.return_value.scan=AsyncMock(return_value={'errors':['Ingestion failed']})
        r=client.post('/api/scans/run',json={'apk_path':str(file)})
        assert client.get('/api/scans/'+r.json()['scan_id']).json()['status'] == 'error'

@pytest.mark.asyncio
async def test_report_formats(tmp_path):
    state=create_initial_state('test','test.apk',str(tmp_path))
    await Orchestrator._save_outputs(object(),state)
    for field in ['report_path','json_report_path','sarif_path']:
        assert Path(state[field]).is_file()

def test_inline_source_and_overwrite():
    engine=TaintEngine()
    assert len(engine.analyze_source_content('web.loadUrl(getIntent().getStringExtra("url"));')) == 1
    assert engine.analyze_source_content('String url = getIntent().getStringExtra("url");\nurl = "https://safe.invalid";\nweb.loadUrl(url);') == []
    assert engine.analyze_source_content('public void a() {\nString url = getIntent().getStringExtra("url");\n}\npublic void b() {\nweb.loadUrl(url);\n}') == []

def test_no_authorization_claim_on_403(client):
    r=client.post('/api/apis/fuzz',json={'url':'https://synthetic.invalid/admin/users','response_status':403,'response_body':'Forbidden'})
    assert all(f['status']=='UNVERIFIED' for f in r.json()['findings'])
    assert not any(f['cwe_id'] in {'CWE-285','CWE-306'} for f in r.json()['findings'])

def test_strict_votes():
    voter=ConsensusVoter(None)
    assert voter._parse_vote('test','{"vulnerable":"false"}') is None
    assert voter._parse_vote('test','{"vulnerable":false}').vulnerable is False
    assert voter._parse_vote('test','{"vulnerable":true,"confidence":2}') is None

@pytest.mark.asyncio
async def test_qdrant_model_contract(monkeypatch):
    from types import SimpleNamespace
    module=importlib.import_module("mobileag.knowledge.qdrant_store")
    if not hasattr(module,"models"):
        monkeypatch.setattr(module,"models",SimpleNamespace(PointStruct=lambda **kwargs:SimpleNamespace(**kwargs)),raising=False)
    from mobileag.knowledge.qdrant_store import PatternMemory
    store=object.__new__(PatternMemory);store._connected=True;store.client=AsyncMock();store.collection_name='test'
    await store.store_finding(Finding(title='Test',description='Test',cwe_id='CWE-22'),[0.]*384)
    assert store.client.upsert.call_args.kwargs['points'][0].payload['cwe'] == 'CWE-22'

def test_ipa_executable(tmp_path):
    file=tmp_path/'test.ipa'
    with zipfile.ZipFile(file,'w') as z:
        z.writestr('Payload/Display.app/Info.plist',plistlib.dumps({'CFBundleExecutable':'Real'}))
        z.writestr('Payload/Display.app/Real',b'synthetic')
    assert IOSSecurityAnalyzer().extract_ipa(file,tmp_path/'extract')['binary_path'].endswith('/Real')

def test_archive_traversal(tmp_path):
    file=tmp_path/'test.apk'
    with zipfile.ZipFile(file,'w') as z:
        z.writestr('AndroidManifest.xml','synthetic')
        z.writestr('../escape','synthetic')
    with pytest.raises(ValueError):validate_archive(file)

def test_network_scope(client):
    assert client.post('/api/apis/test',json={'url':'http://127.0.0.1/'}).status_code == 403

def test_settings_validated(client):
    assert client.post('/api/settings',json={'unknown':True}).status_code==422
    assert client.post('/api/settings',json={'enable_deep_taint':'false'}).status_code==422
    assert client.post('/api/settings',json={'enable_deep_taint':False}).status_code==200

def test_frida_fails_closed():
    from mobileag.dast.frida_runner import FridaRunner
    assert asyncio.run(FridaRunner().execute_script_payload('emulator-5554','synthetic.app','test'))['status']=='unavailable'

@pytest.mark.asyncio
async def test_frida_acknowledgment_and_cleanup(monkeypatch):
    module=importlib.import_module('mobileag.dast.frida_runner')
    native=MagicMock();session=native.get_device.return_value.attach.return_value
    script=session.create_script.return_value
    callback={}
    script.on.side_effect=lambda event,fn: callback.update(fn=fn)
    def loaded():
        import re
        code=session.create_script.call_args.args[0]
        marker=re.search(r"send\('([^']+)'\)",code).group(1)
        callback['fn']({'type':'send','payload':marker},None)
    script.load.side_effect=loaded
    monkeypatch.setattr(module,'HAS_NATIVE_FRIDA',True);monkeypatch.setattr(module,'frida',native)
    result=await module.FridaRunner().execute_script_payload('emulator-5554','synthetic.app','console.log("test");')
    assert result['status']=='executed'
    native.get_device.assert_called_once_with('emulator-5554',timeout=2)
    session.detach.assert_called_once();script.unload.assert_called_once()

@pytest.mark.asyncio
async def test_analysis_resource_routing(tmp_path):
    obj=Orchestrator(Settings(_env_file=None,offline=True))
    java=tmp_path/'jadx_out'; resources=tmp_path/'apktool_out'
    java.mkdir();resources.mkdir();(resources/'Test.smali').write_text('synthetic')
    manifest=resources/'AndroidManifest.xml';manifest.write_text('<manifest package="test.app"><application/></manifest>')
    obj._extractor.extract=AsyncMock(return_value={'jadx_dir':str(java),'apktool_dir':str(resources),'manifest_path':str(manifest),'package_name':'test.app'})
    state=await obj._run_ingestion(create_initial_state('test','test.apk',str(tmp_path)))
    assert state['coverage']['smali_files']==1
    assert state['smali_path']==str(resources)
    assert state['decompiled_path']==str(java)
    for attr,method in [('_manifest_auditor','audit'),('_secret_scanner','scan'),('_code_reviewer','review'),('_native_analyzer','analyze'),('_dependency_scanner','scan'),('_taint_engine','analyze_directory_async'),('_nsc_auditor','audit_directory_async'),('_bin_protection','audit_directory_async'),('_rn_scanner','scan_directory_async')]:
        setattr(getattr(obj,attr),method,AsyncMock(return_value=[]))
    obj._api_mapper.map_apis=AsyncMock(return_value=([],[]))
    obj._call_graph_engine.audit_smali_directory=MagicMock(return_value=[])
    await obj._run_analysis(state)
    obj._call_graph_engine.audit_smali_directory.assert_called_once_with(str(resources))
    obj._nsc_auditor.audit_directory_async.assert_awaited_once_with(str(resources))

def test_deeplink_schema(tmp_path):
    from mobileag.ingestion.manifest_parser import ManifestParser
    manifest=tmp_path/'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app"><application><activity android:name=".Main"><intent-filter><data android:scheme="test" android:host="route" android:path="/item"/></intent-filter></activity></application></manifest>')
    assert ManifestParser().parse(str(manifest))['deep_links'][0]['uri']=='test://route/item'

@pytest.mark.asyncio
async def test_network_pinning_and_limits(monkeypatch):
    from mobileag.security.network import scoped_request
    from http.server import BaseHTTPRequestHandler,HTTPServer
    from threading import Thread
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.end_headers();self.wfile.write(b'synthetic-test-marker')
        def log_message(self,*args):pass
    server=HTTPServer(('127.0.0.1',0),Handler)
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}'
    monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS',url)
    try:
        with pytest.raises(PermissionError):await scoped_request(url)
        monkeypatch.setenv('MOBILEAG_ALLOW_PRIVATE_TARGETS','1')
        assert (await scoped_request(url))['body']=='synthetic-test-marker'
    finally:
        server.shutdown();server.server_close();thread.join()

@pytest.mark.asyncio
async def test_no_hidden_cloud_calls_from_cli(tmp_path):
    from click.testing import CliRunner
    cli=importlib.import_module('mobileag.cli')
    file=tmp_path/'sample.apk';file.write_bytes(apk_bytes())
    with patch.object(cli,'get_settings',return_value=Settings(_env_file=None,OPENAI_API_KEY='synthetic')),patch.object(cli,'Orchestrator') as ctor:
        ctor.return_value.scan=AsyncMock(return_value={'report_path':'synthetic'})
        # CliRunner's asyncio.run cannot execute inside this test event loop.
        result=await asyncio.to_thread(CliRunner().invoke,cli.main,['scan','--apk',str(file),'--offline'])
        assert result.exit_code==0
        assert ctor.call_args.args[0].offline is True
        assert ctor.call_args.args[0].enabled_providers==[]

def test_evidence_redaction():
    finding=Finding(title='test',description='password=synthetic-secret',code_snippet='<string name="auth_token">synthetic-secret</string>')
    assert 'synthetic-secret' not in json.dumps(finding.model_dump())

@pytest.mark.asyncio
async def test_proxy_framing_binary_and_auth(monkeypatch):
    module=importlib.import_module('mobileag.dast.mitm_proxy')
    monkeypatch.setenv('MOBILEAG_PROXY_TOKEN','synthetic-proxy-token')
    request=AsyncMock(return_value={'status_code':200,'headers':{},'body':b'\xff\x00binary'})
    monkeypatch.setattr(module,'scoped_request',request)
    proxy=module.AsyncMITMProxy(port=0)
    await proxy.start()
    port=proxy._server.sockets[0].getsockname()[1]
    try:
        reader,writer=await asyncio.open_connection('127.0.0.1',port)
        writer.write(b'POST http://scope.invalid/ HTTP/1.1\r\nHost: scope.invalid\r\nProxy-Authorization: Bearer synthetic-proxy-token\r\ncontent-length: 3\r\n\r\n\xff')
        await writer.drain();await asyncio.sleep(.01)
        writer.write(b'\x00a');await writer.drain()
        response=await asyncio.wait_for(reader.read(),2)
        assert response.endswith(b'\xff\x00binary')
        assert request.call_args.args[3]==b'\xff\x00a'
        writer.close();await writer.wait_closed()
    finally:await proxy.stop()

@pytest.mark.asyncio
async def test_pipeline_synthetic_end_to_end(tmp_path):
    java=tmp_path/'decoded'/'java';res=tmp_path/'decoded'/'resources'
    java.mkdir(parents=True);res.mkdir()
    (java/'Main.java').write_text('class Main {\nvoid go() {\nString url = getIntent().getStringExtra("url");\nweb.loadUrl(url);\n}\n}')
    manifest=res/'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="synthetic.app"><application android:debuggable="true"><activity android:name="synthetic.app.Main" android:exported="true"/></application></manifest>')
    (res/'Main.smali').write_text('.class public Lsynthetic/app/Main;\n.super Ljava/lang/Object;\n')
    orchestrator=Orchestrator(Settings(_env_file=None,offline=True))
    orchestrator._extractor.extract=AsyncMock(return_value={'jadx_dir':str(java),'apktool_dir':str(res),'manifest_path':str(manifest),'package_name':'synthetic.app'})
    state=await orchestrator.scan('synthetic.apk',str(tmp_path/'reports'),scan_id='integration')
    assert state['errors']==[]
    assert state['current_phase']=='complete'
    assert len(state['raw_findings'])>0
    assert all(f['status']=='UNVERIFIED' for f in state['filtered_findings'])
    assert Path(state['report_path']).is_file()
    assert (Path(state['output_dir'])/'state.json').is_file()

def test_web_ipa_dispatch(client):
    file=web.UPLOAD_DIR/'sample.ipa'
    with zipfile.ZipFile(file,'w') as z:
        z.writestr('Payload/App.app/Info.plist',plistlib.dumps({'CFBundleExecutable':'Actual'}))
        z.writestr('Payload/App.app/Actual',b'synthetic')
    with patch.object(web,'Orchestrator') as android:
        r=client.post('/api/scans/run',json={'apk_path':str(file)})
        assert r.status_code==200
        result=client.get('/api/scans/'+r.json()['scan_id']).json()
        assert result['status']=='error'  # Truncated synthetic executable is not a clean binary audit.
        assert result['coverage']['binary_format']=='unsupported'
        android.assert_not_called()

def test_request_size_limit(client):
    r=client.post('/api/upload/apk',content=b'x',headers={'Content-Length':str(1024**3)})
    assert r.status_code==413

def test_feedback_needs_evidence(client):
    assert client.post('/api/findings/test/feedback',json={'verdict':'CONFIRMED'}).status_code==422

@pytest.mark.asyncio
async def test_proxy_requires_explicit_configuration(monkeypatch):
    from mobileag.dast.mitm_proxy import AsyncMITMProxy
    monkeypatch.delenv('MOBILEAG_PROXY_TOKEN',raising=False)
    with pytest.raises(ValueError):await AsyncMITMProxy(port=0).start()
    monkeypatch.setenv('MOBILEAG_PROXY_TOKEN','synthetic')
    with pytest.raises(ValueError):await AsyncMITMProxy(host='0.0.0.0',port=0).start()

@pytest.mark.asyncio
async def test_offline_secret_candidates_retained_and_redacted(tmp_path):
    from mobileag.analysis.secret_scanner import SecretScanner
    scanner=SecretScanner(LLMRouter(Settings(_env_file=None,offline=True)))
    secret='AKIAIOSFODNN7EXAMPLE'
    (tmp_path/'Key.java').write_text('String key = "'+secret+'";')
    findings=await scanner.scan(str(tmp_path))
    assert any(f.cwe_id=='CWE-798' for f in findings)
    assert secret not in json.dumps([f.model_dump() for f in findings])
