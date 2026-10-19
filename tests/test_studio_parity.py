"""Offline parity adapters and operation catalog; no live device/network execution."""
import importlib
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from mobileag.studio import enable_studio
from mobileag.studio.routes import DISABLED

@pytest.fixture
def studio(monkeypatch):
    web=importlib.import_module('mobileag.web.app')
    monkeypatch.setattr(web.app.state,'studio_enabled',False,raising=False)
    enable_studio(web.app)
    return TestClient(web.app,base_url='http://127.0.0.1'),web,{'Authorization':'Bearer '+web.app.state.auth_token}


def archive(entries):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w') as z:
        for k,v in entries.items():z.writestr(k,v)
    return out.getvalue()


def test_catalog_covers_registered_api_and_retired_actions(studio):
    c,web,h=studio
    assert c.get('/api/studio/catalog').status_code==401
    response=c.get('/api/studio/catalog',headers=h);assert response.status_code==200
    data=response.json();ops={x['id']:x for x in data['operations']}
    expected={method.upper()+' '+path for path,methods in web.app.openapi()['paths'].items() if path.startswith('/api/') and path!='/api/studio/catalog' for method in methods if method in {'get','post','put','patch','delete'}}
    assert set(ops)==expected
    for op in ops.values():
        assert op['group'] and op['effect']
        assert bool(op['disabled_reason'])==(op['path'] in DISABLED)
    assert 'ConfirmationEvidence' in data['schemas']
    assert web.app.state.auth_token not in response.text
    assert 'OPENAI_API_KEY' not in response.text  # configuration values never enter static schema
    assert len(data['cli_mapping'])==9


def test_importers_match_cli_projection_and_never_confirm(studio):
    c,web,h=studio
    sarif={'version':'2.1.0','runs':[{'tool':{'driver':{'name':'synthetic'}},'results':[{'ruleId':'R1','message':{'text':'review only'}}]}]}
    raw=json.dumps(sarif).encode()
    assert c.post('/api/studio/import/sarif',files={'file':('input.sarif',raw)}).status_code==401
    response=c.post('/api/studio/import/sarif',headers=h,files={'file':('input.sarif',raw)})
    assert response.status_code==200,response.text
    from mobileag.reporting.sarif_importer import import_sarif
    actual=response.json();reference=import_sarif(raw)
    assert actual['imported_candidates']==reference['imported_candidates']==1
    assert all(f['status']=='UNVERIFIED' for f in actual['findings'])
    raw=json.dumps({'code_analysis':{'findings':{}}}).encode()
    response=c.post('/api/studio/import/mobsf',headers=h,files={'file':('mobsf.json',raw)})
    assert response.status_code==200,response.text
    assert web.repository().page()[1]==0


@pytest.mark.parametrize('route',['sarif','mobsf'])
def test_invalid_import_error_does_not_echo_input(studio,route):
    c,_,h=studio
    response=c.post('/api/studio/import/'+route,headers=h,files={'file':('invalid.json',b'private-secret-not-json')})
    assert response.status_code==422 and 'private-secret' not in response.text


def test_aab_inventory_same_engine_no_extraction(studio):
    c,_,h=studio
    data=archive({'BundleConfig.pb':b'synthetic','base/manifest/AndroidManifest.xml':b'synthetic'})
    r=c.post('/api/studio/inventory/aab',headers=h,files={'file':('../../unsafe.aab',data)})
    assert r.status_code==200,r.text
    assert r.json()['module_count']==1
    assert r.json()['analysis_state']=='input_inventory_only_not_analyzed'
    r=c.post('/api/studio/inventory/aab',headers=h,files={'file':('a.aab',archive({'../escape':b'bad'}))})
    assert r.status_code==422


def test_reports_normalize_evidence_and_reject_bad_paths(studio):
    c,web,h=studio
    web.repository().save({'scan_id':'scan_report','status':'completed','package_name':'org.example','version':'1','findings':[{'id':'f','title':'<script>test</script>','status':'CONFIRMED'}]})
    r=c.get('/api/studio/scans/scan_report/report',headers=h)
    assert r.status_code==200 and r.json()['findings'][0]['status']=='UNVERIFIED'
    r=c.get('/api/studio/scans/scan_report/report?format=markdown',headers=h)
    assert r.status_code==200 and '    ' in r.text
    assert r.headers['content-type'].startswith('text/markdown')
    assert 'attachment' in r.headers['content-disposition']
    assert c.get('/api/studio/scans/scan_report/report?format=html',headers=h).status_code==422


def test_cli_adapter_uploads_use_generated_paths_and_isolated_entry(studio,monkeypatch):
    c,_,h=studio
    calls=[]
    async def fake(operation,path,request):
        assert Path(path).is_file()
        calls.append((operation,str(path)))
        return {'operation':operation,'proof_status':'not_proven'}
    monkeypatch.setattr('mobileag.studio.jobs.local_tool',fake)
    r=c.post('/api/studio/taint/source-archive',headers=h,files={'file':('../../evil.zip',archive({'src/Main.java':'class Main {}'}))})
    assert r.status_code==200 and calls[0][0]=='taint'
    data=archive({'AndroidManifest.xml':'<manifest/>'})
    r=c.post('/api/studio/compare/apks',headers=h,files={'old_file':('old.apk',data),'new_file':('new.apk',data)})
    assert r.status_code==200 and calls[1][0]=='diff'
    assert all(not Path(path).exists() for _,path in calls)
    r=c.post('/api/studio/compare/apks',headers=h,files={'old_file':('old.apk',b'invalid'),'new_file':('new.apk',data)})
    assert r.status_code==422 and len(calls)==2


def test_source_worker_validates_paths_and_runs_bounded_engine(tmp_path):
    from mobileag.studio.worker import execute
    source=tmp_path/'source.zip';source.write_bytes(archive({'src/Main.java':'class Main { void f() {} }','README.txt':'not source'}))
    work=tmp_path/'work';work.mkdir()
    execute('taint',source,work)
    data=json.loads((work/'result.json').read_text())
    assert data['selected_source_files']==1 and data['non_source_members']==1
    assert data['proof_status']=='not_proven'
    import hashlib
    assert data['adapter_provenance']['input_sha256']==hashlib.sha256(source.read_bytes()).hexdigest()
    bad=tmp_path/'bad.zip';bad.write_bytes(archive({'../Bad.java':'class Bad {}'}))
    with pytest.raises(ValueError):execute('taint',bad,tmp_path/'badwork')
    assert not (tmp_path/'Bad.java').exists()


def test_adapter_fails_closed_without_namespace(studio,monkeypatch):
    c,web,h=studio
    def unavailable(*args):raise RuntimeError('sandbox unavailable')
    monkeypatch.setattr('mobileag.studio.jobs.sandbox_command',unavailable)
    r=c.post('/api/studio/taint/source-archive',headers=h,files={'file':('src.zip',archive({'A.java':'class A {}'}))})
    assert r.status_code==503 and 'No unsafe fallback' in r.text
    assert web.app.state.studio_job_active is False


def test_new_upload_limits_require_length_and_stay_authenticated(studio):
    c,_,h=studio
    assert c.post('/api/studio/inventory/aab',headers=h,files={'file':('empty.aab',b'')}).status_code==422
    assert c.post('/api/studio/import/sarif',headers={**h,'content-length':str(17*1024*1024)},content=b'x').status_code==413


def test_adapter_busy_rejects_without_spawning(studio,monkeypatch):
    c,web,h=studio
    monkeypatch.setattr(web.app.state,'studio_job_active',True,raising=False)
    r=c.post('/api/studio/taint/source-archive',headers=h,files={'file':('src.zip',archive({'A.java':'class A {}'}))})
    assert r.status_code==409


@pytest.mark.asyncio
async def test_adapter_session_revocation_kills_worker_and_cleans_up(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from mobileag.studio import jobs
    web=importlib.import_module('mobileag.web.app')
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(studio_job_active=False)))
    checks=[];folders=[];killed=[]
    def guard(request):
        checks.append(True)
        if len(checks)>1:raise HTTPException(401,'Session expired')
    class Process:
        pid=999999999
        returncode=None
        async def wait(self):self.returncode=-9;return -9
    async def spawn(*args,**kwargs):return Process()
    def sandbox(work,artifact):folders.append(work);return ['fake','worker']
    monkeypatch.setattr(web,'require_current_session',guard)
    monkeypatch.setattr(jobs,'sandbox_command',sandbox)
    monkeypatch.setattr(jobs,'resource_command',lambda command,name:command)
    monkeypatch.setattr(jobs.asyncio,'create_subprocess_exec',spawn)
    monkeypatch.setattr(jobs.os,'killpg',lambda pid,sig:killed.append(pid))
    with pytest.raises(HTTPException) as error:
        await jobs.local_tool('taint',tmp_path/'synthetic.zip',request)
    assert error.value.status_code==401
    assert killed==[999999999] and all(not folder.exists() for folder in folders)
    assert request.app.state.studio_job_active is False
