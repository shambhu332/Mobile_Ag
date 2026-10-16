"""Post-review fixes: synthetic fixtures and mocked egress/device boundaries only."""
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from config.settings import Settings
from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.llm.providers.base import LLMResponse
from mobileag.analysis.secret_scanner import SecretScanner
from mobileag.dast.ui_crawler import UICrawler
from mobileag.web.repository import ScanRepository, private_write
from tests.proof_fixtures import confirmation_evidence

web = importlib.import_module('mobileag.web.app')

@pytest.fixture
def client():
    return TestClient(web.app, headers={'Authorization':'Bearer '+web.app.state.auth_token})


def fixture_scan(sid='scan_one', status='completed'):
    return {'scan_id':sid, 'package_name':'org.example.synthetic', 'status':status,
            'version':'1.0','artifact_sha256':'a'*64,'revision':0, 'created_at':'2026-10-05', 'stats':{'total':1},
            'findings':[{'id':'same-rule','status':'UNVERIFIED','title':'Synthetic review candidate'}]}


def test_scoped_triage_survives_new_repository_and_stale_worker(client):
    repo=web.repository();repo.save(fixture_scan());repo.save(fixture_scan('scan_two'))
    assert client.post('/api/findings/same-rule/feedback', json={'verdict':'FALSE_POSITIVE'}).status_code == 409
    route='/api/scans/scan_one/findings/same-rule/feedback'
    assert client.post(route, json={'verdict':'CONFIRMED','revision':0}).status_code == 422
    result=client.post(route, json={'verdict':'CONFIRMED','notes':'Synthetic observed impact and prerequisites', 'revision':0, 'evidence':confirmation_evidence()})
    assert result.status_code == 200 and result.json()['revision'] == 1
    assert ScanRepository(web.OUTPUT_DIR).get('scan_one')['findings'][0]['status'] == 'CONFIRMED'
    assert ScanRepository(web.OUTPUT_DIR).get('scan_two')['findings'][0]['status'] == 'UNVERIFIED'
    assert repo.save(fixture_scan())['revision'] == 1  # stale worker cannot overwrite analyst revision
    assert client.post(route, json={'verdict':'FALSE_POSITIVE','revision':0}).status_code == 409
    history=client.get('/api/scans/scan_one/decisions').json()['decisions']
    assert len(history)==1 and history[0]['verdict']=='CONFIRMED'


def test_legacy_import_keeps_original(client):
    scan=fixture_scan();original=web.OUTPUT_DIR/'scan_one'/'dashboard.json'
    private_write(original,scan);before=original.read_bytes()
    r=client.post('/api/scans/scan_one/findings/same-rule/feedback', json={'verdict':'FALSE_POSITIVE'})
    assert r.status_code==200
    assert client.get('/api/scans/scan_one').json()['findings'][0]['status']=='FALSE_POSITIVE'
    assert original.read_bytes()==before


def test_running_feedback_blocked(client):
    web.repository().save(fixture_scan(status='running'))
    assert client.post('/api/scans/scan_one/findings/same-rule/feedback',json={'verdict':'FALSE_POSITIVE'}).status_code==409


def test_paginated_scan_summary_excludes_findings(client):
    for i in range(4):web.repository().save(fixture_scan('scan_'+str(i)))
    r=client.get('/api/scans?offset=1&limit=2&summaries=true').json()
    assert r['total']==4 and len(r['items'])==2
    assert all('findings' not in item for item in r['items'])
    assert client.get('/api/scans?limit=101').status_code==422


@pytest.mark.parametrize('transaction',[
    {'url':[]}, {'url':'https://example.invalid','request_headers':[]},
    {'url':'https://example.invalid','request_headers':{'X':123}},
    {'url':'https://example.invalid','response_status':700},
])
def test_nested_capture_validation(client,transaction):
    assert client.post('/api/dast/traffic/audit',json={'transactions':[transaction]}).status_code==422


def test_settings_durable_and_cloud_requires_approval(client,monkeypatch):
    assert client.get('/api/settings').json()['offline'] is True
    assert client.post('/api/settings',json={'offline':False}).status_code==422
    assert client.post('/api/settings',json={'entropy_threshold':3.25}).status_code==200
    monkeypatch.setattr(web,'RUNTIME_SETTINGS',{})
    assert client.get('/api/settings').json()['entropy_threshold']==3.25


def test_browser_script_boundary_and_packaged_assets():
    anon=TestClient(web.app)
    r=anon.get('/')
    assert r.status_code==200
    assert 'script-src' in r.headers['content-security-policy']
    script_policy=r.headers['content-security-policy'].split('script-src',1)[1].split(';',1)[0]
    assert 'unsafe-inline' not in script_policy and 'unsafe-eval' not in script_policy
    assert r.headers['x-frame-options']=='DENY'
    assert anon.get('/static/dashboard.js').status_code==200
    assert anon.get('/static/theme.js').status_code==200
    assert anon.get('/api/scans').status_code==401


@pytest.mark.asyncio
async def test_credentials_never_sent_by_secret_scanner(tmp_path):
    candidate='AKIA'+'Z'*16
    (tmp_path/'Synthetic.java').write_text('String key="'+candidate+'";')
    router=SimpleNamespace(route=AsyncMock())
    findings=await SecretScanner(router).scan(str(tmp_path))
    assert findings and candidate not in json.dumps([f.to_dict() for f in findings])
    router.route.assert_not_awaited()


@pytest.mark.asyncio
async def test_router_redacts_fallback_and_consensus():
    settings=Settings(_env_file=None,offline=False, approved_llm_providers=[])
    router=LLMRouter(settings)
    good=LLMResponse(content='synthetic response',provider='openai',model='test',success=True)
    one=SimpleNamespace(name='openai',model='test',generate=AsyncMock(return_value=LLMResponse.from_error('openai','test','synthetic error')))
    two=SimpleNamespace(name='gemini_pro',model='test',generate=AsyncMock(return_value=good))
    router._providers={'openai':one,'gemini_pro':two}
    candidate='ghp_'+'A'*36
    await router.route(TaskType.API_ANALYSIS,candidate,candidate)
    await router.route_to_multiple(TaskType.CONSENSUS_VOTE,candidate,candidate,count=2)
    for provider in (one,two):
        assert provider.generate.await_count==2
        for call in provider.generate.call_args_list:
            assert candidate not in str(call)
    # Injection of mocks here validates egress masking, not initialization approval.


def test_unapproved_providers_not_initialized():
    with patch('mobileag.llm.router._PROVIDER_CLASSES',{'openai':AsyncMock()}):
        router=LLMRouter(Settings(_env_file=None,offline=False,OPENAI_API_KEY='synthetic',approved_llm_providers=[]))
        assert router.get_available_providers()==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('package',['com.outside.app','com.android.permissioncontroller',''])
async def test_ui_observer_does_not_act_outside_package(package):
    adb=SimpleNamespace(_exec_cmd=AsyncMock())
    crawler=UICrawler(adb)
    crawler.dump_ui_hierarchy=AsyncMock(return_value=f'<hierarchy><node package="{package}" text="Allow" clickable="true" bounds="[1,1][10,10]"/></hierarchy>')
    result=await crawler.crawl_app('synthetic-serial','org.example.synthetic',guard=lambda: None)
    assert result['status']=='blocked' and result['buttons_clicked']==0
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_intended_package_observation_never_taps_or_fills():
    adb=SimpleNamespace(_exec_cmd=AsyncMock())
    crawler=UICrawler(adb)
    crawler.dump_ui_hierarchy=AsyncMock(return_value='<hierarchy><node package="org.example.synthetic" text="Submit" clickable="true" bounds="[1,1][10,10]"/></hierarchy>')
    result=await crawler.crawl_app('synthetic-serial','org.example.synthetic',guard=lambda: None)
    assert result['status']=='observed' and result['planned_actions'][0]['requires_explicit_review']
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_ui_observer_fails_closed_without_scope_and_mutation_helpers_are_inert():
    adb=SimpleNamespace(_exec_cmd=AsyncMock())
    crawler=UICrawler(adb)
    result=await crawler.crawl_app('synthetic-serial','org.example.synthetic')
    assert result['status']=='blocked'
    await crawler.tap_element('synthetic-serial',(100,200))
    await crawler.input_text('synthetic-serial','synthetic text')
    adb._exec_cmd.assert_not_awaited()


@pytest.mark.asyncio
async def test_comments_cannot_silently_remove_review_candidates(tmp_path):
    from mobileag.filters.pipeline import FilterPipeline
    from mobileag.reporting.finding import Finding, Severity
    settings=Settings(_env_file=None,offline=True,confidence_threshold=1.0)
    pipeline=FilterPipeline(LLMRouter(settings),settings=settings)
    priorities=[]
    for comments in ('','// checkCallingPermission SecureRandom ContentValues ? Base64.encode'):
        file=tmp_path/'Synthetic.java';file.write_text(comments+'\nclass Synthetic {}')
        finding=Finding(title='Synthetic',description='Synthetic',severity=Severity.HIGH,file_path=str(file),line_number=2,cwe_id='CWE-89')
        results=await pipeline.filter_findings([finding],str(tmp_path))
        assert len(results)==1 and results[0].status.value=='UNVERIFIED'
        assert results[0].metadata['below_review_priority_threshold'] is True
        priorities.append(results[0].review_priority)
        assert results[0].review_priority is not None
        assert results[0].metadata['filter_stages']['historical']['status']=='unavailable'
        assert results[0].metadata['filter_stages']['consensus']['status']=='not_run'
        assert results[0].metadata['assessment'].startswith('Heuristic review priority')
        assert results[0].false_positive_reasons == []
        assert results[0].metadata['review_priority_disposition'] == 'below_threshold_candidate_retained'
    assert priorities[0] == priorities[1]


@pytest.mark.asyncio
async def test_filter_ranking_does_not_demote_analyst_status_or_overwrite_triage(tmp_path):
    from mobileag.filters.pipeline import FilterPipeline
    from mobileag.reporting.finding import Finding, FindingStatus, Severity
    settings=Settings(_env_file=None,offline=True,confidence_threshold=1.0)
    pipeline=FilterPipeline(LLMRouter(settings),settings=settings)
    finding=Finding(title='Attested finding',description='Synthetic',severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,false_positive_reasons=['analyst triage record'],
                    file_path='Synthetic.java',line_number=1,cwe_id='CWE-89')
    results=await pipeline.filter_findings([finding],str(tmp_path))
    assert len(results)==1
    assert results[0].status is FindingStatus.CONFIRMED
    assert results[0].false_positive_reasons == ['analyst triage record']
    assert results[0].metadata['review_priority_disposition']=='below_threshold_candidate_retained'


def test_private_snapshot_and_database_permissions(tmp_path):
    repo=ScanRepository(tmp_path/'metadata');repo.save(fixture_scan())
    path=tmp_path/'metadata'/'original.json';private_write(path,fixture_scan())
    assert repo.path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_mode & 0o777 == 0o600


def test_scan_records_original_hash_and_effective_policy(client):
    import hashlib
    import io
    import zipfile
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as archive:
        archive.writestr('AndroidManifest.xml','<manifest package="org.example.synthetic"/>')
    original=stream.getvalue()
    uploaded=client.post('/api/upload/apk',files={'file':('synthetic.apk',original)}).json()
    assert client.post('/api/settings',json={'entropy_threshold':3.25}).status_code==200
    with patch.object(web,'Orchestrator') as orchestrator:
        orchestrator.return_value.scan=AsyncMock(return_value={'package_name':'org.example.synthetic','filtered_findings':[], 'coverage':{'synthetic_fixture':1}})
        response=client.post('/api/scans/run',json={'apk_path':uploaded['file_path']})
    assert response.status_code==200
    scan=client.get('/api/scans/'+response.json()['scan_id']).json()
    assert scan['artifact_sha256']==hashlib.sha256(original).hexdigest()
    assert scan['analysis_policy']['offline'] is True
    assert scan['analysis_policy']['entropy_threshold']==3.25
    assert scan['analysis_policy']['approved_llm_providers']==[]
    assert Path(uploaded['file_path']).read_bytes()==original
    assert Path(uploaded['file_path']).stat().st_mode & 0o777 == 0o600


def test_provider_status_matches_effective_approval():
    settings=Settings(_env_file=None,offline=False,OPENAI_API_KEY='synthetic',GEMINI_API_KEY='synthetic',approved_llm_providers=['gemini_pro'])
    assert settings.enabled_providers==['gemini_pro']
    assert settings.model_copy(update={'offline':True}).enabled_providers==[]


def test_unknown_field_content_does_not_reintroduce_inline_js():
    from re import search
    root=Path(web.__file__).parent
    for path in [root/'templates'/'index.html',*list((root/'static').glob('*.js'))]:
        assert search(r'(?<!data-)\bon(?:click|change|input|keydown|drop|dragover|dragleave)\s*=',path.read_text()) is None
