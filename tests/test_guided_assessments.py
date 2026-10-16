"""Synthetic guided orchestration, approval boundaries and mocked vendor APIs."""
import asyncio
import importlib
import json
import zipfile
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from mobileag.assessments.models import Assessment
from mobileag.assessments.service import AssessmentService
from mobileag.automation.models import CreateRun
from mobileag.llm.broker import LLMBroker,aggregate,catalog,PROVIDERS
from mobileag.automation.android import parse_snapshot
from mobileag.automation.engine import AutomationService
web=importlib.import_module('mobileag.web.app')
PKG='org.example.synthetic'

def plan(apk,**kw):
    data={'apk_path':str(apk),'package_name':PKG,'scope':{'devices':[],'packages':[PKG],'origins':[],'methods':['GET','HEAD'],'actions':[]},
          'authorized':True,'scope_change_confirmed':True,'confirmation':'START SCOPED TESTS'}
    return Assessment(**{**data,**kw})

@pytest.fixture
def setup(monkeypatch):
    apk=web.UPLOAD_DIR/'synthetic.apk'
    with zipfile.ZipFile(apk,'w') as z:z.writestr('AndroidManifest.xml','<manifest package="'+PKG+'"/>');z.writestr('classes.dex',b'dex\n035\x00synthetic')
    result={'scan_id':'scan_guided_fixture','status':'completed','package_name':PKG,'findings':[]}
    async def static(apk,linked):await linked(result['scan_id']);return result
    driver=AsyncMock();driver.snapshot.return_value=parse_snapshot(f'<hierarchy><node package="{PKG}" text="Profile" resource-id="profile" class="android.widget.Button" clickable="true" bounds="[10,10][150,60]"/></hierarchy>',PKG)
    driver.metadata.return_value={'adapter':'mocked; no actual device'}
    auto=AutomationService(lambda:web.OUTPUT_DIR,lambda:web.repository().get_policy(),lambda t:t==web.app.state.auth_token,lambda *a:driver)
    svc=AssessmentService(lambda:web.OUTPUT_DIR,lambda:web.UPLOAD_DIR,web.repository,lambda t:t==web.app.state.auth_token,
        AsyncMock(side_effect=static),lambda:auto,web.adb_manager,LLMBroker(AsyncMock()),web.hash_file)
    monkeypatch.setattr(web.app.state,'assessment_service',svc,raising=False)
    return svc,apk,result,driver,web.app.state.auth_token

async def finish(svc,request,token):
    doc=await svc.create(request,token);await svc.tasks[doc['id']];return svc.store().get(doc['id'])

@pytest.mark.asyncio
async def test_guided_static_without_device_or_ai(setup):
    svc,apk,result,driver,token=setup
    doc=await finish(svc,plan(apk),token)
    assert doc['status']=='completed' and doc['stages']['sast']['status']=='completed'
    assert doc['stages']['api']['status']=='not_selected' and doc['stages']['dast']['status']=='not_selected'
    driver.snapshot.assert_not_called();svc.broker.transport.assert_not_called()
    assert not svc.tasks and 'api_authorization' not in json.dumps(doc)

@pytest.mark.asyncio
async def test_package_mismatch_blocks_all_live_stages(setup):
    svc,apk,result,driver,token=setup;result['package_name']='outside.app'
    scope={'devices':['emulator-5554'],'packages':[PKG],'origins':[],'methods':['GET'],'actions':['automation_observe','launch']}
    doc=await finish(svc,plan(apk,dast=True,serial='emulator-5554',component=PKG+'/.Main',dedicated_device_confirmed=True,dedicated_account_confirmed=True,launch=True,scope=scope),token)
    assert doc['status']=='paused' and doc['stages']['dast']['status']=='not_executed'
    web.adb_manager._exec_cmd.assert_not_called();driver.snapshot.assert_not_called()

@pytest.mark.asyncio
async def test_partial_static_does_not_become_live_pass(setup):
    svc,apk,result,driver,token=setup;result['status']='partial'
    doc=await finish(svc,plan(apk),token)
    assert doc['status']=='error' and doc['stages']['sast']['status']=='partial'
    driver.snapshot.assert_not_called()

@pytest.mark.asyncio
async def test_scope_and_model_ceiling_fail_before_static_or_mutation(setup):
    svc,apk,result,driver,token=setup
    with pytest.raises(ValueError):await svc.create(plan(apk,scope={'devices':['outside'],'packages':[PKG],'origins':[],'methods':['GET'],'actions':[]}),token)
    with pytest.raises(PermissionError):await svc.create(plan(apk,llm_provider='openai',llm_metadata_egress_confirmed=True),token)
    svc.static_runner.assert_not_called();assert not svc.store().list()

@pytest.mark.asyncio
async def test_dast_mapping_is_live_observation_not_automatic_taps(setup):
    svc,apk,result,driver,token=setup
    scope={'devices':['emulator-5554'],'packages':[PKG],'origins':[],'methods':['GET'],'actions':['automation_observe']}
    doc=await finish(svc,plan(apk,dast=True,serial='emulator-5554',component=PKG+'/.Main',dedicated_device_confirmed=True,dedicated_account_confirmed=True,scope=scope),token)
    assert doc['status']=='awaiting_action_review' and doc['stages']['dast']['screens']==1
    driver.snapshot.assert_awaited_once();driver.act.assert_not_called()

@pytest.mark.asyncio
async def test_install_cannot_replace_or_grant_or_escape_scope(setup):
    svc,apk,result,driver,token=setup
    scope={'devices':['emulator-5554'],'packages':[PKG],'origins':[],'methods':['GET'],'actions':['automation_observe','install']}
    web.adb_manager._exec_cmd.return_value=(0,b'package:/existing.apk',b'')
    doc=await finish(svc,plan(apk,dast=True,serial='emulator-5554',component=PKG+'/.Main',dedicated_device_confirmed=True,dedicated_account_confirmed=True,install_if_absent=True,scope=scope),token)
    assert doc['status']=='error' and web.adb_manager._exec_cmd.await_count==1
    driver.snapshot.assert_not_called()

@pytest.mark.asyncio
async def test_cancel_and_restart_never_resume(setup):
    svc,apk,result,driver,token=setup;entered=asyncio.Event();release=asyncio.Event()
    async def slow(apk,linked):await linked(result['scan_id']);entered.set();await release.wait();return result
    svc.static_runner=slow
    doc=await svc.create(plan(apk),token);await entered.wait();task=svc.tasks[doc['id']]
    svc.cancel(doc['id']);release.set();await task
    assert svc.store().get(doc['id'])['status']=='cancelled' and not svc.tasks
    doc=svc.store().get(doc['id']);doc['status']='running';svc.store().save(doc);svc.store().recover()
    assert svc.store().get(doc['id'])['status']=='interrupted';driver.snapshot.assert_not_called()

@pytest.mark.asyncio
async def test_guided_api_is_independent_of_device_and_redacts(setup,monkeypatch):
    svc,apk,result,driver,token=setup;origin='https://owned-staging.example'
    monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS',origin)
    mock=AsyncMock(return_value={'status_code':401,'body':'{"token":"private-response"}'})
    # Patch the shared constructor default through the class method transport
    # boundary, not any scope/authorization implementation.
    original=AutomationService.api_case
    async def local_case(service,*a,**k):service.transport=mock;return await original(service,*a,**k)
    monkeypatch.setattr(AutomationService,'api_case',local_case)
    request=plan(apk,api=True,dedicated_account_confirmed=True,api_authorization='Bearer private-account',
        scope={'devices':[],'packages':[PKG],'origins':[origin],'methods':['GET'],'actions':[]},
        captures=[{'url':origin+'/profile?q=private-query','read_only_confirmed':True,'protected':True,'response_status':200}])
    doc=await finish(svc,request,token)
    assert doc['status']=='completed' and doc['stages']['api']['executed']==2
    assert 'private-account' not in json.dumps(doc) and 'private-query' not in json.dumps(doc) and 'private-response' not in json.dumps(doc)
    assert mock.await_count==2;driver.snapshot.assert_not_called();web.adb_manager._exec_cmd.assert_not_called()

@pytest.mark.asyncio
async def test_bad_capture_rejected_before_scope_save_or_sast(setup,monkeypatch):
    svc,apk,result,driver,token=setup;origin='https://owned-staging.example';monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS',origin)
    before=web.repository().get_policy()
    with pytest.raises(ValueError):await svc.create(plan(apk,api=True,dedicated_account_confirmed=True,scope={'devices':[],'packages':[PKG],'origins':[origin],'methods':['GET'],'actions':[]},captures=[{'url':origin+'/profile?token=secret','read_only_confirmed':True}]),token)
    assert web.repository().get_policy()==before;svc.static_runner.assert_not_called()

def test_assessment_router_auth_and_contract_privacy(setup):
    svc,apk,result,driver,token=setup
    assert TestClient(web.app).get('/api/assessments').status_code==401
    client=TestClient(web.app,headers={'Authorization':'Bearer '+token})
    response=client.post('/api/assessments',json=[{'api_authorization':'private-test-header'}])
    assert response.status_code==422 and 'private-test-header' not in response.text
    cat=client.get('/api/assessments/providers').json()
    assert len(cat['providers'])==10 and not any(p['enabled'] for p in cat['providers'])
    assert 'not contacted' in cat['health']

@pytest.mark.parametrize('provider',list(PROVIDERS))
@pytest.mark.asyncio
async def test_all_provider_adapters_protocol_shape_and_metadata_only(provider,monkeypatch):
    spec=PROVIDERS[provider];monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS',provider)
    monkeypatch.setenv('MOBILEAG_LLM_'+provider.upper()+'_MODEL','synthetic-test-model')
    if spec[4]:monkeypatch.setenv(spec[4],'private-provider-key')
    if provider in {'ollama','local_openai'}:monkeypatch.setenv('MOBILEAG_LLM_LOCAL_ORIGINS',spec[2])
    advice='private-provider-key advice' if spec[4] else 'Local advice without credential'
    value={'candidates':[{'content':{'parts':[{'text':advice}]}}]} if provider=='gemini' else {'content':[{'type':'text','text':advice}]} if provider=='claude' else {'message':{'content':advice}} if provider=='ollama' else {'choices':[{'message':{'content':advice}}]}
    transport=AsyncMock(return_value={'status_code':200,'body':json.dumps(value)})
    result=await LLMBroker(transport).review(provider,aggregate({'status':'completed','findings':[{'severity':'high','description':'private-source'}]}),lambda:None)
    args,kwargs=transport.call_args;body=json.loads(kwargs['body'])
    assert args[1]=='POST' and kwargs['allowed_origins']=={spec[2]} and kwargs['loopback_only']==(provider in {'ollama','local_openai'})
    assert 'private-source' not in json.dumps(body) and 'private-provider-key' not in json.dumps(body)
    assert 'private-provider-key' not in result['advice'] and not result['tools_executed']
    assert all('key' not in row for row in catalog()['providers'])

@pytest.mark.asyncio
async def test_broker_denied_arbitrary_metadata_and_scope_without_network(monkeypatch):
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS','openai');monkeypatch.setenv('OPENAI_API_KEY','private-provider-key');monkeypatch.setenv('MOBILEAG_LLM_OPENAI_MODEL','test-model')
    transport=AsyncMock();broker=LLMBroker(transport)
    with pytest.raises(ValueError):await broker.review('openai',{**aggregate({'status':'completed','findings':[]}),'source':'private'},lambda:None)
    assert not broker.busy;transport.assert_not_called()
    def denied():raise PermissionError()
    with pytest.raises(PermissionError):await broker.review('openai',aggregate({'status':'completed','findings':[]}),denied)
    transport.assert_not_called()

@pytest.mark.asyncio
async def test_real_local_model_transport_uses_separate_origin_scope(monkeypatch):
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import threading
    observed=[]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            observed.append((self.path,json.loads(self.rfile.read(int(self.headers['Content-Length']))),self.headers.get('Authorization')))
            body=json.dumps({'choices':[{'message':{'content':'Synthetic local model advice'}}]}).encode()
            self.send_response(200);self.end_headers();self.wfile.write(body)
        def log_message(self,*a):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin=f'http://127.0.0.1:{server.server_port}'
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS','local_openai');monkeypatch.setenv('MOBILEAG_LLM_LOCAL_OPENAI_MODEL','synthetic-model')
    monkeypatch.setenv('MOBILEAG_LLM_LOCAL_OPENAI_ORIGIN',origin);monkeypatch.setenv('MOBILEAG_LLM_LOCAL_ORIGINS',origin)
    monkeypatch.setenv('MOBILEAG_LOCAL_LLM_KEY','synthetic-local-key')
    try:
        result=await LLMBroker().review('local_openai',aggregate({'status':'completed','findings':[]}),lambda:None)
        assert result['advice']=='Synthetic local model advice' and len(observed)==1 and observed[0][0]=='/v1/chat/completions'
        assert observed[0][2]=='Bearer synthetic-local-key'
        assert not observed[0][1].get('tools') and 'model' in observed[0][1]
    finally:server.shutdown();server.server_close();thread.join(timeout=2)

@pytest.mark.asyncio
async def test_local_model_dns_cannot_resolve_outside_loopback(monkeypatch):
    import socket
    from mobileag.security.network import scoped_request
    loop=asyncio.get_running_loop()
    monkeypatch.setattr(loop,'getaddrinfo',AsyncMock(return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',1234))]))
    with pytest.raises(PermissionError):await scoped_request('http://localhost:1234/v1/chat/completions','POST',allowed_origins={'http://localhost:1234'},allow_private=True,loopback_only=True)

@pytest.mark.asyncio
async def test_non_replacing_install_command_never_uses_r_or_g(setup):
    svc,apk,result,driver,token=setup
    web.adb_manager._exec_cmd.return_value=(0,b'Success',b'')
    await web.adb_manager.install_apk('emulator-5554',str(apk),grant_permissions=False,replace=False,guard=lambda: True)
    args=web.adb_manager._exec_cmd.call_args[0][0]
    assert '-r' not in args and '-g' not in args

@pytest.mark.asyncio
async def test_large_response_shape_is_bounded(setup,monkeypatch):
    svc,apk,result,driver,token=setup;origin='https://owned-staging.example';monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS',origin)
    body=json.dumps({'data':{str(i):{str(j):'value' for j in range(30)} for i in range(30)}})
    original=AutomationService.api_case
    async def local_case(service,*a,**k):service.transport=AsyncMock(return_value={'status_code':200,'body':body});return await original(service,*a,**k)
    monkeypatch.setattr(AutomationService,'api_case',local_case)
    doc=await finish(svc,plan(apk,api=True,dedicated_account_confirmed=True,scope={'devices':[],'packages':[PKG],'origins':[origin],'methods':['GET'],'actions':[]},captures=[{'url':origin+'/owned','read_only_confirmed':True}]),token)
    assert doc['stages']['api']['results'][0]['response_shape']=='omitted_shape_budget'
    assert doc['stages']['api']['results'][0]['executed']

@pytest.mark.asyncio
async def test_concurrent_create_cannot_bypass_reservation(setup,monkeypatch):
    svc,apk,result,driver,token=setup
    import mobileag.assessments.service as module
    original=asyncio.to_thread
    # Force both creates to await at validation before returning to reservation.
    entered=0;release=asyncio.Event()
    async def coordinated(fn,*args,**kw):
        nonlocal entered
        if fn is module.validate_archive:
            entered+=1
            if entered==2:release.set()
            await release.wait()
        return await original(fn,*args,**kw)
    monkeypatch.setattr(module.asyncio,'to_thread',coordinated)
    waiting=asyncio.Event()
    async def slow(apk,linked):await waiting.wait();return result
    svc.static_runner=slow
    responses=await asyncio.gather(svc.create(plan(apk),token),svc.create(plan(apk),token),return_exceptions=True)
    assert sum(isinstance(r,ValueError) for r in responses)==1 and len(svc.tasks)==1
    tasks=list(svc.tasks.values());waiting.set();await asyncio.gather(*tasks)
    assert not svc.tasks

@pytest.mark.parametrize('provider', list(PROVIDERS))
def test_provider_catalog_has_specific_setup_without_secrets(provider, monkeypatch):
    from mobileag.llm.broker import configured
    row = next(row for row in catalog()['providers'] if row['id'] == provider)
    assert not row['enabled']
    assert provider in row['reason'] and 'MOBILEAG_LLM_ALLOWED_PROVIDERS' in row['reason']
    assert row['setup']['model_variable'] == 'MOBILEAG_LLM_' + provider.upper() + '_MODEL'
    spec = PROVIDERS[provider]
    if spec[4]:
        assert row['setup']['key_variable'] == spec[4]
        monkeypatch.setenv(spec[4], 'synthetic-private-provider-key-never-in-catalog')
    monkeypatch.setenv('MOBILEAG_LLM_' + provider.upper() + '_MODEL', 'synthetic-exact-model')
    if provider in {'ollama', 'local_openai'}:
        monkeypatch.setenv('MOBILEAG_LLM_LOCAL_ORIGINS', spec[2])
        assert row['setup']['default_origin'] == spec[2]
    assert 'synthetic-private-provider-key-never-in-catalog' not in json.dumps(catalog())
    assert not configured(provider)['enabled']  # Key/model alone never approve egress.
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS', provider)
    assert configured(provider)['enabled'] and configured(provider)['reason'] is None


def test_catalog_reasons_distinguish_missing_model_key_and_bad_configuration(monkeypatch):
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS', 'openai')
    row = next(row for row in catalog()['providers'] if row['id'] == 'openai')
    assert 'MOBILEAG_LLM_OPENAI_MODEL' in row['reason'] and 'OPENAI_API_KEY' in row['reason']
    monkeypatch.setenv('MOBILEAG_LLM_OPENAI_MODEL', 'synthetic-model')
    row = next(row for row in catalog()['providers'] if row['id'] == 'openai')
    assert row['reason'] == 'Set OPENAI_API_KEY privately on the server'
    monkeypatch.setenv('OPENAI_API_KEY', 'synthetic-invalid\nprivate-value')
    row = next(row for row in catalog()['providers'] if row['id'] == 'openai')
    assert row['reason'] == 'Invalid server configuration' and not row['enabled']
    assert row['setup']['key_variable'] == 'OPENAI_API_KEY'
    assert 'private-value' not in json.dumps(catalog())


def test_catalog_publishes_enforced_limits_not_usage_or_credentials():
    from mobileag.llm.broker import OUTPUT_TOKEN_LIMIT, REQUEST_TIMEOUT_SECONDS, TRANSPORT_TIMEOUT_SECONDS
    limits=catalog()['limits']
    assert limits == {'max_attempts':2,'output_token_limit':OUTPUT_TOKEN_LIMIT,
        'request_timeout_seconds':REQUEST_TIMEOUT_SECONDS,'transport_timeout_seconds':TRANSPORT_TIMEOUT_SECONDS,
        'fallback_trigger':'HTTP 429 only','usage':'not metered'}
    assert (OUTPUT_TOKEN_LIMIT,REQUEST_TIMEOUT_SECONDS,TRANSPORT_TIMEOUT_SECONDS)==(1024,25,15)
