"""Synthetic state-machine + owned loopback HTTP validation. No device commands."""
import asyncio
import importlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import AsyncMock,MagicMock
import pytest
from fastapi.testclient import TestClient
from mobileag.automation.android import parse_snapshot,AndroidDriver
from mobileag.automation.engine import AutomationService
from mobileag.automation.models import CreateRun,ExecuteRun,Capture
from mobileag.automation.report import layout_svg
from mobileag.automation.store import Conflict
from mobileag.dast.adb_manager import ADBManager

web=importlib.import_module('mobileag.web.app')
ORIGINAL_EXEC=ADBManager._exec_cmd
PACKAGE='org.example.synthetic'

def screen(name='Home',bounds='[10,10][200,90]',duplicate=False,secret='device-secret-should-never-persist'):
    rid='profile' if name=='Home' else 'settings'
    nodes=f'<node package="{PACKAGE}" class="android.widget.Button" resource-id="{PACKAGE}:id/{rid}" text="{rid.title()}" clickable="true" enabled="true" bounds="{bounds}"/>'
    if duplicate:nodes+=nodes
    if name!='Home':nodes+=f'<node package="{PACKAGE}" class="android.widget.Button" resource-id="{PACKAGE}:id/delete" text="Delete account" clickable="true" bounds="[10,100][200,180]"/>'
    nodes+=f'<node package="{PACKAGE}" class="android.widget.EditText" text="{secret}" password="true" resource-id="{PACKAGE}:id/password" bounds="[10,200][200,280]"/>'
    return parse_snapshot('<hierarchy>'+nodes+'</hierarchy>',PACKAGE)

class Driver:
    def __init__(self):self.state='Home';self.calls=[];self.snapshots=0;self.callback=None
    async def snapshot(self):
        self.snapshots+=1
        if self.callback:await self.callback(self)
        return screen(self.state)
    async def act(self,action,element=None):
        self.calls.append((action,element))
        self.state='Home' if action=='back' else 'Profile'

def request(**kw):
    data={'serial':'emulator-5554','package_name':PACKAGE,'component':PACKAGE+'/.Main',
          'environment':'synthetic','dedicated_account_confirmed':True,'dedicated_device_confirmed':True,'max_steps':2,'max_requests':4,'request_interval_seconds':.5}
    return CreateRun(**{**data,**kw})

@pytest.fixture
def setup(monkeypatch):
    driver=Driver()
    svc=AutomationService(lambda:web.OUTPUT_DIR,lambda:web.repository().get_policy(),lambda t:t==web.app.state.auth_token,
                          lambda serial,package:driver)
    monkeypatch.setattr(web.app.state,'automation_service',svc,raising=False)
    return svc,driver,web.app.state.auth_token

async def batch(svc,doc,token,**kw):
    req=ExecuteRun(revision=doc['revision'],confirmation=doc['id'],**kw)
    active=await svc.execute(doc['id'],req,token)
    task=svc.tasks[doc['id']];await task
    return svc.store().get(active['id'])

@pytest.mark.asyncio
async def test_observation_map_private_layout_and_generated_not_executed(setup):
    svc,driver,token=setup
    doc=await svc.create(request(),token)
    assert doc['status']=='awaiting_review' and not driver.calls
    report=svc.get_report(doc['id'])
    assert report['executive_summary']['executed']==0 and report['untested']
    assert all(not row['ui_tested'] and not row['api_tested'] for row in report['coverage'])
    assert 'device-secret' not in json.dumps(doc) and 'device-secret' not in layout_svg(doc['screens'][0])
    assert report['executive_summary']['production_readiness_score'] is None

@pytest.mark.asyncio
async def test_approved_navigation_pauses_at_unknown_new_screen(setup):
    svc,driver,token=setup;doc=await svc.create(request(),token)
    aid=next(a['id'] for a in doc['actions'] if not a['blocked_reason'])
    result=await batch(svc,doc,token,approved_action_ids=[aid])
    assert len(driver.calls)==1 and result['status']=='awaiting_review'
    assert len(result['screens'])==2 and len(result['edges'])==1
    assert result['results'][0]['executed'] is True
    assert svc.get_report(doc['id'])['untested']
    delete=next(a for a in result['actions'] if a['blocked_reason'] and 'impactful' in a['blocked_reason'])
    with pytest.raises(ValueError):await batch(svc,result,token,approved_action_ids=[delete['id']])

@pytest.mark.asyncio
async def test_stale_revision_and_duplicate_approvals_fail_closed(setup):
    svc,driver,token=setup;doc=await svc.create(request(),token)
    aid=next(a['id'] for a in doc['actions'] if not a['blocked_reason'])
    with pytest.raises(ValueError):await batch(svc,doc,token,approved_action_ids=[aid,aid])
    await svc.observe(doc['id'],doc['revision'],token)
    with pytest.raises(Conflict):await batch(svc,doc,token,approved_action_ids=[aid])
    assert not driver.calls

@pytest.mark.asyncio
async def test_scope_revocation_before_input(setup):
    svc,driver,token=setup;doc=await svc.create(request(),token)
    aid=next(a['id'] for a in doc['actions'] if not a['blocked_reason'])
    async def revoke(d):
        if d.snapshots>=2:
            p=web.repository().get_policy();p['actions']=[];web.repository().save_policy(p)
    driver.callback=revoke
    result=await batch(svc,doc,token,approved_action_ids=[aid])
    assert result['status']=='paused' and not driver.calls

@pytest.mark.asyncio
async def test_ambiguous_missing_locators_never_automated(setup):
    svc,driver,token=setup
    driver.snapshot=AsyncMock(return_value=screen(duplicate=True))
    doc=await svc.create(request(),token)
    assert all(a['blocked_reason'] for a in doc['actions'])
    with pytest.raises(ValueError):await batch(svc,doc,token,approved_action_ids=[doc['actions'][0]['id']])
    assert not driver.calls

@pytest.mark.asyncio
async def test_foreground_escape_and_consent_stop(setup):
    svc,driver,token=setup
    driver.snapshot=AsyncMock(side_effect=PermissionError('outside'))
    doc=await svc.create(request(),token)
    assert doc['status']=='paused' and not driver.calls
    with pytest.raises(PermissionError):parse_snapshot('<hierarchy><node package="android" text="Allow"/></hierarchy>',PACKAGE)
    with pytest.raises(ValueError):parse_snapshot('<bad',PACKAGE)

@pytest.mark.asyncio
async def test_position_healing_requires_same_unique_screen_locator(setup):
    svc,driver,token=setup;doc=await svc.create(request(max_steps=1),token)
    aid=next(a['id'] for a in doc['actions'] if not a['blocked_reason'])
    original=driver.snapshot
    async def moved():
        result=await original()
        if driver.snapshots==3:return screen(bounds='[20,20][210,100]')
        return result
    driver.snapshot=moved
    result=await batch(svc,doc,token,approved_action_ids=[aid])
    assert result['steps'][0]['locator_changed'] and driver.calls[0][1]['bounds']==[20,20,210,100]

@pytest.mark.asyncio
async def test_cancel_and_device_concurrency(setup):
    svc,driver,token=setup;doc=await svc.create(request(),token)
    aid=next(a['id'] for a in doc['actions'] if not a['blocked_reason'])
    waiting=asyncio.Event();release=asyncio.Event()
    async def pause(d):
        if d.snapshots==2:waiting.set();await release.wait()
    driver.callback=pause
    await svc.execute(doc['id'],ExecuteRun(revision=doc['revision'],confirmation=doc['id'],approved_action_ids=[aid]),token)
    task=svc.tasks[doc['id']];await waiting.wait()
    with pytest.raises(Conflict):await svc.create(request(),token)
    svc.cancel(doc['id']);release.set();await task
    assert svc.store().get(doc['id'])['status']=='cancelled' and not driver.calls
    assert not svc.busy and not svc.tasks

@pytest.mark.asyncio
async def test_wall_budget_and_restart_no_replay(setup):
    svc,driver,token=setup;doc=await svc.create(request(),token);svc.wall_seconds=.05
    async def slow(d):await asyncio.sleep(1)
    driver.callback=slow
    result=await batch(svc,doc,token)
    assert result['status']=='paused' and not driver.calls
    previous=result['revision'];result.update(status='running',revision=previous+1);svc.store().save(result,previous)
    svc.store().recover();assert svc.store().get(doc['id'])['status']=='interrupted' and not driver.calls

@pytest.fixture
def server(monkeypatch):
    state={'broken':False,'seen':[]}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state['seen'].append((time.monotonic(),self.headers.get('Authorization'),self.path))
            status=200 if self.headers.get('Authorization') or state['broken'] else 401
            body=json.dumps({'data':{'id':'owned-test-id','token':'response-secret-must-not-persist'},'unexpected-secret-value-as-key':'value'}).encode()
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Set-Cookie','secret-cookie');self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin=f'http://127.0.0.1:{server.server_port}'
    monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS',origin);monkeypatch.setenv('MOBILEAG_ALLOW_PRIVATE_TARGETS','1')
    policy=web.repository().get_policy();policy['origins']=[origin];policy['methods']=['GET'];web.repository().save_policy(policy)
    yield origin,state
    server.shutdown();server.server_close();thread.join(timeout=2)

@pytest.mark.asyncio
async def test_real_loopback_api_auth_redaction_rate_and_retest(setup,server):
    svc,driver,token=setup;origin,state=server
    capture=Capture(url=origin+'/profile?q=query-secret',read_only_confirmed=True,protected=True,response_status=200,query_names=['q'])
    doc=await svc.create(request(captures=[capture]),token)
    selected=[t['id'] for t in doc['tests'] if t['kind']=='api' and t['variant'] in {'baseline','unauthenticated'}]
    result=await batch(svc,doc,token,approved_api_cases=selected,test_authorization='Bearer explicit-owned-fixture-token')
    assert result['request_count']==2 and all(r['result']=='passed' for r in result['results'])
    assert state['seen'][0][1] and state['seen'][1][1] is None
    assert state['seen'][1][0]-state['seen'][0][0]>=.49
    stored=json.dumps(result);assert all(s not in stored for s in ['query-secret','explicit-owned-fixture-token','response-secret','unexpected-secret-value-as-key','secret-cookie','/profile'])
    state['broken']=True
    before=await svc.create(request(captures=[capture]),token)
    anonymous=next(t['id'] for t in before['tests'] if t['variant']=='unauthenticated')
    before=await batch(svc,before,token,approved_api_cases=[anonymous])
    assert before['observations'][0]['verification_status'].startswith('Dynamically observed lead')
    assert svc.get_report(before['id'])['executive_summary']['confirmed_security_issues']==0
    state['broken']=False
    after=await svc.create(request(captures=[capture],parent_run_id=before['id']),token)
    after=await batch(svc,after,token,approved_api_cases=[anonymous])
    assert svc.get_report(after['id'])['regression'][0]['verification_status']=='Assertion now passes'
    assert 'not proof' in svc.get_report(after['id'])['regression'][0]['boundary']

@pytest.mark.asyncio
async def test_not_executed_budget_missing_token_and_restart_targets(setup,server):
    svc,driver,token=setup;origin,state=server
    cap=Capture(url=origin+'/owned',read_only_confirmed=True,protected=True)
    doc=await svc.create(request(captures=[cap],max_requests=0),token)
    tid=next(t['id'] for t in doc['tests'] if t['kind']=='api')
    result=await batch(svc,doc,token,approved_api_cases=[tid])
    assert not state['seen'] and not next(c for c in svc.get_report(doc['id'])['coverage'] if c['test_id']==tid)['api_tested']
    svc.targets.clear()
    with pytest.raises(Conflict):await batch(svc,result,token,approved_api_cases=[tid])

@pytest.mark.asyncio
async def test_api_scope_rejected_before_capture_persist(setup):
    svc,driver,token=setup
    with pytest.raises(PermissionError):await svc.create(request(captures=[Capture(url='https://unapproved.example/data',read_only_confirmed=True)]),token)
    assert not svc.store().list() and not driver.calls

def test_router_auth_scope_and_no_hidden_bypass(setup):
    svc,driver,token=setup
    assert TestClient(web.app).get('/api/automation/runs').status_code==401
    client=TestClient(web.app,headers={'Authorization':'Bearer '+token})
    data=request().model_dump(mode='json');data['dedicated_account_confirmed']=False
    assert client.post('/api/automation/runs',json=data).status_code==422
    policy=web.repository().get_policy();policy['actions']=[];web.repository().save_policy(policy)
    assert client.post('/api/automation/runs',json=request().model_dump(mode='json')).status_code==403
    assert not driver.calls

@pytest.mark.asyncio
async def test_adb_cancel_kills_owned_command(monkeypatch):
    entered=asyncio.Event()
    async def blocked():entered.set();await asyncio.sleep(20)
    proc=MagicMock(returncode=None);proc.communicate=AsyncMock(side_effect=blocked);proc.wait=AsyncMock()
    monkeypatch.setattr(asyncio,'create_subprocess_exec',AsyncMock(return_value=proc))
    task=asyncio.create_task(ORIGINAL_EXEC(ADBManager(),['-s','owned','shell','id']))
    await entered.wait();task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    proc.kill.assert_called_once();proc.wait.assert_awaited_once()

@pytest.mark.asyncio
async def test_bounded_local_tool_output_is_not_buffered_without_limit():
    import sys
    manager=ADBManager(adb_path=sys.executable)
    # A controlled Python child, NOT an ADB command or device interaction.
    code,out,error=await ORIGINAL_EXEC(manager,['-c','import sys;sys.stdout.write("A"*2097152)'],output_limit=65536)
    assert code==-1 and out==b'' and b'output limit' in error

@pytest.mark.asyncio
async def test_api_query_variants_are_observed_not_invented_validation_passes(setup,server):
    svc,driver,token=setup;origin,state=server
    cap=Capture(url=origin+'/search?q=original',read_only_confirmed=True,query_names=['q'])
    doc=await svc.create(request(captures=[cap]),token)
    ids=[t['id'] for t in doc['tests'] if t['kind']=='api' and t['variant'].endswith('_query')]
    final=await batch(svc,doc,token,approved_api_cases=ids,test_authorization='Bearer explicit-owned-test')
    assert final['request_count']==3 and len(state['seen'])==3
    assert all(r['result']=='observed' and r['executed'] for r in final['results'])
    assert '?q=' not in state['seen'][0][2] and state['seen'][1][2].endswith('q=')
    assert len(state['seen'][2][2].split('q=')[1])==128

def test_unique_accessibility_label_fallback_and_secret_text_not_a_locator():
    xml=f'<hierarchy><node package="{PACKAGE}" class="android.widget.Button" clickable="true" content-desc="Profile" bounds="[10,10][180,90]"/><node package="{PACKAGE}" class="android.widget.Button" clickable="true" text="secret-personal-value" bounds="[10,100][180,180]"/></hierarchy>'
    snapshot=parse_snapshot(xml,PACKAGE)
    assert snapshot['elements'][0]['locator_kind']=='unique_accessibility_name' and snapshot['elements'][0]['locator']
    assert snapshot['elements'][1]['locator'] is None and 'secret-personal-value' not in json.dumps(snapshot)


def test_curated_uppercase_labels_and_unknown_taps(setup):
    svc,driver,token=setup
    xml=f'<hierarchy><node package="{PACKAGE}" class="android.widget.Button" clickable="true" text="PROFILE" bounds="[10,10][180,90]"/><node package="{PACKAGE}" class="android.widget.Button" resource-id="private-id" clickable="true" text="Execute something" bounds="[10,100][180,180]"/></hierarchy>'
    snapshot=parse_snapshot(xml,PACKAGE)
    assert snapshot['elements'][0]['label']=='Profile'
    doc={'screens':[],'actions':[],'tests':[],'observations':[],'package_name':PACKAGE}
    svc.map_screen(doc,snapshot)
    assert not doc['actions'][0]['blocked_reason']
    assert doc['actions'][1]['blocked_reason'].startswith('Unknown control')

@pytest.mark.asyncio
async def test_adapter_factory_failure_releases_device(setup):
    svc,driver,token=setup;doc=await svc.create(request(),token)
    def fail(*a):raise RuntimeError('private-error-must-not-persist')
    svc.driver_factory=fail
    result=await batch(svc,doc,token)
    assert result['status']=='error' and not svc.busy and not svc.tasks
    assert 'private-error' not in json.dumps(result)
    other=await svc.create(request(),token)
    assert other['status']=='paused' and not svc.busy

@pytest.mark.asyncio
async def test_failed_evidence_write_always_releases_device(setup,monkeypatch):
    svc,driver,token=setup;doc=await svc.create(request(),token)
    def fail(doc):raise ValueError('disk unavailable')
    monkeypatch.setattr(svc,'persist',fail)
    with pytest.raises(ValueError):await batch(svc,doc,token)
    assert not svc.busy and not svc.tasks
    svc.store().recover()
    assert svc.store().get(doc['id'])['status']=='interrupted'

@pytest.mark.asyncio
async def test_router_capture_rebind_after_restart_validates_scope(setup,server):
    svc,driver,token=setup;origin,state=server
    cap=Capture(url=origin+'/owned?q=private-query',read_only_confirmed=True)
    doc=await svc.create(request(captures=[cap]),token);svc.targets.clear()
    client=TestClient(web.app,headers={'Authorization':'Bearer '+token})
    response=client.post(f"/api/automation/runs/{doc['id']}/captures",json={'revision':doc['revision'],'captures':[cap.model_dump()]})
    assert response.status_code==200 and len(response.json()['captures'])==1
    assert svc.targets[doc['id']] and 'private-query' not in response.text
    policy=web.repository().get_policy();policy['origins']=[];web.repository().save_policy(policy)
    svc.targets.clear()
    response=client.post(f"/api/automation/runs/{doc['id']}/captures",json={'revision':response.json()['revision'],'captures':[cap.model_dump()]})
    assert response.status_code==403 and not svc.targets and not state['seen']


def test_invalid_automation_contract_does_not_echo_ephemeral_credential(setup):
    svc,driver,token=setup
    client=TestClient(web.app,headers={'Authorization':'Bearer '+token})
    secret='Bearer private-test-value-not-for-report'
    # Wrong request shape causes the default validator to include the full input.
    response=client.post('/api/automation/runs/auto_'+'a'*32+'/execute',json=[{'test_authorization':secret}])
    assert response.status_code==422 and secret not in response.text
    response=client.post('/api/automation/runs',json={**request().model_dump(),'unknown-secret-field':secret})
    assert response.status_code==422 and secret not in response.text and 'unknown-secret-field' not in response.text
