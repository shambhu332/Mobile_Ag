"""Bounded discover/map/approve/execute/observe/report loop.

The operator approves exact actions/cases. Unknown UI is mapped, never clicked.
Captured credentials are not reused. API tests are read-only and rate-limited.
"""
import asyncio
from datetime import datetime, timezone
import json
import re
import time
import uuid
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
from mobileag.automation.android import digest, AndroidDriver
from mobileag.automation.models import CreateRun, ExecuteRun
from mobileag.automation.store import RunStore, Conflict
from mobileag.automation.report import report
from mobileag.security.network import scoped_request
from mobileag.web.policy import check_action, check_replay
from mobileag.web.security import check_device

VARIANTS=['happy_path','empty_input','invalid_input','boundary','unexpected_state','authentication_state','authorization_state','recovery']
LIMITATIONS=['ADB input is device-wide: package checks are non-atomic guardrails, not isolation; dedicated device authorization is required.',
 'No permission acceptance, root, hooks, credential entry, destructive transactions, writes, account creation or data resets.',
 'Layouts omit pixels/text. Contrast, screen-reader behavior, clipping, app memory, ANRs and native iOS runtime are not assessed.',
 'Imported captures/correlations are operator-declared; no transparent TLS capture, automatic pinning bypass or causal network proof.',
 'Authentication state is operator-declared. Logout/refresh/expired-session/ownership flows need controlled account fixtures; status alone is not proof.',
 'Driver timings include ADB/snapshot overhead. Test assertions do not prove vulnerability impact or production readiness.']

def stamp():return datetime.now(timezone.utc).isoformat()

def safe_shape(value,depth=0):
    if depth>3:return 'nested'
    if isinstance(value,dict):
        return {(k if k in {'status','message','error','data','items','id','profile','name','email','token','access_token','count','user','users','role','permissions','success'} else 'field_'+digest(str(k))):safe_shape(v,depth+1) for k,v in list(value.items())[:30]}
    if isinstance(value,list):return {'type':'array','length':len(value),'item':safe_shape(value[0],depth+1) if value else None}
    return type(value).__name__

class RunCancelled(Exception): pass

class AutomationService:
    def __init__(self,output,policy,session_valid,driver_factory,transport=scoped_request,wall_seconds=120):
        self.output,self.policy,self.session_valid=output,policy,session_valid
        self.driver_factory,self.transport=driver_factory,transport
        self.tasks={};self.busy=set();self.targets={}
        self.wall_seconds=min(120,max(.05,wall_seconds))
    def store(self):return RunStore(self.output())
    def guard(self,doc,token,execute=False):
        if not self.session_valid(token):raise PermissionError('Session expired or rotated; reconnect and review')
        if execute and doc.get('status')=='running' and self.store().get(doc['id']).get('cancel_requested'):raise RunCancelled()
        action='automation_execute' if execute else 'automation_observe'
        if not check_device(doc['serial']) or not check_action(self.policy(),action,doc):raise PermissionError('Device/package/action scope was revoked or not approved')
    def persist(self,doc):
        latest=self.store().get(doc['id']);old=latest['revision']
        doc['cancel_requested']=latest.get('cancel_requested',False)
        doc['revision']=old+1;self.store().save(doc,old)
    def captures(self,doc,captures):
        if len(doc['captures'])+len(captures)>10:raise ValueError('Capture budget exceeded')
        added=[]
        for c in captures:
            parsed=urlsplit(c.url)
            if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError('Capture URL must be scoped HTTP(S), without credentials/fragments')
            if any(re.search(r'(?i)(token|password|secret|authorization|api.?key|session|cookie)',k) for k,v in parse_qsl(parsed.query)):
                raise ValueError('Credential-bearing URLs cannot be automated; use an ephemeral test Authorization header')
            if not check_replay(self.policy(),c.url,c.method):raise PermissionError('Captured endpoint is outside saved origin/method scope')
            # Also enforce environment ceilings before any planned request.
            from mobileag.web.security import configured_list
            origin=f'{parsed.scheme}://{parsed.netloc}'
            if origin not in configured_list('MOBILEAG_ALLOWED_ORIGINS'):raise PermissionError('Captured origin is outside server scope')
            cid=digest(c.method+' '+c.url)
            if any(x['id']==cid for x in doc['captures']):raise ValueError('Duplicate capture')
            names=[k for k in c.query_names if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,32}',k) and not re.search('(?i)(token|secret|password|key|session|cookie)',k)]
            meta={'id':cid,'origin':origin,'method':c.method,'label':'Imported request '+str(len(doc['captures'])+1),
                  'query_names':names,'imported_status':c.response_status,'protected':c.protected,
                  'provenance':'operator_import_not_independently_verified','ui_action_id':c.ui_action_id,
                  'curl':f'curl --request {c.method} "$TEST_ENDPOINT_{cid}" --header "Authorization: Bearer $TEST_TOKEN"'}
            doc['captures'].append(meta);added.append((cid,c.url))
            variants=['baseline']+(['unauthenticated'] if c.protected else [])+(['missing_query','empty_query','boundary_query'] if names else [])
            for variant in variants:
                doc['tests'].append({'id':cid+'_'+variant,'kind':'api','feature':meta['label'],'variant':variant,'capture_id':cid,'priority':'P1' if c.protected else 'P2'})
            if c.ui_action_id:
                linked=any(s['action_id']==c.ui_action_id for s in doc['steps'])
                doc['correlations'].append({'capture_id':cid,'ui_action_id':c.ui_action_id,'linked_to_recorded_action':linked,'confidence':'operator_declared_not_causal_proof'})
        return added
    def map_screen(self,doc,snapshot):
        if not any(s['id']==snapshot['id'] for s in doc['screens']):
            if len(doc['screens'])>=60 or sum(len(s['elements']) for s in doc['screens'])+len(snapshot['elements'])>1500:raise ValueError('Screen/node budget exhausted')
            doc['screens'].append(snapshot)
        doc['current_screen']=snapshot['id']
        existing={a['id'] for a in doc['actions']}
        for e in snapshot['elements']:
            if not e['clickable'] and not e['scrollable'] and not e['editable']:continue
            action='scroll' if e['scrollable'] else 'tap'
            aid=digest(snapshot['id']+str(e['locator'])+action+e['class'])
            if aid in existing:continue
            count=sum(x['locator']==e['locator'] for x in snapshot['elements'])
            reason=('Credential/form input requires operator-prepared state' if e['editable'] else
                    'State-changing toggle is not navigation; prepare state manually' if e['class'] in {'Switch','CheckBox','RadioButton','Spinner'} else
                    'Potentially impactful/consent control is not automated' if e['dangerous'] else
                    'Unknown control semantics; prepare and inspect manually' if action=='tap' and e['label']=='Control' else
                    'Locator missing, ambiguous, disabled or has no safe geometry' if not e['locator'] or count!=1 or not e['bounds'] or not e['enabled'] else None)
            if len(doc['actions'])>=80:raise ValueError('Generated-action budget exhausted')
            doc['actions'].append({'id':aid,'screen':snapshot['id'],'locator':e['locator'],'class':e['class'],'label':e['label'],
                'action':action,'blocked_reason':reason,'original_bounds':e['bounds']})
            for variant in VARIANTS:
                doc['tests'].append({'id':aid+'_'+variant,'kind':'ui','feature':e['label'],'screen':snapshot['id'],'action_id':aid,
                    'variant':variant,'priority':'P1' if e['label'] in {'Login','Log in','Sign in','Register','Profile','Settings'} else 'P2',
                    'blocked_reason':reason or (None if variant=='happy_path' else 'Needs explicit test data/state and behavior assertions; generation is not execution')})
        for index,e in enumerate(snapshot['elements']):
            if e['clickable'] and not e['named']:
                oid=digest(snapshot['id']+str(index)+'name')
                if len(doc['observations'])<80 and not any(o['id']==oid for o in doc['observations']):
                    doc['observations'].append({'id':oid,'finding':'Potential unnamed interactive control','severity':'Informational','confidence':.5,'component':doc['package_name'],'screen':snapshot['id'],'api':None,'root_cause':'Accessible relationships cannot be determined from hierarchy alone','evidence':{'element_index':index},'impact':'May confuse assistive technology users','recommended_fix':'Verify accessible name/label relationships with the platform accessibility tooling','regression_test':'Human screen-reader navigation plus accessibility instrumentation','verification_status':'UX recommendation, not confirmed WCAG failure'})
    async def create(self,req:CreateRun,token):
        if req.serial in self.busy or len(self.busy)>=2:raise Conflict('Device busy or concurrent run limit reached')
        if not re.fullmatch(re.escape(req.package_name)+r'/(?:\.[\w.$]+|'+re.escape(req.package_name)+r'\.[\w.$]+)',req.component):raise ValueError('Component must belong to the exact package')
        doc={'id':'auto_'+uuid.uuid4().hex,'serial':req.serial,'package_name':req.package_name,'component':req.component,
             'environment':req.environment,'auth_state':req.auth_state,'auth_state_source':'operator_declared',
             'max_steps':req.max_steps,'max_requests':req.max_requests,'request_interval_seconds':req.request_interval_seconds,
             'status':'discovering','revision':0,'created_at':stamp(),'current_screen':None,'screens':[],'edges':[],'actions':[],
             'captures':[],'tests':[],'steps':[],'results':[],'observations':[],'correlations':[],'measurements':[],
             'request_count':0,'cancel_requested':False,'limitations':LIMITATIONS,'parent_run_id':req.parent_run_id}
        self.guard(doc,token)
        if req.parent_run_id:
            parent=self.store().get(req.parent_run_id)
            if parent['package_name']!=req.package_name or parent['environment']!=req.environment:raise ValueError('Regression baseline must match app/environment')
        targets=self.captures(doc,req.captures)
        self.busy.add(req.serial)
        try:
            self.store().save(doc)
            self.targets[doc['id']]=dict(targets)
            start=time.monotonic()
            try:
                driver=self.driver_factory(req.serial,req.package_name)
                snapshot=await driver.snapshot()
                if hasattr(driver,'metadata'):doc['device_metadata']=await driver.metadata()
                else:doc['device_metadata']={'coverage':'synthetic adapter; build/root/version not observed'}
                self.guard(doc,token);self.map_screen(doc,snapshot)
                doc.update(status='awaiting_review',reason='Review exact controls/cases before execution')
            except Exception:
                doc.update(status='paused',reason='Scoped foreground/hierarchy unavailable; resolve on device, then observe again')
            doc['measurements'].append({'kind':'snapshot_driver_elapsed_ms','value':round((time.monotonic()-start)*1000,2)})
            self.persist(doc)
            return doc
        finally:self.busy.discard(req.serial)
    async def observe(self,rid,revision,token):
        doc=self.store().get(rid)
        if doc['revision']!=revision or doc['status'] in {'running','discovering'} or doc['serial'] in self.busy:raise Conflict('Run changed or device busy')
        self.guard(doc,token);self.busy.add(doc['serial'])
        try:
            snapshot=await self.driver_factory(doc['serial'],doc['package_name']).snapshot()
            self.guard(doc,token);self.map_screen(doc,snapshot);doc.update(status='awaiting_review',reason='New snapshot; review exact actions')
            self.persist(doc);return doc
        finally:self.busy.discard(doc['serial'])
    async def execute(self,rid,req:ExecuteRun,token):
        doc=self.store().get(rid);self.guard(doc,token,True)
        if req.confirmation!=rid:raise ValueError('Explicit run-ID confirmation required')
        actions={a['id']:a for a in doc['actions']}
        tests={t['id']:t for t in doc['tests'] if t['kind']=='api'}
        if len(set(req.approved_action_ids))!=len(req.approved_action_ids) or any(x not in actions or actions[x]['blocked_reason'] for x in req.approved_action_ids):raise ValueError('Action is unknown, unsafe or ambiguous')
        if any(x not in tests for x in req.approved_api_cases) or len(set(req.approved_api_cases))!=len(req.approved_api_cases):raise ValueError('Unknown or duplicate API test')
        if req.approved_api_cases and any(tests[x]['capture_id'] not in self.targets.get(rid,{}) for x in req.approved_api_cases):raise Conflict('Targets were not retained across restart; re-import scoped capture URLs')
        if doc['serial'] in self.busy or len(self.busy)>=2:raise Conflict('Device busy or concurrent limit reached')
        doc=self.store().claim(rid,req.revision);self.busy.add(doc['serial'])
        task=asyncio.create_task(self.run(doc,req,token));self.tasks[rid]=task
        return doc
    async def run(self,doc,req,token):
        stack=[];used={s['action_id'] for s in doc['steps']};api_done={r['test_id'] for r in doc['results'] if r.get('executed')}
        try:
            driver=self.driver_factory(doc['serial'],doc['package_name'])
            async with asyncio.timeout(self.wall_seconds):
                while len(doc['steps'])<doc['max_steps']:
                    self.guard(doc,token,True)
                    if self.store().get(doc['id']).get('cancel_requested'):doc['status']='cancelled';return
                    snapshot=await driver.snapshot();self.guard(doc,token,True);self.map_screen(doc,snapshot)
                    choices=[a for a in doc['actions'] if a['id'] in req.approved_action_ids and a['id'] not in used and a['screen']==snapshot['id'] and not a['blocked_reason']]
                    if not choices:
                        if stack and req.allow_back:
                            before=snapshot['id'];start=time.monotonic();await driver.act('back');after=await driver.snapshot();self.guard(doc,token,True)
                            self.map_screen(doc,after);stack.pop()
                            doc['steps'].append({'action_id':'back_'+str(len(doc['steps'])),'action':'back','from':before,'to':after['id'],'at':stamp(),'elapsed_ms':round((time.monotonic()-start)*1000,2)})
                            self.persist(doc);continue
                        break
                    a=choices[0]
                    # Re-resolve immediately against a fresh in-scope snapshot. No guessing.
                    fresh=await driver.snapshot();self.guard(doc,token,True)
                    if fresh['id']!=snapshot['id']:raise PermissionError('Screen changed before input; review again')
                    matches=[e for e in fresh['elements'] if e['locator']==a['locator'] and e['class']==a['class']]
                    if len(matches)!=1 or matches[0]['dangerous'] or matches[0]['editable'] or not matches[0]['enabled'] or not matches[0]['bounds'] or not matches[0]['clickable' if a['action']=='tap' else 'scrollable']:raise PermissionError('Locator became unsafe or ambiguous')
                    before=snapshot['id'];start=time.monotonic();await driver.act(a['action'],matches[0]);after=await driver.snapshot();self.guard(doc,token,True)
                    self.map_screen(doc,after);used.add(a['id'])
                    step={'action_id':a['id'],'action':a['action'],'from':before,'to':after['id'],'at':stamp(),'elapsed_ms':round((time.monotonic()-start)*1000,2),
                          'locator_changed':matches[0]['bounds']!=a['original_bounds'],'locator_confidence':1.0,'healing':'same unique approved locator and class; position re-resolved' if matches[0]['bounds']!=a['original_bounds'] else None}
                    doc['steps'].append(step);doc['edges'].append({'from':before,'to':after['id'],'action_id':a['id']})
                    if after['id']!=before:stack.append(before)
                    doc['results'].append({'test_id':a['id']+'_happy_path','result':'passed','evidence':step,'executed':True,'assertion':'Input acknowledged and in-package hierarchy observed; not business/security correctness'})
                    doc['measurements'].append({'kind':'UI_driver_elapsed_ms','value':step['elapsed_ms'],'action_id':a['id']});self.persist(doc)
                for tid in req.approved_api_cases:
                    if tid in api_done:continue
                    if self.store().get(doc['id']).get('cancel_requested'):doc['status']='cancelled';return
                    self.guard(doc,token,True)
                    await self.api_case(doc,tid,req.test_authorization.get_secret_value() if req.test_authorization else None,token)
                    self.persist(doc)
                doc['status']='completed' if not any(a['id'] not in used and not a['blocked_reason'] for a in doc['actions']) else 'awaiting_review'
                doc['reason']='Batch finished; coverage distinguishes generated, executed and untested cases'
        except asyncio.CancelledError:
            doc.update(status='interrupted',reason='Task stopped; issued input cannot be undone; no automatic continuation')
            raise
        except RunCancelled:doc.update(status='cancelled',reason='Operator stopped the run; no automatic continuation')
        except asyncio.TimeoutError:doc.update(status='paused',reason='120-second batch budget reached; no automatic retry')
        except (PermissionError,ValueError,Conflict):doc.update(status='paused',reason='Scope, foreground, locator, transport or evidence boundary failed; operator review required')
        except Exception:doc.update(status='error',reason='Automation adapter failed; raw error/credentials were not retained')
        finally:
            try:self.persist(doc)
            finally:
                self.busy.discard(doc['serial']);self.tasks.pop(doc['id'],None)
    async def api_case(self,doc,tid,authorization,token,guard=None):
        test=next(t for t in doc['tests'] if t['id']==tid);capture=next(c for c in doc['captures'] if c['id']==test['capture_id'])
        url=self.targets[doc['id']][capture['id']];p=urlsplit(url);variant=test['variant']
        headers={}
        if authorization and variant!='unauthenticated':
            if len(authorization)>4096 or '\n' in authorization or '\r' in authorization:raise ValueError('Invalid test Authorization')
            if p.scheme!='https' and p.hostname not in {'127.0.0.1','localhost','::1'}:raise PermissionError('Test credentials require HTTPS except explicit loopback fixtures')
            headers['Authorization']=authorization
        if variant in {'missing_query','empty_query','boundary_query'}:
            names=set(capture['query_names']);pairs=[(k,v) for k,v in parse_qsl(p.query,keep_blank_values=True) if k not in names]
            if variant!='missing_query':pairs.extend((n,'' if variant=='empty_query' else 'Q'*128) for n in sorted(names))
            url=urlunsplit((p.scheme,p.netloc,p.path,urlencode(pairs),''))
        if not check_replay(self.policy(),url,capture['method']):raise PermissionError('API replay scope revoked')
        if doc['request_count']>=doc['max_requests']:
            doc['results'].append({'test_id':tid,'result':'inconclusive','executed':False,'reason':'Request budget exhausted; not executed'});return
        if variant=='baseline' and capture['protected'] and not authorization:
            doc['results'].append({'test_id':tid,'result':'inconclusive','executed':False,'reason':'Explicit ephemeral test-account authorization missing; not executed'});return
        await asyncio.sleep(doc['request_interval_seconds'])
        (guard or (lambda:self.guard(doc,token,True)))()
        if not check_replay(self.policy(),url,capture['method']):raise PermissionError('API replay scope changed')
        doc['request_count']+=1;start=time.monotonic()
        try:result=await self.transport(url,capture['method'],headers=headers)
        except PermissionError:raise
        except Exception:
            doc['results'].append({'test_id':tid,'result':'inconclusive','executed':False,'request_attempted':True,'reason':'Transport failed or timed out; no response/secret was retained'})
            raise ValueError('API transport unavailable')
        status=result['status_code'];elapsed=round((time.monotonic()-start)*1000,2)
        try:shape=safe_shape(json.loads(result.get('body','')))
        except (ValueError,TypeError):shape='non_json_or_truncated'
        if len(json.dumps(shape).encode())>8192:shape='omitted_shape_budget'
        assertion='401/403 for operator-declared protected request' if variant=='unauthenticated' else 'Imported baseline status' if variant=='baseline' and capture['imported_status'] else 'Response observed; no correctness oracle supplied'
        passed=status in {401,403} if variant=='unauthenticated' else status==capture['imported_status'] if variant=='baseline' and capture['imported_status'] else None
        receipt={'test_id':tid,'executed':True,'result':'passed' if passed is True else 'failed' if passed is False else 'observed',
            'status_code':status,'elapsed_ms':elapsed,'response_shape':shape,'auth_mechanism':'operator_supplied_test_header' if headers else 'none',
            'provenance':'agent_read_only_replay','assertion':assertion,'redirect_followed':False,'response_body_retained':False}
        doc['results'].append(receipt);doc['measurements'].append({'kind':'API_driver_elapsed_ms','value':elapsed,'test_id':tid})
        if variant=='unauthenticated' and status in range(200,300):
            doc['observations'].append({'id':digest(tid),'finding':'Anonymous 2xx on operator-declared protected endpoint','severity':'Informational','confidence':.5,
                'component':doc['package_name'],'screen':None,'api':capture['id'],'root_cause':'Not determined; server authorization/data sensitivity need validation',
                'evidence':receipt,'impact':'Potential exposure, not demonstrated ownership or protected-data impact','recommended_fix':'Verify server-side authorization with owned baselines; preserve intentionally public functionality',
                'regression_test':tid,'verification_status':'Dynamically observed lead; not a confirmed vulnerability'})
    def cancel(self,rid):
        doc=self.store().get(rid)
        if doc['status']!='running':raise Conflict('Run is not active')
        doc['cancel_requested']=True;old=doc['revision'];doc['revision']+=1;self.store().save(doc,old)
        return doc
    def get_report(self,rid):
        doc=self.store().get(rid)
        parent=self.store().get(doc['parent_run_id']) if doc.get('parent_run_id') else None
        return report(doc,parent)
