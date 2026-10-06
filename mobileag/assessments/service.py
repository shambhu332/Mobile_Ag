"""One approved assessment: isolated SAST → scoped API → DAST map → optional AI.

No raw worker source reaches the broker; discovery does not grant execution.
"""
import asyncio
import re
import uuid
from pathlib import Path
from datetime import datetime,timezone
from mobileag.assessments.store import AssessmentStore
from mobileag.web.policy import validate_policy,check_action,check_replay
from mobileag.web.security import check_device,configured_list
from mobileag.automation.android import digest
from mobileag.automation.models import CreateRun,ExecuteRun
from mobileag.security.archives import validate_archive
from mobileag.llm.broker import aggregate,configured

class AssessmentCancelled(Exception):pass

class AssessmentService:
    def __init__(self,output,uploads,repository,session_valid,static_runner,automation,adb,broker,hash_file):
        self.output,self.uploads,self.repository,self.session_valid=output,uploads,repository,session_valid
        self.static_runner,self.automation,self.adb,self.broker,self.hash_file=static_runner,automation,adb,broker,hash_file
        self.tasks={}
    def store(self):return AssessmentStore(self.output())
    def guard(self,doc,token):
        if not self.session_valid(token):raise PermissionError('Session expired/rotated')
        if self.store().get(doc['id']).get('cancel_requested'):raise AssessmentCancelled()
        current=self.repository().get_policy()
        # Never expand the originally approved scope because Settings changed.
        if any(not set(doc['scope'][k])<=set(current.get(k,[])) for k in doc['scope']):raise PermissionError('Assessment scope revoked')
        if not set(doc['scope']['devices'])<=configured_list('MOBILEAG_ALLOWED_DEVICES') or not set(doc['scope']['origins'])<=configured_list('MOBILEAG_ALLOWED_ORIGINS'):raise PermissionError('Server scope revoked')
    async def create(self,req,token):
        if not self.session_valid(token):raise PermissionError('Session unavailable')
        if len(self.tasks)>=1:raise ValueError('One guided assessment at a time')
        apk=Path(req.apk_path).resolve()
        if not apk.is_relative_to(self.uploads().resolve()) or apk.is_symlink():raise ValueError('Select an immutable dashboard upload')
        if await asyncio.to_thread(validate_archive,apk)!='android':raise ValueError('Guided live assessment currently requires an Android APK')
        policy=validate_policy(req.scope.model_dump())
        if req.package_name not in policy['packages']:raise PermissionError('APK package must be approved in scope')
        if req.api:
            if not req.captures or not req.dedicated_account_confirmed:raise ValueError('API stage needs explicit read-only captures and dedicated account confirmation')
            for c in req.captures:
                if not check_replay(policy,c.url,c.method):raise PermissionError('API capture outside approved scope')
            self.api_plan(req,policy)  # Validate URLs/privacy before saving or starting SAST.
        elif req.captures:raise ValueError('Select API testing before providing captures')
        if req.dast:
            if not req.serial or not req.component or not req.dedicated_device_confirmed or not req.dedicated_account_confirmed:raise ValueError('DAST needs exact dedicated device, account and component')
            if not check_device(req.serial) or not re.fullmatch(re.escape(req.package_name)+r'/(?:\.[\w.$]+|'+re.escape(req.package_name)+r'\.[\w.$]+)',req.component):raise PermissionError('Invalid scoped DAST device/component')
            data={'serial':req.serial,'package_name':req.package_name}
            if not check_action(policy,'automation_observe',data):raise PermissionError('DAST observation scope required')
            for enabled,action in [(req.install_if_absent,'install'),(req.launch,'launch')]:
                if enabled and not check_action(policy,action,{**data,'component':req.component}):raise PermissionError('Install/launch needs explicit device-wide approval')
        elif req.install_if_absent or req.launch:raise ValueError('Install/launch requires DAST')
        if req.llm_provider:
            if not req.llm_metadata_egress_confirmed or not configured(req.llm_provider)['enabled']:raise PermissionError('AI stage needs explicit aggregate-metadata approval and server-configured provider')
        sha=await asyncio.to_thread(self.hash_file,apk)
        # Reserve only after awaited validation/hash: concurrent creates cannot
        # both pass the one-assessment limit and replace each other's policy.
        if self.tasks:raise ValueError('One guided assessment at a time')
        doc={'id':'assess_'+uuid.uuid4().hex,'status':'running','created_at':datetime.now(timezone.utc).isoformat(),
            'package_name':req.package_name,'artifact_sha256':sha,'scope':policy,'cancel_requested':False,'scan_id':None,'automation_run_id':None,
            'stages':{name:{'status':'queued' if enabled else 'not_selected'} for name,enabled in [('sast',True),('api',req.api),('dast',req.dast),('llm',bool(req.llm_provider))]},
            'limitations':['SAST candidates are not confirmed vulnerabilities.','DAST maps in-package UI; taps require later exact action approval.','API tests are read-only operator-imported requests, not transparent capture.','AI receives aggregate counts only, never executes actions.']}
        # The UI explicitly approves replacing global scope. Saved policy is also
        # used by every subsequent legacy operation; not a client-only allowlist.
        self.store().save(doc);self.repository().save_policy(policy)
        self.tasks[doc['id']]=asyncio.create_task(self.run(doc,req,token,apk))
        return doc
    def persist(self,doc):
        latest=self.store().get(doc['id']);doc['cancel_requested']=latest.get('cancel_requested',False);self.store().save(doc)
    async def run(self,doc,req,token,apk):
        try:
            async with asyncio.timeout(480):
                self.guard(doc,token)
                if await asyncio.to_thread(self.hash_file,apk)!=doc['artifact_sha256']:raise PermissionError('Uploaded artifact changed')
                doc['stages']['sast']['status']='running';self.persist(doc)
                async def linked(sid):doc['scan_id']=sid;self.persist(doc)
                scan=await self.static_runner(apk,linked)
                self.guard(doc,token)
                doc['stages']['sast'].update(status=scan['status'],scan_id=scan['scan_id'])
                self.persist(doc)
                if scan.get('package_name')!=req.package_name:raise PermissionError('Static package differs from explicitly approved package')
                if scan['status']!='completed':raise ValueError('Static analysis incomplete; live stages not started')
                if await asyncio.to_thread(self.hash_file,apk)!=doc['artifact_sha256']:raise PermissionError('Artifact changed after static analysis')
                executed=0;screens=0
                if req.api:
                    doc['stages']['api']['status']='running';self.persist(doc)
                    # API phase has no device adapter or ADB calls. Reuse bounded
                    # capture generation/evidence, but a separate API-only plan.
                    result=await self.api_tests(doc,req,token)
                    executed=sum(bool(r.get('executed')) for r in result['results'])
                    doc['stages']['api'].update(status='completed_with_observations' if result['status'] not in {'paused','error','cancelled'} else result['status'],executed=executed,
                        results=result['results'],observations=result['observations'],untested=max(0,len(result['tests'])-executed));self.persist(doc)
                    if result['status'] in {'paused','error','cancelled'}:raise ValueError('API stage stopped; remaining live phases not started')
                self.guard(doc,token)
                if req.dast:
                    doc['stages']['dast']['status']='running';self.persist(doc)
                    if req.install_if_absent:
                        self.guard(doc,token)
                        if not check_action(self.repository().get_policy(),'install',{'serial':req.serial,'package_name':req.package_name}):raise PermissionError('Install scope revoked')
                        code,present,_=await self.adb._exec_cmd(['-s',req.serial,'shell','pm','path',req.package_name],output_limit=16384)
                        if code not in {0,1}:raise ValueError('Installed package state unavailable')
                        if present.strip():raise ValueError('Refusing to replace an existing package; install-if-absent only')
                        self.guard(doc,token)
                        result=await self.adb.install_apk(req.serial,str(apk),grant_permissions=False,replace=False)
                        if result['status']!='success':raise ValueError('Install failed or timed out')
                    if req.launch:
                        self.guard(doc,token)
                        if not check_action(self.repository().get_policy(),'launch',{'serial':req.serial,'component':req.component}):raise PermissionError('Launch scope revoked')
                        result=await self.adb.launch_activity(req.serial,req.component)
                        if result['status']!='success':raise ValueError('Launch failed')
                    self.guard(doc,token)
                    auto=await self.automation().create(CreateRun(serial=req.serial,package_name=req.package_name,component=req.component,
                        environment='dedicated_staging',dedicated_device_confirmed=True,dedicated_account_confirmed=True,max_steps=req.max_steps,max_requests=0),token)
                    doc['automation_run_id']=auto['id'];screens=len(auto['screens'])
                    doc['stages']['dast'].update(status='awaiting_action_review' if screens else 'paused',screens=screens,run_id=auto['id']);self.persist(doc)
                if req.llm_provider:
                    self.guard(doc,token);doc['stages']['llm']['status']='running';self.persist(doc)
                    try:
                        advice=await self.broker.review(req.llm_provider,aggregate(scan,executed,screens),lambda:self.guard(doc,token))
                        doc['stages']['llm'].update(status='completed',review=advice)
                    except (PermissionError,AssessmentCancelled):raise
                    except Exception:doc['stages']['llm'].update(status='error',reason='Provider unavailable, timed out or returned invalid text; no fallback egress')
                doc['status']=('paused' if doc['stages']['dast']['status']=='paused' else 'awaiting_action_review') if req.dast else 'completed'
        except asyncio.CancelledError:
            doc.update(status='interrupted',reason='Task stopped; issued operations cannot be undone');raise
        except AssessmentCancelled:doc.update(status='cancelled',reason='Operator stopped future stages; issued operations cannot be undone')
        except PermissionError:doc.update(status='paused',reason='Scope/session/artifact/package boundary failed; no automatic continuation')
        except Exception:doc.update(status='error',reason='Stage incomplete; inspect actual scan/API/DAST coverage. No clean result inferred')
        finally:
            for stage in doc['stages'].values():
                if stage['status']=='queued':stage.update(status='not_executed',reason='Earlier stage stopped')
                elif stage['status']=='running':stage.update(status='incomplete',reason='Execution stopped without a completed observation')
            try:self.persist(doc)
            finally:self.tasks.pop(doc['id'],None)
    async def api_tests(self,doc,req,token):
        from mobileag.automation.engine import AutomationService
        # Separate guard: no synthetic device is presented as authorized scope.
        svc=AutomationService(self.output,lambda:self.repository().get_policy(),lambda t:self.session_valid(t),lambda *a:None)
        plan={'captures':[],'tests':[],'steps':[],'results':[],'observations':[],'correlations':[],'measurements':[],
              'max_requests':req.max_requests,'request_count':0,'request_interval_seconds':1,'status':'running','id':doc['id'],'package_name':req.package_name}
        svc.targets[doc['id']]=dict(svc.captures(plan,req.captures))
        # No auto-retry; requests with no oracle are observations, never passes.
        try:
            for test in plan['tests']:
                self.guard(doc,token)
                try:await svc.api_case(plan,test['id'],req.api_authorization.get_secret_value() if req.api_authorization else None,token,guard=lambda:self.guard(doc,token))
                finally:
                    doc['stages']['api'].update(inventory=plan['captures'],generated_tests=plan['tests'],results=plan['results'],observations=plan['observations'],executed=sum(bool(r.get('executed')) for r in plan['results']))
                    self.persist(doc)
            return plan
        finally:svc.targets.clear()
    def api_plan(self,req,policy):
        from mobileag.automation.engine import AutomationService
        helper=AutomationService(self.output,lambda:policy,self.session_valid,lambda *a:None)
        return helper.captures({'captures':[],'tests':[],'steps':[],'correlations':[]},req.captures)
    def report(self,rid):
        doc=self.store().get(rid)
        if doc.get('automation_run_id'):
            doc['latest_navigation_report']=self.automation().get_report(doc['automation_run_id'])
        return doc
    def cancel(self,rid):
        doc=self.store().get(rid)
        if doc['status']!='running':raise ValueError('Assessment is not active')
        doc['cancel_requested']=True;self.store().save(doc)
        if doc.get('scan_id'):
            from mobileag.web.jobs import CANCELLED
            CANCELLED.add(doc['scan_id'])
        return doc
