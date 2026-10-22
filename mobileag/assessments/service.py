"""One approved assessment: isolated SAST → scoped API → DAST map → optional AI.

No raw worker source reaches the broker; discovery does not grant execution.
"""
import asyncio
import re
import uuid
from pathlib import Path
from datetime import datetime,timezone
from mobileag.assessments.store import AssessmentStore
from mobileag.reporting.coverage import guided_coverage
from mobileag.web.policy import validate_policy,check_action,check_replay
from mobileag.web.security import check_device,configured_list
from mobileag.automation.android import digest
from mobileag.automation.models import CreateRun,ExecuteRun
from mobileag.security.archives import validate_archive
from mobileag.security.network import scoped_request
from mobileag.llm.broker import aggregate,configured,validate_review_selection,LLMReviewError

class AssessmentCancelled(Exception):pass

class AssessmentService:
    def __init__(self,output,uploads,repository,session_valid,static_runner,automation,adb,broker,hash_file):
        self.output,self.uploads,self.repository,self.session_valid=output,uploads,repository,session_valid
        self.static_runner,self.automation,self.adb,self.broker,self.hash_file=static_runner,automation,adb,broker,hash_file
        self.api_transport=scoped_request
        self.tasks={}
        self.authorization_probe_busy=set()
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
        if not self.session_valid(token):raise PermissionError('Session unavailable')
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
        validate_review_selection(req.llm_provider,req.llm_secondary_provider,req.llm_fallback_egress_confirmed)
        sha=await asyncio.to_thread(self.hash_file,apk)
        # Validation/hash can yield while the operator revokes the credential or
        # server scope. Revalidate before durable state/policy mutation.
        if not self.session_valid(token):raise PermissionError('Session unavailable')
        policy=validate_policy(policy)
        # Reserve only after awaited validation/hash: concurrent creates cannot
        # both pass the one-assessment limit and replace each other's policy.
        if self.tasks:raise ValueError('One guided assessment at a time')
        doc={'id':'assess_'+uuid.uuid4().hex,'status':'running','created_at':datetime.now(timezone.utc).isoformat(),
            'package_name':req.package_name,'artifact_sha256':sha,'scope':policy,'cancel_requested':False,'scan_id':None,'automation_run_id':None,
            'stages':{name:{'status':'queued' if enabled else 'not_selected'} for name,enabled in [('sast',True),('api',req.api),('dast',req.dast),('llm',bool(req.llm_provider))]},
            'ai_selection':{'primary_provider':req.llm_provider,'secondary_provider':req.llm_secondary_provider,'metadata_egress_confirmed':req.llm_metadata_egress_confirmed,'fallback_egress_confirmed':req.llm_fallback_egress_confirmed,'fallback_trigger':'HTTP 429 only','maximum_provider_attempts':2 if req.llm_secondary_provider else 1},
            'limitations':['SAST candidates are not confirmed vulnerabilities.','DAST maps in-package UI; taps require later exact action approval.','API tests are read-only operator-imported requests, not transparent capture.','AI receives aggregate counts only, never executes actions.']}
        # The UI explicitly approves replacing global scope. Saved policy is also
        # used by every subsequent legacy operation; not a client-only allowlist.
        doc['coverage_ledger']=guided_coverage(doc)
        self.store().save(doc);self.repository().save_policy(policy)
        self.tasks[doc['id']]=asyncio.create_task(self.run(doc,req,token,apk))
        return doc
    def persist(self,doc):
        latest=self.store().get(doc['id'])
        doc['cancel_requested']=latest.get('cancel_requested',False)
        doc['coverage_ledger']=guided_coverage(doc)
        self.store().save(doc)
    async def run(self,doc,req,token,apk):
        try:
            async with asyncio.timeout(480):
                self.guard(doc,token)
                if await asyncio.to_thread(self.hash_file,apk)!=doc['artifact_sha256']:raise PermissionError('Uploaded artifact changed')
                self.guard(doc,token)
                doc['stages']['sast']['status']='running';self.persist(doc)
                async def linked(sid):doc['scan_id']=sid;self.persist(doc)
                scan=await self.static_runner(apk,linked)
                self.guard(doc,token)
                doc['stages']['sast'].update(status=scan['status'],scan_id=scan['scan_id'],
                    assessment_coverage=scan.get('assessment_coverage','unknown'))
                self.persist(doc)
                if scan.get('package_name')!=req.package_name:raise PermissionError('Static package differs from explicitly approved package')
                if scan['status']!='completed':raise ValueError('Static analysis incomplete; live stages not started')
                if await asyncio.to_thread(self.hash_file,apk)!=doc['artifact_sha256']:raise PermissionError('Artifact changed after static analysis')
                self.guard(doc,token)
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
                        def install_guard():
                            self.guard(doc,token)
                            if not check_action(self.repository().get_policy(),'install',{'serial':req.serial,'package_name':req.package_name}):
                                raise PermissionError('Install scope revoked')
                        self.guard(doc,token)
                        install_guard()
                        code,present,_=await self.adb._exec_cmd(['-s',req.serial,'shell','pm','path',req.package_name],output_limit=16384)
                        if code not in {0,1}:raise ValueError('Installed package state unavailable')
                        if present.strip():raise ValueError('Refusing to replace an existing package; install-if-absent only')
                        self.guard(doc,token)
                        result=await self.adb.install_apk(req.serial,str(apk),grant_permissions=False,replace=False,guard=install_guard)
                        if result['status']!='success':raise ValueError('Install failed or timed out')
                    # Bind any subsequent live observation to the exact APK
                    # analyzed above. Package/version strings alone do not
                    # identify a build; split installs require separate
                    # artifact support and therefore fail closed here.
                    self.guard(doc,token)
                    def identity_guard():
                        self.guard(doc,token)
                        if not check_action(self.repository().get_policy(),'automation_observe',
                                            {'serial':req.serial,'package_name':req.package_name}):
                            raise PermissionError('Runtime identity observation scope revoked')
                    identity_guard()
                    identity=await self.adb.installed_apk_identity(req.serial,req.package_name,
                                                                   doc['artifact_sha256'],guard=identity_guard)
                    doc['stages']['dast']['runtime_artifact_identity']=identity
                    self.persist(doc)
                    if identity.get('status')!='matched':
                        raise PermissionError('Installed build could not be matched to the analyzed APK; DAST was not launched')
                    # Collect a read-only installed permission snapshot only
                    # after the installed base APK has matched the analyzed one.
                    # Never persist dumpsys output, code paths or data paths.
                    try:
                        package_info=await self.adb.get_package_info(req.serial,req.package_name,guard=identity_guard)
                        from mobileag.dast.runtime_package_auditor import summarize_runtime_package
                        manifest=scan.get('manifest_data') if isinstance(scan.get('manifest_data'),dict) else {}
                        static_permissions=manifest.get('permissions') if isinstance(manifest.get('permissions'),list) else None
                        snapshot=summarize_runtime_package(req.package_name,package_info,static_permissions)
                        doc['stages']['dast']['runtime_permission_snapshot']=snapshot
                    except PermissionError:
                        raise
                    except Exception:
                        doc['stages']['dast']['runtime_permission_snapshot']={
                            'status':'unavailable','reason':'Package-manager permission state could not be safely observed',
                            'proof_status':'not_proven'}
                    self.persist(doc)
                    if req.launch:
                        def launch_guard():
                            self.guard(doc,token)
                            if not check_action(self.repository().get_policy(),'launch',{'serial':req.serial,'component':req.component}):
                                raise PermissionError('Launch scope revoked')
                        self.guard(doc,token)
                        launch_guard()
                        result=await self.adb.launch_activity(req.serial,req.component,guard=launch_guard)
                        if result['status']!='success':raise ValueError('Launch failed')
                    self.guard(doc,token)
                    # Keep a bounded shared-buffer baseline; only new lines
                    # attributed to the exact target package/PIDs are examined.
                    try:
                        from mobileag.dast.runtime_evidence import new_lines
                        from mobileag.dast.logcat_auditor import LogcatAuditor
                        baseline_pids=await self.adb.get_process_pids(req.serial,req.package_name,guard=identity_guard)
                        before_logs=await self.adb.get_logcat_dump(req.serial,lines=500,guard=identity_guard)
                        self.guard(doc,token)
                    except PermissionError:
                        raise
                    except Exception:
                        baseline_pids=[];before_logs=[]
                    log_baseline_available=isinstance(before_logs,list) and bool(before_logs)
                    auto=await self.automation().create(CreateRun(serial=req.serial,package_name=req.package_name,component=req.component,
                        environment='dedicated_staging',dedicated_device_confirmed=True,dedicated_account_confirmed=True,max_steps=req.max_steps,max_requests=0),token)
                    doc['automation_run_id']=auto['id'];screens=len(auto['screens'])
                    doc['stages']['dast'].update(status='awaiting_action_review' if screens else 'paused',screens=screens,run_id=auto['id'],
                        device_metadata=auto.get('device_metadata',{}),authentication_state=auto.get('auth_state','unknown'));self.persist(doc)
                    try:
                        await asyncio.sleep(0.5)
                        self.guard(doc,token)
                        after_pids=await self.adb.get_process_pids(req.serial,req.package_name,guard=identity_guard)
                        after_logs=await self.adb.get_logcat_dump(req.serial,lines=500,guard=identity_guard)
                        if not isinstance(after_logs,list):raise ValueError('Logcat collection did not return a bounded line list')
                        pids=sorted(set(baseline_pids+after_pids))
                        post_snapshot_available=bool(after_logs)
                        delta=new_lines(before_logs,after_logs) if log_baseline_available and post_snapshot_available else []
                        findings=LogcatAuditor().audit_lines(delta,package_name=req.package_name,
                                                              process_pids=pids or None)
                        doc['stages']['dast']['runtime_log_observation']={
                            'status':'observed' if log_baseline_available and post_snapshot_available else
                                'post_snapshot_empty_or_unavailable' if log_baseline_available else 'baseline_unavailable',
                            'new_lines_examined':len(delta),'attributed_pid_count':len(pids),
                            'candidate_count':len(findings),
                            'observations':[finding.model_dump(mode='json',include={
                                'title','description','severity','cwe_id','affected_component','file_path',
                                'line_number','code_snippet','detection_method','status','remediation'})
                                for finding in findings[:20]],
                            'proof_status':'not_proven',
                            'limitations':['Only bounded logcat output collected during startup/UI mapping was examined.',
                                           'A shared log buffer and timing do not establish causal input or ordinary-app exploitability.',
                                           'No new log lines is not evidence that sensitive values are never logged.'],
                        }
                    except PermissionError:
                        raise
                    except Exception:
                        doc['stages']['dast']['runtime_log_observation']={
                            'status':'unavailable','reason':'Target-attributed log observation could not be completed',
                            'proof_status':'not_proven'}
                    self.persist(doc)
                if req.llm_provider:
                    self.guard(doc,token);doc['stages']['llm']['status']='running';self.persist(doc)
                    try:
                        advice=await self.broker.review(req.llm_provider,aggregate(scan,executed,screens),lambda:self.guard(doc,token),secondary=req.llm_secondary_provider,fallback_confirmed=req.llm_fallback_egress_confirmed)
                        doc['stages']['llm'].update(status='completed',review=advice)
                    except (PermissionError,AssessmentCancelled):raise
                    except LLMReviewError as error:doc['stages']['llm'].update(status='error',reason=str(error),attempts=error.attempts)
                    except Exception:doc['stages']['llm'].update(status='error',reason='Provider unavailable or invalid configuration; no automatic continuation')
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
    def record_authorization_pair(self,rid,pair,token):
        from mobileag.analysis.authorization_pair import compare_authorization_pair
        doc=self.store().get(rid)
        self.guard(doc,token)
        if rid in self.tasks or doc['status']=='running':
            raise ValueError('Wait for assessment stages to finish before importing evidence')
        if pair.artifact_sha256 != doc['artifact_sha256']:
            raise ValueError('Evidence artifact differs from this assessment')
        captures=doc['stages'].get('api',{}).get('inventory',[])
        capture=next((c for c in captures if c.get('id')==pair.capture_id),None)
        if (not capture or not capture.get('protected') or capture.get('origin') not in doc['scope']['origins']
                or capture.get('method') not in doc['scope']['methods']
                or doc['stages']['api']['status']=='not_selected'):
            raise PermissionError('Pair must reference an approved protected API capture')
        rows=doc.setdefault('authorization_comparisons',[])
        if len(rows)>=20:
            raise ValueError('Authorization evidence budget exhausted')
        evidence_ids={ref for row in rows for ref in row['evidence_refs']}
        result=compare_authorization_pair(pair)
        if evidence_ids.intersection(result['evidence_refs']):
            raise ValueError('Evidence IDs already recorded; use a new capture set')
        rows.append(result)
        self.persist(doc)
        return result

    async def run_authorization_probe(self,rid,probe,token):
        """Run three exact, read-only API requests and retain only a marker comparison."""
        from urllib.parse import urlsplit
        from mobileag.analysis.authorization_pair import compare_authorization_pair
        from mobileag.web.security import configured_list

        doc=self.store().get(rid)
        self.guard(doc,token)
        if rid in self.tasks or doc.get('status') in {'running','cancelled','interrupted'}:
            raise ValueError('Assessment must be stopped or complete before a paired API probe')
        if doc.get('stages',{}).get('api',{}).get('status') not in {'completed_with_observations','completed'}:
            raise PermissionError('A completed, explicitly scoped API stage is required')
        owner_parts=urlsplit(probe.owner_url);other_parts=urlsplit(probe.other_url)
        owner_origin=f'{owner_parts.scheme}://{owner_parts.netloc}'
        other_origin=f'{other_parts.scheme}://{other_parts.netloc}'
        if owner_origin != other_origin:
            raise PermissionError('Both controlled-account URLs must use the same approved origin')
        if (owner_origin not in doc['scope'].get('origins',[]) or
                owner_origin not in configured_list('MOBILEAG_ALLOWED_ORIGINS') or
                'GET' not in doc['scope'].get('methods',[]) or
                not check_replay(self.repository().get_policy(),probe.owner_url,'GET') or
                not check_replay(self.repository().get_policy(),probe.other_url,'GET')):
            raise PermissionError('Paired probe origin or GET method is outside current exact scope')
        inventory=doc.get('stages',{}).get('api',{}).get('inventory',[])
        owner_capture=next((c for c in inventory if c.get('id')==probe.owner_capture_id),None)
        other_capture=next((c for c in inventory if c.get('id')==probe.other_capture_id),None)
        if not owner_capture or not other_capture or any(
            not c.get('protected') or c.get('method')!='GET' or c.get('origin')!=owner_origin
            for c in (owner_capture,other_capture)
        ):
            raise PermissionError('Both URLs must match protected GET captures from this assessment')
        if (digest('GET '+probe.owner_url)!=probe.owner_capture_id or
                digest('GET '+probe.other_url)!=probe.other_capture_id):
            raise PermissionError('Probe URLs do not match the approved imported captures')
        comparisons=doc.setdefault('authorization_dynamic_comparisons',[])
        if rid in self.authorization_probe_busy:
            raise ValueError('A paired API probe is already active for this assessment')
        if doc.get('authorization_probe_attempts',0)>=1:
            raise ValueError('Paired API probe budget exhausted: one three-request probe per assessment')
        if not callable(self.api_transport):
            raise ValueError('Scoped API transport is unavailable')

        # Reserve the fixed three-request budget before network I/O so retries
        # after timeouts or process interruption cannot silently multiply it.
        self.authorization_probe_busy.add(rid)
        try:
            doc['authorization_probe_attempts']=doc.get('authorization_probe_attempts',0)+1
            self.persist(doc)
        except Exception:
            self.authorization_probe_busy.discard(rid)
            raise

        requests=[
            (probe.owner_url,probe.owner_authorization.get_secret_value()),
            (probe.other_url,probe.other_authorization.get_secret_value()),
            (probe.owner_url,probe.other_authorization.get_secret_value()),
        ]
        try:
            observations=[]
            for url,authorization in requests:
                self.guard(doc,token)
                if not check_replay(self.repository().get_policy(),url,'GET'):
                    raise PermissionError('Paired probe scope was revoked')
                await asyncio.sleep(0.5)
                self.guard(doc,token)
                result=await self.api_transport(url,'GET',headers={'Authorization':authorization})
                body=result.get('body','')
                if not isinstance(body,str) or len(body.encode('utf-8',errors='replace'))>16384:
                    body='{}'  # bounded evidence parser treats oversize/non-text as inconclusive
                observations.append({'status_code':int(result.get('status_code',0)),
                    'response_json':body,'evidence_id':'probe-'+uuid.uuid4().hex})
            from mobileag.analysis.authorization_pair import AuthorizationPair
            pair=AuthorizationPair.model_validate({
                'artifact_sha256':doc['artifact_sha256'],'capture_id':probe.owner_capture_id,
                'owner_baseline':observations[0],'other_account_baseline':observations[1],
                'cross_account':observations[2],'marker_path':probe.marker_path,
                'owner_marker':probe.owner_marker,'other_marker':probe.other_marker,
                'authorized_synthetic_captures':True,'distinct_controlled_accounts_confirmed':True,
                'same_owner_resource_requested':True,'identities_checked':True,
            })
            result=compare_authorization_pair(pair)
            result.update({'network_requests_sent':3,'basis':'live_scoped_read_only_probe',
                'origin':owner_origin,'owner_capture_id':probe.owner_capture_id,
                'other_capture_id':probe.other_capture_id,
                'limitations':['Account identities, synthetic markers, resource ownership and URL semantics are operator assertions.',
                               'Only exact JSON marker equality is compared; non-JSON, oversized, or changed schemas are inconclusive.',
                               'A denial observation is not exhaustive authorization proof.']})
            comparisons.append(result)
            self.persist(doc)
            return result
        finally:
            self.authorization_probe_busy.discard(rid)

    def report(self,rid):
        doc=self.store().get(rid)
        if doc.get('automation_run_id'):
            doc['latest_navigation_report']=self.automation().get_report(doc['automation_run_id'])
        doc['coverage_ledger']=guided_coverage(doc)
        return doc
    def cancel(self,rid):
        doc=self.store().get(rid)
        if doc['status']!='running':raise ValueError('Assessment is not active')
        doc['cancel_requested']=True;self.store().save(doc)
        if doc.get('scan_id'):
            from mobileag.web.jobs import CANCELLED
            CANCELLED.add(doc['scan_id'])
        return doc
