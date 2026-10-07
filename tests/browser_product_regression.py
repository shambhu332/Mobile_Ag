"""Opt-in Chromium regression against an isolated real loopback server.

Run outside pytest (requires Playwright plus a cached Chromium):
  python tests/browser_product_regression.py --server-python /path/to/project/venv/bin/python
No real device commands, cloud model calls, or external runtime assets.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright

SERVER = r'''
import asyncio,importlib,json,os
from pathlib import Path
from unittest.mock import AsyncMock
import uvicorn
from config.settings import Settings
from mobileag.llm.router import LLMRouter
from mobileag.analysis.secret_scanner import SecretScanner
root=Path(os.environ['MOBILEAG_DATA_DIR'])
async def fixture():
    source=root/'source';source.mkdir()
    (source/'Example.java').write_text('class Example { String marker = "\'-window.auditXssProbe(1)-\'"; Object c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }')
    findings=await SecretScanner(LLMRouter(Settings(_env_file=None,offline=True))).scan(str(source))
    result=[f.model_dump(mode='json') for f in findings]
    result[0]['id']='synthetic-finding'
    return {'scan_id':'scan_synthetic','package_name':'org.example.review','status':'completed','version':'synthetic','stats':{'total':1,'high':1},'findings':result,'coverage':{},'revision':0,'api_endpoints':[{'id':'synthetic-api','method':'GET','url':'https://owned-fixture.invalid/profile','path':'/profile','host':'owned-fixture.invalid','status':'UNVERIFIED','source':'Synthetic declared fixture, not captured traffic','auth_type':'Not assessed'}]}
scan=asyncio.run(fixture());m=importlib.import_module('mobileag.web.app')
m.repository().save(scan)
m.attack_graph.verify_connection=AsyncMock(return_value=False)
m.adb_manager.list_devices=AsyncMock(return_value=[])
m.adb_manager.is_adb_available=AsyncMock(return_value=False)
m.adb_manager._exec_cmd=AsyncMock(side_effect=RuntimeError('Real device operations are prohibited in this regression'))
from mobileag.automation.models import CreateRun
from mobileag.automation.android import parse_snapshot
class SyntheticNavigator:
    def __init__(self):self.screen='Profile'
    async def snapshot(self):
        pkg='org.example.automation'
        control='Settings' if self.screen=='Profile' else 'Home'
        return parse_snapshot(f'<hierarchy><node package="{pkg}" class="android.widget.Button" resource-id="{pkg}:id/{control.lower()}" text="{control}" clickable="true" bounds="[20,20][220,100]"/></hierarchy>',pkg)
    async def act(self,action,element=None):self.screen='Settings' if self.screen=='Profile' else 'Home'
navigator=SyntheticNavigator();service=m.automation_service()
async def guided_static(apk,linked):
    await linked('scan_guided_ui_fixture')
    return {'scan_id':'scan_guided_ui_fixture','status':'completed','package_name':'org.example.automation','findings':[]}
m.assessment_service().static_runner=guided_static
async def synthetic_model_transport(url,method,**kwargs):
    assert method=='POST'
    body=json.loads(kwargs['body'])
    if url.startswith('https://generativelanguage.googleapis.com/v1beta/models/'):
        summary=json.loads(body['contents'][0]['parts'][0]['text'])
        assert set(summary)=={'static_status','static_candidate_counts','static_confirmed','api_cases_executed','dast_screens_observed','production_readiness'}
        return {'status_code':429,'body':'{"error":"Synthetic rate limit; never a real model call"}'}
    assert url in {'https://api.openai.com/v1/chat/completions','https://api.x.ai/v1/chat/completions'}
    summary=json.loads(body['messages'][1]['content'])
    assert set(summary)=={'static_status','static_candidate_counts','static_confirmed','api_cases_executed','dast_screens_observed','production_readiness'}
    return {'status_code':200,'body':json.dumps({'choices':[{'message':{'content':'Synthetic protocol advice; no actual commercial model contacted.'}}]})}
m.assessment_service().broker.transport=synthetic_model_transport
service.driver_factory=lambda serial,package:navigator
m.repository().save_policy({'devices':['emulator-synthetic'],'packages':['org.example.automation'],'origins':[],'methods':['GET'],'actions':['automation_observe','automation_execute']})
auto=asyncio.run(service.create(CreateRun(serial='emulator-synthetic',package_name='org.example.automation',component='org.example.automation/.Main',environment='synthetic',dedicated_account_confirmed=True,dedicated_device_confirmed=True,max_steps=2),m.app.state.auth_token))
uvicorn.run(m.app,host='127.0.0.1',port=int(os.environ['TEST_PORT']),log_level='warning')
'''


def wait_condition(page, expression, timeout=30):
    # Playwright's wait_for_function uses page-side eval; a strict CSP rightly
    # rejects it. Poll with DevTools evaluation without weakening the page CSP.
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            if page.evaluate('Boolean(' + expression + ')'):return
        except Exception:
            pass
        time.sleep(.1)
    raise AssertionError('Condition did not become true: ' + expression)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server-python',default=sys.executable)
    parser.add_argument('--chromium',default=str(Path.home()/'.cache/ms-playwright/chromium-1247/chrome-linux64/chrome'))
    parser.add_argument('--axe',default=None,help='Optional local axe-core/axe.min.js for automated accessibility checks')
    parser.add_argument('--output',default='docs/product-security-review-2026-10-05/fix-validation')
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[1];out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mobileag-browser-regression-') as temporary:
        root=Path(temporary)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        env=os.environ.copy()
        for key in ['OPENAI_API_KEY','GEMINI_API_KEY','ANTHROPIC_API_KEY','DEEPSEEK_API_KEY','XAI_API_KEY','GROQ_API_KEY','MISTRAL_API_KEY','OPENROUTER_API_KEY','MOBILEAG_LOCAL_LLM_KEY']:
            env.pop(key,None)
        for key in list(env):
            if key.startswith('MOBILEAG_LLM_'):env.pop(key,None)
        env.update(MOBILEAG_DATA_DIR=str(root),MOBILEAG_API_TOKEN='synthetic-local-only',OFFLINE='true',APPROVED_LLM_PROVIDERS='[]',MOBILEAG_ALLOWED_DEVICES='emulator-synthetic',MOBILEAG_ALLOWED_ORIGINS='',MOBILEAG_ALLOWED_CONNECT='',TEST_PORT=str(port),PYTHONPATH=str(repo),MOBILEAG_LLM_ALLOWED_PROVIDERS='openai,gemini,grok',MOBILEAG_LLM_OPENAI_MODEL='synthetic-browser-model',OPENAI_API_KEY='synthetic-browser-provider-key',MOBILEAG_LLM_GEMINI_MODEL='synthetic-gemini',MOBILEAG_LLM_GROK_MODEL='synthetic-grok',GEMINI_API_KEY='synthetic-gemini-key',XAI_API_KEY='synthetic-grok-key')
        runner=root/'runner.py';runner.write_text(SERVER)
        with (root/'server.log').open('w') as log:
            server=subprocess.Popen([args.server_python,str(runner)],cwd=root,env=env,stdout=log,stderr=log)
            try:
                url=f'http://127.0.0.1:{port}'
                deadline=time.monotonic()+90
                while True:
                    if server.poll() is not None:raise RuntimeError('Isolated server stopped; inspect dependency installation')
                    try:
                        with urllib.request.urlopen(url,timeout=1) as response:
                            if response.status==200:break
                    except OSError:
                        if time.monotonic()>=deadline:raise RuntimeError('Isolated server did not become ready')
                        time.sleep(.25)
                with sync_playwright() as p:
                    browser=p.chromium.launch(executable_path=args.chromium,headless=True)
                    context=browser.new_context(viewport={'width':1440,'height':1000},permissions=['clipboard-read','clipboard-write'])
                    page=context.new_page();errors=[];console=[];requests=[];assessment_posts=[]
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.on('console',lambda m:console.append(m.text) if m.type=='error' else None)
                    page.on('request',lambda r:requests.append(r.url))
                    page.on('request',lambda r:assessment_posts.append(r.url) if r.method=='POST' and r.url.endswith('/api/assessments') else None)
                    page.on('dialog',lambda d:d.accept('synthetic-local-only') if d.type=='prompt' else d.dismiss())
                    page.emulate_media(reduced_motion='reduce')
                    page.goto(url,wait_until='domcontentloaded',timeout=90000)
                    page.locator('#session-token').wait_for(state='visible')
                    keyboard_initial_focus=page.locator('#session-token').evaluate('(e) => e === document.activeElement')
                    page.keyboard.press('Tab')
                    keyboard_submit_focus=page.locator('#session-connect button').evaluate('(e) => e === document.activeElement')
                    page.locator('#session-token').fill('invalid-synthetic-token')
                    page.locator('#session-connect button').click()
                    page.locator('#session-connect [role=alert]').wait_for(state='visible')
                    page.locator('#session-token').fill('synthetic-local-only')
                    page.locator('#session-token').press('Enter')
                    wait_condition(page,'typeof currentScan !== "undefined" && currentScan && currentScan.findings.length === 1')
                    # Workspace search is keyboard-first navigation, not execution.
                    post_methods=[]
                    page.on('request',lambda r:post_methods.append(r.url) if r.method in {'POST','PUT','PATCH','DELETE'} else None)
                    page.locator('#workspace-command-open').focus()
                    page.keyboard.press('Control+k')
                    page.locator('#workspace-command-dialog').wait_for(state='visible')
                    assert page.locator('#workspace-command-search').evaluate('(el)=>el===document.activeElement')
                    page.locator('#workspace-command-search').fill('history')
                    assert page.locator('#workspace-command-results button').count()==1
                    page.keyboard.press('ArrowDown')
                    assert page.locator('#workspace-command-results button').evaluate('(el)=>el===document.activeElement')
                    page.keyboard.press('Enter')
                    assert page.locator('#view-scans').is_visible()
                    assert not page.locator('#workspace-command-dialog').evaluate('(el)=>el.open')
                    page.locator('#workspace-command-open').focus();page.keyboard.press('Control+k')
                    page.locator('#workspace-command-search').fill('<img src=x onerror=alert(1)>')
                    assert page.locator('#workspace-command-results button').count()==0
                    assert 'No matching sections' in page.locator('#workspace-command-status').inner_text()
                    if args.axe:
                        page.evaluate(Path(args.axe).read_text())
                        violations=page.evaluate("async()=> (await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
                        assert not violations, violations
                    page.keyboard.press('Escape')
                    wait_condition(page,'!document.querySelector("#workspace-command-dialog").open && document.querySelector("#workspace-command-open")===document.activeElement')
                    page.locator('#workspace-density').select_option('compact')
                    assert page.locator('body').get_attribute('data-density')=='compact'
                    page.locator('#workspace-focus-toggle').click()
                    assert not page.locator('body>aside').is_visible()
                    page.locator('#workspace-command-open').click()
                    page.locator('#workspace-command-search').fill('manifest');page.keyboard.press('Enter')
                    assert page.locator('#view-surface').is_visible()
                    page.locator('#workspace-focus-toggle').click()
                    assert page.locator('body>aside').is_visible()
                    page.locator('#workspace-guide summary').click()
                    assert 'Selected job: scan_synthetic' in page.locator('#workspace-guide-job').inner_text()
                    page.evaluate('()=>{window.experienceSavedScan=currentScan;currentScan=null;window.dispatchEvent(new Event("workspace-scan-changed"));}')
                    assert 'No job selected' in page.locator('#workspace-guide-job').inner_text()
                    assert page.locator('#export-menu-button').is_disabled()
                    page.evaluate('()=>{currentScan=window.experienceSavedScan;delete window.experienceSavedScan;window.dispatchEvent(new Event("workspace-scan-changed"));}')
                    assert len(post_methods)==0, post_methods
                    page.screenshot(path=str(out/'advanced-workspace-guide.png'))
                    page.locator('#workspace-guide summary').click()
                    page.locator('#workspace-density').select_option('comfortable')
                    # Typing slash in an editable control must never hijack navigation.
                    page.locator('#nav-findings').click()
                    page.locator('#findings-search-input').fill('')
                    page.locator('#findings-search-input').press('/')
                    assert page.locator('#findings-search-input').input_value()=='/'
                    assert not page.locator('#workspace-command-dialog').evaluate('(el)=>el.open')
                    page.locator('#findings-search-input').fill('')
                    # A block is essential: an expression returning a function can
                    # be invoked by Playwright itself, creating a false marker.
                    page.evaluate('() => {window.auditXssCount=0;window.auditXssProbe=()=>{window.auditXssCount++;return 0};}')
                    assert page.evaluate('window.auditXssCount')==0
                    page.locator('#nav-findings').click()
                    copied={}
                    for pane,expression in [('poc','getOrGeneratePocGuide(currentScan.findings[0])'),('adb',"'adb shell ' + getOrGenerateAdbCommand(currentScan.findings[0])"),('frida','getOrGenerateFridaScript(currentScan.findings[0])'),('ast','currentScan.findings[0].code_snippet')]:
                        page.locator('#subtab-btn-'+pane).click()
                        expected=page.evaluate(expression)
                        page.locator('#poc-pane-'+pane+' button').first.click()
                        copied[pane]=page.evaluate('navigator.clipboard.readText()')==expected
                    page.locator('#subtab-btn-proof').click();proof=page.locator('#poc-pane-proof').inner_text()
                    result={'keyboard_connection':{'initial_token_focus':keyboard_initial_focus,'tab_to_submit':keyboard_submit_focus,'enter_submits':not page.locator('#session-connect').evaluate('(e) => e.open')}, 'reduced_motion_media':page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches"), 'browser':browser.version,'source_to_finding':'Real SecretScanner + synthetic Java; not compiled APK/decompiler proof',
                            'xss_marker_executions':page.evaluate('window.auditXssCount'),'exact_clipboard_copies':copied,
                            'proof_text':proof,'finding_count':page.locator('#kpi-total').inner_text(),'masvs':page.locator('#kpi-masvs').inner_text(),
                            'inline_handlers':page.evaluate('() => [...document.querySelectorAll("*")].flatMap(e=>[...e.attributes]).filter(a=>/^on/i.test(a.name)).length'),
                            'inline_scripts':page.evaluate('document.querySelectorAll("script:not([src])").length'),'implicit_device_selection':page.evaluate('dastActiveDevice')}
                    hostile='Synthetic <img id="injected-marker" src=x onerror="window.auditXssProbe()"> title'
                    page.evaluate('(title) => {currentScan.findings[0].title=title;inspectFinding("synthetic-finding");}',hostile)
                    result['hostile_title_kept_as_text']=page.locator('#detail-content h4').inner_text()==hostile and page.locator('#injected-marker').count()==0
                    # Real response CSP negative control: an arbitrary inline handler is blocked.
                    page.evaluate("() => {const e=document.createElement('button');e.setAttribute('onclick','window.auditXssProbe()');document.body.append(e);e.click();e.remove();}")
                    result['csp_control_marker_executions']=page.evaluate('window.auditXssCount')
                    page.locator('#advanced-tools').evaluate('(el)=>el.open=true')
                    result['screens']={}
                    for view in ['surface','findings','scans','agents','settings','dast','taint','api','automation','assessment']:
                        page.locator('#nav-'+view).click();page.wait_for_timeout(250)
                        result['screens'][view]={'visible':page.locator('#view-'+view).is_visible(),'label':page.locator('#workspace-title').inner_text(),'current_nav_count':page.locator('.nav-item[aria-current="page"]').count()}
                        assert result['screens'][view]['label'] and result['screens'][view]['current_nav_count']==1
                        page.screenshot(path=str(out/('view-'+view+'.png')))
                    # Workspace-wide usable controls and honest evidence states.
                    assert page.locator('.nav-item[aria-current="page"]').count()==1
                    assert page.locator('#workspace-title').inner_text()=='Start Assessment'
                    page.locator('#export-menu-button').click()
                    assert page.locator('#export-dropdown').is_visible()
                    page.keyboard.press('Escape')
                    assert not page.locator('#export-dropdown').is_visible()
                    assert page.locator('#export-menu-button').evaluate('(el)=>el===document.activeElement')
                    page.locator('#export-menu-button').click()
                    with page.expect_download() as download:
                        page.locator('#export-dropdown button').first.click()
                    exported=json.loads(Path(download.value.path()).read_text())
                    assert exported['scan_id']=='scan_synthetic'
                    page.locator('#nav-findings').click()
                    page.locator('#findings-search-input').fill('Example.java')
                    assert page.locator('#findings-full-list [role="button"]').count()==1
                    page.locator('#findings-full-list [role="button"]').first.focus()
                    page.keyboard.press('Enter')
                    page.locator('#findings-search-input').fill('')
                    before_triage=len([u for u in requests if u.endswith('/feedback')])
                    page.get_by_role('button',name='Confirm TP',exact=True).click()
                    assert page.locator('#triage-notes-dialog').is_visible()
                    page.locator('#triage-notes-dialog button[type=submit]').click()
                    assert page.locator('#triage-notes-dialog').is_visible()
                    assert len([u for u in requests if u.endswith('/feedback')])==before_triage
                    page.keyboard.press('Escape')
                    wait_condition(page,'!document.querySelector("#triage-notes-dialog")')
                    assert page.locator('#triage-notes-dialog').count()==0
                    assert len([u for u in requests if u.endswith('/feedback')])==before_triage
                    page.locator('#nav-scans').click()
                    scan_url=url+'/api/scans?limit=25&summaries=true&offset=0'
                    page.route(scan_url,lambda route:route.fulfill(status=503,content_type='application/json',body='{"detail":"Synthetic history outage"}'))
                    page.locator('#nav-scans').click()
                    wait_condition(page,'document.querySelector("#scans-table-body").textContent.includes("Synthetic history outage")')
                    page.unroute(scan_url)
                    page.locator('#scans-table-body').get_by_role('button',name='Retry',exact=True).click()
                    wait_condition(page,'document.querySelector("#scans-table-body").textContent.includes("scan_synthetic")')
                    page.locator('#nav-api').click()
                    wait_condition(page,'document.querySelector("#api-detail-status-badge").textContent === "NOT ASSESSED"')
                    page.locator('#api-subtab-btn-response').click()
                    assert page.locator('#api-resp-status-badge').inner_text()=='Not observed'
                    page.locator('#api-subtab-btn-request').click()
                    page.locator('#api-req-headers').fill('{invalid json')
                    before_replay=len([u for u in requests if u.endswith('/api/apis/test')])
                    page.locator('#btn-replay-req').click()
                    assert len([u for u in requests if u.endswith('/api/apis/test')])==before_replay
                    before_analysis=len([u for u in requests if u.endswith('/api/apis/fuzz')])
                    page.locator('#btn-fuzz-api').click()
                    assert len([u for u in requests if u.endswith('/api/apis/fuzz')])==before_analysis
                    page.locator('#api-subtab-btn-owasp').click()
                    page.locator('#api-observed-status').fill('200')
                    page.locator('#api-observed-body').fill('{"data":"synthetic-owned-capture"}')
                    page.locator('#api-observed-confirm').check()
                    with page.expect_response(lambda response: response.url.endswith('/api/apis/fuzz')) as captured:
                        page.locator('#btn-fuzz-api').click()
                    assert captured.value.status==200
                    assert all(f['status']=='UNVERIFIED' for f in captured.value.json()['findings'])
                    wait_condition(page,'document.querySelector("#api-live-fuzz-results").textContent.includes("Unverified candidates")')
                    result['advanced_experience']={'keyboard_search_navigation':True,'search_has_no_mutations':True,'escape_restores_focus':True,'editable_slash_not_hijacked':True,'compact_and_focus_layouts':True,'contextual_guidance_uses_recorded_job':True}
                    result['interface']={'export_menu_usable':True,'json_export_matches_scan':True,'keyboard_finding_review':True,
                        'file_path_filter_works':True,'cancelled_or_empty_triage_has_no_mutation':True,'history_failure_retry_recovers':True,
                        'unobserved_api_not_marked_secure':True,'invalid_headers_send_no_request':True,'capture_requires_observation':True,
                        'local_capture_analysis_only':True,'section_title_and_aria_current':True}
                    # Provider controls live only in Configuration; approval is
                    # assessment-local and no provider or target is contacted by selection.
                    def configure_provider(selector,value):
                        page.locator('#nav-settings').click()
                        page.locator('#'+selector).select_option(value)
                    def approve_ai(selector):
                        page.locator('#nav-assessment').click()
                        page.locator('#'+selector).check()
                    def refresh_providers():
                        page.locator('#nav-settings').click()
                        page.get_by_role('button',name='Refresh providers',exact=True).click()
                    def start_assessment():
                        page.locator('#nav-assessment').click()
                        page.locator('#assessment-start').click()
                    page.locator('#nav-settings').click()
                    assert page.locator('#configuration-llm #assessment-provider').is_visible()
                    assert page.locator('#configuration-llm #assessment-secondary').count()==1
                    assert page.locator('#view-assessment #assessment-provider').count()==0
                    assert page.locator('#view-assessment #assessment-egress').count()==1
                    # Select every integration for setup, even with missing server
                    # settings. Availability/consent gates still block execution.
                    page.locator('#nav-settings').click()
                    wait_condition(page,'document.querySelector("#assessment-provider").options.length === 11')
                    assert page.locator('#assessment-provider option:disabled').count()==0
                    configure_provider('assessment-provider','mistral')
                    assert 'MISTRAL_API_KEY' in page.locator('#assessment-provider-info').inner_text()
                    assert 'MOBILEAG_LLM_MISTRAL_MODEL' in page.locator('#assessment-provider-info').inner_text()
                    assert page.locator('#assessment-start').is_disabled()
                    page.locator('#assessment-provider-info details').evaluate('(el)=>el.open=true')
                    page.screenshot(path=str(out/'provider-setup-required.png'))
                    before_assessment=len(assessment_posts)
                    approve_ai('assessment-egress')
                    assert page.locator('#assessment-start').is_disabled()
                    # A forged submit cannot silently skip AI or create a run.
                    page.locator('#assessment-start').evaluate('(el)=>el.form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}))')
                    assert len(assessment_posts)==before_assessment
                    refresh_providers()
                    wait_condition(page,'document.querySelector("#assessment-provider-info").textContent.includes("MISTRAL_API_KEY")')
                    assert page.locator('#assessment-provider').input_value()=='mistral'
                    configure_provider('assessment-provider','openai')
                    assert page.locator('#assessment-model').input_value()=='synthetic-browser-model'
                    assert page.locator('#assessment-start').is_disabled() and not page.locator('#assessment-egress').is_checked()
                    approve_ai('assessment-egress')
                    assert page.locator('#assessment-start').is_enabled()
                    refresh_providers()
                    wait_condition(page,'!document.querySelector("#assessment-start").disabled')
                    assert page.locator('#assessment-provider').input_value()=='openai'
                    # A failed refresh must block selected AI, not silently reset
                    # to a deterministic run or trust a stale ready catalog.
                    catalog_url=url+'/api/assessments/providers'
                    page.route(catalog_url,lambda route:route.fulfill(status=503,content_type='application/json',body='{"detail":"Synthetic catalog unavailable"}'))
                    refresh_providers()
                    wait_condition(page,'document.querySelector("#assessment-provider-info").textContent.includes("Could not load provider configuration")')
                    assert page.locator('#assessment-provider').input_value()=='openai'
                    assert page.locator('#assessment-start').is_disabled()
                    page.unroute(catalog_url)
                    refresh_providers()
                    wait_condition(page,'!document.querySelector("#assessment-start").disabled')
                    configure_provider('assessment-provider','')
                    assert page.locator('#assessment-start').is_enabled()
                    page.locator('#nav-settings').click()
                    assert page.locator('#cfg-llm-primary').count()==page.locator('#cfg-llm-fallback').count()==0
                    page.get_by_role('button',name='Return to Start Assessment',exact=True).click()
                    assert page.locator('#view-assessment').is_visible()
                    page.locator('#assessment-configure-ai').click()
                    assert page.locator('#view-settings').is_visible()
                    assert page.locator('#assessment-provider').is_visible()
                    page.locator('#nav-assessment').click()
                    page.locator('#modal-open-ai').evaluate('(el)=>el.click()')
                    assert page.locator('#view-settings').is_visible()
                    assert page.locator('#scan-modal').is_hidden()
                    result['provider_selection']={'all_ten_selectable_for_setup':True,'missing_settings_visible':True,
                        'unconfigured_execution_blocked':True,'forged_submit_blocked':True,'refresh_preserves_selection':True,
                        'configured_model_visible':True,'explicit_consent_required':True,'configuration_hosts_provider_controls':True,'assessment_keeps_explicit_consent':True,
                        'configuration_not_connectivity':True,'catalog_failure_blocks_selected_ai':True}
                    # Actual router/service/SQLite exercised through approval UI.
                    # Only the navigator is a synthetic adapter; auth/scope/CAS remain real.
                    page.locator('#nav-automation').click()
                    page.locator('#automation-runs button').first.click()
                    page.locator('#automation-confirmation').wait_for(state='visible')
                    runid=page.locator('#automation-status').inner_text().split(' · ')[0]
                    before_requests=len([r for r in requests if '/execute' in r])
                    page.get_by_role('button',name='Execute approved batch',exact=True).click()
                    assert len([r for r in requests if '/execute' in r])==before_requests
                    page.locator('#automation-detail input[data-action-id]').first.check()
                    page.locator('#automation-confirmation').fill(runid)
                    page.get_by_role('button',name='Execute approved batch',exact=True).click()
                    wait_condition(page,'document.querySelector("#automation-report") && JSON.parse(document.querySelector("#automation-report").textContent || "{}").executive_summary?.executed === 1')
                    automation_report=json.loads(page.locator('#automation-report').inner_text())
                    result['automation']={'unconfirmed_execution_blocked':True,'actual_service_with_synthetic_adapter':True,'executed':automation_report['executive_summary']['executed'],
                        'screens':len(automation_report['screen_graph']['nodes']),'edges':len(automation_report['screen_graph']['edges']),'untested':len(automation_report['untested']),
                        'score':automation_report['executive_summary']['production_readiness_score']}
                    assert result['automation']['screens']==2 and result['automation']['edges']==1 and result['automation']['untested']>0 and result['automation']['score'] is None
                    # Primary workflow: real archive upload/auth/scope/orchestration;
                    # only static executor and Android adapter are synthetic.
                    import io,zipfile
                    payload=io.BytesIO()
                    with zipfile.ZipFile(payload,'w') as archive:
                        archive.writestr('AndroidManifest.xml','<manifest package="org.example.automation"/>')
                        archive.writestr('classes.dex',b'dex\n035\x00synthetic-ui-fixture')
                    page.locator('#nav-assessment').click()
                    before=len([u for u in requests if '/api/scans/run' in u])
                    page.locator('#assessment-file').set_input_files({'name':'synthetic-ui-fixture.apk','mimeType':'application/vnd.android.package-archive','buffer':payload.getvalue()})
                    wait_condition(page,'document.querySelector("#assessment-artifact").value.length>0')
                    assert len([u for u in requests if '/api/scans/run' in u])==before
                    page.locator('#assessment-package').fill('org.example.automation')
                    page.locator('#assessment-dast').check()
                    page.locator('#assessment-serial').fill('emulator-synthetic')
                    page.locator('#assessment-component').fill('org.example.automation/.Main')
                    for name in ['account','device','authorized','scope']:page.locator('#assessment-'+name).check()
                    page.locator('#assessment-confirmation').fill('START SCOPED TESTS')
                    start_assessment()
                    wait_condition(page,'document.querySelector("#assessment-status").textContent.includes("awaiting_action_review")')
                    page.locator('#assessment-results summary').click()
                    guided=json.loads(page.locator('#assessment-results pre').inner_text())
                    result['guided_assessment']={'upload_did_not_start_tests':True,'status':guided['status'],'sast_executor':'synthetic callback; not actual decompiler proof',
                        'sast':guided['stages']['sast']['status'],'dast_screens':guided['stages']['dast']['screens'],'api':guided['stages']['api']['status'],'llm':guided['stages']['llm']['status']}
                    assert guided['stages']['dast']['screens']==1 and guided['stages']['llm']['status']=='not_selected'
                    result['guided_assessment']['scrollable']=page.locator('#view-assessment').evaluate('(el)=>el.scrollHeight>el.clientHeight && getComputedStyle(el).overflowY==="auto"')
                    assert result['guided_assessment']['scrollable']
                    page.locator('#view-assessment').evaluate('(el)=>el.scrollTop=0')
                    page.screenshot(path=str(out/'guided-assessment-desktop.png'))

                    # A second, static-only assessment includes an explicitly
                    # selected/approved model using ONLY the synthetic broker
                    # transport. No provider account or commercial network call.
                    page.locator('#assessment-dast').uncheck()
                    configure_provider('assessment-provider','openai')
                    assert page.locator('#assessment-start').is_disabled()
                    approve_ai('assessment-egress')
                    start_assessment()
                    wait_condition(page,'document.querySelector("#assessment-results pre") && JSON.parse(document.querySelector("#assessment-results pre").textContent).stages?.llm?.status === "completed"')
                    page.locator('#assessment-results summary').click()
                    ai_run=json.loads(page.locator('#assessment-results pre').inner_text())
                    assert ai_run['stages']['llm']['review']['provider']=='openai'
                    assert ai_run['stages']['llm']['review']['model']=='synthetic-browser-model'
                    assert ai_run['stages']['dast']['status']=='not_selected'
                    result['provider_selection']['selected_provider_reaches_broker']=True
                    result['provider_selection']['transport']='Mocked protocol callback; not live inference'
                    page.screenshot(path=str(out/'provider-selection.png'))

                    # Both destinations require consent; only real HTTP 429 shape
                    # in the mocked transport permits one secondary request.
                    configure_provider('assessment-provider','gemini')
                    configure_provider('assessment-secondary','grok')
                    approve_ai('assessment-egress')
                    assert page.locator('#assessment-start').is_disabled()
                    before_fallback=len(assessment_posts)
                    page.locator('#assessment-start').evaluate('(el)=>el.form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}))')
                    assert len(assessment_posts)==before_fallback
                    approve_ai('assessment-fallback-egress')
                    assert page.locator('#assessment-start').is_enabled()
                    configure_provider('assessment-secondary','gemini')
                    approve_ai('assessment-fallback-egress')
                    assert page.locator('#assessment-start').is_disabled()
                    configure_provider('assessment-secondary','grok')
                    assert not page.locator('#assessment-fallback-egress').is_checked()
                    approve_ai('assessment-fallback-egress')
                    refresh_providers()
                    wait_condition(page,'!document.querySelector("#assessment-start").disabled')
                    assert page.locator('#assessment-provider').input_value()=='gemini'
                    assert page.locator('#assessment-secondary').input_value()=='grok'
                    page.locator('#view-settings').evaluate('(el)=>el.scrollTop=0')
                    page.screenshot(path=str(out/'configuration-providers.png'))
                    page.get_by_role('button',name='Return to Start Assessment',exact=True).click()
                    assert 'Gemini' in page.locator('#assessment-ai-summary').inner_text()
                    assert 'Grok' in page.locator('#assessment-ai-summary').inner_text()
                    start_assessment()
                    wait_condition(page,'document.querySelector("#assessment-results pre") && JSON.parse(document.querySelector("#assessment-results pre").textContent).stages?.llm?.review?.fallback_used === true')
                    page.locator('#assessment-results summary').click()
                    fallback_run=json.loads(page.locator('#assessment-results pre').inner_text())
                    review=fallback_run['stages']['llm']['review']
                    assert review['provider']=='grok' and review['primary_provider']=='gemini'
                    assert [a['http_status'] for a in review['attempts']]==[429,200]
                    assert 'secondary used after primary HTTP 429' in page.locator('#assessment-results').inner_text()
                    assert 'synthetic-gemini-key' not in json.dumps(fallback_run) and 'synthetic-grok-key' not in json.dumps(fallback_run)
                    result['rate_limit_fallback']={'primary':'gemini','secondary':'grok','attempt_statuses':[429,200],'separate_consent_required':True,'forged_unconsented_submit_blocked':True,'same_provider_blocked':True,'refresh_retains_pair_and_consent':True,'secondary_after_429_visible':True,'no_credentials_in_evidence':True,'transport':'Synthetic only; no commercial provider contacted'}
                    page.screenshot(path=str(out/'rate-limit-fallback.png'))

                    # Actual durable triage API reached via the migrated UI callback.
                    page.locator('#nav-findings').click();page.evaluate('inspectFinding("synthetic-finding")')
                    page.locator('#detail-content button',has_text='False Positive').click()
                    wait_condition(page,'currentScan.revision === 1')
                    result['durable_feedback_status']=page.evaluate("async () => (await (await fetch('/api/scans/scan_synthetic')).json()).findings[0].status")
                    page.locator('#nav-scans').click();page.wait_for_timeout(250)
                    page.locator('#scans-table-body button').first.click();page.wait_for_timeout(250)
                    page.screenshot(path=str(out/'fixed-desktop.png'))
                    page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(out/'fixed-narrow.png'))
                    result.update(page_errors=errors,console_errors=console,narrow_scrollwidth=page.evaluate('document.documentElement.scrollWidth'),
                                  api_requests_outside_loopback=[r for r in requests if '/api/' in r and not r.startswith(url)],
                                  runtime_requests_outside_loopback=[r for r in requests if not r.startswith(url)],
                                  device_operations='Mocked and disabled; no real ADB/Frida commands',cloud_model_calls=0)
                    page.set_viewport_size({'width':1440,'height':1000})
                    page.locator('#workspace-navigation').wait_for(state='visible')
                    result['a11y']={}
                    if args.axe:
                        page.evaluate(Path(args.axe).read_text())
                        for view in ['surface','findings','scans','agents','settings','dast','taint','api','automation','assessment']:
                            page.locator('#nav-'+view).click();page.wait_for_timeout(200)
                            assessment=page.evaluate("async () => await axe.run(document, {runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})")
                            result['a11y'][view]=[{'id':v['id'],'impact':v['impact'],'count':len(v['nodes']),'nodes':[{'html':n['html'],'failure':n['failureSummary']} for n in v['nodes']]} for v in assessment['violations']]
                    if args.axe:
                        assert all(not violations for violations in result['a11y'].values()), result['a11y']
                    page.set_viewport_size({'width':320,'height':844})
                    result['small_screen_scrollwidth']=page.evaluate('document.documentElement.scrollWidth')
                    result['interface']['mobile_views']={}
                    result['mobile_a11y']={}
                    page.locator('#workspace-navigation').wait_for(state='hidden')
                    assert page.locator('#workspace-menu-toggle').is_visible()
                    assert not page.locator('#workspace-navigation').is_visible()
                    for view in ['surface','findings','scans','agents','settings','dast','taint','api','automation','assessment']:
                        page.locator('#workspace-menu-toggle').click()
                        assert page.locator('#workspace-navigation').is_visible()
                        page.locator('#nav-'+view).click();page.wait_for_timeout(200)
                        assert not page.locator('#workspace-navigation').is_visible()
                        width=page.evaluate('document.documentElement.scrollWidth')
                        result['interface']['mobile_views'][view]=width
                        assert width<=320, (view,width)
                        if view=='settings':
                            page.locator('#view-settings').evaluate('(el)=>el.scrollTop=0')
                            page.screenshot(path=str(out/'configuration-mobile.png'))
                        if args.axe:
                            assessment=page.evaluate("async () => await axe.run(document, {runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})")
                            result['mobile_a11y'][view]=[{'id':v['id'],'impact':v['impact'],'nodes':[n['html'] for n in v['nodes']]} for v in assessment['violations']]
                            assert not result['mobile_a11y'][view], result['mobile_a11y'][view]
                    page.locator('#workspace-command-open').click()
                    page.locator('#workspace-command-search').fill('provider')
                    assert page.locator('#workspace-command-results button').count()==1
                    assert page.locator('#workspace-command-dialog').bounding_box()['width']<=320
                    if args.axe:
                        violations=page.evaluate("async()=> (await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
                        assert not violations, violations
                    page.screenshot(path=str(out/'mobile-command-search.png'))
                    page.keyboard.press('Escape')
                    wait_condition(page,'!document.querySelector("#workspace-command-dialog").open')
                    result['advanced_experience']['mobile_command_search']=True
                    # Search leaves the current view unchanged until a match is chosen.
                    assert page.locator('#view-assessment').is_visible()
                    assert page.locator('#workspace-title').bounding_box()['y'] < 500
                    result['interface']['mobile_menu_collapses_after_selection']=True
                    page.screenshot(path=str(out/'fixed-320px.png'))
                    (out/'browser-results.json').write_text(json.dumps(result,indent=2))
                    assert all(result['keyboard_connection'].values()) and result['reduced_motion_media']
                    assert result['xss_marker_executions']==result['csp_control_marker_executions']==0
                    assert all(copied.values()) and result['hostile_title_kept_as_text']
                    assert result['inline_handlers']==result['inline_scripts']==0
                    assert result['durable_feedback_status']=='FALSE_POSITIVE'
                    assert result['finding_count']=='1' and result['implicit_device_selection'] is None
                    assert 'SINK_REACHED' not in proof and 'No runtime validation' in proof
                    assert not errors and not result['api_requests_outside_loopback'] and not result['runtime_requests_outside_loopback']
                    print(json.dumps(result,indent=2));context.close();browser.close()
            finally:
                server.terminate()
                try:server.wait(timeout=10)
                except subprocess.TimeoutExpired:server.kill();server.wait()

if __name__=='__main__':main()
