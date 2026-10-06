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
    return {'scan_id':'scan_synthetic','package_name':'org.example.review','status':'completed','version':'synthetic','stats':{'total':1,'high':1},'findings':result,'coverage':{},'revision':0,'api_endpoints':[]}
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
        for key in ['OPENAI_API_KEY','GEMINI_API_KEY','ANTHROPIC_API_KEY','DEEPSEEK_API_KEY','XAI_API_KEY']:
            env.pop(key,None)
        env.update(MOBILEAG_DATA_DIR=str(root),MOBILEAG_API_TOKEN='synthetic-local-only',OFFLINE='true',APPROVED_LLM_PROVIDERS='[]',MOBILEAG_ALLOWED_DEVICES='emulator-synthetic',MOBILEAG_ALLOWED_ORIGINS='',MOBILEAG_ALLOWED_CONNECT='',TEST_PORT=str(port),PYTHONPATH=str(repo))
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
                    page=context.new_page();errors=[];console=[];requests=[]
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.on('console',lambda m:console.append(m.text) if m.type=='error' else None)
                    page.on('request',lambda r:requests.append(r.url))
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
                    result['screens']={}
                    for view in ['surface','findings','scans','agents','settings','dast','taint','api','automation']:
                        page.locator('#nav-'+view).click();page.wait_for_timeout(250)
                        result['screens'][view]={'visible':page.locator('#view-'+view).is_visible()}
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
                    result['a11y']={}
                    if args.axe:
                        page.evaluate(Path(args.axe).read_text())
                        for view in ['surface','findings','scans','agents','settings','dast','taint','api','automation']:
                            page.locator('#nav-'+view).click();page.wait_for_timeout(200)
                            assessment=page.evaluate("async () => await axe.run(document, {runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})")
                            result['a11y'][view]=[{'id':v['id'],'impact':v['impact'],'count':len(v['nodes']),'nodes':[{'html':n['html'],'failure':n['failureSummary']} for n in v['nodes']]} for v in assessment['violations']]
                    if args.axe:
                        assert all(not violations for violations in result['a11y'].values()), result['a11y']
                    page.set_viewport_size({'width':320,'height':844})
                    result['small_screen_scrollwidth']=page.evaluate('document.documentElement.scrollWidth')
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
