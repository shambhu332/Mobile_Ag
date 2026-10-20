"""Standalone local UI regression. Synthetic temporary data; no APK analysis/device/network tests.

python tests/browser_studio.py --output /tmp/mobileag-studio-browser
"""
import argparse, json, os, secrets, socket, subprocess, sys, tempfile, time, urllib.request, zipfile
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--output',default='/tmp/mobileag-studio-browser');parser.add_argument('--axe',help='Optional local axe.min.js');parser.add_argument('--advanced',action='store_true');args=parser.parse_args()
output=Path(args.output);output.mkdir(parents=True,exist_ok=True)
(output/'results.json').write_text(json.dumps({'status':'incomplete','note':'A new run has started; only a terminal passed result validates it.'}))
with tempfile.TemporaryDirectory(prefix='mobileag-studio-test-') as temp:
    token=secrets.token_urlsafe(32)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env={**os.environ,'PYTHONPATH':str(ROOT),'PYTHON_DOTENV_DISABLED':'1','MOBILEAG_DATA_DIR':temp,'MOBILEAG_API_TOKEN':token,'MOBILEAG_ALLOWED_HOSTS':'','MOBILEAG_ALLOWED_DEVICES':'synthetic-device','MOBILEAG_ALLOWED_ORIGINS':''}
    server_code='''
from mobileag.web.app import app,repository
from mobileag.studio import enable_studio
import uvicorn
repo=repository()
for i,(name,package,status,n) in enumerate([('Research Notes','org.example.notes','completed',3),('Sample Wallet','org.example.wallet','partial',1),('Demo Reader','org.example.reader','error',0)]):
 repo.save({'scan_id':'scan_fixture_'+str(i),'app_name':name,'package_name':package,'version':'1.0.0','status':status,'artifact_sha256':'a'*64,'created_at':'2026-10-17T08:30:00Z','stats':{'total':n},'attack_surface_graph':{'nodes':[{'id':'entry','label':'Synthetic entry'},{'id':'sink','label':'Synthetic sink'}],'edges':[{'from':'entry','to':'sink'}]},'findings':[{'id':'finding_'+str(j),'title':['Untrusted URI reaches WebView','Exported component needs review','Sensitive logging candidate'][j],'description':'Synthetic regression fixture. Not an actual security finding.','severity':['HIGH','MEDIUM','LOW'][j],'status':'UNVERIFIED','cwe_id':'CWE-926','affected_component':'org.example.MainActivity','file_path':'MainActivity.java','line_number':42,'code_snippet':'<img src=x onerror="window.injected=true">','poc_guide':'Synthetic review guide only; no application behavior was tested.','validation_evidence':{'record':{'attacker_context':'static_artifact','entry_point':'Synthetic fixture entrypoint only','reproduction_steps':['Inspect the synthetic fixture record.','Confirm no app or device operation was invoked.'],'positive_control':'Synthetic expected marker present.','negative_control':'Synthetic expected marker absent.','evidence_refs':['fixture-1']}},'remediation':'Validate input and enforce authorization at the sensitive operation.'} for j in range(n)],'assessment_coverage':'bounded_static_only' if status=='completed' else 'incomplete','coverage':{'manifest':{'static_status':'analyzed_heuristically','runtime_status':'not_tested','proof_status':'not_proven','limitations':['Synthetic coverage only.']}},'errors':['Synthetic tool failure'] if status=='error' else []})
source=repo.output/'scan_fixture_0'/'jadx_out'/'sources'/'org'/'example'/'Fixture.java'
source.parent.mkdir(parents=True,exist_ok=True);source.write_text('class Fixture { void f() {} }')
enable_studio(app)
uvicorn.run(app,host='127.0.0.1',port=PORT,log_level='error')
'''.replace('PORT',str(port))
    log=open(Path(temp)/'server.log','w')
    proc=subprocess.Popen([sys.executable,'-c',server_code],env=env,cwd=temp,stdout=log,stderr=log)
    try:
        base=f'http://127.0.0.1:{port}'
        for _ in range(150):
            if proc.poll() is not None:raise RuntimeError('Test server stopped: '+(Path(temp)/'server.log').read_text())
            try:
                urllib.request.urlopen(base+'/ui',timeout=.3);break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('Server not ready')
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,executable_path='/home/shambhu/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome')
            page=browser.new_page(viewport={'width':1440,'height':1100},device_scale_factor=1)
            errors=[];external=[];posts=[];a11y=[]
            def accessibility(name):
                if not args.axe:return
                page.evaluate(Path(args.axe).read_text())
                result=page.evaluate("async () => { const r = await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}}); return r.violations.map(v => ({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})); }")
                a11y.append({'view':name,'violations':result})
                assert not result, (name,result)
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.on('request',lambda r:external.append(r.url) if not r.url.startswith(base) else None)
            page.on('request',lambda r:posts.append(r.url.removeprefix(base)) if r.method=='POST' else None)
            page.goto(base+'/ui');page.get_by_role('heading',name='Your workspace is ready').wait_for()
            assert not posts
            accessibility('disconnected')
            page.screenshot(path=str(output/'overview-disconnected.png'),full_page=True)
            page.get_by_role('button',name='Connect workspace',exact=True).click();page.locator('#token').fill(token);page.locator('#connect').click();page.locator('#metric-total').filter(has_text='3').wait_for()
            assert page.locator('#token').input_value()==''
            assert page.evaluate('localStorage.length + sessionStorage.length')==0
            accessibility('overview')
            page.screenshot(path=str(output/'overview-synthetic.png'),full_page=True)
            page.get_by_role('link',name='Assessments',exact=True).click();page.locator('#scan-search').fill('wallet');assert page.locator('#scan-list tbody tr').count()==1
            page.locator('#scan-search').fill('absent');assert page.get_by_role('heading',name='No matching assessments').is_visible()
            page.locator('#scan-search').fill('')
            page.get_by_role('button',name='Research Notes',exact=True).last.click()
            page.get_by_role('button',name='Untrusted URI reaches WebView').wait_for()
            page.get_by_role('button',name='Untrusted URI reaches WebView').click()
            assert page.locator('#finding-summary .finding-count strong').all_text_contents()==['0','1','1','1','0']
            assert page.locator('#detail-content pre').first.inner_text().startswith('<img')
            assert page.evaluate('window.injected') is None
            assert page.locator('#detail-content').get_by_text('Full finding record',exact=True).count()==1
            assert 'CWE' in page.locator('#detail-content').inner_text()
            assert page.locator('#detail-content').get_by_text('Review-only guidance and analyst-recorded evidence.',exact=False).count()==1
            actual_steps=page.locator('#detail-content ol li').all_text_contents()
            assert actual_steps==['Inspect the synthetic fixture record.','Confirm no app or device operation was invoked.'],actual_steps
            accessibility('evidence-dialog')
            page.screenshot(path=str(output/'finding-synthetic.png'),full_page=True);page.get_by_role('button',name='Close evidence inspector').click()
            page.get_by_role('link',name='Coverage & evidence',exact=True).click();assert page.get_by_text('Runtime: not tested · Proof: not proven').is_visible()
            with page.expect_download() as dl:page.locator('#export').click()
            assert dl.value.suggested_filename.endswith('.sarif')
            page.get_by_role('link',name='Scope & boundaries',exact=True).click();page.get_by_text('Server environment ceilings').wait_for()
            page.get_by_role('link',name='System',exact=True).click();page.get_by_text('MobileAg static review heuristics',exact=True).wait_for()
            page.get_by_role('button',name='New assessment',exact=False).first.click()
            archive=Path(temp)/'synthetic.apk'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('AndroidManifest.xml','<manifest package="org.example.fixture"/>')
            page.locator('#archive').set_input_files({'name':'invalid.txt','mimeType':'text/plain','buffer':b'invalid'});page.get_by_text('Choose an APK, IPA or ZIP no larger than 128 MiB.').wait_for();assert posts==[]
            page.locator('#archive').set_input_files(archive);page.get_by_text('Staged: synthetic.apk',exact=False).wait_for();assert posts==['/api/upload/apk'];assert page.locator('#run').is_disabled()
            page.locator('#consent').check();assert page.locator('#run').is_enabled()
            # Execution is intercepted; UI integration is not an engine exploit/scan test.
            run_payload=[]
            def reject_run(route):
                run_payload.append(route.request.post_data_json);route.fulfill(status=409,content_type='application/json',body=json.dumps({'detail':'Synthetic blocked worker'}))
            page.route('**/api/scans/run',reject_run);page.locator('#run').click();page.get_by_text('Synthetic blocked worker',exact=True).wait_for()
            assert run_payload[0]['auto_dast'] is False and run_payload[0]['serial'] is None
            accessibility('upload-dialog')
            page.unroute('**/api/scans/run',reject_run)
            page.route('**/api/scans/run',lambda route:route.fulfill(status=200,content_type='application/json',body=json.dumps({'status':'initiated','scan_id':'scan_fixture_0'})))
            page.locator('#run').click();page.locator('#new-dialog').wait_for(state='hidden');page.get_by_text('Runtime: not tested · Proof: not proven').wait_for();assert page.locator('#archive').input_value()=='';assert not page.locator('#consent').is_checked()
            advanced={}
            if args.advanced:
                from studio_advanced_checks import run
                advanced=run(page,base,output,temp,posts,accessibility)
            for width in (390,320):
                page.set_viewport_size({'width':width,'height':844});page.get_by_role('link',name='Overview',exact=True).click();assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),f'Overflow {width}'
                accessibility(f'mobile-{width}')
                page.screenshot(path=str(output/f'mobile-{width}.png'),full_page=True)
                for tab in ('Assessments','Findings','Coverage & evidence','Scope & boundaries','System'):
                    page.get_by_role('link',name=tab,exact=True).click();assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),(width,tab)
            page.set_viewport_size({'width':1440,'height':1100})
            # Explicit disconnect clears displayed findings and staged artifact.
            page.locator('#session-button').click();page.locator('#disconnect').click();assert page.locator('#session-state').inner_text()=='Not connected';assert page.locator('#detail-content').inner_text()==''
            page.get_by_role('link',name='Overview',exact=True).click();page.get_by_role('heading',name='Your workspace is ready').wait_for()
            # Bad bearer token remains denied by the real API.
            page.get_by_role('button',name='Connect workspace',exact=True).click();page.locator('#token').fill('invalid-synthetic-token');page.locator('#connect').click();page.get_by_text('Session expired or token rejected.',exact=False).wait_for()
            assert not errors,errors
            assert not external,external
            assert posts==['/api/upload/apk','/api/scans/run','/api/scans/run']+advanced.get('expected_posts',[]),posts
            result={'status':'passed','advanced':advanced,'browser':browser.version,'desktop':'1440x1100','mobile_widths':[390,320],'page_errors':errors,'accessibility':a11y,'external_requests':external,'posts':posts,'scan_execution':'intercepted synthetic 409 and 200; no real engine/device/API testing','screenshots':'synthetic fixtures, not real findings','checks':['disconnected state','real bearer authentication','memory-only token','real scan reads','search','finding source rendered as text','review-only reproduction guide and structured analyst steps','coverage','SARIF download','read-only scope/system','real archive staging','consent gate','safe scan payload','invalid file rejection','run error','successful submission/reset','responsive navigation','disconnect','invalid token']}
            (output/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));browser.close()
    finally:
        proc.terminate()
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        log.close()
