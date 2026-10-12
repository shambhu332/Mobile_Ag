"""Synthetic end-to-end dashboard tools UI; no mobile input or external traffic."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_console_regression import existing_fixture, isolated_environment, start_ready, check_accessibility
from mobileag.dashboard.client import DashboardClient


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium',required=True)
    parser.add_argument('--axe',default=str(ROOT/'assets/node_modules/axe-core/axe.min.js'))
    parser.add_argument('--output',default='/tmp/mobileag-dashboard-tools-ui')
    args=parser.parse_args();out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    source,wait=existing_fixture();result={'scope':'synthetic loopback only','page_errors':[],'blocked_requests':[],'screens':{}}
    with tempfile.TemporaryDirectory(prefix='mobileag-dashboard-tools-ui-') as temporary:
        root=Path(temporary)
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        runner=root/'runner.py';runner.write_text(source)
        with (root/'server.log').open('w') as log:
            server=subprocess.Popen([sys.executable,str(runner)],cwd=root,env=isolated_environment(root,port),stdout=log,stderr=log)
            try:
                origin=f'http://127.0.0.1:{port}';start_ready(server,origin)
                client=DashboardClient(origin,'synthetic-local-only')
                before_runs=client.get('/api/automation/runs')['data'];before_assessments=client.get('/api/assessments')['data']
                with sync_playwright() as p:
                    browser=p.chromium.launch(executable_path=args.chromium,headless=True)
                    context=browser.new_context(viewport={'width':1440,'height':1100},permissions=['clipboard-read','clipboard-write'])
                    def guard(route):
                        request=route.request;parsed=urlsplit(request.url)
                        if parsed.path=='/api/assessments/assess_ui_fixture/authorization-evidence':
                            route.fulfill(status=422,content_type='application/json',body=json.dumps({'detail':'Synthetic fixture rejection'}));return
                        if parsed.netloc!=urlsplit(origin).netloc or (request.method!='GET' and parsed.path!='/api/dashboard/read'):
                            result['blocked_requests'].append({'method':request.method,'path':parsed.path});route.abort()
                        else:route.continue_()
                    context.route('**/*',guard)
                    page=context.new_page();page.on('pageerror',lambda error:result['page_errors'].append(str(error)))
                    page.goto(origin,wait_until='domcontentloaded')
                    page.locator('#session-token').fill('synthetic-local-only');page.locator('#session-token').press('Enter')
                    wait(page,'currentScan?.scan_id === "scan_synthetic"')
                    page.locator('#dashboard-tools-open').click();page.locator('#dashboard-tools-dialog').wait_for(state='visible')
                    wait(page,'!document.querySelector("#dashboard-read-run").disabled')
                    assert 'Connected' in page.locator('#dashboard-session-label').inner_text()
                    page.locator('#dashboard-verify').click();wait(page,'document.querySelector("#dashboard-session-state").textContent.includes("verified now")')
                    for transport in ('httpx','curl'):
                        page.locator('#dashboard-read-transport').select_option(transport)
                        page.locator('#dashboard-read-run').click()
                        wait(page,f'document.querySelector("#dashboard-read-status").textContent.includes("HTTP 200 · {transport}")')
                        data=json.loads(page.locator('#dashboard-read-result').inner_text())
                        assert data['status']=='online'
                        assert 'synthetic-local-only' not in page.locator('#dashboard-tools-dialog').inner_text()
                    page.locator('#dashboard-read-copy').click()
                    command=page.evaluate('navigator.clipboard.readText()')
                    assert 'synthetic-local-only' not in command and '--transport curl' in command
                    result['http_and_curl_reads']='passed'
                    for name,width,height in [('desktop',1440,1100),('mobile',390,844)]:
                        page.set_viewport_size({'width':width,'height':height})
                        if args.axe:
                            page.evaluate(Path(args.axe).read_text())
                            violations=check_accessibility(page);assert not violations,violations
                        assert page.evaluate('document.querySelector("#dashboard-tools-dialog").scrollWidth <= document.querySelector("#dashboard-tools-dialog").clientWidth + 1')
                        path=out/(name+'-tools.png');page.screenshot(path=str(path),full_page=True);result['screens'][name]=str(path)
                    page.set_viewport_size({'width':1440,'height':1100})
                    page.locator('#dashboard-read-clear').click();assert 'No endpoint read yet' in page.locator('#dashboard-read-result').inner_text()
                    page.locator('#dashboard-tour-start').click()
                    for index in range(5):
                        assert f'Step {index+1}/5' in page.locator('#dashboard-tour-status').inner_text()
                        page.locator('#dashboard-tour-next').click()
                    assert page.locator('#dashboard-tour').is_hidden()
                    result['navigation_only_tour']='passed'
                    page.evaluate('switchView("findings");inspectFinding(currentScan.findings[0].id)')
                    assert 'Independent exploit verification: not established' in page.locator('#finding-evidence-review').inner_text()
                    # Text-only evidence rendering: finding/model strings cannot inject markup.
                    page.evaluate('''() => {const host=document.createElement('section');host.id='synthetic-evidence';document.body.append(host);
                        MobileAgEvidence.finding(host,{status:'UNVERIFIED',evidence_assessment:{basis:'<img src=x onerror=alert(1)>',missing_fields:['fixture']}});
                    }''')
                    assert page.locator('#synthetic-evidence img').count()==0
                    page.evaluate('document.querySelector("#synthetic-evidence").remove()')
                    page.evaluate('''() => {const host=document.createElement('section');host.id='synthetic-pair-ui';document.body.append(host);
                        MobileAgAuthorizationEvidence.add(host,{id:'assess_ui_fixture',status:'completed',artifact_sha256:'a'.repeat(64),
                          stages:{api:{inventory:[{id:'b'.repeat(24),protected:true}]}},authorization_comparisons:[]},async()=>{});
                    }''')
                    page.locator('#synthetic-pair-ui button').click()
                    page.locator('#authorization-pair-json').fill('{invalid')
                    page.locator('#authorization-pair-consent').check()
                    page.locator('#authorization-pair-submit').click()
                    assert 'No import was sent' in page.locator('#authorization-pair-dialog').inner_text()
                    page.locator('#authorization-pair-json').fill('{"unexpected":"synthetic-private-marker"}')
                    page.locator('#authorization-pair-submit').click()
                    wait(page,'document.querySelector("#authorization-pair-dialog").textContent.includes("Import rejected")')
                    assert page.locator('#authorization-pair-json').input_value()==''
                    assert 'synthetic-private-marker' not in page.locator('#authorization-pair-dialog').inner_text()
                    page.locator('#authorization-pair-dialog').get_by_role('button',name='Cancel',exact=True).click()
                    page.evaluate('document.querySelector("#synthetic-pair-ui").remove()')
                    result['paired_import_rejection_clears_raw_input']='passed'
                    page.locator('#dashboard-tools-open').click()
                    wait(page,'!document.querySelector("#dashboard-read-run").disabled')
                    page.evaluate('''() => {window.savedDashboardFetch=window.fetch;
                        window.fetch=(input,options)=>input==='/api/dashboard/read'?new Promise(resolve=>window.resolveSyntheticRead=resolve):window.savedDashboardFetch(input,options);
                    }''')
                    page.locator('#dashboard-read-run').click()
                    assert page.locator('#dashboard-read-run').is_disabled()
                    page.locator('#dashboard-disconnect').click()
                    page.evaluate('''() => {window.resolveSyntheticRead({json:async()=>({status_code:200,transport:'httpx',data:{marker:'stale-private-marker'}})});
                        window.fetch=window.savedDashboardFetch;delete window.savedDashboardFetch;delete window.resolveSyntheticRead;
                    }''')
                    result['disconnect_blocks_stale_response']='passed'
                    assert 'Disconnected' in page.locator('#dashboard-session-label').inner_text()
                    assert page.evaluate('accessToken')==''
                    assert 'Result cleared' in page.locator('#dashboard-read-result').inner_text()
                    page.locator('#dashboard-tools-open').click();assert page.locator('#dashboard-read-run').is_disabled()
                    page.locator('#dashboard-connect').click();page.locator('#session-token').fill('synthetic-local-only');page.locator('#session-token').press('Enter')
                    wait(page,'document.querySelector("#dashboard-session-label").textContent.startsWith("Connected")')
                    assert page.evaluate('localStorage.length')==0
                    assert not result['page_errors'],result
                    assert not result['blocked_requests'],result
                    context.close();browser.close()
                assert client.get('/api/automation/runs')['data']==before_runs
                assert client.get('/api/assessments')['data']==before_assessments
                result.update(status='passed',jobs_started=0,credential_persistence=False,accessibility='axe WCAG A/AA automated; not full certification')
            finally:
                server.terminate()
                try:server.wait(timeout=10)
                except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
                (out/'results.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
