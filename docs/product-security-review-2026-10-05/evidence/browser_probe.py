"""Local isolated Chromium browser probes; public CDN assets may load, no targets tested."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
OUT=Path(__file__).resolve().parent
with sync_playwright() as p:
 b=p.chromium.launch(executable_path=str(Path.home()/'.cache/ms-playwright/chromium-1247/chrome-linux64/chrome'),headless=True)
 context=b.new_context(viewport={'width':1440,'height':1000},permissions=['clipboard-read','clipboard-write'])
 page=context.new_page(); errors=[]; requests=[]; failed=[]; console=[]
 page.on('console',lambda m:console.append({'type':m.type,'text':m.text}) if m.type in {'error','warning'} else None)
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('request',lambda r: requests.append(r.url))
 page.on('requestfailed',lambda r: failed.append({'url':r.url,'error':r.failure}))
 page.on('dialog',lambda d:d.accept('synthetic-review-only') if d.type=='prompt' else d.dismiss())
 page.goto('http://127.0.0.1:18764',wait_until='networkidle',timeout=60000)
 page.wait_for_timeout(1500)
 result={'browser':b.version,'page_errors':errors,'failed_requests':failed,'initial_title':page.title(),'libraries':page.evaluate('({vis:typeof vis,lucide:typeof lucide,Chart:typeof Chart,tailwind:typeof tailwind})')}
 result['console']=console
 result['dashboard_render']=page.evaluate('''() => {let error=null;try{renderDashboard(currentScan)}catch(e){error=String(e)}return {error,missingObfuscationElement:!document.getElementById('top-obfuscation'),actualFindings:currentScan.findings.length,displayedFindings:document.getElementById('kpi-total').textContent,displayedMasvs:document.getElementById('kpi-masvs').textContent}}''')
 page.screenshot(path=str(OUT/'desktop.png'))
 result['semantic_counts']=page.evaluate('''() => ({dialogs:document.querySelectorAll('[role="dialog"],dialog').length,liveRegions:document.querySelectorAll('[aria-live],[role="status"],[role="alert"]').length,inlineHandlers:document.querySelectorAll('[onclick]').length,unlabelledInputs:[...document.querySelectorAll('input,select,textarea')].filter(e=>!e.labels?.length&&!e.getAttribute('aria-label')&&!e.getAttribute('aria-labelledby')).map(e=>e.id)})''')
 # Fixture passed through actual analyzer -> disk -> authenticated API -> currentScan.
 page.evaluate("switchView('findings'); inspectFinding('synthetic-finding'); switchFindingSubTab('ast')")
 page.evaluate("() => { window.auditXssCount=0; window.auditXssProbe=()=>{window.auditXssCount++; fetch('/api/status').then(r=>{window.auditAuthenticatedRead=r.status;});return 0}; }")
 original_snippet=page.evaluate('currentScan.findings[0].code_snippet')
 page.evaluate("currentScan.findings[0].code_snippet='class Example {}'; inspectFinding('synthetic-finding'); switchFindingSubTab('ast')")
 page.locator('#poc-pane-ast button').click()
 benign_count=page.evaluate('window.auditXssCount')
 page.evaluate("(s)=>{currentScan.findings[0].code_snippet=s;inspectFinding('synthetic-finding');switchFindingSubTab('ast')}",original_snippet)
 handler=page.locator('#poc-pane-ast button').get_attribute('onclick')
 page.locator('#poc-pane-ast button').click()
 page.wait_for_timeout(500)
 result['xss']={'benign_control_executions':benign_count,'handler':handler,'marker_executions':page.evaluate('window.auditXssCount'),'authenticated_read_status':page.evaluate('window.auditAuthenticatedRead || null'),'finding_status':page.evaluate("currentScan.findings[0].status")}
 page.evaluate("switchFindingSubTab('proof')")
 result['proof_text']=page.locator('#poc-pane-proof').inner_text()
 page.screenshot(path=str(OUT/'proof-without-runtime.png'))
 before=len(requests);page.evaluate("runSingleAgent('manifest_auditor'); triggerAllAgents()");page.wait_for_timeout(500)
 result['agent_action_requests']=requests[before:]
 # Every primary view, basic visible controls/width metrics; no device action clicks.
 result['screens']={}
 for view in ['surface','findings','scans','agents','settings','dast','taint','api']:
  page.evaluate('(v)=>switchView(v)',view);page.wait_for_timeout(300)
  result['screens'][view]=page.evaluate('''() => {const es=[...document.querySelectorAll('button,input,select,textarea')].filter(e=>e.getClientRects().length);return {visibleControls:es.length,smallTargets:es.filter(e=>{const r=e.getBoundingClientRect();return r.width<24||r.height<24}).length,scrollWidth:document.documentElement.scrollWidth,viewport:innerWidth}}''')
 page.evaluate("switchView('surface')");page.set_viewport_size({'width':390,'height':844});page.wait_for_timeout(500)
 result['narrow']=page.evaluate('''() => ({viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth,bodyOverflow:getComputedStyle(document.body).overflow,main:[...document.querySelectorAll('main')].map(e=>({x:e.getBoundingClientRect().x,width:e.getBoundingClientRect().width})),offscreenButtons:[...document.querySelectorAll('button')].filter(e=>e.getClientRects().length&&e.getBoundingClientRect().right>innerWidth).length})''')
 page.screenshot(path=str(OUT/'narrow390.png'))
 result['requests']=requests
 (OUT/'browser-results.json').write_text(json.dumps(result,indent=2))
 print(json.dumps({k:v for k,v in result.items() if k not in {'requests','proof_text','semantic_counts','screens'}},indent=2))
 assert benign_count == 0, 'Benign control unexpectedly executed marker'
 assert result['xss']['marker_executions'] == 1, 'Crafted copy did not execute exactly once'
 assert result['xss']['authenticated_read_status'] == 200, 'Authenticated-read boundary not demonstrated'
 context.close();b.close()
