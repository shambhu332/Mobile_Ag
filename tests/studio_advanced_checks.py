"""Called by browser_studio with --advanced. Mutating live work is intercepted or denied."""
import json
import zipfile
from pathlib import Path
from playwright.sync_api import expect


def run(page,base,output,temp,posts,accessibility):
    before=len(posts);checks=[];mocked=[]
    def tools():
        page.locator('.advanced-nav').evaluate('(node)=>node.open=true')
        page.get_by_role('link',name='Workflow controls',exact=True).click()
        page.locator('#operation-group').select_option('');page.locator('#operation-search').fill('')
        page.locator('.operation-card').first.wait_for()
    def select(method,path):
        tools();page.locator('.operation-card').filter(has=page.locator('small',has_text=path)) if False else None
        page.locator(f'[data-operation="{method} {path}"]').click()
    def fill(name,value):
        control=page.locator('#operation-fields [data-field="'+name+'"]')
        if isinstance(value,bool):control.set_checked(value)
        elif control.evaluate('(n)=>n.tagName')=='SELECT':control.select_option(json.dumps(value,separators=(',',':')))
        else:control.fill(json.dumps(value) if isinstance(value,(list,dict)) else str(value))
    def execute():
        page.locator('#op-review').click();assert page.locator('#op-preview').inner_text(), {'notice':page.locator('#notice').inner_text(),'invalid':page.locator('#operation-form :invalid').evaluate_all('(nodes)=>nodes.map(n=>({name:n.dataset.field,tag:n.tagName,type:n.type,message:n.validationMessage}))')}
        assert page.locator('#op-execute').is_disabled();page.locator('#op-approve').check();page.locator('#op-execute').click()
        expect(page.locator('#op-message')).not_to_have_text('Operation in progress. Do not repeat until its outcome is known.',timeout=30000)
    def stub(path,payload):
        def handler(route):
            mocked.append({'path':path,'body':route.request.post_data_json})
            route.fulfill(status=200,content_type='application/json',body=json.dumps(payload))
        page.route('**'+path,handler)
        return handler
    tools();count=page.locator('.operation-card').count();assert count>80
    # Visit every schema-driven operation without issuing any action requests.
    for i in range(count):
        page.locator('.operation-card').nth(i).click()
        expect(page.locator('#operation-title')).not_to_be_empty()
    assert len(posts)==before
    checks.append(f'all {count} operation forms render without execution')
    tools();page.locator('#parity-list .parity-row').filter(has_text='diff --old --new').get_by_role('button',name='Open related controls').click()
    expect(page.locator('#operation-group')).to_have_value('Scans & comparison')
    expect(page.locator('#operation-search')).to_have_value('compare')
    assert page.locator('#operation-list .operation-card').count()>0
    assert page.locator('#parity-list .parity-row').filter(has_text='web --host --port').get_by_role('button',name='Open related controls').count()==0
    checks.append('CLI parity links open matching controls and do not expose terminal lifecycle')
    select('POST','/api/dast/frida');assert page.locator('#op-review').is_disabled();checks.append('retired hooks stay disabled')
    select('POST','/api/scope')
    for k in ['devices','packages','origins','methods','actions']:fill(k,[])
    page.locator('#op-review').click();page.locator('#op-approve').check();fill('methods',['GET']);assert page.locator('#op-execute').is_disabled()
    execute();expect(page.locator('#operation-result')).to_contain_text('saved');checks.append('review invalidated on input edit; real bounded scope save')
    select('POST','/api/settings');fill('entropy_threshold',4.5);fill('offline',True);execute();expect(page.locator('#operation-result')).to_contain_text('saved');checks.append('analysis settings persisted')
    select('GET','/api/assessments/providers');execute();expect(page.locator('#operation-result')).to_contain_text('server environment only');checks.append('provider setup without credential storage')
    select('POST','/api/studio/import/sarif')
    raw={'version':'2.1.0','runs':[{'tool':{'driver':{'name':'synthetic-browser'}},'results':[{'ruleId':'R','message':{'text':'synthetic review candidate'}}]}]}
    page.locator('[data-field="file"]').set_input_files({'name':'fixture.sarif','mimeType':'application/json','buffer':json.dumps(raw).encode()})
    execute();expect(page.locator('#operation-result')).to_contain_text('UNVERIFIED')
    with page.expect_download() as download:page.locator('#op-download').click()
    assert download.value.suggested_filename.endswith('.json');checks.append('real SARIF import + download')
    select('POST','/api/studio/import/mobsf');page.locator('[data-field="file"]').set_input_files({'name':'fixture.json','mimeType':'application/json','buffer':b'{"code_analysis":{"findings":{}}}'})
    execute();expect(page.locator('#operation-result')).to_contain_text('imported_candidates');checks.append('real MobSF import')
    bundle=Path(temp)/'fixture.aab'
    with zipfile.ZipFile(bundle,'w') as z:z.writestr('BundleConfig.pb',b'synthetic');z.writestr('base/manifest/AndroidManifest.xml',b'synthetic')
    select('POST','/api/studio/inventory/aab');page.locator('[data-field="file"]').set_input_files(bundle);execute();expect(page.locator('#operation-result')).to_contain_text('input_inventory_only_not_analyzed');checks.append('real AAB inventory')
    select('POST','/api/analysis/taint');fill('source_code','class Main { void f() {} }');execute();expect(page.locator('#operation-result')).to_contain_text('findings');checks.append('real source snippet analysis')
    # Empty server scope ensures these are denied before device or network access.
    select('POST','/api/dast/root');fill('serial','outside-synthetic-scope');execute();expect(page.locator('#operation-result')).to_contain_text('outside configured scope');checks.append('real device scope denial')
    select('POST','/api/apis/test');fill('url','https://outside.invalid/synthetic');execute();expect(page.locator('#operation-result')).to_contain_text('scope');checks.append('real API scope denial')
    # Scan-scoped triage is real; optional evidence must be omittable for UNVERIFIED.
    select('POST','/api/scans/{scan_id}/findings/{finding_id}/feedback');fill('scan_id','scan_fixture_0');fill('finding_id','finding_0');fill('verdict','UNVERIFIED');fill('notes','Synthetic browser review only.');fill('revision',0);execute();expect(page.locator('#operation-result')).to_contain_text('saved');checks.append('real scan-scoped triage and optional evidence fields')
    select('GET','/api/studio/scans/{scan_id}/report');fill('scan_id','scan_fixture_0');fill('format','markdown');execute();expect(page.locator('#operation-result')).to_contain_text('MobileAg evidence report');checks.append('Markdown export')
    # Full guided creation contract: selected target and confirmations, no actual job.
    stub('/api/assessments',{'id':'assess_synthetic','status':'running'})
    select('POST','/api/assessments');fill('apk_path','/synthetic/upload.apk');fill('package_name','org.example.notes');fill('packages',['org.example.notes']);fill('authorized',True);fill('scope_change_confirmed',True);fill('confirmation','START SCOPED TESTS');execute()
    body=mocked[-1]['body'];assert body['authorized'] and body['scope']['packages']==['org.example.notes'];assert body['api'] is False and body['dast'] is False;checks.append('guided assessment payload intercepted')
    rid='auto_'+'b'*32
    stub('/api/automation/runs/'+rid+'/execute',{'id':rid,'status':'completed'})
    select('POST','/api/automation/runs/{rid}/execute');fill('rid',rid);fill('revision',1);fill('approved_action_ids',['synthetic-action']);fill('confirmation',rid);fill('test_authorization','Bearer synthetic-private-value')
    page.locator('#op-review').click();assert 'synthetic-private-value' not in page.locator('#op-preview').inner_text();page.locator('#op-approve').check();page.locator('#op-execute').click();expect(page.locator('#op-message')).to_contain_text('Response received');assert page.locator('[data-field="test_authorization"]').input_value()=='';assert mocked[-1]['body']['test_authorization']=='Bearer synthetic-private-value';checks.append('exact automation approval + memory-only private input intercepted')
    # Cancel/retry never run real jobs during browser validation.
    stub('/api/scans/scan_fixture_0/cancel',{'status':'cancelled'})
    select('POST','/api/scans/{scan_id}/cancel');fill('scan_id','scan_fixture_0');execute();expect(page.locator('#operation-result')).to_contain_text('cancelled');checks.append('cancel request intercepted')
    stub('/api/scans/scan_fixture_0/retry',{'status':'initiated','scan_id':'scan_fixture_0'})
    select('POST','/api/scans/{scan_id}/retry');fill('scan_id','scan_fixture_0');execute();checks.append('retry request intercepted')
    accessibility('advanced-controls');page.screenshot(path=str(output/'advanced-controls.png'),full_page=True)
    # Artifact-bound source and graph reads + real authenticated WebSocket.
    page.get_by_role('link',name='Source, graph & live events',exact=True).click();page.locator('#investigation-select').select_option('scan_fixture_0')
    expect(page.locator('#investigation-scan')).to_contain_text('Research Notes')
    page.locator('#source-list').click();page.locator('#source-files button').first.wait_for();page.locator('#source-files button').first.click();expect(page.locator('#source-result')).to_contain_text('class Fixture')
    page.locator('#source-query').fill('Fixture');page.locator('#source-search').click();expect(page.locator('#source-files')).to_contain_text('Fixture.java');checks.append('real hash-bound source listing/read/search')
    page.locator('#graph-load').click();page.locator('#graph-result svg').wait_for();expect(page.locator('#graph-result circle')).to_have_count(2);expect(page.locator('#graph-result line')).to_have_count(1);checks.append('real graph inventory renderer')
    urls=[];page.on('websocket',lambda ws:urls.append(ws.url));page.locator('#telemetry-start').click();expect(page.locator('#telemetry-state')).to_have_text('Connected to selected scan');expect(page.locator('#telemetry-events')).to_contain_text('connection_established');assert all('?token' not in u for u in urls)
    page.locator('#telemetry-stop').click();checks.append('real scan-specific authenticated WebSocket')
    page.get_by_role('link',name='Logs & runtime',exact=True).click();page.locator('#logcat-scan').select_option('scan_fixture_0');expect(page.locator('#scan-event-list')).to_contain_text('Historical synthetic event');expect(page.locator('#scan-events-state')).to_contain_text('stored event');expect(page.locator('#scan-events-download')).to_be_enabled()
    with page.expect_download() as event_download:page.locator('#scan-events-download').click()
    assert event_download.value.suggested_filename.endswith('.json')
    expect(page.locator('#logcat-scope-state')).to_contain_text('No devices are approved');expect(page.locator('#logcat-capture')).to_be_disabled();expect(page.locator('#scan-events-start')).to_be_enabled();checks.append('historical scan-event display/export and fail-closed logcat without approved device scope');accessibility('logs-no-device-scope');page.screenshot(path=str(output/'logs-no-device-scope.png'),full_page=True)
    # Add a synthetic exact device/package/action to the test-only policy. Mock the
    # logcat response so the browser renderer is tested without invoking ADB.
    page.get_by_role('link',name='Workflow controls',exact=True).click();select('POST','/api/scope')
    fill('devices',['synthetic-device']);fill('packages',['org.example.notes']);fill('origins',[]);fill('methods',['GET']);fill('actions',['logcat']);execute();expect(page.locator('#operation-result')).to_contain_text('saved')
    synthetic_log={'serial':'synthetic-device','line_count':1,'lines':['06-01 10:00:00.000  4123  4123 E Fixture: [REDACTED synthetic runtime line]'],'findings':[{'title':'Synthetic logcat observation','description':'Synthetic, unverified diagnostic candidate.','severity':'INFO','status':'UNVERIFIED','cwe_id':'CWE-532','file_path':'logcat','line_number':1,'code_snippet':'[Sensitive log value omitted]'}]}
    page.route('**/api/dast/logcat?*',lambda route:route.fulfill(status=200,content_type='application/json',body=json.dumps(synthetic_log)))
    page.get_by_role('link',name='Logs & runtime',exact=True).click();page.locator('#logcat-scan').select_option('scan_fixture_0');page.locator('#logcat-device').select_option('synthetic-device');expect(page.locator('#logcat-capture')).to_be_enabled();page.locator('#logcat-capture').click();expect(page.locator('#logcat-findings')).to_contain_text('Synthetic logcat observation');expect(page.locator('#logcat-lines-view')).to_contain_text('[REDACTED synthetic runtime line]');expect(page.locator('#logcat-download')).to_be_enabled()
    with page.expect_download() as log_download:page.locator('#logcat-download').click()
    assert log_download.value.suggested_filename.endswith('.json')
    checks.append('synthetic scoped logcat renderer and redacted evidence download; request intercepted before ADB');accessibility('logs-synthetic-preview');page.screenshot(path=str(output/'logs-synthetic.png'),full_page=True)
    accessibility('source-graph-telemetry');page.screenshot(path=str(output/'investigation.png'),full_page=True)
    for width in (390,320):
        page.set_viewport_size({'width':width,'height':844});tools();assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        accessibility('advanced-mobile-'+str(width));page.screenshot(path=str(output/f'advanced-mobile-{width}.png'),full_page=True)
    page.set_viewport_size({'width':1440,'height':1100})
    expected=['/api/scope','/api/settings','/api/studio/import/sarif','/api/studio/import/mobsf','/api/studio/inventory/aab','/api/analysis/taint','/api/dast/root','/api/apis/test','/api/scans/scan_fixture_0/findings/finding_0/feedback','/api/assessments','/api/automation/runs/'+rid+'/execute','/api/scans/scan_fixture_0/cancel','/api/scans/scan_fixture_0/retry','/api/scope']
    assert posts[before:]==expected,posts[before:]
    # Do not persist mocked bodies: they deliberately include an ephemeral test credential.
    return {'operation_forms':count,'checks':checks,'mocked_mutations':[x['path'] for x in mocked],'actual_device_or_target_network_actions':0,'expected_posts':expected}
