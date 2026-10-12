"""Opt-in isolated browser check of real taint renderer; no server or targets."""
import argparse
import json
from pathlib import Path
from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium', required=True)
    args = parser.parse_args()
    root = Path(__file__).parents[1]
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.chromium, headless=True)
        page = browser.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.route('**/*', lambda route: route.abort())
        ids = ['taint-findings-container', 'taint-findings-badge', 'taint-stat-sinks', 'taint-stat-sev', 'taint-stat-conf']
        page.set_content(''.join(f'<div id="{i}"></div>' for i in ids))
        page.add_script_tag(content=(root / 'mobileag/web/static/taint.js').read_text())
        finding = {'severity': 'INFO', 'cwe_id': 'CWE-829', 'title': '<img src=x onerror=alert(1)>',
                   'description': 'Synthetic candidate', 'cvss_score': 0}
        page.evaluate('(f) => renderTaintFindings([f])', finding)
        assert page.locator('#taint-stat-sev').inner_text() == 'INFO'
        assert page.locator('#taint-stat-conf').inner_text() == 'Not measured'
        assert 'Not assessed' in page.locator('#taint-findings-container').inner_text()
        assert page.locator('#taint-findings-container img').count() == 0
        for score in (None, '9.9', 99, -1):
            page.evaluate('(f) => renderTaintFindings([f])', {**finding, 'cvss_score': score})
            assert 'Not assessed' in page.locator('#taint-findings-container').inner_text()
        page.evaluate('renderTaintFindings([])')
        assert page.locator('#taint-stat-sev').inner_text() == 'NOT ASSESSED'

        # Exercise actual triage handlers with a synthetic acknowledgement.
        # No backend/network requests; rejected or malformed receipts cannot
        # change local status, revision, or the attested KPI.
        page.set_content('<div id="kpi-critical-high">0</div><div id="kpi-med-low">0</div>')
        for module in ('workspace.js', 'findings.js'):
            page.add_script_tag(content=(root / 'mobileag/web/static' / module).read_text())
        page.evaluate('''() => {
            currentScan = {scan_id:'synthetic',revision:0,findings:[{id:'test',status:'UNVERIFIED',severity:'HIGH'}]};
            window.MobileAgUI = {askNotes:async()=>({notes:'Synthetic controls'})};
            showToast = inspectFinding = applyFindingsFilter = () => {};
            window.fetch = async()=>{throw new Error('Synthetic rejected request')};
        }''')
        page.evaluate("submitTriage('test','CONFIRMED')")
        assert page.evaluate('currentScan.revision') == 0
        assert page.evaluate('currentScan.findings[0].status') == 'UNVERIFIED'
        page.evaluate("window.fetch = async()=>({json:async()=>({status:'saved',revision:1})})")
        page.evaluate("submitTriage('test','CONFIRMED')")
        assert page.evaluate('currentScan.revision') == 0
        page.evaluate('''window.fetch = async()=>({json:async()=>({status:'saved',revision:1,
            finding:{id:'test',severity:'HIGH',status:'CONFIRMED',evidence_assessment:{basis:'analyst_attested',
                artifact_binding:'checked',independently_verified:false,validation_errors:[]}}})})''')
        page.evaluate("submitTriage('test','CONFIRMED')")
        assert page.evaluate('currentScan.revision') == 1
        assert page.locator('#kpi-critical-high').inner_text() == '1'
        page.evaluate('''window.fetch = async()=>({json:async()=>({status:'saved',revision:2,
            finding:{id:'test',severity:'HIGH',status:'UNVERIFIED',evidence_assessment:{basis:'not_proven'}}})})''')
        page.evaluate("submitTriage('test','UNVERIFIED')")
        assert page.locator('#kpi-critical-high').inner_text() == '0'
        assert not errors, errors
        browser.close()
    print(json.dumps({'status': 'passed', 'scope': 'synthetic isolated renderer; no live testing', 'browser_errors': errors}))


if __name__ == '__main__':
    main()
