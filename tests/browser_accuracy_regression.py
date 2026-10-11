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
        assert not errors, errors
        browser.close()
    print(json.dumps({'status': 'passed', 'scope': 'synthetic isolated renderer; no live testing', 'browser_errors': errors}))


if __name__ == '__main__':
    main()
