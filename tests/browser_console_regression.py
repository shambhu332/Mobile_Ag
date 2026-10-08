"""Opt-in console regression using the existing isolated synthetic server fixture.

Run with Playwright and cached Chromium installed, for example:
  python tests/browser_console_regression.py --server-python /path/to/venv/bin/python

No real devices, providers, production data or remote browser assets are used.
Screenshots and a JSON result are written to --output, including on failure.
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile

from playwright.sync_api import sync_playwright


REPO = Path(__file__).resolve().parents[1]
VIEWS = (
    'overview', 'assessment', 'surface', 'findings', 'scans', 'agents',
    'settings', 'dast', 'taint', 'api', 'automation',
)


def existing_fixture():
    """Import without running or modifying the broader product regression."""
    spec = importlib.util.spec_from_file_location(
        'mobileag_browser_fixture', REPO / 'tests/browser_product_regression.py',
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SERVER, module.wait_condition


def isolated_environment(root, port):
    env = os.environ.copy()
    for name in list(env):
        if name.endswith('_API_KEY') or name.startswith('MOBILEAG_LLM_'):
            env.pop(name)
    env.pop('MOBILEAG_LOCAL_LLM_KEY', None)
    env.update(
        MOBILEAG_DATA_DIR=str(root), MOBILEAG_API_TOKEN='synthetic-local-only',
        OFFLINE='true', APPROVED_LLM_PROVIDERS='[]',
        MOBILEAG_ALLOWED_DEVICES='emulator-synthetic',
        MOBILEAG_ALLOWED_ORIGINS='', MOBILEAG_ALLOWED_CONNECT='',
        TEST_PORT=str(port), PYTHONPATH=str(REPO),
        MOBILEAG_LLM_ALLOWED_PROVIDERS='openai,gemini,grok',
        MOBILEAG_LLM_OPENAI_MODEL='synthetic-browser-model',
        MOBILEAG_LLM_GEMINI_MODEL='synthetic-gemini',
        MOBILEAG_LLM_GROK_MODEL='synthetic-grok',
        OPENAI_API_KEY='synthetic-browser-provider-key',
        GEMINI_API_KEY='synthetic-gemini-key', XAI_API_KEY='synthetic-grok-key',
    )
    return env


def start_ready(server, url):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError('Synthetic server exited; check --server-python dependencies')
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(.25)
    raise RuntimeError('Synthetic server did not become ready')


def check_accessibility(page):
    violations = page.evaluate("""async () => (await axe.run(document, {
        runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}
    })).violations""")
    return [
        {'id': item['id'], 'impact': item['impact'], 'nodes': [
            {'html': node['html'], 'failure': node.get('failureSummary', '')}
            for node in item['nodes']
        ]}
        for item in violations
    ]


def synthetic_apk():
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest package="org.example.automation"/>')
        archive.writestr('classes.dex', b'dex\n035\x00synthetic-console-fixture')
    return {
        'name': 'synthetic-console-fixture.apk',
        'mimeType': 'application/vnd.android.package-archive',
        'buffer': payload.getvalue(),
    }


def run_browser(args, url, out, result, wait_condition):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, headless=True)
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})
        page = context.new_page()
        origin = urlsplit(url).netloc
        result.update(browser=browser.version, page_errors=[], external_requests=[],
                      execution_posts=[], upload_posts=0, screens={})

        def guard(route):
            if urlsplit(route.request.url).netloc != origin:
                result['external_requests'].append(route.request.url)
                route.abort()
            else:
                route.continue_()

        def record_request(request):
            path = urlsplit(request.url).path
            if request.method == 'POST':
                if path == '/api/upload/apk':
                    result['upload_posts'] += 1
                if path == '/api/assessments' or path.startswith('/api/scans/'):
                    result['execution_posts'].append(path)

        context.route('**/*', guard)
        page.on('request', record_request)
        page.on('pageerror', lambda error: result['page_errors'].append(str(error)))
        page.on('websocket', lambda ws: result['external_requests'].append(ws.url)
                if urlsplit(ws.url).netloc != origin else None)
        page.emulate_media(reduced_motion='reduce')
        try:
            page.goto(url, wait_until='domcontentloaded', timeout=90000)
            page.locator('#session-token').fill('synthetic-local-only')
            page.locator('#session-token').press('Enter')
            wait_condition(page, 'currentScan?.scan_id === "scan_synthetic"')
            wait_condition(page, 'document.querySelector("#auto-ready-status").textContent.startsWith("Checked ")')
            page.locator('#advanced-tools').evaluate('(element) => element.open = true')
            page.locator('#nav-overview').click()
            page.locator('#view-overview').wait_for(state='visible')
            assert page.locator('#console-upload-button').is_enabled()
            assert page.evaluate('dastActiveDevice') is None
            result['severity_counts_match_recorded_findings'] = page.evaluate("""() =>
                ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].every(severity =>
                    document.querySelector('#console-count-' + severity.toLowerCase()).textContent
                    === String(currentScan.findings.filter(finding =>
                        String(finding.severity || '').toUpperCase() === severity).length))
            """)
            assert result['severity_counts_match_recorded_findings']
            assert 'org.example.review' in page.locator('#view-overview').inner_text()

            # Absence of a job is not displayed as a clean scan or measured zero.
            page.evaluate('() => { window.savedConsoleScan=currentScan; currentScan=null; window.dispatchEvent(new Event("workspace-scan-changed")); }')
            assert page.locator('#console-count-high').inner_text() == '—'
            assert 'No scan selected' in page.locator('#view-overview').inner_text()
            page.evaluate('() => { currentScan=window.savedConsoleScan; delete window.savedConsoleScan; window.dispatchEvent(new Event("workspace-scan-changed")); }')
            result['empty_state_has_no_invented_counts'] = True

            if args.axe:
                page.evaluate(Path(args.axe).read_text())
            result['accessibility'] = 'WCAG A/AA automated checks' if args.axe else 'not run: no local axe asset'
            for size, width, height in [('desktop', 1440, 1000), ('mobile', 320, 844)]:
                page.set_viewport_size({'width': width, 'height': height})
                if size == 'mobile':
                    page.locator('#workspace-navigation').wait_for(state='hidden')
                for view in VIEWS:
                    if size == 'mobile':
                        page.locator('#workspace-menu-toggle').click()
                        assert page.locator('#workspace-navigation').is_visible()
                    page.locator('#nav-' + view).click()
                    page.locator('#view-' + view).wait_for(state='visible')
                    page.wait_for_timeout(200)
                    if size == 'mobile':
                        assert not page.locator('#workspace-navigation').is_visible()
                    current = page.locator('.nav-item[aria-current="page"]')
                    assert current.count() == 1 and current.get_attribute('id') == 'nav-' + view
                    assert page.locator('#workspace-title').inner_text().strip()
                    page.locator('#view-' + view).evaluate('(element) => element.scrollTop = 0')
                    measurements = page.evaluate('({width:innerWidth, scrollWidth:document.documentElement.scrollWidth})')
                    violations = check_accessibility(page) if args.axe else None
                    result['screens'][size + '-' + view] = {**measurements, 'a11y': violations}
                    page.screenshot(path=str(out / f'{size}-{view}.png'))

            # The overview uses the real upload endpoint, but must never start a job.
            page.set_viewport_size({'width': 1440, 'height': 1000})
            page.locator('#workspace-navigation').wait_for(state='visible')
            page.locator('#nav-overview').click()
            page.locator('#console-upload-file').set_input_files(synthetic_apk())
            wait_condition(page, 'document.querySelector("#assessment-artifact").value.length > 0')
            page.locator('#view-assessment').wait_for(state='visible')
            assert result['upload_posts'] == 1
            assert not result['execution_posts']
            assert page.evaluate('dastActiveDevice') is None
            assert 'No tests started' in page.locator('#assessment-status').inner_text()
            result['upload_only_does_not_start_tests_or_select_device'] = True
            page.screenshot(path=str(out / 'uploaded-awaiting-approval.png'))

            assert not result['page_errors'], result['page_errors']
            assert not result['external_requests'], result['external_requests']
            assert all(item['scrollWidth'] <= item['width'] for item in result['screens'].values()), result['screens']
            assert all(not item['a11y'] for item in result['screens'].values()), result['screens']
            result['passed'] = True
        except Exception:
            # The connection form may contain a token; never screenshot it.
            if not page.locator('#session-connect').evaluate('(element) => element.open'):
                page.screenshot(path=str(out / 'failure.png'))
            raise
        finally:
            context.close()
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-python', default=sys.executable)
    parser.add_argument('--chromium', default=None, help='Chromium executable; defaults to the Playwright-managed browser')
    local_axe = REPO / 'assets/node_modules/axe-core/axe.min.js'
    parser.add_argument('--axe', default=str(local_axe) if local_axe.is_file() else None,
                        help='Local axe-core asset; defaults to the existing assets dependency when present')
    parser.add_argument('--output', default='/tmp/mobileag-console-regression')
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    fixture, wait_condition = existing_fixture()
    result = {'passed': False, 'fixture': 'Existing real local server; synthetic static inputs and mocked devices/providers',
              'live_device_testing': False, 'live_provider_testing': False}
    try:
        with tempfile.TemporaryDirectory(prefix='mobileag-console-regression-') as temporary:
            root = Path(temporary)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            runner = root / 'runner.py'
            runner.write_text(fixture)
            with (root / 'server.log').open('w') as log:
                server = subprocess.Popen([args.server_python, str(runner)], cwd=root,
                                          env=isolated_environment(root, port), stdout=log, stderr=log)
                try:
                    url = f'http://127.0.0.1:{port}'
                    start_ready(server, url)
                    run_browser(args, url, out, result, wait_condition)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
    except Exception as error:
        result['failure'] = str(error)
        raise
    finally:
        (out / 'console-results.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
