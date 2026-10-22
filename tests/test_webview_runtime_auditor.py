from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mobileag.dast.webview_runtime_auditor import WebViewRuntimeAuditor


PACKAGE = 'org.example.fixture'


def test_webview_runtime_observation_only_counts_widget_classes():
    auditor = WebViewRuntimeAuditor()
    result = auditor.audit_elements([
        {'package': PACKAGE, 'class': 'android.webkit.WebView', 'text': 'synthetic private page'},
        {'package': PACKAGE, 'class': 'org.example.fixture.CustomWebView', 'text': 'secret'},
        {'package': PACKAGE, 'class': 'android.widget.TextView', 'text': 'token=syntheticSecret'},
    ], PACKAGE)
    assert result['status'] == 'observed'
    assert result['visible_webview_count'] == 2
    assert result['snapshot_node_count'] == 3
    assert 'synthetic' not in repr(result) and 'secret' not in repr(result)
    assert result['proof_status'] == 'not_proven'


def test_webview_zero_count_is_only_a_snapshot_observation():
    result = WebViewRuntimeAuditor().audit_elements([
        {'package': PACKAGE, 'class': 'android.widget.TextView', 'text': 'not retained'},
    ], PACKAGE)
    assert result['status'] == 'not_observed_in_snapshot'
    assert result['visible_webview_count'] == 0
    assert any('not evidence' in limitation for limitation in result['limitations'])


@pytest.mark.parametrize('elements,package,expected', [
    ([{'package': 'org.other.app', 'class': 'android.webkit.WebView'}], PACKAGE, 'foreground_package_mismatch'),
    ([{}] * 5001, PACKAGE, 'incomplete_snapshot'),
    ([object()], PACKAGE, 'incomplete_snapshot'),
    ([], 'invalid package', 'invalid_package'),
])
def test_webview_runtime_observation_fails_closed(elements, package, expected):
    assert WebViewRuntimeAuditor().audit_elements(elements, package)['status'] == expected


@pytest.mark.asyncio
async def test_ui_crawler_reports_only_webview_widget_metadata(monkeypatch):
    import mobileag.dast.ui_crawler as module
    monkeypatch.setattr(module, 'asyncio', SimpleNamespace(sleep=AsyncMock()))
    xml = (f'<hierarchy><node package="{PACKAGE}" class="android.webkit.WebView" '
           'text="user=syntheticUser token=syntheticSecret" clickable="false" bounds="[0,0][10,10]"/>'
           '</hierarchy>')
    adb = SimpleNamespace(_exec_cmd=AsyncMock(side_effect=[
        (0, b'', b''), (0, xml.encode(), b''), (0, b'', b''),
    ]))
    report = await module.UICrawler(adb=adb).crawl_app(
        'emulator-5554', PACKAGE, guard=lambda: True,
    )
    observation = report['webview_runtime_observation']
    assert report['status'] == 'observed'
    assert observation['status'] == 'observed'
    assert observation['visible_webview_count'] == 1
    assert 'syntheticUser' not in repr(report) and 'syntheticSecret' not in repr(report)
    assert observation['proof_status'] == 'not_proven'
