"""Draft workflow modules must not create proof or perform unapproved work."""
import json
from unittest.mock import AsyncMock
import pytest
from mobileag.analysis.auth_session_auditor import AuthSessionAuditor
from mobileag.analysis.firebase_auditor import FirebaseAuditor
from mobileag.analysis.webview_auditor import WebViewAuditor
from mobileag.dast.api_security_tester import APISecurityTester


@pytest.mark.asyncio
async def test_auth_candidate_constructs_with_valid_schema(tmp_path):
    (tmp_path / 'Auth.java').write_text('String password = "syntheticOpaqueCredential";')
    findings = await AuthSessionAuditor().audit_source(tmp_path)
    assert findings
    assert all(f.cvss_score == 0 and f.status.value == 'UNVERIFIED' for f in findings)
    assert 'syntheticOpaqueCredential' not in json.dumps([f.model_dump(mode='json') for f in findings])


@pytest.mark.asyncio
async def test_auth_draft_never_collects_global_device_secrets():
    adb = AsyncMock()
    with pytest.raises(PermissionError):
        await AuthSessionAuditor().audit_live_auth('synthetic', 'com.example', adb)
    assert not adb.mock_calls


@pytest.mark.asyncio
async def test_firebase_public_key_is_not_auth_bypass():
    assert await FirebaseAuditor().audit_auth_api('synthetic-public-key') == []


@pytest.mark.asyncio
@pytest.mark.parametrize('method,args', [
    ('audit_auth_api', ['synthetic']), ('audit_realtime_db', ['synthetic']),
    ('audit_storage_bucket', ['synthetic']), ('full_audit', ['/nonexistent']),
])
async def test_firebase_live_entrypoints_fail_closed(monkeypatch, method, args):
    import httpx
    client = AsyncMock()
    monkeypatch.setattr(httpx, 'AsyncClient', client)
    with pytest.raises(PermissionError):
        await getattr(FirebaseAuditor(), method)(*args, allow_network=True)
    assert not client.mock_calls


@pytest.mark.asyncio
async def test_api_url_metadata_not_auth_or_rate_limit_proof():
    auditor = APISecurityTester()
    endpoints = [{'url': 'https://fixture.invalid/api/admin/graphql', 'headers': {}}]
    assert await auditor.analyze_endpoints_static(endpoints) == []
    assert await auditor.check_rate_limiting(endpoints[0]['url']) == []
    assert await auditor.test_auth_bypass(endpoints) == []
    assert auditor.observations['authentication'] == 'not_tested'


@pytest.mark.asyncio
async def test_api_query_secrets_never_copied_to_evidence():
    findings = await APISecurityTester().test_endpoint('https://fixture.invalid/item?token=syntheticOpaqueCredential')
    assert len(findings) == 1
    assert 'syntheticOpaqueCredential' not in json.dumps(findings[0].model_dump(mode='json'))
    assert findings[0].cvss_score == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('method,args', [
    ('test_endpoint', ['https://fixture.invalid']),
    ('check_rate_limiting', ['https://fixture.invalid']),
    ('test_auth_bypass', [[{'url': 'https://fixture.invalid'}]]),
])
async def test_api_draft_live_entrypoints_fail_closed(method, args):
    with pytest.raises(PermissionError):
        await getattr(APISecurityTester(), method)(*args, allow_network=True)


@pytest.mark.asyncio
async def test_webview_comments_and_smali_boolean_are_not_proof(tmp_path):
    (tmp_path / 'Comment.java').write_text('// view.setAllowUniversalAccessFromFileURLs(true);')
    (tmp_path / 'False.smali').write_text('invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V')
    auditor = WebViewAuditor('synthetic')
    assert await auditor.audit_source(tmp_path) == []
    (tmp_path / 'Real.java').write_text('class A { void f() { view.setAllowUniversalAccessFromFileURLs(true); } }')
    findings = await auditor.audit_source(tmp_path)
    assert len(findings) == 1
    assert findings[0].cvss_score == 0
    assert findings[0].metadata['proof_state'] == 'not_proven'


def test_report_does_not_invent_testing_or_risk():
    from mobileag.reporting.professional_report import ProfessionalReportExporter
    report = ProfessionalReportExporter().generate_report([], {'access_token': 'syntheticOpaqueCredential'})
    assert 'syntheticOpaqueCredential' not in report
    assert 'comprehensive security assessment' not in report
    assert 'Overall Risk Rating: **Low**' not in report
    assert 'missing stages remain not tested' in report
    assert '✅ Pass' not in report
    assert 'Not assessed from finding counts' in report


def test_checklist_is_explicitly_planning_not_execution():
    from mobileag.reporting.pentest_checklist import PentestChecklist
    checklist = PentestChecklist()
    assert checklist.progress()['completed'] == 0
    assert 'Planning reference only' in checklist.to_markdown()
