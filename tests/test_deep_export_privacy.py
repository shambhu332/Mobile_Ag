"""Synthetic privacy/export contracts from the whole-codebase review.

These cases never contact a device, SDK service or application backend.
"""
import json
import importlib
import pytest
from fastapi.testclient import TestClient
from mobileag import __version__
from mobileag.reporting.finding import Finding
from mobileag.reporting.sarif_exporter import SARIFExporter
from mobileag.security.privacy import redact


@pytest.mark.parametrize('name', [
    'access_token', 'refresh_token', 'client_secret', 'passwd',
    'X-Api-Key', 'x-goog-api-key', 'X-Auth-Token', 'Authorization',
    'X-Session-ID', 'X-Refresh-Token', 'X-Client-Secret', 'X-Private-Key',
])
def test_opaque_credentials_redacted_in_nested_fields(name):
    value = {'captured': {name: 'syntheticOpaqueCredential', 'public': 'keep'}}
    result = redact(value)
    assert result['captured'][name] == '[REDACTED]'
    assert result['captured']['public'] == 'keep'
    assert value['captured'][name] == 'syntheticOpaqueCredential'


def test_namespaced_redaction_preserves_noncredential_suffix_lookalikes():
    value = {'tokenizer': 'synthetic-public-tokenizer',
             'secretariat': 'synthetic-public-secretariat',
             'X-Request-Trace': 'synthetic-public-trace',
             'X-Request-Token': 'synthetic-sensitive-token'}
    result = redact(value)
    assert result['tokenizer'] == 'synthetic-public-tokenizer'
    assert result['secretariat'] == 'synthetic-public-secretariat'
    assert result['X-Request-Trace'] == 'synthetic-public-trace'
    assert result['X-Request-Token'] == '[REDACTED]'


def test_url_redaction_strips_userinfo_even_when_it_contains_only_username():
    result = redact('https://synthetic-user@api.example.test:8443/v1/profile?access_token=synthetic-token')
    assert 'synthetic-user' not in result
    assert 'synthetic-token' not in result
    assert result == 'https://api.example.test:8443/v1/profile?[REDACTED]'
    # A userinfo-free IPv6 authority remains valid and unchanged.
    assert redact('https://[2001:db8::1]:8443/v1/profile') == 'https://[2001:db8::1]:8443/v1/profile'


@pytest.mark.parametrize('name', ['access_token', 'refresh_token', 'api_key', 'client_secret'])
def test_quoted_json_credentials_redacted(name):
    result = redact(json.dumps({name: 'syntheticOpaqueCredential', 'public': 'keep'}))
    assert 'syntheticOpaqueCredential' not in result
    assert 'keep' in result


@pytest.mark.parametrize('field', ['poc_guide', 'remediation', 'file_path', 'affected_component'])
def test_all_generated_finding_evidence_redacted(field):
    finding = Finding(title='Synthetic', description='Synthetic', **{field: 'password=syntheticOpaqueCredential'})
    assert 'syntheticOpaqueCredential' not in finding.model_dump()[field]


def test_legacy_frida_script_field_is_never_exported():
    finding = Finding(title='Synthetic', description='Synthetic', frida_script='synthetic hook payload')
    assert 'frida_script' not in finding.model_dump()
    assert 'frida_script' not in finding.to_report_dict()
    assert finding.frida_script == 'synthetic hook payload'


@pytest.mark.parametrize('decision', ['FALSE_POSITIVE', 'DUPLICATE'])
def test_sarif_honors_suppressed_analyst_decisions(decision):
    finding = Finding(title='Synthetic rejected', description='Synthetic', status=decision)
    report = SARIFExporter.generate_sarif([finding])
    assert report['runs'][0]['results'] == []


def test_sarif_preserves_candidate_proof_and_actual_version():
    report = SARIFExporter.generate_sarif([{'id': 'synthetic', 'title': 'Synthetic candidate', 'severity': 'INFO', 'status': 'UNVERIFIED'}])
    run = report['runs'][0]
    assert run['tool']['driver']['version'] == __version__
    properties = run['results'][0]['properties']
    assert properties['cvss'] == 0.0
    assert properties['status'] == 'UNVERIFIED'
    assert properties['proof_basis'] == 'not_proven'


def test_sarif_redacts_raw_dictionary_evidence():
    report = SARIFExporter.generate_sarif([{
        'id': 'synthetic', 'title': 'Synthetic', 'severity': 'INFO',
        'description': '{"access_token":"syntheticOpaqueCredential"}',
        'code_snippet': 'password=syntheticOpaqueCredential',
    }])
    assert 'syntheticOpaqueCredential' not in json.dumps(report)


def test_validation_errors_do_not_echo_sensitive_rejected_input():
    web = importlib.import_module('mobileag.web.app')
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + web.app.state.auth_token})
    response = client.post('/api/scans/scan_synthetic/findings/synthetic/feedback', json={
        'verdict': 'CONFIRMED', 'notes': 'Synthetic observation',
        'evidence': {'attacker_context': 'access_token=syntheticOpaqueCredential'},
    })
    assert response.status_code == 422
    assert 'syntheticOpaqueCredential' not in response.text
