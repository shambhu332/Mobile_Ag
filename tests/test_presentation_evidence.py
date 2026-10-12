"""Synthetic evidence boundary tests; no live apps, devices or providers."""
import copy
import importlib

import pytest
from fastapi.testclient import TestClient

from mobileag.reporting.evidence_contract import prepare_observation, prepare_scan
from mobileag.reporting.validation import bind_confirmation
from tests.proof_fixtures import confirmation_evidence

web = importlib.import_module('mobileag.web.app')


def scan():
    value = {'scan_id': 'scan_evidence', 'status': 'completed', 'revision': 0,
             'artifact_sha256': 'a' * 64, 'package_name': 'org.example.synthetic',
             'version': '1.0', 'created_at': '2026-10-11',
             'findings': [{'id': 'test', 'status': 'CONFIRMED', 'severity': 'HIGH', 'title': 'Synthetic'}]}
    return value


@pytest.mark.parametrize('source', ['stored', 'running', 'legacy'])
def test_bare_confirmation_downgraded_in_detail_and_list_without_storage_mutation(source):
    value = scan()
    if source == 'running':
        value['status'] = 'running'
        web.ACTIVE_SCANS[value['scan_id']] = value
    elif source == 'legacy':
        from mobileag.web.repository import private_write
        private_write(web.OUTPUT_DIR / value['scan_id'] / 'dashboard.json', value)
    else:
        web.repository().save(value)
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + web.app.state.auth_token})
    response = client.get('/api/scans/scan_evidence')
    assert response.status_code == 200
    effective = response.json()['findings'][0]
    assert effective['status'] == 'UNVERIFIED'
    assert effective['reported_status'] == 'CONFIRMED'
    assert effective['evidence_assessment']['basis'] == 'not_proven'
    listed = client.get('/api/scans').json()[0]['findings'][0]
    assert listed['status'] == 'UNVERIFIED'
    assert web.repository().get(value['scan_id'])['findings'][0]['status'] == 'CONFIRMED'
    assert value['findings'][0]['status'] == 'CONFIRMED'


@pytest.mark.parametrize('field,bad', [('artifact_sha256', 'b'*64), ('package_name', 'org.example.other'), ('version', '2.0'), ('version', None)])
def test_scan_binding_rechecked_on_presentation(field, bad):
    value = scan()
    value['findings'][0]['validation_evidence'] = bind_confirmation(confirmation_evidence(), value)
    value[field] = bad
    original = copy.deepcopy(value)
    assert prepare_scan(value)['findings'][0]['status'] == 'UNVERIFIED'
    assert value == original


def test_valid_triage_receipt_contains_effective_attestation_and_revocation():
    value = scan(); value['findings'][0]['status'] = 'UNVERIFIED'
    web.repository().save(value)
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + web.app.state.auth_token})
    path = '/api/scans/scan_evidence/findings/test/feedback'
    response = client.post(path, json={'verdict': 'CONFIRMED', 'notes': 'Synthetic observed controls', 'revision': 0, 'evidence': confirmation_evidence()})
    assert response.status_code == 200
    finding = response.json()['finding']
    assert finding['status'] == 'CONFIRMED'
    assert finding['evidence_assessment'] == client.get('/api/scans/scan_evidence').json()['findings'][0]['evidence_assessment']
    assert finding['evidence_assessment']['artifact_binding'] == 'checked'
    assert finding['evidence_assessment']['independently_verified'] is False
    response = client.post(path, json={'verdict': 'UNVERIFIED', 'revision': 1})
    assert response.status_code == 200
    assert response.json()['finding']['evidence_assessment']['basis'] == 'not_proven'


def test_live_observation_cannot_self_attest_even_with_valid_record():
    value = scan()
    finding = value['findings'][0]
    finding['validation_evidence'] = bind_confirmation(confirmation_evidence(), value)
    result = prepare_observation(finding)
    assert result['status'] == 'UNVERIFIED'
    assert result['evidence_assessment']['basis'] == 'not_proven'
    assert finding['status'] == 'CONFIRMED'
