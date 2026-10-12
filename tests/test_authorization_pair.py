"""Synthetic imported captures; no live device or API proof is claimed."""
import copy
import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from mobileag.analysis.authorization_pair import AuthorizationPair, compare_authorization_pair
from tests.test_guided_assessments import setup, plan, finish, web


def payload():
    owner = 'mobileag-test-owner-fixture-marker'
    other = 'mobileag-test-other-fixture-marker'
    def observation(marker, eid):
        return {'status_code': 200, 'response_json': json.dumps({'data': {'marker': marker}}), 'evidence_id': eid}
    return {'artifact_sha256': 'a' * 64, 'capture_id': 'b' * 24,
            'owner_baseline': observation(owner, 'owner-evidence'),
            'other_account_baseline': observation(other, 'other-evidence'),
            'cross_account': observation(owner, 'cross-evidence'),
            'owner_marker': owner, 'other_marker': other, 'marker_path': ['data', 'marker'],
            'authorized_synthetic_captures': True, 'distinct_controlled_accounts_confirmed': True,
            'same_owner_resource_requested': True, 'identities_checked': True}


def test_exact_marker_with_distinct_baselines_produces_only_an_imported_candidate():
    data = payload()
    result = compare_authorization_pair(AuthorizationPair.model_validate(data))
    assert result['outcome'] == 'cross_account_disclosure_candidate'
    assert result['status'] == 'UNVERIFIED'
    assert result['network_requests_sent'] == 0
    assert data['owner_marker'] not in json.dumps(result)
    assert data['other_marker'] not in json.dumps(result)


@pytest.mark.parametrize('body', ['{}', '{bad', '"mobileag-test-owner-fixture-marker"', '{"data":{"marker":"prefix-mobileag-test-owner-fixture-marker"}}'])
def test_status_alone_substring_or_wrong_json_path_cannot_prove_disclosure(body):
    data = payload(); data['cross_account']['response_json'] = body
    assert compare_authorization_pair(AuthorizationPair.model_validate(data))['outcome'] == 'inconclusive'


def test_failed_baseline_or_inconsistent_denial_is_inconclusive():
    data = payload(); data['owner_baseline']['status_code'] = 401
    assert compare_authorization_pair(AuthorizationPair.model_validate(data))['outcome'] == 'inconclusive_controls_failed'
    data = payload(); data['cross_account']['status_code'] = 403
    assert compare_authorization_pair(AuthorizationPair.model_validate(data))['outcome'] == 'inconclusive'
    data['cross_account']['response_json'] = '{}'
    assert compare_authorization_pair(AuthorizationPair.model_validate(data))['outcome'] == 'denial_observed_not_exhaustive'


@pytest.mark.parametrize('mutation', ['same_marker', 'same_evidence', 'large_body', 'missing_consent'])
def test_invalid_controls_rejected(mutation):
    data = payload()
    if mutation == 'same_marker': data['other_marker'] = data['owner_marker']
    if mutation == 'same_evidence': data['cross_account']['evidence_id'] = data['owner_baseline']['evidence_id']
    if mutation == 'large_body': data['cross_account']['response_json'] = 'x' * 16385
    if mutation == 'missing_consent': data['identities_checked'] = False
    with pytest.raises(ValidationError): AuthorizationPair.model_validate(data)


@pytest.mark.asyncio
async def test_import_is_bound_scoped_private_and_cannot_start_network(setup, monkeypatch):
    svc, apk, _, driver, token = setup
    origin = 'https://synthetic.invalid'
    monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS', origin)
    request = plan(apk, scope={'devices': [], 'packages': [plan(apk).package_name], 'origins': [origin], 'methods': ['GET'], 'actions': []})
    doc = await finish(svc, request, token)
    data = payload(); data['artifact_sha256'] = doc['artifact_sha256']
    pair = AuthorizationPair.model_validate(data)
    with pytest.raises(PermissionError): svc.record_authorization_pair(doc['id'], pair, token)
    doc['stages']['api']['status'] = 'completed_with_observations'
    doc['stages']['api']['inventory'] = [{'id': data['capture_id'], 'protected': True, 'origin': origin, 'method': 'GET'}]
    svc.store().save(doc)
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + token})
    result = client.post('/api/assessments/' + doc['id'] + '/authorization-evidence', json=data)
    assert result.status_code == 200
    saved = json.dumps(svc.store().get(doc['id']))
    assert data['owner_marker'] not in saved and 'response_json' not in saved
    assert svc.report(doc['id'])['coverage_ledger']['stages']['api']['imported_comparisons'] == 1
    assert client.post('/api/assessments/' + doc['id'] + '/authorization-evidence', json=data).status_code == 422
    bad = copy.deepcopy(data); bad['unexpected'] = 'secret-not-to-echo'
    response = client.post('/api/assessments/' + doc['id'] + '/authorization-evidence', json=bad)
    assert response.status_code == 422 and 'secret-not-to-echo' not in response.text
    driver.snapshot.assert_not_called()
    svc.broker.transport.assert_not_called()
    with pytest.raises(PermissionError): svc.record_authorization_pair(doc['id'], pair, 'wrong-token')


@pytest.mark.parametrize('location', ['owner_baseline', 'other_account_baseline', 'cross_account'])
def test_ambiguous_duplicate_json_keys_never_produce_disclosure_candidate(location):
    data = payload()
    data[location]['response_json'] = '{"data":{"marker":"ignored","marker":"' + data['owner_marker'] + '"}}'
    result = compare_authorization_pair(AuthorizationPair.model_validate(data))
    assert result['outcome'] != 'cross_account_disclosure_candidate'
    if location != 'cross_account':
        assert result['baseline_controls_satisfied'] is False


@pytest.mark.asyncio
@pytest.mark.parametrize('failure,expected', [('artifact', 422), ('running', 422), ('cancelled', 409), ('policy_revoked', 403), ('server_revoked', 403), ('unprotected', 403), ('wrong_method', 403)])
async def test_pair_import_rechecks_artifact_lifecycle_and_current_scope(setup, monkeypatch, failure, expected):
    svc, apk, _, driver, token = setup
    origin = 'https://synthetic.invalid'
    monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS', origin)
    request = plan(apk, scope={'devices': [], 'packages': [plan(apk).package_name], 'origins': [origin], 'methods': ['GET'], 'actions': []})
    doc = await finish(svc, request, token)
    data = payload(); data['artifact_sha256'] = doc['artifact_sha256']
    doc['stages']['api']['status'] = 'completed_with_observations'
    doc['stages']['api']['inventory'] = [{'id': data['capture_id'], 'protected': True, 'origin': origin, 'method': 'GET'}]
    if failure == 'artifact': data['artifact_sha256'] = 'f'*64
    elif failure == 'running': doc['status'] = 'running'
    elif failure == 'cancelled': doc.update(status='cancelled', cancel_requested=True)
    elif failure == 'policy_revoked':
        policy = svc.repository().get_policy(); policy['origins'] = []; svc.repository().save_policy(policy)
    elif failure == 'server_revoked': monkeypatch.delenv('MOBILEAG_ALLOWED_ORIGINS')
    elif failure == 'unprotected': doc['stages']['api']['inventory'][0]['protected'] = False
    elif failure == 'wrong_method': doc['stages']['api']['inventory'][0]['method'] = 'POST'
    svc.store().save(doc)
    client = TestClient(web.app, headers={'Authorization': 'Bearer ' + token})
    response = client.post('/api/assessments/' + doc['id'] + '/authorization-evidence', json=data)
    assert response.status_code == expected
    assert 'authorization_comparisons' not in svc.store().get(doc['id'])
    driver.snapshot.assert_not_called()
    svc.broker.transport.assert_not_called()
