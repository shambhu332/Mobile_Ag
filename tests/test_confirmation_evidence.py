"""Evidence acceptance is tested with fabricated fixtures, not real exploit proof."""
import copy
import importlib
import json
from fastapi.testclient import TestClient
import pytest
from tests.proof_fixtures import confirmation_evidence
from mobileag.reporting.validation import bind_confirmation,EvidenceError

web=importlib.import_module('mobileag.web.app')

@pytest.fixture
def fixture():
    scan={'scan_id':'scan_evidence','package_name':'org.example.synthetic','artifact_sha256':'a'*64,'version':'1.0','revision':0,'status':'completed','findings':[{'id':'fixture','status':'UNVERIFIED'}]}
    web.repository().save(scan)
    client=TestClient(web.app,headers={'Authorization':'Bearer '+web.app.state.auth_token})
    return client,scan,'/api/scans/scan_evidence/findings/fixture/feedback'


def test_notes_alone_and_wrong_binding_rejected_without_mutation(fixture):
    client,scan,url=fixture
    assert client.post(url,json={'verdict':'CONFIRMED','notes':'Claimed impact only','revision':0}).status_code==422
    for field,value in [('artifact_sha256','b'*64),('package_name','org.example.other'),('app_version','2.0')]:
        evidence=confirmation_evidence();evidence[field]=value
        assert client.post(url,json={'verdict':'CONFIRMED','notes':'Synthetic attestation','evidence':evidence,'revision':0}).status_code==422
    assert web.repository().get(scan['scan_id'])['revision']==0
    assert web.repository().history(scan['scan_id'])==[]


@pytest.mark.parametrize('field',['os_build','entry_point','attacker_control','sensitive_sink','security_boundary','observed_impact','reproduction_steps','positive_control','negative_control','evidence_refs','unprivileged_attacker_confirmed','unmodified_authorization_confirmed','synthetic_data_confirmed','scope_confirmed'])
def test_missing_evidence_field_cannot_confirm(fixture,field):
    client,scan,url=fixture;evidence=confirmation_evidence();del evidence[field]
    assert client.post(url,json={'verdict':'CONFIRMED','notes':'Synthetic attestation','evidence':evidence}).status_code==422


@pytest.mark.parametrize('field,value',[('attacker_context','root_diagnostic'),('attacker_context','shell_diagnostic'),('evidence_refs',['../arbitrary-file']),('evidence_refs',['https://fixture.invalid']),('reproduction_steps',['']),('negative_control','Fixture accepts the authorized synthetic marker'),('unprivileged_attacker_confirmed',False),('unmodified_authorization_confirmed',False),('observed_impact','   '),('os_build','unknown')])
def test_bad_context_refs_controls_or_flags_rejected(fixture,field,value):
    client,scan,url=fixture;evidence=confirmation_evidence();evidence[field]=value
    assert client.post(url,json={'verdict':'CONFIRMED','notes':'Synthetic attestation','evidence':evidence}).status_code==422


def test_structured_attestation_is_not_independent_proof_and_keeps_history(fixture):
    client,scan,url=fixture;evidence=confirmation_evidence()
    evidence['observed_impact']='Synthetic marker; api_key=synthetic_private_value'
    result=client.post(url,json={'verdict':'CONFIRMED','notes':'Synthetic attestation','evidence':evidence,'revision':0})
    assert result.status_code==200
    proof=result.json()['validation_evidence']
    assert proof['basis']=='analyst_attested' and proof['independently_verified'] is False
    assert 'synthetic_private_value' not in json.dumps(proof)
    assert client.post(url,json={'verdict':'FALSE_POSITIVE','revision':0}).status_code==409
    assert client.post(url,json={'verdict':'UNVERIFIED','revision':1}).status_code==200
    stored=web.repository().get(scan['scan_id'])['findings'][0]
    assert not stored['validation_evidence']['active']
    history=web.repository().history(scan['scan_id'])
    assert len(history)==2 and history[0]['evidence']['active'] is True


def test_internal_triage_cannot_bypass_schema(fixture):
    _,scan,_=fixture
    with pytest.raises(EvidenceError):web.repository().triage(scan['scan_id'],'fixture','CONFIRMED','notes',0)
    scan['version']='unknown'
    with pytest.raises(EvidenceError):bind_confirmation(confirmation_evidence(version='unknown'),scan)
