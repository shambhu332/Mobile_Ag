"""Presentation-time evidence gate and deterministic investigation requirements.

This validates record structure, not truth. No networking, device operations,
LLM calls, confidence-based confirmation or mutation of stored triage occurs.
"""
from copy import deepcopy

from mobileag.reporting.validation import ConfirmationEvidence


REQUIREMENTS = (
    'artifact_sha256', 'package_name', 'app_version', 'os_build', 'attacker_context',
    'entry_point', 'attacker_control', 'sensitive_sink', 'security_boundary',
    'observed_impact', 'reproduction_steps', 'positive_control', 'negative_control',
    'evidence_refs',
)


def prepare_finding(value: dict, artifact: dict | None = None) -> dict:
    """Return an export copy with an effective status and visible evidence gaps.

    Optional artifact binding must come from the scan, not the finding. Without
    it we only validate an attestation's schema and explicitly label binding as
    unchecked. Independent verification is never inferred from any supplied flag.
    """
    result = deepcopy(value)
    envelope = value.get('validation_evidence')
    envelope = envelope if isinstance(envelope, dict) else {}
    record = envelope.get('record')
    record = record if isinstance(record, dict) else {}
    errors = []
    schema_valid = False
    try:
        ConfirmationEvidence.model_validate(record)
        schema_valid = True
    except ValueError:
        errors.append('confirmation_schema_invalid_or_missing')
    if envelope.get('basis') != 'analyst_attested' or envelope.get('active') is not True:
        errors.append('active_analyst_attestation_missing')
    if artifact is not None:
        for field in ('artifact_sha256', 'package_name', 'app_version'):
            if not artifact.get(field) or record.get(field) != artifact[field]:
                errors.append(f'artifact_binding_mismatch:{field}')
    requested = value.get('status', 'UNVERIFIED')
    attested = requested == 'CONFIRMED' and schema_valid and not errors
    if requested == 'CONFIRMED' and not attested:
        result['reported_status'] = requested
        result['status'] = 'UNVERIFIED'
    result['evidence_assessment'] = {
        'basis': 'analyst_attested' if attested else 'not_proven',
        'independently_verified': False,
        'artifact_binding': 'checked' if artifact is not None and not any(e.startswith('artifact_binding') for e in errors) else 'not_verified',
        'missing_fields': [field for field in REQUIREMENTS if not record.get(field)],
        'validation_errors': errors,
    }
    # Planning hints only. They cannot grant authorization or execute actions.
    if attested:
        next_step = 'independent_review_and_scoped_fix_retest'
    elif not record.get('entry_point') or not record.get('attacker_control'):
        next_step = 'establish_external_reachability_and_attacker_control'
    elif not record.get('security_boundary') or not record.get('sensitive_sink'):
        next_step = 'trace_checks_and_sensitive_operation'
    else:
        next_step = 'obtain_scoped_reproduction_and_distinct_controls'
    result['investigation_plan'] = {
        'next_step': next_step, 'execution_authorized': False,
        'stop_conditions': ['scope_missing_or_revoked', 'artifact_mismatch',
                            'required_environment_unavailable', 'evidence_inconclusive'],
        'alternative_explanations': ['input_not_attacker_controlled', 'guard_blocks_reachability',
                                     'observation_requires_modified_authorization'],
        'automatic_confirmation': False,
    }
    return result


def prepare_scan(scan: dict) -> dict:
    """Validate finding presentation against authoritative scan metadata.

    Stored decisions and immutable legacy artifacts remain untouched. A missing
    scan binding fails closed; finding-supplied hashes are never substitutes.
    """
    result = deepcopy(scan)
    artifact = {
        'artifact_sha256': scan.get('artifact_sha256'),
        'package_name': scan.get('package_name'),
        'app_version': scan.get('version'),
    }
    result['findings'] = [prepare_finding(f, artifact) for f in scan.get('findings', [])]
    return result


def prepare_observation(finding: dict) -> dict:
    """Live/device observations cannot create analyst confirmation records."""
    value = deepcopy(finding)
    if value.get('status') == 'CONFIRMED':
        value['reported_status'] = 'CONFIRMED'
    value['status'] = 'UNVERIFIED'
    result = prepare_finding(value)
    result['evidence_assessment']['validation_errors'].append('observation_not_analyst_triage')
    return result
