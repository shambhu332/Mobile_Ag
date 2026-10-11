"""Offline comparison of operator-imported, synthetic multi-account captures.

No HTTP requests, credentials, mutation, inferred ownership, or automatic
confirmation. Baselines and a distinct marker are required before raising a lead.
"""
import json
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class Observation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status_code: int = Field(ge=100, le=599)
    response_json: SecretStr
    evidence_id: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$')

    @model_validator(mode='after')
    def bound_body(self):
        if len(self.response_json.get_secret_value().encode()) > 16384:
            raise ValueError('Capture exceeds the bounded offline comparison size')
        return self


class AuthorizationPair(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    capture_id: str = Field(pattern=r'^[a-f0-9]{24}$')
    owner_baseline: Observation
    other_account_baseline: Observation
    cross_account: Observation
    marker_path: list[str] = Field(min_length=1, max_length=8)
    owner_marker: SecretStr
    other_marker: SecretStr
    authorized_synthetic_captures: Literal[True]
    distinct_controlled_accounts_confirmed: Literal[True]
    same_owner_resource_requested: Literal[True]
    identities_checked: Literal[True]

    @model_validator(mode='after')
    def distinct_controls(self):
        markers = [self.owner_marker.get_secret_value(), self.other_marker.get_secret_value()]
        if markers[0] == markers[1] or any(not m.startswith('mobileag-test-') or not 24 <= len(m) <= 128 for m in markers):
            raise ValueError('Use distinct bounded synthetic test markers')
        ids = [o.evidence_id for o in (self.owner_baseline, self.other_account_baseline, self.cross_account)]
        if len(set(ids)) != 3 or any(not key or len(key) > 128 for key in self.marker_path):
            raise ValueError('Distinct evidence IDs and bounded JSON keys are required')
        return self


def compare_authorization_pair(pair: AuthorizationPair) -> dict:
    """Compare a precise JSON value, never substrings or HTTP status alone."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Ambiguous duplicate JSON key')
            result[key] = value
        return result

    def value(observation):
        try:
            data = json.loads(observation.response_json.get_secret_value(), object_pairs_hook=unique_object)
            for key in pair.marker_path:
                if not isinstance(data, dict) or key not in data:
                    return None
                data = data[key]
            return data if isinstance(data, str) else None
        except (ValueError, RecursionError):
            return None
    owner = pair.owner_marker.get_secret_value()
    other = pair.other_marker.get_secret_value()
    baseline_valid = (200 <= pair.owner_baseline.status_code < 300
                      and 200 <= pair.other_account_baseline.status_code < 300
                      and value(pair.owner_baseline) == owner
                      and value(pair.other_account_baseline) == other)
    cross_value = value(pair.cross_account)
    target_observed = cross_value == owner
    if not baseline_valid:
        outcome = 'inconclusive_controls_failed'
    elif 200 <= pair.cross_account.status_code < 300 and target_observed:
        outcome = 'cross_account_disclosure_candidate'
    elif pair.cross_account.status_code in {401, 403} and not target_observed:
        outcome = 'denial_observed_not_exhaustive'
    else:
        outcome = 'inconclusive'
    return {'schema_version': 1, 'artifact_sha256': pair.artifact_sha256,
            'capture_id': pair.capture_id, 'outcome': outcome,
            'baseline_controls_satisfied': baseline_valid,
            'owner_marker_observed_in_cross_account_response': target_observed,
            'evidence_refs': [o.evidence_id for o in (pair.owner_baseline, pair.other_account_baseline, pair.cross_account)],
            'status': 'UNVERIFIED', 'basis': 'operator_import_not_independently_verified',
            'network_requests_sent': 0, 'raw_response_retained': False,
            'limitations': ['Account identity, resource ownership and request correspondence are operator assertions.',
                            'Exact synthetic marker comparison is not independent exploit or fix verification.']}
