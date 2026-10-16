"""Unit tests for TokenLifecycleAuditor and JWT parsing."""
import json
import base64
import time
import pytest
from mobileag.analysis.token_lifecycle_auditor import TokenLifecycleAuditor


def _create_jwt(header: dict, payload: dict, signature: str = "valid_sig") -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.{signature}"


def test_token_lifecycle_auditor_detects_weak_algorithm():
    auditor = TokenLifecycleAuditor()
    weak_jwt = _create_jwt({"alg": "none"}, {"sub": "user_123", "exp": int(time.time()) + 3600}, signature="")
    
    parsed = auditor.parse_jwt(weak_jwt)
    assert parsed is not None
    assert parsed.weak_algorithm is True
    assert parsed.has_signature is False

    report = auditor.audit_captured_tokens([weak_jwt])
    assert report.tokens_discovered == 1
    assert report.weak_tokens == 1
    assert any("Insecure JWT Signing Algorithm" in f.title for f in report.findings)


def test_token_lifecycle_auditor_detects_missing_expiration():
    auditor = TokenLifecycleAuditor()
    no_exp_jwt = _create_jwt({"alg": "HS256"}, {"sub": "user_456"}, signature="signed")
    
    parsed = auditor.parse_jwt(no_exp_jwt)
    assert parsed is not None
    assert parsed.expiration is None
    assert parsed.weak_algorithm is False

    report = auditor.audit_captured_tokens([no_exp_jwt])
    assert report.tokens_discovered == 1
    assert any("Lacks Expiration Claim" in f.title for f in report.findings)


def test_token_lifecycle_auditor_handles_valid_signed_token():
    auditor = TokenLifecycleAuditor()
    valid_jwt = _create_jwt({"alg": "RS256"}, {"sub": "user_789", "exp": int(time.time()) + 7200}, signature="valid_rs256")
    
    parsed = auditor.parse_jwt(valid_jwt)
    assert parsed is not None
    assert parsed.expiration is not None
    assert parsed.weak_algorithm is False
    assert parsed.is_expired is False

    report = auditor.audit_captured_tokens([valid_jwt])
    assert report.tokens_discovered == 1
    assert len(report.findings) == 0
