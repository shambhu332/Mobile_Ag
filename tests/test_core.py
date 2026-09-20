"""Core tests for MobileAg orchestration and finding models."""

import pytest
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.filters.confidence import ConfidenceScorer


def test_finding_creation():
    """Test that a finding can be properly instantiated."""
    finding = Finding(
        title="Test Hardcoded Secret",
        description="Found API key in code",
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        cvss_score=7.5,
        affected_component="com.target.Config",
        detection_method="SecretScanner",
    )
    
    assert finding.status == FindingStatus.UNVERIFIED
    assert finding.cwe_id == "CWE-798"
    assert finding.id is not None
    assert len(finding.id) > 10


def test_confidence_scorer():
    """Test the confidence scoring aggregation logic."""
    scorer = ConfidenceScorer()
    
    # Perfect score scenario
    scores = {
        "reachability": 1.0,
        "sanitizer": 1.0,
        "consensus": 1.0,
        "historical": 1.0,
    }
    
    # CRITICAL severity gives max bonus
    final = scorer.score(scores, "CRITICAL")
    assert final > 0.9
    
    # Weak score scenario
    low_scores = {
        "reachability": 0.1,
        "sanitizer": 0.2,
        "consensus": 0.3,
        "historical": 0.1,
    }
    
    final_low = scorer.score(low_scores, "LOW")
    assert final_low < 0.4
