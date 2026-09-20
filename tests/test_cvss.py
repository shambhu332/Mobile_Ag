import pytest
from mobileag.reporting.cvss import calculate_cvss, get_default_cvss_for_cwe

def test_calculate_cvss_critical():
    """Test CVSS calculation for a Critical severity issue (e.g., RCE)."""
    score, vector = calculate_cvss(
        attack_vector="N", attack_complexity="L", privileges_required="N",
        user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
    )
    assert score == 10.0
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" == vector

def test_calculate_cvss_high():
    """Test CVSS calculation for a High severity issue (e.g., SQLi/Data Leak)."""
    score, vector = calculate_cvss(
        attack_vector="N", attack_complexity="L", privileges_required="N",
        user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"
    )
    assert score == 7.5
    assert "CVSS:3.1/AV:N" in vector

def test_get_default_cvss_for_cwe():
    """Test the CWE to CVSS default mapping."""
    # CWE-89 (SQL Injection)
    score, vector = get_default_cvss_for_cwe("CWE-89")
    assert score >= 7.0
    assert "CVSS:3.1" in vector
    
    # CWE-926 (Exported Component)
    score, vector = get_default_cvss_for_cwe("CWE-926")
    assert score > 0.0
    assert "AV:L" in vector
