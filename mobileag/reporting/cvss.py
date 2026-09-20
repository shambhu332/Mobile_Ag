"""CVSS 3.1 Base Score calculator.

Implements the full CVSS 3.1 base score equation per the FIRST standard:
https://www.first.org/cvss/v3.1/specification-document
"""

import math
from typing import Optional


# ── CVSS 3.1 Metric Value Weights ──

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}  # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Privileges Required (Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Privileges Required (Changed)
_UI = {"N": 0.85, "R": 0.62}  # User Interaction
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}  # Confidentiality / Integrity / Availability


def calculate_cvss(
    attack_vector: str = "L",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "N",
    integrity: str = "N",
    availability: str = "N",
) -> tuple[float, str]:
    """Calculate CVSS 3.1 base score and vector string.

    Args:
        attack_vector: N(etwork), A(djacent), L(ocal), P(hysical)
        attack_complexity: L(ow), H(igh)
        privileges_required: N(one), L(ow), H(igh)
        user_interaction: N(one), R(equired)
        scope: U(nchanged), C(hanged)
        confidentiality: N(one), L(ow), H(igh)
        integrity: N(one), L(ow), H(igh)
        availability: N(one), L(ow), H(igh)

    Returns:
        Tuple of (score: float, vector_string: str)
    """
    vector = (
        f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
        f"/PR:{privileges_required}/UI:{user_interaction}"
        f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    )

    # Impact Sub Score (ISS)
    iss = 1.0 - (
        (1.0 - _CIA[confidentiality])
        * (1.0 - _CIA[integrity])
        * (1.0 - _CIA[availability])
    )

    # If ISS is 0, the score is 0
    if iss <= 0:
        return 0.0, vector

    # Select PR weights based on scope
    pr_weights = _PR_C if scope == "C" else _PR_U

    # Exploitability
    exploitability = (
        8.22
        * _AV[attack_vector]
        * _AC[attack_complexity]
        * pr_weights[privileges_required]
        * _UI[user_interaction]
    )

    # Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Base Score
    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = min(impact + exploitability, 10.0)
    else:
        base_score = min(1.08 * (impact + exploitability), 10.0)

    # Round up to one decimal
    base_score = math.ceil(base_score * 10) / 10

    return base_score, vector


# ── Common Presets for Mobile Vulnerabilities ──

def cvss_exported_component() -> tuple[float, str]:
    """Exported Activity/Service without permission — local access."""
    return calculate_cvss(
        attack_vector="L", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U", confidentiality="L", integrity="L", availability="N",
    )


def cvss_content_provider_traversal() -> tuple[float, str]:
    """ContentProvider path traversal — local data exfiltration."""
    return calculate_cvss(
        attack_vector="L", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U", confidentiality="H", integrity="N", availability="N",
    )


def cvss_hardcoded_secret() -> tuple[float, str]:
    """Hardcoded API key or encryption key in source code."""
    return calculate_cvss(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U", confidentiality="H", integrity="N", availability="N",
    )


def cvss_webview_rce() -> tuple[float, str]:
    """WebView with JavascriptInterface on remote content — potential RCE."""
    return calculate_cvss(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="R",
        scope="C", confidentiality="H", integrity="H", availability="N",
    )


def cvss_deep_link_redirect() -> tuple[float, str]:
    """Deep link open redirect / token theft."""
    return calculate_cvss(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="R",
        scope="U", confidentiality="H", integrity="N", availability="N",
    )


def cvss_weak_crypto() -> tuple[float, str]:
    """Weak cryptography (ECB mode, hardcoded IV, DES)."""
    return calculate_cvss(
        attack_vector="N", attack_complexity="H",
        privileges_required="N", user_interaction="N",
        scope="U", confidentiality="H", integrity="N", availability="N",
    )


def cvss_insecure_storage() -> tuple[float, str]:
    """Plaintext sensitive data in SharedPreferences/SQLite."""
    return calculate_cvss(
        attack_vector="L", attack_complexity="L",
        privileges_required="L", user_interaction="N",
        scope="U", confidentiality="H", integrity="N", availability="N",
    )


# ── CWE to Default CVSS Mapping ──

CWE_CVSS_DEFAULTS: dict[str, tuple[float, str]] = {
    "CWE-22": cvss_content_provider_traversal(),
    "CWE-78": calculate_cvss("L", "L", "N", "N", "C", "H", "H", "H"),  # Command injection
    "CWE-89": calculate_cvss("N", "L", "N", "N", "U", "H", "H", "N"),  # SQLi
    "CWE-200": cvss_insecure_storage(),
    "CWE-311": cvss_insecure_storage(),
    "CWE-319": calculate_cvss("N", "H", "N", "N", "U", "H", "N", "N"),
    "CWE-321": cvss_hardcoded_secret(),
    "CWE-327": cvss_weak_crypto(),
    "CWE-329": cvss_weak_crypto(),
    "CWE-489": calculate_cvss("L", "L", "N", "N", "U", "L", "N", "N"),
    "CWE-530": calculate_cvss("L", "L", "L", "N", "U", "L", "N", "N"),
    "CWE-532": calculate_cvss("L", "L", "L", "N", "U", "H", "N", "N"),
    "CWE-601": cvss_deep_link_redirect(),
    "CWE-749": cvss_webview_rce(),
    "CWE-798": cvss_hardcoded_secret(),
    "CWE-922": cvss_insecure_storage(),
    "CWE-925": calculate_cvss("L", "L", "N", "N", "U", "L", "N", "N"),
    "CWE-926": cvss_exported_component(),
    "CWE-927": calculate_cvss("L", "L", "N", "N", "U", "L", "H", "N"),
}


def get_default_cvss_for_cwe(cwe_id: str) -> tuple[float, str]:
    """Look up the default CVSS score for a known CWE ID."""
    return CWE_CVSS_DEFAULTS.get(
        cwe_id,
        (5.0, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    )
