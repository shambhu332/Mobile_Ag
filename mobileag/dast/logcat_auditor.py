"""Logcat runtime auditor for detecting sensitive data leakage (CWE-532) and unhandled crashes."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Final, Optional

from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Patterns for sensitive data leaked into Logcat
_LEAK_PATTERNS: Final[list[tuple[str, re.Pattern[str], str]]] = [
    (
        "Bearer / JWT Token Leaked in Logcat",
        re.compile(r"\bBearer\s+(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"),
        "A JSON Web Token (JWT) or OAuth Bearer credential was printed directly to system logcat.",
    ),
    (
        "Hardcoded Google API Key Printed in Logcat",
        re.compile(r"\b(AIzaSy[0-9A-Za-z_-]{33})\b"),
        "A Google Cloud / Firebase API key was observed in plaintext in the log stream.",
    ),
    (
        "AWS Access Key ID Leaked in Logcat",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "An AWS Access Key ID was observed in plaintext in logcat output.",
    ),
    (
        "Plaintext Password or Credential in Logcat",
        re.compile(r"(?i)\b(?:password|passwd|pwd|auth_token|secret_key)\s*[:=]\s*([^\s,;\"'<>]{4,})"),
        "A user password or authentication secret parameter was written to system logcat.",
    ),
    (
        "Private Cryptographic Key Header in Logcat",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "A private cryptographic key block was written to the Android log buffer.",
    ),
]

_CRASH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:FATAL EXCEPTION|AndroidRuntime:\s+Process:\s+([a-zA-Z0-9_.]+).*?(?:NullPointerException|BadParcelableException|SecurityException|IndexOutOfBoundsException))",
    re.DOTALL
)


class LogcatAuditor:
    """Audits Android logcat streams for data leakage and uncaught runtime crashes."""

    def __init__(self) -> None:
        pass

    def audit_lines(self, lines: list[str], package_name: str = "") -> list[Finding]:
        """Analyze log lines and extract CWE-532 findings and fatal crash records."""
        findings: list[Finding] = []
        full_text = "\n".join(lines)

        # 1. Audit for sensitive leaks (CWE-532)
        for title, pattern, desc in _LEAK_PATTERNS:
            for idx, line in enumerate(lines):
                match = pattern.search(line)
                if match:
                    # Sanitize token preview
                    matched_val = match.group(0)
                    masked = matched_val[:6] + "..." + matched_val[-4:] if len(matched_val) > 12 else "[MASKED]"
                    snippet = line.replace(matched_val, masked).strip()

                    cwe = "CWE-532"
                    score, vector = get_default_cvss_for_cwe(cwe)

                    findings.append(Finding(
                        title=f"{title}: {package_name or 'Runtime'}",
                        description=f"{desc}\n\nEvidence observed in logcat:\n`{snippet}`",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-STORAGE-2",
                        affected_component=package_name or "Android Logcat Buffer",
                        file_path="logcat",
                        line_number=idx + 1,
                        code_snippet=snippet,
                        detection_method="LogcatAuditor (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation="Remove logging calls (Log.d, Log.v, Log.i, println) from production builds using ProGuard/R8 rules: `-assumenosideeffects class android.util.Log { *; }`.",
                    ))
                    break  # One finding per pattern category to avoid log flood

        # 2. Audit for fatal crashes (CWE-703 / CWE-755)
        crash_match = _CRASH_PATTERN.search(full_text)
        if crash_match:
            cwe = "CWE-755"
            score, vector = get_default_cvss_for_cwe(cwe)
            crash_snippet = crash_match.group(0)[:300]

            findings.append(Finding(
                title=f"Fatal Application Crash (Unhandled Exception): {package_name or 'Process'}",
                description=f"A fatal runtime exception occurred causing an application crash:\n\n`{crash_snippet}`",
                severity=Severity.MEDIUM,
                confidence=1.0,
                cwe_id=cwe,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                owasp_masvs="MASVS-CODE-4",
                affected_component=package_name or "Runtime Process",
                file_path="logcat",
                line_number=1,
                code_snippet=crash_snippet,
                detection_method="LogcatAuditor (Dynamic)",
                status=FindingStatus.CONFIRMED,
                remediation="Wrap intent extra parsing and dynamic inputs in defensive try-catch blocks and validate parcelable formats before deserialization.",
            ))

        return findings
