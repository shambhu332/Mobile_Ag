"""Logcat runtime auditor for detecting sensitive data leakage (CWE-532) and unhandled crashes."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Final, Optional

from mobileag.dast.runtime_evidence import attributed_crashes, _PROCESS, _THREADTIME
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
        re.compile(r"(?i)\b(?:password|passwd|pwd|auth_token|access_token|refresh_token|id_token|client_secret|secret_key|session(?:_id|_token)?)\s*[:=]\s*[\"']?([^\s,;\"'<>]{4,})"),
        "A credential or session-secret-like parameter was written to system logcat.",
    ),
    (
        "Session Cookie in Logcat",
        re.compile(r"(?i)\b(?:set-cookie|cookie)\s*:\s*[^\r\n]*(?:session(?:id|_id|_token)?|auth|sid|jwt)\s*=\s*[^;\s,]{8,}"),
        "A cookie header containing a session/authentication-like value was written to system logcat.",
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

_RUNTIME_SIGNALS: Final[list[tuple[str, re.Pattern[str], str]]] = [
    ("Application not responding (ANR) observation", re.compile(r"(?i)\bANR in\s+"),
     "An ANR marker attributed to the target process was observed. Confirm with a reproducible user-visible hang; this log marker alone does not establish cause."),
    ("StrictMode violation observation", re.compile(r"(?i)StrictMode policy violation|StrictMode.*(disk|network).*violation"),
     "A StrictMode violation was logged for the target process. Review and reproduce the operation; this is a diagnostic candidate, not a security finding."),
    ("Uncaught runtime exception observation", re.compile(r"(?i)uncaught exception"),
     "An uncaught runtime exception marker was observed in target-process logs. Reproduce with controlled input and inspect a redacted stack trace before classifying impact."),
]


class LogcatAuditor:
    """Audits Android logcat streams for data leakage and uncaught runtime crashes."""

    def __init__(self) -> None:
        pass

    def audit_lines(self, lines: list[str], package_name: str = "", process_pids=None) -> list[Finding]:
        """Analyze log lines and extract CWE-532 findings and fatal crash records."""
        findings: list[Finding] = []
        lines = lines[:10000]
        # Without an exact package and matching Process/PID markers, the shared
        # Android log buffer cannot be safely attributed to the tested app.
        if not package_name:
            return findings
        pids = {m[2] for line in lines if (m := _PROCESS.search(line)) and
                (m[1] == package_name or m[1].startswith(package_name + ':'))}
        if process_pids is not None:
            pids = {str(pid) for pid in process_pids if str(pid).isdecimal() and int(pid) > 0}
        if not pids:
            return findings
        for title, pattern, desc in _LEAK_PATTERNS:
            for idx, line in enumerate(lines):
                header = _THREADTIME.match(line)
                if not header or header[1] not in pids:
                    continue
                if pattern.search(line):
                    component = package_name
                    findings.append(Finding(
                        title=f'{title}: {component}',
                        description=desc + ' Diagnostic observation only; log access, secret validity and security impact are unverified.',
                        severity=Severity.INFO, confidence=0.4, cwe_id='CWE-532',
                        cvss_score=0.0, cvss_vector='', affected_component=component,
                        file_path='logcat', line_number=idx+1, code_snippet='[Sensitive log value omitted]',
                        detection_method='LogcatAuditor (ADB diagnostic)', status=FindingStatus.UNVERIFIED,
                        remediation='Remove sensitive logging; verify the production build and ordinary-app log access separately.'))
                    break
        # Runtime-health signals are analyst leads, not proof of a security bug.
        for title, pattern, desc in _RUNTIME_SIGNALS:
            for idx, line in enumerate(lines):
                header = _THREADTIME.match(line)
                if header and header[1] in pids and pattern.search(line):
                    findings.append(Finding(
                        title=f'{title}: {package_name}', description=desc,
                        severity=Severity.INFO, confidence=0.3, cwe_id='CWE-755',
                        cvss_score=0.0, cvss_vector='', affected_component=package_name,
                        file_path='logcat', line_number=idx+1,
                        code_snippet='[Runtime diagnostic marker; raw values omitted]',
                        detection_method='LogcatAuditor (ADB diagnostic)', status=FindingStatus.UNVERIFIED,
                        remediation='Reproduce with synthetic input and a minimal redacted trace; assess ordinary-app reachability and user impact separately.'))
                    break
        if package_name and attributed_crashes(lines, package_name):
            findings.append(Finding(
                title=f'Fatal Application Crash observation: {package_name}',
                description='A target-PID fatal log was observed. ADB-shell invocation is not ordinary-app exploit proof; timing is not causation.',
                severity=Severity.INFO, confidence=0.5, cwe_id='CWE-755',
                cvss_score=0.0, cvss_vector='', affected_component=package_name,
                file_path='logcat', line_number=1, code_snippet='Target PID fatal exception (values omitted)',
                detection_method='LogcatAuditor (ADB diagnostic)', status=FindingStatus.UNVERIFIED,
                remediation='Reproduce with controlled inputs and an ordinary caller before assessing impact.'))
        return findings
