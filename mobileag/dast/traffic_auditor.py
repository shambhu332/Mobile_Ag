"""Dynamic network traffic security auditor for MobileAg."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class HTTPTransaction:
    url: str
    method: str = "GET"
    request_headers: dict[str, str] = field(default_factory=dict)
    response_status: int = 200
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_body: Optional[str] = None


class TrafficAuditor:
    """Audits captured HTTP/HTTPS traffic streams for transport and header vulnerabilities."""

    def __init__(self) -> None:
        self._sensitive_param_re = re.compile(
            r"(?i)^(token|access_token|auth|password|pwd|api_key|secret|session_id|jwt)$"
        )

    def audit_transactions(self, transactions: list[HTTPTransaction]) -> list[Finding]:
        """Evaluate a list of recorded HTTP transactions for security policy violations."""
        findings: list[Finding] = []

        for tx in transactions:
            parsed = urlparse(tx.url)

            # 1. Cleartext HTTP Traffic (CWE-319)
            if parsed.scheme == "http" and not (parsed.hostname in ("localhost", "127.0.0.1")):
                cwe = "CWE-319"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Cleartext HTTP Transmission to {parsed.netloc}",
                    description=(
                        f"The mobile application initiated an unencrypted HTTP connection to:\n"
                        f"`{tx.method} {tx.url}`\n\n"
                        f"Unencrypted network requests expose credentials and application payloads to "
                        f"Man-in-the-Middle (MitM) eavesdropping and tampering on untrusted Wi-Fi."
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-NETWORK-1",
                    affected_component=parsed.netloc,
                    file_path=tx.url,
                    line_number=1,
                    code_snippet=f"{tx.method} {tx.url}",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Migrate all endpoint URLs to HTTPS and enforce TLS 1.3.",
                ))

            # 2. Sensitive Credentials in GET Query Parameters (CWE-598)
            if tx.method.upper() == "GET" and parsed.query:
                query_params = parse_qs(parsed.query)
                leaked_params = [k for k in query_params if self._sensitive_param_re.search(k)]
                if leaked_params:
                    cwe = "CWE-598"
                    score, vector = get_default_cvss_for_cwe(cwe)
                    findings.append(Finding(
                        title=f"Sensitive Token/Credential Passed in GET Query String: {parsed.netloc}",
                        description=(
                            f"The query parameter(s) `{', '.join(leaked_params)}` appear in a GET URL:\n"
                            f"`{tx.url}`\n\n"
                            f"Parameters in GET requests are permanently recorded in intermediate proxy logs, "
                            f"browser caches, and server access logs."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-NETWORK-2",
                        affected_component=parsed.netloc,
                        file_path=tx.url,
                        line_number=1,
                        code_snippet=f"GET {tx.url}",
                        detection_method="TrafficAuditor (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation="Transmit sensitive authentication tokens in HTTP request headers (Authorization: Bearer <token>) or in encrypted POST bodies.",
                    ))

            # 3. Missing Cache-Control on Sensitive Auth Responses (CWE-524)
            resp_headers = {k.lower(): v for k, v in tx.response_headers.items()}
            is_sensitive_path = any(s in parsed.path.lower() for s in ("/auth", "/login", "/user", "/account", "/payment"))
            cache_ctrl = resp_headers.get("cache-control", "").lower()

            if is_sensitive_path and ("no-store" not in cache_ctrl):
                cwe = "CWE-524"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Missing 'Cache-Control: no-store' on Sensitive API Route: {parsed.path}",
                    description=(
                        f"The sensitive endpoint `{parsed.path}` returned response status `{tx.response_status}` "
                        f"without setting `Cache-Control: no-store`. Cached responses can be recovered from device flash memory."
                    ),
                    severity=Severity.LOW,
                    confidence=0.85,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-STORAGE-1",
                    affected_component=parsed.netloc,
                    file_path=tx.url,
                    line_number=1,
                    code_snippet=f"HTTP {tx.response_status}\nCache-Control: {resp_headers.get('cache-control', 'MISSING')}",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Include `Cache-Control: no-store, no-cache` in all sensitive authentication and user data API responses.",
                ))

            # 4. OWASP API1 - Broken Object Level Authorization / Predictable Sequential ID (CWE-639)
            bola_pattern = re.search(r"/(?:users|accounts|orders|customers|profiles|messages|invoices)/(\d+)(?:/|$|\?)", parsed.path, re.IGNORECASE)
            if bola_pattern:
                rec_id = bola_pattern.group(1)
                cwe = "CWE-639"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Predictable Resource Identifier (Potential BOLA/IDOR): {parsed.path}",
                    description=(
                        f"The endpoint `{parsed.path}` uses an incremental or predictable numeric identifier `{rec_id}`. "
                        "If the backend does not strictly validate object ownership against the session token, "
                        "attackers can enumerate and access other users' private resources (OWASP API Security Top 10 - API1:2023)."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-NETWORK-2",
                    affected_component=parsed.netloc,
                    file_path=tx.url,
                    line_number=1,
                    code_snippet=f"{tx.method} {parsed.path}",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Migrate from predictable integer IDs to non-sequential UUIDs (v4) and enforce backend authorization checks.",
                ))

            # 5. OWASP API3 - Sensitive Data / PII Leaks in Response Payload (CWE-359)
            if tx.response_body:
                body = tx.response_body
                leaks = []
                if re.search(r"\b\d{3}-\d{2}-\d{4}\b", body):
                    leaks.append("Social Security Number (SSN)")
                if re.search(r"-----BEGIN (?:RSA|EC|PRIVATE|DSA) KEY-----", body):
                    leaks.append("Unencrypted Private Key")
                if re.search(r'(?i)"(?:password|user_password|secret_pin)"\s*:\s*"[^"]+"', body):
                    leaks.append("Plaintext Password/Secret")
                if re.search(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b", body):
                    leaks.append("Credit Card Number (PAN)")

                if leaks:
                    cwe = "CWE-359"
                    score, vector = get_default_cvss_for_cwe(cwe)
                    findings.append(Finding(
                        title=f"Sensitive PII / Credential Exposure in API Response: {', '.join(leaks)}",
                        description=(
                            f"The response from `{parsed.netloc}{parsed.path}` contained unencrypted sensitive data: "
                            f"{', '.join(leaks)}.\n\n"
                            "APIs should filter and omit sensitive PII from client-facing payloads."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.9,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-STORAGE-1",
                        affected_component=parsed.netloc,
                        file_path=tx.url,
                        line_number=1,
                        code_snippet=f"Payload matches sensitive patterns: {', '.join(leaks)}",
                        detection_method="TrafficAuditor (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation="Filter sensitive attributes at the serialization layer before returning API responses.",
                    ))

            # 6. OWASP API7 - Missing HSTS Header on Production HTTPS (CWE-16)
            if parsed.scheme == "https" and not (parsed.hostname in ("localhost", "127.0.0.1")):
                if "strict-transport-security" not in resp_headers:
                    cwe = "CWE-16"
                    score, vector = get_default_cvss_for_cwe(cwe)
                    findings.append(Finding(
                        title=f"Missing HSTS Header on HTTPS Endpoint: {parsed.netloc}",
                        description=(
                            f"The HTTPS server at `{parsed.netloc}` does not send a `Strict-Transport-Security` header. "
                            "Clients may be vulnerable to SSL stripping attacks on initial connection."
                        ),
                        severity=Severity.LOW,
                        confidence=0.85,
                        cwe_id=cwe,
                        cvss_score=score,
                        cvss_vector=vector,
                        owasp_masvs="MASVS-NETWORK-1",
                        affected_component=parsed.netloc,
                        file_path=tx.url,
                        line_number=1,
                        code_snippet=f"Response headers missing Strict-Transport-Security",
                        detection_method="TrafficAuditor (Dynamic)",
                        status=FindingStatus.CONFIRMED,
                        remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header.",
                    ))

            # 7. Permissive CORS Policy with Credentials (CWE-942)
            allow_origin = resp_headers.get("access-control-allow-origin", "")
            allow_creds = resp_headers.get("access-control-allow-credentials", "").lower()
            if allow_origin == "*" and allow_creds == "true":
                cwe = "CWE-942"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Overly Permissive CORS Policy with Credentials: {parsed.netloc}",
                    description=(
                        f"The server at `{parsed.netloc}` specifies `Access-Control-Allow-Origin: *` "
                        f"combined with `Access-Control-Allow-Credentials: true`. This allows malicious third-party "
                        "web contexts to issue authenticated cross-origin requests."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-NETWORK-1",
                    affected_component=parsed.netloc,
                    file_path=tx.url,
                    line_number=1,
                    code_snippet="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Do not combine wildcard origins with Allow-Credentials. Whitelist specific trusted origins.",
                ))

        return findings
