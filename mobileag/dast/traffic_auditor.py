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

        return findings
