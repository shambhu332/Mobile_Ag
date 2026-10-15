"""Dynamic network traffic security auditor for MobileAg."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

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
        self._session_cookie_re = re.compile(
            r"(?i)(?:^|[-_])(?:session|sess|auth|access|refresh|id)[-_]?(?:id|token)?$"
        )

    def _audit_session_cookies(self, tx: HTTPTransaction, parsed) -> list[Finding]:
        """Flag risky attributes on likely session cookies without retaining values.

        This is deliberately a review candidate: cookie names are application-specific,
        and HttpOnly/SameSite requirements depend on whether a browser/WebView consumes it.
        """
        raw = next((v for k, v in tx.response_headers.items()
                    if k.lower() == "set-cookie"), "")
        if not raw:
            return []

        findings = []
        safe_origin = self._safe_api_origin(parsed) or "<unknown-origin>"
        safe_path = self._canonical_api_path(parsed.path or "/")
        safe_location = f"{safe_origin}{safe_path}" if safe_origin != "<unknown-origin>" else safe_path
        # A comma can occur in Expires, so split only on new-cookie boundaries.
        cookies = re.split(r",(?=\s*[^;,=\s]+\s*=)", raw)
        for cookie in cookies[:20]:
            parts = [part.strip() for part in cookie.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()
            if not self._session_cookie_re.search(name):
                continue
            attrs = {part.split("=", 1)[0].strip().lower() for part in parts[1:] if part}
            missing = []
            if parsed.scheme == "https" and "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if not missing:
                continue
            # Pick the most directly applicable classification when multiple flags
            # are absent; the complete missing-attribute list remains in evidence.
            cwe_id = ("CWE-614" if "Secure" in missing else
                      "CWE-1004" if "HttpOnly" in missing else "CWE-1275")
            findings.append(Finding(
                title=f"Session Cookie Attribute Review: {name}",
                description=(
                    f"A response from {safe_location} set a cookie whose name "
                    f"resembles a session/authentication cookie and omitted: {', '.join(missing)}. "
                    "Cookie names are heuristic; confirm that this value is a session credential "
                    "and whether a browser or WebView consumes it. Cookie values are not recorded."
                ),
                severity=Severity.INFO,
                confidence=0.4,
                cwe_id=cwe_id,
                cvss_score=0.0,
                cvss_vector="",
                owasp_masvs="MASVS-NETWORK-1",
                affected_component=safe_origin,
                file_path=safe_location,
                line_number=1,
                code_snippet=f"Set-Cookie: {name}=<redacted>; missing {', '.join(missing)}",
                detection_method="TrafficAuditor (Dynamic)",
                status=FindingStatus.UNVERIFIED,
                remediation=(
                    "For browser/WebView session cookies, set Secure over HTTPS, HttpOnly, and an "
                    "appropriate SameSite policy; validate required behavior for the actual client."
                ),
            ))
        return findings

    def audit_transactions(self, transactions: list[HTTPTransaction]) -> list[Finding]:
        """Evaluate a list of recorded HTTP transactions for security policy violations."""
        findings: list[Finding] = []

        for tx in transactions:
            try:
                parsed = urlparse(tx.url)
            except (TypeError, ValueError):
                continue
            safe_origin = self._safe_api_origin(parsed) or "<unknown-origin>"
            safe_path = self._canonical_api_path(parsed.path or "/")
            safe_location = f"{safe_origin}{safe_path}" if safe_origin != "<unknown-origin>" else safe_path
            method_token = tx.method.upper() if isinstance(tx.method, str) and len(tx.method) <= 16 else ""
            safe_method = (method_token if method_token in
                           {"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}
                           else "UNKNOWN")

            # Likely session-cookie flags are based on observed Set-Cookie headers.
            findings.extend(self._audit_session_cookies(tx, parsed))

            # 1. Cleartext HTTP Traffic (CWE-319)
            if parsed.scheme == "http" and not (parsed.hostname in ("localhost", "127.0.0.1")):
                cwe = "CWE-319"
                findings.append(Finding(
                    title=f"Cleartext HTTP Transmission to {safe_origin}",
                    description=(
                        f"The mobile application initiated an unencrypted HTTP connection to:\n"
                        f"`{safe_method} {safe_location}`\n\n"
                        f"Unencrypted network requests expose credentials and application payloads to "
                        f"Man-in-the-Middle (MitM) eavesdropping and tampering on untrusted Wi-Fi."
                    ),
                    severity=Severity.INFO,
                    confidence=0.6,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    owasp_masvs="MASVS-NETWORK-1",
                    affected_component=safe_origin,
                    file_path=safe_location,
                    line_number=1,
                    code_snippet=f"{safe_method} {safe_location}",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Migrate all endpoint URLs to HTTPS and enforce TLS 1.3.",
                ))

            # 2. Sensitive Credentials in GET Query Parameters (CWE-598)
            if safe_method == "GET" and parsed.query:
                query_params = parse_qs(parsed.query)
                leaked_params = [k for k in query_params if self._sensitive_param_re.search(k)]
                if leaked_params:
                    cwe = "CWE-598"
                    findings.append(Finding(
                        title=f"Sensitive Token/Credential Passed in GET Query String: {safe_origin}",
                        description=(
                            f"The query parameter(s) `{', '.join(leaked_params)}` appear in a GET URL:\n"
                            f"`{safe_location}`\n\n"
                            f"Parameters in GET requests are permanently recorded in intermediate proxy logs, "
                            f"browser caches, and server access logs."
                        ),
                            severity=Severity.INFO,
                            confidence=0.5,
                        cwe_id=cwe,
                            cvss_score=0.0,
                            cvss_vector="",
                        owasp_masvs="MASVS-NETWORK-2",
                        affected_component=safe_origin,
                        file_path=safe_location,
                        line_number=1,
                        code_snippet=f"GET {safe_location}",
                        detection_method="TrafficAuditor (Dynamic)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Transmit sensitive authentication tokens in HTTP request headers (Authorization: Bearer <token>) or in encrypted POST bodies.",
                    ))

            # 3. Missing Cache-Control on Sensitive Auth Responses (CWE-524)
            resp_headers = {k.lower(): v for k, v in tx.response_headers.items()}
            is_sensitive_path = any(s in parsed.path.lower() for s in ("/auth", "/login", "/user", "/account", "/payment"))
            cache_ctrl = resp_headers.get("cache-control", "").lower()

            if is_sensitive_path and ("no-store" not in cache_ctrl):
                cwe = "CWE-524"
                findings.append(Finding(
                    title=f"Missing 'Cache-Control: no-store' on Sensitive API Route: {safe_path}",
                    description=(
                        f"The sensitive endpoint `{safe_path}` returned response status `{tx.response_status}` "
                        f"without setting `Cache-Control: no-store`. Cached responses can be recovered from device flash memory."
                    ),
                    severity=Severity.INFO,
                    confidence=0.4,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    owasp_masvs="MASVS-STORAGE-1",
                    affected_component=safe_origin,
                    file_path=safe_location,
                    line_number=1,
                    code_snippet=("Cache-Control: no-store absent"),
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Include `Cache-Control: no-store, no-cache` in all sensitive authentication and user data API responses.",
                ))

            # 4. OWASP API1 - Broken Object Level Authorization / Predictable Sequential ID (CWE-639)
            bola_pattern = re.search(r"/(?:users|accounts|orders|customers|profiles|messages|invoices)/(\d+)(?:/|$|\?)", parsed.path, re.IGNORECASE)
            if bola_pattern:
                findings.append(Finding(
                    title=f"Numeric Resource Identifier (Authorization Review Lead): {safe_path}",
                    description=(
                        f"The endpoint `{safe_path}` contains a numeric resource identifier. "
                        "An identifier alone does not demonstrate predictability, missing ownership checks, or BOLA. "
                        "Validate authorization using two controlled accounts before classifying this lead."
                    ),
                    severity=Severity.INFO,
                    confidence=0.3,
                    cwe_id="CWE-639",
                    cvss_score=0.0,
                    cvss_vector="",
                    owasp_masvs="MASVS-NETWORK-2",
                    affected_component=safe_origin,
                    file_path=safe_location,
                    line_number=1,
                    code_snippet=f"{safe_method} {safe_path}",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Manually verify object ownership authorization; sequential IDs alone are not a vulnerability.",
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
                    findings.append(Finding(
                        title=f"Sensitive PII / Credential Exposure in API Response: {', '.join(leaks)}",
                        description=(
                            f"The response from `{safe_location}` contained unencrypted sensitive data: "
                            f"{', '.join(leaks)}.\n\n"
                            "APIs should filter and omit sensitive PII from client-facing payloads."
                        ),
                        severity=Severity.INFO,
                        confidence=0.5,
                        cwe_id=cwe,
                        cvss_score=0.0,
                        cvss_vector="",
                        owasp_masvs="MASVS-STORAGE-1",
                        affected_component=safe_origin,
                        file_path=safe_location,
                        line_number=1,
                        code_snippet=f"Payload matches sensitive patterns: {', '.join(leaks)}",
                        detection_method="TrafficAuditor (Dynamic)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Filter sensitive attributes at the serialization layer before returning API responses.",
                    ))

            # 6. OWASP API7 - Missing HSTS Header on Production HTTPS (CWE-16)
            if parsed.scheme == "https" and not (parsed.hostname in ("localhost", "127.0.0.1")):
                if "strict-transport-security" not in resp_headers:
                    cwe = "CWE-16"
                    findings.append(Finding(
                        title=f"Missing HSTS Header on HTTPS Endpoint: {safe_origin}",
                        description=(
                            f"The HTTPS server at `{safe_origin}` does not send a `Strict-Transport-Security` header. "
                            "Clients may be vulnerable to SSL stripping attacks on initial connection."
                        ),
                        severity=Severity.INFO,
                        confidence=0.3,
                        cwe_id=cwe,
                        cvss_score=0.0,
                        cvss_vector="",
                        owasp_masvs="MASVS-NETWORK-1",
                        affected_component=safe_origin,
                        file_path=safe_location,
                        line_number=1,
                        code_snippet=f"Response headers missing Strict-Transport-Security",
                        detection_method="TrafficAuditor (Dynamic)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header.",
                    ))

            # 7. Permissive CORS Policy with Credentials (CWE-942)
            allow_origin = resp_headers.get("access-control-allow-origin", "")
            allow_creds = resp_headers.get("access-control-allow-credentials", "").lower()
            if allow_origin == "*" and allow_creds == "true":
                cwe = "CWE-942"
                findings.append(Finding(
                    title=f"CORS Wildcard/Credentials Configuration Review: {safe_origin}",
                    description=(
                        f"The response from `{safe_origin}` combines wildcard origin with credentials. "
                        "This is an informational configuration signal, not proof of browser credential exposure: "
                        "standards-conforming browsers reject wildcard origins for credentialed CORS reads. "
                        "Verify the actual Origin-specific responses and client context before reporting."
                    ),
                    severity=Severity.INFO,
                    confidence=0.4,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    owasp_masvs="MASVS-NETWORK-1",
                    affected_component=safe_origin,
                    file_path=safe_location,
                    line_number=1,
                    code_snippet="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    detection_method="TrafficAuditor (Dynamic)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Use explicit trusted origins when credentialed browser access is intended; assess the actual CORS response behavior.",
                ))

        return findings

    def catalog_traffic(self, transactions: list[HTTPTransaction], title: str = "Mobile App Backend APIs") -> Any:
        """Catalog transactions into a MobileApiCataloger and produce OpenAPI models."""
        from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest
        cataloger = MobileApiCataloger(title=title)
        for tx in transactions:
            parsed = urlparse(tx.url)
            query_params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
            cataloger.ingest_request(
                CapturedRequest(
                    method=tx.method,
                    url=tx.url,
                    headers=dict(tx.request_headers),
                    query_params=query_params,
                    body=tx.request_body,
                    response_status=tx.response_status,
                    response_body=tx.response_body,
                )
            )
        return cataloger

    @staticmethod
    def _safe_api_origin(parsed) -> str | None:
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        host = parsed.hostname
        try:
            ipaddress.IPv6Address(host.split("%", 1)[0])
            host = f"[{host}]"
        except ValueError:
            pass
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        return f"{scheme}://{host}" + (f":{port}" if port is not None else "")

    @staticmethod
    def _canonical_api_path(path: str) -> str:
        from mobileag.dast.api_cataloger import MobileApiCataloger

        templated = MobileApiCataloger._path_template(path or "/")
        segments = templated.split("/")
        index = 0
        for position, segment in enumerate(segments):
            if re.fullmatch(r"\{[^{}]+\}", segment):
                index += 1
                segments[position] = f"{{id{index}}}"
        return "/".join(segments) or "/"

    def find_shadow_apis(
            self, transactions: list[HTTPTransaction], declared_endpoints: list[Any]) -> list[Finding]:
        """Return review leads for observed routes absent from supplied declarations.

        Declarations may be URL/path strings (method wildcard) or objects with
        ``method`` and ``url`` fields. This is not proof that static extraction
        was complete; findings intentionally omit query values, userinfo, and
        identifier-shaped path values.
        """
        openapi_methods = {"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}
        wildcard_paths: set[str] = set()
        wildcard_methods_by_origin: set[tuple[str, str]] = set()
        methods_across_origins: set[tuple[str, str]] = set()
        exact_routes: set[tuple[str, str, str]] = set()
        for item in declared_endpoints[:10000]:
            if isinstance(item, str):
                endpoint, declared_method = item, None
            elif isinstance(item, dict):
                endpoint = item.get("url")
                declared_method = item.get("method")
                if not isinstance(endpoint, str):
                    continue
                if declared_method is not None:
                    if not isinstance(declared_method, str) or len(declared_method) > 16:
                        continue
                    declared_method = declared_method.upper()
                    if declared_method not in openapi_methods:
                        continue
            else:
                continue
            if len(endpoint) > 8192:
                continue
            try:
                parsed_declared = urlparse(endpoint)
            except ValueError:
                continue
            if parsed_declared.scheme and parsed_declared.scheme.lower() not in {"http", "https"}:
                continue
            path = self._canonical_api_path(parsed_declared.path or endpoint)
            origin = self._safe_api_origin(parsed_declared)
            if declared_method is None and origin is None:
                wildcard_paths.add(path)
            elif declared_method is None:
                wildcard_methods_by_origin.add((origin, path))
            elif origin is None:
                methods_across_origins.add((path, declared_method))
            else:
                exact_routes.add((origin, path, declared_method))

        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for tx in transactions[:10000]:
            if not isinstance(tx.url, str) or len(tx.url) > 8192:
                continue
            try:
                parsed = urlparse(tx.url)
            except ValueError:
                continue
            if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
                continue
            path = self._canonical_api_path(parsed.path)
            origin = self._safe_api_origin(parsed)
            raw_method = tx.method.upper() if isinstance(tx.method, str) and len(tx.method) <= 16 else ""
            method = raw_method if raw_method in openapi_methods else "UNKNOWN"
            key = (origin or "", path, method)
            if key in seen:
                continue
            seen.add(key)
            is_declared = (
                path in wildcard_paths
                or (origin is not None and (origin, path) in wildcard_methods_by_origin)
                or (path, method) in methods_across_origins
                or (origin is not None and (origin, path, method) in exact_routes)
            )
            if is_declared:
                continue
            safe_url = f"{origin}{path}" if origin else path
            findings.append(Finding(
                title=f"Potential Shadow API Endpoint: {method} {path}",
                description=(
                    f"An intercepted {method} route at {safe_url} was not found in the supplied "
                    "static endpoint declarations. This is an unverified review lead; static "
                    "extraction may be incomplete and route reachability is not established."
                ),
                severity=Severity.INFO,
                status=FindingStatus.UNVERIFIED,
                cwe_id="CWE-1059",
                affected_component=path,
                file_path=safe_url,
                metadata={
                    "endpoint": path, "method": method, "origin": origin,
                    "evidence_state": "observed_unverified",
                    "query_values_included": False,
                    "userinfo_included": False,
                },
            ))
        return findings
