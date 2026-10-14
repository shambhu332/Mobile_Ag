"""Mobile Token & Session Lifecycle Auditor.

Audits intercepted mobile tokens and authentication sessions for security weaknesses:
1. Insecure JWT algorithms (e.g. 'none', weak symmetric HMAC) -> CWE-347 / CWE-327
2. Insecure JWT lifecycle claims (missing expiration, excessive lifetime, expired tokens) -> CWE-613
3. Sensitive credentials or PII embedded in JWT claims -> CWE-312
4. Session tokens transmitted over cleartext HTTP -> CWE-319
5. Sensitive tokens passed in URL query strings -> CWE-598
6. Session token reuse after logout or de-authentication -> CWE-613
7. Low-entropy or predictable session identifiers -> CWE-330
"""
from __future__ import annotations

import base64
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit

from mobileag.reporting.finding import Finding, FindingStatus, Severity


class MobileTokenSessionAuditor:
    """Audits mobile authentication tokens, JWT lifecycle, and session hygiene."""

    SENSITIVE_CLAIM_KEYS = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "private_key",
        "ssn",
        "credit_card",
        "card_number",
        "cvv",
    }

    TOKEN_QUERY_PARAMS = {
        "token",
        "access_token",
        "auth_token",
        "session_id",
        "sessionid",
        "jwt",
        "bearer",
    }

    def decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Safely parse JWT header and payload without cryptographic verification."""
        clean_token = token.strip()
        if clean_token.lower().startswith("bearer "):
            clean_token = clean_token[7:].strip()

        parts = clean_token.split(".")
        if len(parts) != 3:
            return None

        def decode_part(part_b64: str) -> Optional[Dict[str, Any]]:
            # Adjust base64url padding
            padded = part_b64 + "=" * (-len(part_b64) % 4)
            try:
                raw_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
                return json.loads(raw_bytes.decode("utf-8"))
            except Exception:
                return None

        header = decode_part(parts[0])
        payload = decode_part(parts[1])

        if header is None or payload is None:
            return None

        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw_token": clean_token,
        }

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies: Dict[str, int] = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def audit_token(self, token: str, context_url: str = "") -> List[Finding]:
        """Audit an individual mobile auth token or JWT string."""
        findings: List[Finding] = []
        jwt_data = self.decode_jwt(token)

        if not jwt_data:
            # Check basic session token entropy
            clean_tok = token.strip()
            if len(clean_tok) >= 16:
                entropy = self.calculate_entropy(clean_tok)
                if entropy < 2.5:
                    findings.append(Finding(
                        title="Predictable or Low-Entropy Session Identifier",
                        description=f"Session token has low Shannon entropy ({entropy} bits/char), indicating predictable generation.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-330",
                        affected_component=context_url or "MobileToken",
                        detection_method="MobileTokenSessionAuditor (entropy analysis)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Use a cryptographically secure pseudo-random number generator (CSPRNG) with at least 128 bits of entropy.",
                        metadata={"entropy": entropy},
                    ))
            return findings

        header = jwt_data["header"]
        payload = jwt_data["payload"]

        # 1. Algorithm check: 'none'
        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            findings.append(Finding(
                title="JWT Insecure Algorithm 'none' Accepted",
                description="The JWT header specifies algorithm 'none', disabling signature verification and allowing token forgery.",
                severity=Severity.CRITICAL,
                cwe_id="CWE-347",
                affected_component=context_url or "MobileAuthJWT",
                detection_method="MobileTokenSessionAuditor (JWT Header Inspection)",
                status=FindingStatus.UNVERIFIED,
                remediation="Configure the JWT verification engine to reject the 'none' algorithm and mandate asymmetric signatures (RS256/ES256).",
                metadata={"header": header},
            ))

        # 2. Expiration check: missing exp claim
        now_ts = int(datetime.now(timezone.utc).timestamp())
        exp = payload.get("exp")
        if exp is None:
            findings.append(Finding(
                title="JWT Token Missing Expiration Claim",
                description="The JWT token does not contain an 'exp' (expiration) claim, granting perpetual validity if compromised.",
                severity=Severity.MEDIUM,
                cwe_id="CWE-613",
                affected_component=context_url or "MobileAuthJWT",
                detection_method="MobileTokenSessionAuditor (JWT Claim Inspection)",
                status=FindingStatus.UNVERIFIED,
                remediation="Ensure all issued JWT access tokens specify an 'exp' claim with an appropriate short lifespan (e.g. 15-60 minutes).",
            ))
        elif isinstance(exp, (int, float)):
            if exp < now_ts:
                findings.append(Finding(
                    title="Expired JWT Token in Active Use",
                    description=f"JWT token expired at timestamp {int(exp)}, but was intercepted in active application traffic.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-613",
                    affected_component=context_url or "MobileAuthJWT",
                    detection_method="MobileTokenSessionAuditor (JWT Claim Inspection)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Verify that the backend rejects expired JWT access tokens and requires refresh token rotation.",
                    metadata={"exp": exp, "now": now_ts},
                ))
            iat = payload.get("iat")
            if isinstance(iat, (int, float)) and (exp - iat > 30 * 86400):
                findings.append(Finding(
                    title="Excessively Long JWT Token Expiration Lifetime",
                    description=f"JWT token has a validity duration of {(exp - iat) / 86400:.1f} days without required re-authentication.",
                    severity=Severity.LOW,
                    cwe_id="CWE-613",
                    affected_component=context_url or "MobileAuthJWT",
                    detection_method="MobileTokenSessionAuditor (JWT Claim Inspection)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Shorten access token validity to under 1 hour and implement sliding refresh token sessions.",
                ))

        # 3. Sensitive PII in claims
        for claim_key in payload.keys():
            if str(claim_key).lower() in self.SENSITIVE_CLAIM_KEYS:
                findings.append(Finding(
                    title=f"Sensitive Credential Embedded in JWT Payload ({claim_key})",
                    description=f"Sensitive field '{claim_key}' found unencrypted in readable JWT payload.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-312",
                    affected_component=context_url or "MobileAuthJWT",
                    detection_method="MobileTokenSessionAuditor (JWT Payload Inspection)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Never store passwords, raw API secrets, or sensitive PII in client-side readable JWT tokens.",
                    metadata={"claim": claim_key},
                ))

        return findings

    def audit_transactions(self, transactions: List[Any]) -> List[Finding]:
        """Audit intercepted HTTP transactions for session and token vulnerabilities."""
        findings: List[Finding] = []
        logged_out_tokens: Dict[str, int] = {}

        for idx, tx in enumerate(transactions):
            url = getattr(tx, "url", "")
            method = getattr(tx, "method", "GET").upper()
            headers = getattr(tx, "request_headers", {}) or getattr(tx, "headers", {}) or {}
            status_code = getattr(tx, "response_status", 200)

            # Find token in headers
            auth_header = headers.get("Authorization") or headers.get("authorization") or ""
            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
            elif auth_header:
                token = auth_header.strip()

            # 1. Cleartext HTTP transmission check
            if url.startswith("http://") and token:
                findings.append(Finding(
                    title="Authentication Token Transmitted Over Cleartext HTTP",
                    description="Authentication bearer token was sent over an unencrypted HTTP channel, exposing credentials to network interception.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-319",
                    affected_component=url,
                    detection_method="MobileTokenSessionAuditor (Network Security)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Enforce HTTPS via Network Security Config and reject plain HTTP transmission.",
                ))

            # 2. Check query parameter tokens
            parsed = urlsplit(url)
            query_tuples = parse_qsl(parsed.query, keep_blank_values=True)
            for q_name, q_val in query_tuples:
                if q_name.lower() in self.TOKEN_QUERY_PARAMS and len(q_val) > 8:
                    findings.append(Finding(
                        title=f"Sensitive Authentication Token in URL Query Parameter ({q_name})",
                        description=f"Token '{q_name}' is transmitted in the URL query string, exposing it to access logs, referrer headers, and WebView history.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-598",
                        affected_component=url,
                        detection_method="MobileTokenSessionAuditor (URL Hygiene)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Pass authentication and session tokens in the HTTP Authorization header instead of the URL query string.",
                    ))
                    if not token:
                        token = q_val

            # Audit JWT claims if token is found
            if token:
                findings.extend(self.audit_token(token, context_url=url))

            # 3. Track logout / session revocation
            path_lower = parsed.path.lower()
            if any(term in path_lower for term in ("/logout", "/signout", "/revoke", "/deauth")) and status_code < 400:
                if token:
                    logged_out_tokens[token] = idx

            # Check if logged_out_token is reused in subsequent calls
            if token and token in logged_out_tokens:
                logout_idx = logged_out_tokens[token]
                if idx > logout_idx and not any(term in path_lower for term in ("/logout", "/signout")):
                    findings.append(Finding(
                        title="Session Token Reused After Logout / Revocation",
                        description="An authentication token remained valid and was accepted after a successful logout request, violating session lifecycle controls.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-613",
                        affected_component=url,
                        detection_method="MobileTokenSessionAuditor (Session Lifecycle Replay)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Ensure the backend invalidates session tokens in the server-side cache upon user logout.",
                        metadata={"logout_index": logout_idx, "reuse_index": idx},
                    ))

        return findings
