"""Mobile Token & Session Lifecycle Auditor.

Audits intercepted mobile tokens and authentication sessions for security weaknesses:
1. Unverified JWT header and lifecycle claim indicators -> CWE-347 / CWE-613
2. Insecure JWT lifecycle claims (missing expiration, excessive lifetime, expired tokens) -> CWE-613
3. Sensitive credentials or PII embedded in JWT claims -> CWE-312
4. Session tokens transmitted over cleartext HTTP -> CWE-319
5. Sensitive tokens passed in URL query strings -> CWE-598
6. Session token reuse after logout or de-authentication -> CWE-613
7. Low-entropy or predictable session identifiers -> CWE-330

JWT parsing is bounded. Signature verification is an explicit offline helper
limited to researcher-keyed HS256/HS384/HS512 checks; it does not estimate key
entropy or establish server-side token acceptance. Findings are review leads.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

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
        "api_key",
        "apikey",
        "auth_token",
        "access_token",
        "refresh_token",
        "session_token",
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
    TOKEN_QUERY_SUFFIXES = ("token", "secret", "apikey", "password", "signature")

    MAX_TOKEN_CHARS = 64 * 1024
    MAX_JWT_SEGMENT_CHARS = 16 * 1024
    MAX_TRANSACTIONS = 10_000
    MAX_TRACKED_LOGOUT_TOKENS = 1_000
    MAX_VERIFICATION_KEY_BYTES = 4 * 1024

    HMAC_ALGORITHMS = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    @staticmethod
    def _safe_context_url(url: str) -> str:
        """Return an endpoint locator with userinfo, query and fragment removed."""
        try:
            if not isinstance(url, str):
                return "MobileAuth"
            parsed = urlsplit(url[:8192])
            hostname = parsed.hostname
            if not parsed.scheme or not hostname:
                return "MobileAuth"
            host = f"[{hostname}]" if ":" in hostname else hostname
            # Ports can be malformed in attacker-controlled capture input.
            try:
                port = parsed.port
            except ValueError:
                return "MobileAuth"
            netloc = f"{host}:{port}" if port is not None else host
            path_segments = parsed.path[:2048].split("/")
            safe_segments: list[str] = []
            redact_next = False
            for segment in path_segments:
                if redact_next or len(segment) >= 24 and re.fullmatch(r"[A-Za-z0-9._~-]+", segment):
                    safe_segments.append("[REDACTED]")
                    redact_next = False
                    continue
                safe_segments.append(segment[:128])
                redact_next = segment.lower() in {
                    "token", "access_token", "auth_token", "session", "sessionid",
                    "session_id", "jwt", "reset", "verify", "password", "secret",
                }
            safe_path = "/".join(safe_segments)
            return urlunsplit((parsed.scheme[:16], netloc[:512], safe_path, "", ""))
        except (TypeError, ValueError, UnicodeError):
            return "MobileAuth"

    @staticmethod
    def _valid_numeric_claim(value: Any) -> bool:
        if type(value) not in (int, float):
            return False

    @classmethod
    def _is_sensitive_query_key(cls, name: str) -> bool:
        """Recognize common credential-key aliases without reading their values."""
        normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
        exact = {re.sub(r"[^a-z0-9]", "", key) for key in cls.TOKEN_QUERY_PARAMS}
        exact.update({"authorization", "clientsecret", "signature", "sig", "codeverifier"})
        return normalized in exact or normalized.endswith(cls.TOKEN_QUERY_SUFFIXES)
        try:
            return math.isfinite(value) and abs(value) <= 253402300799
        except (OverflowError, TypeError, ValueError):
            return False

    def decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Safely parse JWT header and payload without cryptographic verification."""
        if not isinstance(token, str) or len(token) > self.MAX_TOKEN_CHARS:
            return None
        clean_token = token.strip()
        if clean_token.lower().startswith("bearer "):
            clean_token = clean_token[7:].strip()

        parts = clean_token.split(".")
        if (len(parts) != 3 or any(len(part) > self.MAX_JWT_SEGMENT_CHARS for part in parts)
                or not re.fullmatch(r"[A-Za-z0-9_-]+", parts[0])
                or not re.fullmatch(r"[A-Za-z0-9_-]+", parts[1])
                or (parts[2] and not re.fullmatch(r"[A-Za-z0-9_-]+", parts[2]))):
            return None

        def decode_part(part_b64: str) -> Optional[Dict[str, Any]]:
            # Adjust base64url padding
            padded = part_b64 + "=" * (-len(part_b64) % 4)
            try:
                raw_bytes = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
                value = json.loads(raw_bytes.decode("utf-8"))
                return value if isinstance(value, dict) else None
            except (ValueError, UnicodeError, binascii.Error, RecursionError):
                return None

        header = decode_part(parts[0])
        payload = decode_part(parts[1])

        if header is None or payload is None:
            return None

        algorithm = header.get("alg")
        safe_header = {"alg": algorithm[:32]} if isinstance(algorithm, str) else {}
        safe_payload: Dict[str, Any] = {}
        safe_payload["has_exp_claim"] = "exp" in payload
        for claim in ("exp", "iat"):
            value = payload.get(claim)
            if self._valid_numeric_claim(value):
                safe_payload[claim] = value
        safe_payload["sensitive_claim_names"] = sorted(
            key[:64] for key in payload
            if isinstance(key, str) and key.lower() in self.SENSITIVE_CLAIM_KEYS
        )[:32]
        return {"header": safe_header, "payload": safe_payload, "has_signature": bool(parts[2])}

    def verify_hmac_jwt_signature(self, token: str, verification_key: str | bytes | None) -> Dict[str, Any]:
        """Optionally verify compact JWT HMAC using a researcher-supplied local key.

        Implements HS256/HS384/HS512 JWS verification only (RFC 7515/7518),
        including JWA's minimum key byte length and constant-time MAC comparison.
        It does not discover keys, fetch JWKS, verify asymmetric algorithms, infer
        key entropy/strength, or establish that any server accepts the token.
        The key and token are never copied into the result.
        """
        if not isinstance(token, str) or len(token) > self.MAX_TOKEN_CHARS:
            return {"status": "invalid_input", "algorithm": None, "key_source": "researcher_supplied"}

        clean_token = token.strip()
        if clean_token.lower().startswith("bearer "):
            clean_token = clean_token[7:].strip()
        parsed = self.decode_jwt(clean_token)
        algorithm = parsed["header"].get("alg") if parsed else None
        if verification_key is None:
            return {"status": "not_tested", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}

        if isinstance(verification_key, str):
            if len(verification_key) > self.MAX_VERIFICATION_KEY_BYTES:
                return {"status": "invalid_key", "algorithm": algorithm,
                        "key_source": "researcher_supplied"}
            key = verification_key.encode("utf-8")
        elif isinstance(verification_key, bytes):
            key = verification_key
        else:
            return {"status": "invalid_key", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}
        if not key or len(key) > self.MAX_VERIFICATION_KEY_BYTES:
            return {"status": "invalid_key", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}
        if not parsed:
            return {"status": "invalid_compact_token", "algorithm": None,
                    "key_source": "researcher_supplied"}
        parts = clean_token.split(".")
        digest = self.HMAC_ALGORITHMS.get(algorithm)
        if digest is None:
            return {"status": "unsupported_algorithm", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}

        # Fail closed on duplicate header members or unimplemented JOSE
        # extensions so verification semantics cannot be guessed.
        try:
            decoded_segments = []
            for segment in parts[:2]:
                decoded = base64.b64decode(
                    (segment + "=" * (-len(segment) % 4)).encode("ascii"),
                    altchars=b"-_", validate=True,
                )
                canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
                if canonical != segment:
                    raise ValueError("non-canonical base64url segment")
                decoded_segments.append(decoded)
            header_bytes = decoded_segments[0].decode("utf-8")

            def reject_duplicate_header_members(pairs):
                header_obj = {}
                for name, value in pairs:
                    if name in header_obj:
                        raise ValueError("duplicate protected header member")
                    header_obj[name] = value
                return header_obj

            protected_header = json.loads(
                header_bytes, object_pairs_hook=reject_duplicate_header_members,
            )
            if (not isinstance(protected_header, dict)
                    or protected_header.get("alg") != algorithm
                    or "crit" in protected_header
                    or ("b64" in protected_header and protected_header["b64"] is not True)):
                raise ValueError("unsupported protected header")
        except (ValueError, UnicodeError, binascii.Error, RecursionError):
            return {"status": "unsupported_header_parameters", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}

        if len(key) < digest().digest_size:
            return {"status": "key_too_short", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}

        signature_segment = parts[2]
        if not signature_segment:
            return {"status": "missing_signature", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}
        try:
            padded = signature_segment + "=" * (-len(signature_segment) % 4)
            supplied_signature = base64.b64decode(
                padded.encode("ascii"), altchars=b"-_", validate=True,
            )
            canonical_segment = base64.urlsafe_b64encode(supplied_signature).rstrip(b"=").decode("ascii")
        except (ValueError, UnicodeError, binascii.Error):
            return {"status": "invalid_compact_token", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}
        if canonical_segment != signature_segment:
            return {"status": "invalid_compact_token", "algorithm": algorithm,
                    "key_source": "researcher_supplied"}

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        expected_signature = hmac.new(key, signing_input, digest).digest()
        valid = hmac.compare_digest(expected_signature, supplied_signature)
        return {
            "status": "valid_for_supplied_key" if valid else "invalid_for_supplied_key",
            "algorithm": algorithm,
            "key_source": "researcher_supplied",
            "server_acceptance": "not_tested",
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
        if not isinstance(token, str) or len(token) > self.MAX_TOKEN_CHARS:
            return findings
        safe_context = self._safe_context_url(context_url) if context_url else "MobileAuthJWT"
        jwt_data = self.decode_jwt(token)

        if not jwt_data:
            # Check basic session token entropy
            clean_tok = token.strip()
            if len(clean_tok) >= 16:
                entropy = self.calculate_entropy(clean_tok)
                if entropy < 2.5:
                    findings.append(Finding(
                        title="Low-Entropy Session Identifier Candidate",
                        description=f"Captured token text has low Shannon entropy ({entropy} bits/char). This heuristic alone does not establish how the identifier was generated or whether it is accepted by a server.",
                        severity=Severity.HIGH,
                        cwe_id="CWE-330",
                        affected_component=safe_context if context_url else "MobileToken",
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
        if alg == "none":
            findings.append(Finding(
                title="JWT Declares alg=none (Verification Not Established)",
                description="The observed JWT header declares alg=none. This decoded header alone does not show that a server accepted the token or disabled signature verification.",
                severity=Severity.MEDIUM,
                cwe_id="CWE-347",
                affected_component=safe_context,
                detection_method="MobileTokenSessionAuditor (JWT Header Inspection)",
                status=FindingStatus.UNVERIFIED,
                remediation="Verify server-side JWT validation rejects unsigned tokens and enforces an explicit algorithm allow-list.",
                metadata={"algorithm": "none", "verification_status": "not_tested"},
            ))

        # 2. Expiration check: missing exp claim
        now_ts = int(datetime.now(timezone.utc).timestamp())
        exp = payload.get("exp")
        if not payload.get("has_exp_claim", False):
            findings.append(Finding(
                title="JWT Token Missing Expiration Claim",
                description="The decoded JWT payload has no 'exp' claim. This does not establish the server's independent expiration or revocation controls.",
                severity=Severity.MEDIUM,
                cwe_id="CWE-613",
                affected_component=safe_context,
                detection_method="MobileTokenSessionAuditor (JWT Claim Inspection)",
                status=FindingStatus.UNVERIFIED,
                remediation="Ensure all issued JWT access tokens specify an 'exp' claim with an appropriate short lifespan (e.g. 15-60 minutes).",
            ))
        elif self._valid_numeric_claim(exp):
            if exp < now_ts:
                findings.append(Finding(
                    title="Expired JWT Observed in Traffic (Acceptance Not Established)",
                    description="A captured JWT has an expiration claim in the past. The capture alone does not establish whether a server accepted or rejected it.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-613",
                    affected_component=safe_context,
                    detection_method="MobileTokenSessionAuditor (JWT Claim Inspection)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Verify that the backend rejects expired JWT access tokens and requires refresh token rotation.",
                    metadata={"expiration_status": "expired_claim_observed", "backend_acceptance": "not_tested"},
                ))
            iat = payload.get("iat")
            if self._valid_numeric_claim(iat) and (exp - iat > 30 * 86400):
                findings.append(Finding(
                    title="Excessively Long JWT Token Expiration Lifetime",
                    description=f"The decoded 'iat' and 'exp' claims advertise a lifetime of {(exp - iat) / 86400:.1f} days; this does not prove backend enforcement or refresh policy.",
                    severity=Severity.LOW,
                    cwe_id="CWE-613",
                    affected_component=safe_context,
                    detection_method="MobileTokenSessionAuditor (JWT Claim Inspection)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Shorten access token validity to under 1 hour and implement sliding refresh token sessions.",
                ))

        # 3. Sensitive PII in claims
        for claim_key in payload.get("sensitive_claim_names", []):
            if claim_key in self.SENSITIVE_CLAIM_KEYS:
                findings.append(Finding(
                    title="Sensitive-Looking Claim Name in Readable JWT Payload",
                    description=f"The decoded JWT payload contains a claim named '{claim_key}'. Claim-name matching does not establish that its value contains a credential or sensitive data.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-312",
                    affected_component=safe_context,
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

        for idx, tx in enumerate(transactions[:self.MAX_TRANSACTIONS]):
            url = getattr(tx, "url", "")
            if not isinstance(url, str) or len(url) > 8192:
                url = ""
            safe_url = self._safe_context_url(url)
            headers = getattr(tx, "request_headers", {}) or getattr(tx, "headers", {}) or {}
            if not isinstance(headers, dict):
                headers = {}
            status_code = getattr(tx, "response_status", 200)
            if type(status_code) is not int or not 100 <= status_code <= 599:
                status_code = None

            # Find token in headers
            auth_header = next((value for key, value in headers.items()
                                if isinstance(key, str) and key.lower() == "authorization"), "")
            if not isinstance(auth_header, str):
                auth_header = ""
            if len(auth_header) > self.MAX_TOKEN_CHARS + 16:
                auth_header = ""
            token = ""
            auth_scheme, separator, auth_value = auth_header.partition(" ")
            if separator and auth_scheme.lower() == "bearer":
                token = auth_value.strip()
            elif auth_header:
                token = auth_header.strip()

            # 1. Cleartext HTTP transmission check
            if url.lower().startswith("http://") and token:
                findings.append(Finding(
                    title="Authentication Credential Transmitted Over Cleartext HTTP",
                    description="An Authorization credential was sent over an unencrypted HTTP channel, exposing it to network interception.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-319",
                    affected_component=safe_url,
                    detection_method="MobileTokenSessionAuditor (Network Security)",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Enforce HTTPS via Network Security Config and reject plain HTTP transmission.",
                ))

            # 2. Check query parameter tokens
            try:
                parsed = urlsplit(url)
            except ValueError:
                parsed = urlsplit("")
            try:
                query_tuples = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256)
            except ValueError:
                query_tuples = []
            for q_name, q_val in query_tuples:
                if self._is_sensitive_query_key(q_name):
                    findings.append(Finding(
                        title="Sensitive Authentication Token in URL Query Parameter",
                        description="A token-like query parameter is present in the captured URL, which can expose credentials to access logs, referrer headers, or WebView history. The value is omitted from evidence.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-598",
                        affected_component=safe_url,
                        detection_method="MobileTokenSessionAuditor (URL Hygiene)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Pass authentication and session tokens in the HTTP Authorization header instead of the URL query string.",
                    ))
                    if not token:
                        token = q_val

            # Audit JWT claims if token is found
            if token:
                findings.extend(self.audit_token(token, context_url=safe_url))

            # 3. Track logout / session revocation
            path_lower = parsed.path.lower()
            logout_paths = {"logout", "signout", "revoke", "deauth"}
            if (bool(logout_paths.intersection(path_lower.split("/")))
                    and status_code is not None and 200 <= status_code < 300):
                if token and (len(logged_out_tokens) < self.MAX_TRACKED_LOGOUT_TOKENS or token in logged_out_tokens):
                    logged_out_tokens[token] = idx

            # Check if logged_out_token is reused in subsequent calls
            if token and token in logged_out_tokens:
                logout_idx = logged_out_tokens[token]
                if (idx > logout_idx and status_code is not None and 200 <= status_code < 300
                        and not any(term in path_lower for term in ("/logout", "/signout"))):
                    findings.append(Finding(
                        title="Session Token Observed on a Successful Request After Logout (Acceptance Unverified)",
                        description="The same token was observed on a later request with a 2xx response after a logout/revocation response. This capture does not by itself prove that a protected operation was authorized or that the server accepted the token.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-613",
                        affected_component=safe_url,
                        detection_method="MobileTokenSessionAuditor (Session Lifecycle Replay)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Ensure the backend invalidates session tokens in the server-side cache upon user logout.",
                        metadata={"logout_index": logout_idx, "reuse_index": idx},
                    ))

        return findings
