"""Automated Broken Object Level Authorization (BOLA/IDOR) Dual-Session Replay Fuzzer.

Replays authenticated requests belonging to User A using User B's credentials to detect
authorization bypasses and object leaks (OWASP API Security Top 10 API1:2023).
"""
from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import urllib.parse


@dataclass
class BolaTestResult:
    endpoint: str
    method: str
    resource_id: str
    status_code: int
    is_vulnerable: bool
    evidence_reason: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    response_sha256: str = ""
    marker_observed: bool = False
    response_hash_status: str = "complete"
    reference_marker_observed: bool = False
    comparison_status: str = "not_compared"


class BolaFuzzer:
    """Offline BOLA candidate extraction and researcher-supplied response evaluation."""

    # Patterns matching resource IDs in URL paths or queries
    ID_PATTERN = re.compile(r"/(?:users|accounts|orders|items|profiles|invoices|documents)/([a-zA-Z0-9_\-]+)", re.IGNORECASE)
    MAX_URL_LENGTH = 8192
    MAX_QUERY_FIELDS = 100
    MAX_CANDIDATES = 100
    MAX_CANDIDATE_LENGTH = 256
    MAX_RESPONSE_CHARS = 1024 * 1024
    SENSITIVE_QUERY_KEY_PARTS = (
        "token", "auth", "authorization", "password", "secret", "session", "cookie",
        "bearer", "credential", "key", "apikey",
    )
    _UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    _EMAIL = re.compile(r"^[^/@\s]{1,64}@[^/@\s]+\.[^/@\s]+$")
    _OPAQUE_ID = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{24,}$")

    @classmethod
    def _safe_endpoint(cls, endpoint: str) -> str:
        """Return a report-safe route template; omit credentials and query data."""
        if not isinstance(endpoint, str) or len(endpoint) > cls.MAX_URL_LENGTH:
            return "[REDACTED ENDPOINT]"
        try:
            parsed = urllib.parse.urlsplit(endpoint)
            hostname, port = parsed.hostname, parsed.port
        except (TypeError, ValueError):
            return "[REDACTED ENDPOINT]"
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return "[REDACTED ENDPOINT]"
        segments = parsed.path.split("/")
        index = 0
        for position, segment in enumerate(segments):
            known_resource_segment = (position > 0 and segments[position - 1].lower() in {
                "users", "accounts", "orders", "items", "profiles", "invoices", "documents"
            })
            if (known_resource_segment or segment.isdigit() or cls._UUID.fullmatch(segment) or cls._EMAIL.fullmatch(segment)
                    or cls._OPAQUE_ID.fullmatch(segment)):
                index += 1
                segments[position] = f"{{id{index}}}"
        path = "/".join(segments) or "/"
        if parsed.scheme:
            if not hostname:
                return "[REDACTED ENDPOINT]"
            host = hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            origin = f"{parsed.scheme.lower()}://{host}"
            if port is not None:
                origin += f":{port}"
            return origin + path
        return path

    def extract_resource_candidates(self, url: str) -> List[str]:
        """Identify bounded candidate object IDs from a URL, without network access."""
        if not isinstance(url, str) or len(url) > self.MAX_URL_LENGTH:
            return []
        candidates = []
        try:
            parsed = urllib.parse.urlparse(url)
            # Validate authority syntax (notably malformed brackets and ports).
            _ = parsed.hostname, parsed.port
        except (TypeError, ValueError):
            return []

        # Check path segments
        path_matches = self.ID_PATTERN.findall(parsed.path)
        candidates.extend(value for value in path_matches if len(value) <= self.MAX_CANDIDATE_LENGTH)

        # Check query params for id keys
        if parsed.query:
            try:
                params = urllib.parse.parse_qsl(
                    parsed.query, keep_blank_values=True, max_num_fields=self.MAX_QUERY_FIELDS
                )
            except ValueError:
                return []
            for key, value in params:
                normalized_key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).casefold()
                key_parts = set(re.findall(r"[a-z0-9]+", normalized_key))
                if key_parts.intersection(self.SENSITIVE_QUERY_KEY_PARTS):
                    continue
                if (len(key) <= self.MAX_CANDIDATE_LENGTH
                        and len(value) <= self.MAX_CANDIDATE_LENGTH
                        and any(sub in normalized_key for sub in ("id", "account", "user", "order"))):
                    candidates.append(value)

        return list(dict.fromkeys(candidates))[:self.MAX_CANDIDATES]

    def evaluate_response_discrepancy(
        self,
        endpoint: str,
        method: str,
        resource_id: str,
        status_code: int,
        response_body: str,
        user_a_marker: Optional[str] = None,
    ) -> BolaTestResult:
        """Evaluate whether a request made with User B's token leaked User A's private data."""
        is_vuln = False
        reason = "Access denied or safe behavior observed."
        valid_response = isinstance(response_body, str)
        bounded_response = response_body[:self.MAX_RESPONSE_CHARS] if valid_response else ""
        hash_status = "invalid_input" if not valid_response else (
            "truncated" if len(response_body) > self.MAX_RESPONSE_CHARS else "complete"
        )
        marker_observed = bool(
            isinstance(user_a_marker, str) and user_a_marker and valid_response
            and user_a_marker in bounded_response
        )

        if status_code in {200, 206}:
            # A successful response alone cannot establish that the object is
            # private or belongs to account A. Require an independently known,
            # synthetic account-A canary to be reflected by account B's response.
            if marker_observed:
                is_vuln = True
                reason = "Endpoint returned User A's synthetic canary in User B's response; canary value omitted."
            else:
                reason = (
                    "HTTP success observed, but no researcher-provided User A canary matched; "
                    "object ownership and confidentiality are unverified."
                )
        elif status_code in {401, 403}:
            reason = f"Proper authorization enforcement observed (HTTP {status_code})."
        elif status_code == 404:
            reason = f"Resource not found (HTTP 404); potential object-level isolation or absent resource."

        return BolaTestResult(
            endpoint=self._safe_endpoint(endpoint),
            method=method,
            resource_id="[REDACTED]",
            status_code=status_code,
            is_vulnerable=is_vuln,
            evidence_reason=reason,
            # Avoid retaining potentially real account data. Digest, status,
            # and the explicit synthetic-canary match are sufficient for a
            # bounded observation record; raw HTTP evidence belongs in an
            # authorized, separately redacted capture store.
            response_body_preview="",
            response_sha256=(
                hashlib.sha256(bounded_response.encode("utf-8", errors="replace")).hexdigest()
                if valid_response else ""
            ),
            marker_observed=marker_observed,
            response_hash_status=hash_status,
        )

    def evaluate_dual_session_observations(
        self,
        endpoint: str,
        method: str,
        resource_id: str,
        account_a_status: int,
        account_a_response_body: str,
        account_b_status: int,
        account_b_response_body: str,
        account_a_marker: Optional[str] = None,
    ) -> BolaTestResult:
        """Compare supplied A-control and B-observation responses without sending requests.

        A positive comparison requires a researcher-supplied canary to occur in
        both successful responses. The evaluator cannot verify account identity,
        request equivalence, resource ownership, or server authorization.
        """
        result = self.evaluate_response_discrepancy(
            endpoint=endpoint,
            method=method,
            resource_id=resource_id,
            status_code=account_b_status,
            response_body=account_b_response_body,
            user_a_marker=account_a_marker,
        )
        reference_valid = isinstance(account_a_response_body, str)
        reference_bounded = (
            account_a_response_body[:self.MAX_RESPONSE_CHARS] if reference_valid else ""
        )
        reference_marker = bool(
            isinstance(account_a_marker, str) and account_a_marker
            and reference_valid and account_a_marker in reference_bounded
        )
        result.reference_marker_observed = reference_marker
        if not reference_marker or account_a_status not in {200, 206}:
            result.is_vulnerable = False
            result.comparison_status = "reference_not_established"
            result.evidence_reason = (
                "Account-A control did not establish the researcher-provided canary in a successful "
                "response; cross-account exposure is not established."
            )
        elif result.is_vulnerable:
            result.comparison_status = "canary_observed_in_both_responses"
            result.evidence_reason = (
                "Researcher-provided canary was observed in both supplied account-A and account-B "
                "responses; account identity, request equivalence, and authorization remain unverified."
            )
        else:
            result.comparison_status = "canary_not_observed_in_b_response"
        return result
