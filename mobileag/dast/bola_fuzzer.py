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


class BolaFuzzer:
    """Detects IDOR and BOLA vulnerabilities by performing dual-session cross-account replays."""

    # Patterns matching resource IDs in URL paths or queries
    ID_PATTERN = re.compile(r"/(?:users|accounts|orders|items|profiles|invoices|documents)/([a-zA-Z0-9_\-]+)", re.IGNORECASE)

    def extract_resource_candidates(self, url: str) -> List[str]:
        """Identify candidate object IDs within URL paths or query parameters."""
        candidates = []
        parsed = urllib.parse.urlparse(url)

        # Check path segments
        path_matches = self.ID_PATTERN.findall(parsed.path)
        candidates.extend(path_matches)

        # Check query params for id keys
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for k, vals in params.items():
                if any(sub in k.lower() for sub in ["id", "account", "user", "order"]):
                    candidates.extend(vals)

        return list(set(candidates))

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
        marker_observed = bool(user_a_marker and user_a_marker in response_body)

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
            endpoint=endpoint,
            method=method,
            resource_id=resource_id,
            status_code=status_code,
            is_vulnerable=is_vuln,
            evidence_reason=reason,
            # Avoid retaining potentially real account data. Digest, status,
            # and the explicit synthetic-canary match are sufficient for a
            # bounded observation record; raw HTTP evidence belongs in an
            # authorized, separately redacted capture store.
            response_body_preview="",
            response_sha256=hashlib.sha256(response_body.encode("utf-8", errors="replace")).hexdigest(),
            marker_observed=marker_observed,
        )
