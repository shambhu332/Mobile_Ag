"""Mobile Token and Session Lifecycle Auditor.

Analyzes JWT tokens, OAuth tokens, session storage mechanisms, expiration/revocation,
and token transmission channels (OWASP MASVS-AUTH, CWE-613, CWE-384).
"""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from mobileag.reporting.finding import Finding, FindingStatus, Severity


@dataclass
class ParsedJwtClaims:
    algorithm: str
    issuer: Optional[str] = None
    subject: Optional[str] = None
    audience: Optional[str] = None
    expiration: Optional[int] = None
    issued_at: Optional[int] = None
    is_expired: bool = False
    has_signature: bool = True
    weak_algorithm: bool = False  # e.g., 'none', HS256 without key protection


@dataclass
class TokenAuditReport:
    tokens_discovered: int = 0
    weak_tokens: int = 0
    findings: List[Finding] = field(default_factory=list)


class TokenLifecycleAuditor:
    """Audits mobile authentication tokens, JWT lifetimes, and session invalidation handling."""

    JWT_REGEX = re.compile(r'\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?)\b')

    @classmethod
    def parse_jwt(cls, token_str: str) -> Optional[ParsedJwtClaims]:
        """Safely decode JWT header and payload without verifying signature."""
        parts = token_str.split(".")
        if len(parts) not in {2, 3}:
            return None

        header_part = parts[0]
        payload_part = parts[1]

        def _b64_decode(data: str) -> Dict[str, Any]:
            # Add padding if required
            rem = len(data) % 4
            if rem > 0:
                data += "=" * (4 - rem)
            raw = base64.urlsafe_b64decode(data.encode("ascii"))
            return json.loads(raw.decode("utf-8", errors="replace"))

        try:
            header = _b64_decode(header_part)
            payload = _b64_decode(payload_part)
        except Exception:
            return None

        alg = str(header.get("alg", "UNKNOWN"))
        exp = payload.get("exp")
        iat = payload.get("iat")

        is_expired = False
        if isinstance(exp, (int, float)):
            is_expired = exp < time.time()

        weak_alg = alg.lower() in {"none", "null", ""}

        return ParsedJwtClaims(
            algorithm=alg,
            issuer=payload.get("iss"),
            subject=payload.get("sub"),
            audience=payload.get("aud"),
            expiration=int(exp) if isinstance(exp, (int, float)) else None,
            issued_at=int(iat) if isinstance(iat, (int, float)) else None,
            is_expired=is_expired,
            has_signature=len(parts) == 3 and len(parts[2]) > 0,
            weak_algorithm=weak_alg,
        )

    def audit_captured_tokens(self, tokens: List[str], source_context: str = "intercepted_traffic") -> TokenAuditReport:
        """Audit a collection of captured or discovered token strings."""
        report = TokenAuditReport()

        for token in set(tokens):
            jwt = self.parse_jwt(token)
            if not jwt:
                continue

            report.tokens_discovered += 1

            if jwt.weak_algorithm or not jwt.has_signature:
                report.weak_tokens += 1
                report.findings.append(Finding(
                    id=f"TOKEN-WEAK-ALG-{abs(hash(token)) % 100000:05d}",
                    title="Insecure JWT Signing Algorithm (alg=none / unsigned)",
                    description=(
                        f"A JWT discovered in {source_context} specifies an insecure or missing signing "
                        f"algorithm ('{jwt.algorithm}'). Unsigned or 'none'-algorithm tokens allow attackers "
                        "to forge claims and elevate privileges without cryptographic validation."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-347",
                    status=FindingStatus.UNVERIFIED,
                    detection_method="TokenLifecycleAuditor (JWT signature audit)",
                    remediation="Enforce strong asymmetric (RS256/ES256) or symmetric (HS256) signatures server-side and reject 'none'.",
                ))

            if jwt.expiration is None:
                report.findings.append(Finding(
                    id=f"TOKEN-NO-EXP-{abs(hash(token)) % 100000:05d}",
                    title="JWT Token Lacks Expiration Claim ('exp')",
                    description=(
                        f"A JWT discovered in {source_context} does not specify an expiration ('exp') timestamp. "
                        "Non-expiring mobile authentication tokens expand the vulnerability window indefinitely "
                        "if intercepted or harvested from local storage."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-613",
                    status=FindingStatus.UNVERIFIED,
                    detection_method="TokenLifecycleAuditor (JWT expiration audit)",
                    remediation="Configure bounded short-lived access tokens with a valid 'exp' claim combined with secure refresh token rotation.",
                ))

        return report
