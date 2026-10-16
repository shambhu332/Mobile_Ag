"""Conservative API review; live testing belongs to the approved replay workflow."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, parse_qsl
from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor


class APISecurityTester:
    MAX_URL_CHARS = 8192
    MAX_QUERY_FIELDS = 100

    def __init__(self, scan_id: str | None = None):
        self.scan_id = scan_id
        self.observations: dict[str, Any] = {}

    def _telemetry(self, key: str, value: Any):
        # No web-app import, implicit server initialization, or token-bearing URL keys.
        self.observations[key] = value

    @staticmethod
    def _reject_live(allow_network):
        if allow_network:
            raise PermissionError("Use the approved API replay workflow with exact scope; draft live testing is disabled")

    async def test_endpoint(self, url: str, method: str = "GET", headers=None,
                            body=None, allow_network: bool = False) -> list[Finding]:
        self._reject_live(allow_network)
        findings = await self._analyze_url_structure(url)
        self._telemetry("endpoint_review", "static_only")
        return findings

    async def _analyze_url_structure(self, url: str) -> list[Finding]:
        if not isinstance(url, str) or not url or len(url) > self.MAX_URL_CHARS:
            self.observations["url_structure_status"] = "incomplete_input"
            return []
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                self.observations["url_structure_status"] = "unsupported_or_invalid_url"
                return []
            # Validate authority syntax and bound query parsing before scanning.
            _ = parsed.port
            query = parse_qsl(parsed.query, keep_blank_values=True,
                              max_num_fields=self.MAX_QUERY_FIELDS)
        except (TypeError, ValueError, UnicodeError):
            self.observations["url_structure_status"] = "incomplete_input"
            return []
        self.observations["url_structure_status"] = "analyzed"
        if not any(MobileTokenSessionAuditor._is_sensitive_query_key(key) for key, _ in query):
            return []
        # Do not copy any URL/userinfo/query/path values into durable evidence.
        return [Finding(
            title="Review credential-named URL query parameter",
            description="A credential-named query parameter was found. Its value, sensitivity, transmission and impact have not been verified.",
            severity=Severity.INFO, cwe_id="CWE-598", confidence=0.4,
            status=FindingStatus.UNVERIFIED, detection_method="APISecurityTester (static URL structure)",
            remediation="Determine whether this carries credentials; use an appropriate protected channel and avoid URL logging.",
            metadata={"proof_state": "not_proven", "automatic_exploit_proof": False},
        )]

    async def analyze_endpoints_static(self, endpoints: list[dict[str, Any]]) -> list[Finding]:
        findings = []
        for endpoint in endpoints:
            findings.extend(await self._analyze_url_structure(endpoint.get("url", "")))
        # Missing request headers, route names, GraphQL and absent version strings
        # do not demonstrate backend authentication or access-control defects.
        self._telemetry("static_candidate_count", len(findings))
        return findings

    async def generate_fuzzing_plan(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        return {"status": "manual_scope_required", "executed": False,
                "endpoint_count": len(endpoints), "endpoints": [],
                "required": ["exact authorized fixture URLs", "allowed methods", "request budget", "synthetic accounts", "negative controls"]}

    async def check_rate_limiting(self, url: str, method: str = "GET", headers=None,
                                 allow_network: bool = False) -> list[Finding]:
        self._reject_live(allow_network)
        self._telemetry("rate_limiting", "not_tested")
        return []

    async def test_auth_bypass(self, endpoints: list[dict[str, Any]],
                              allow_network: bool = False) -> list[Finding]:
        self._reject_live(allow_network)
        self._telemetry("authentication", "not_tested")
        return []

    def get_bola_fuzzer(self) -> Any:
        """Return an automated BolaFuzzer for dual-session BOLA/IDOR auditing."""
        from mobileag.dast.bola_fuzzer import BolaFuzzer
        return BolaFuzzer()

    def get_token_auditor(self) -> Any:
        """Return a MobileTokenSessionAuditor for token lifecycle and session auditing."""
        from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
        return MobileTokenSessionAuditor()


