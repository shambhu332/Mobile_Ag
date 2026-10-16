import asyncio
import logging
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)


class APIMapper:
    """Agent for extracting API endpoints and identifying associated security issues."""

    def __init__(self, router: LLMRouter):
        """Initialize the API mapper with an LLM router."""
        self.router = router
        self.retrofit_pattern = re.compile(r'@(GET|POST|PUT|DELETE|PATCH)\(\s*"([^"]+)"\s*\)')
        self.url_pattern = re.compile(
            r'https?://(?:\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.-]+)'
            r'(?::\d+)?(?:/[a-zA-Z0-9._/?%&=+-]*)?'
        )
        # Decompiled APKs are not always available as Java/Kotlin: obfuscated
        # apps and cross-platform bundles often leave useful route literals in
        # Smali, XML/JSON resources, JS bundles, or Dart output. These are
        # inventory leads only; the HTTP method and reachability are unknown.
        self.route_literal_pattern = re.compile(
            r'''["']((?:/)(?:api|graphql|v[0-9]+|auth|oauth|login|users?|account|payments?)(?:/[A-Za-z0-9._~%{}:-]+)*(?:\?[A-Za-z0-9._~%{}=&%-]*)?)["']''',
            re.IGNORECASE,
        )
        self.graphql_pattern = re.compile(r'query\s*\{|mutation\s*\{')
        self.coverage = {"static_status":"not_analyzed", "runtime_status":"not_tested",
                         "proof_status":"not_proven", "exhaustive":False}

    @staticmethod
    def _safe_route(value: str) -> str:
        """Keep route shape, but never retain query, fragment, or opaque path values."""
        try:
            parsed = urlsplit(value[:8192])
            origin = ""
            if parsed.scheme or parsed.netloc:
                hostname = parsed.hostname
                scheme = parsed.scheme.lower()
                if hostname and (not scheme or scheme in {"http", "https"}):
                    if not re.fullmatch(r"[A-Za-z0-9.:%-]+", hostname):
                        return "[REDACTED URL]"
                    host = f"[{hostname}]" if ":" in hostname else hostname
                    try:
                        port = parsed.port
                    except ValueError:
                        return "[REDACTED URL]"
                    origin = f"{scheme}://{host}" if scheme else f"//{host}"
                    if port is not None:
                        origin += f":{port}"
            segments = (parsed.path or "/").split("/")
            safe_segments: list[str] = []
            redact_next = False
            opaque_id = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~%-]{24,}$")
            uuid = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            email = re.compile(r"^[^/@\s]{1,64}@[^/@\s]+\.[^/@\s]+$")
            sensitive_segments = {
                "token", "access_token", "auth_token", "session", "sessionid",
                "session_id", "jwt", "reset", "verify", "password", "secret", "key",
                "api_key", "client_secret", "secret_key", "auth",
            }
            for segment in segments:
                if (redact_next or len(segment) > 128 or segment.isdigit()
                        or uuid.fullmatch(segment) or email.fullmatch(segment)
                        or opaque_id.fullmatch(segment)):
                    safe_segments.append("{id}")
                    redact_next = False
                    continue
                safe_segments.append(quote(segment, safe="!$&'()*+,;=:@%{}._~-"))
                redact_next = segment.lower() in sensitive_segments
            safe_path = "/".join(safe_segments) or "/"
            return f"{origin}{safe_path}"[:4096]
        except (TypeError, ValueError, UnicodeError):
            return "[REDACTED URL]"

    @staticmethod
    def _matches_with_line_numbers(pattern, content: str):
        """Iterate regex matches with 1-based line numbers in one linear pass."""
        offset = 0
        line_number = 1
        for match in pattern.finditer(content):
            line_number += content.count("\n", offset, match.start())
            yield match, line_number
            line_number += content.count("\n", match.start(), match.end())
            offset = match.end()

    def _sync_map_apis(self, base_path: Path) -> tuple[list[dict], list[dict]]:
        """Synchronously scan source files for API definitions and URL references."""
        endpoints: list[dict] = []
        raw_findings: list[dict] = []
        seen_endpoint_urls: set[str] = set()
        deduplicated_endpoint_count = 0

        inventory = SourceInventory()
        for file_path, data in inventory.read(
                base_path, {".java", ".kt", ".smali", ".xml", ".json", ".js", ".mjs", ".dart"}):
            try:
                content = data.decode("utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                stem = file_path.stem
                
                # Extract Retrofit annotations
                for match, line_number in self._matches_with_line_numbers(self.retrofit_pattern, content):
                    if len(endpoints) >= 5000:
                        inventory.record_limit('endpoint_count')
                        break
                    method, path = match.groups()
                    safe_path = self._safe_route(path)
                    endpoints.append({
                        "method": method,
                        "url": safe_path,
                        "class_name": stem,
                        "source_file": rel_path,
                        "line_number": line_number,
                        # Header occurrences elsewhere in this class are not a
                        # reliable endpoint-specific authorization signal.
                        "requires_auth": None
                    })
                    seen_endpoint_urls.add(safe_path)

                    if "admin" in path.lower() or "privilege" in path.lower():
                        if len(raw_findings) < 500:
                            raw_findings.append({
                            "type": "sensitive_route_name",
                            "path": safe_path,
                            "component": stem,
                            "file_path": rel_path,
                            "line_number": line_number
                            })
                        else:
                            inventory.record_limit('finding_count')

                # Extract route-shaped literals from binary/resource/decompiled
                # sources, without pretending a literal is a callable endpoint.
                if file_path.suffix.lower() not in {".java", ".kt"}:
                    for match, line_number in self._matches_with_line_numbers(self.route_literal_pattern, content):
                        if len(endpoints) >= 5000:
                            inventory.record_limit('endpoint_count')
                            break
                        route = match.group(1)
                        safe_route = self._safe_route(route)
                        if safe_route not in seen_endpoint_urls:
                            endpoints.append({"method": "UNKNOWN", "url": safe_route,
                                              "class_name": stem, "requires_auth": None,
                                              "evidence_type": "route_literal",
                                              "source_file": rel_path,
                                              "line_number": line_number})
                            seen_endpoint_urls.add(safe_route)
                        else:
                            deduplicated_endpoint_count += 1

                # Extract hardcoded URLs
                for match, line_number in self._matches_with_line_numbers(self.url_pattern, content):
                    url = match.group(0)
                    hostname = (urlsplit(url).hostname or "").lower()
                    host_labels = {part for part in re.split(r"[.-]+", hostname) if part}
                    environment_labels = {
                        "dev", "development", "stage", "staging", "test", "testing",
                        "qa", "internal", "sandbox", "preprod",
                    }
                    if host_labels & environment_labels:
                        if len(raw_findings) < 500:
                            raw_findings.append({
                            "type": "staging_url",
                                "url": self._safe_route(url),
                            "component": stem,
                            "file_path": rel_path,
                            "line_number": line_number
                            })
                        else:
                            inventory.record_limit('url_count')
                    elif (urlsplit(url).scheme.lower() == "http"
                          and hostname not in {"localhost", "127.0.0.1", "::1"}):
                        if len(raw_findings) < 500:
                            raw_findings.append({
                            "type": "cleartext_url",
                                "url": self._safe_route(url),
                            "component": stem,
                            "file_path": rel_path,
                            "line_number": line_number
                            })
                        else:
                            inventory.record_limit('http_url_candidate_count')

            except (OSError, UnicodeError) as e:
                logger.debug(f"Could not read file {file_path}: {e}")
                continue
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status='not_tested', proof_status='not_proven', exhaustive=False,
                             candidate_count=len(raw_findings), endpoints_count=len(endpoints),
                             deduplicated_endpoint_count=deduplicated_endpoint_count,
                             limits={**inventory.coverage['limits'], 'endpoints':5000,'findings':500})
        return endpoints, raw_findings

    async def map_apis(self, decompiled_path: str) -> tuple[list[dict], list[Finding]]:
        """Map API endpoints and identify API-related vulnerabilities."""
        logger.info(f"Starting API mapping in: {decompiled_path}")
        findings: list[Finding] = []
        if not isinstance(decompiled_path, (str, Path)) or not str(decompiled_path).strip():
            self.coverage = {
                "static_status": "not_analyzed", "runtime_status": "not_tested",
                "proof_status": "not_proven", "exhaustive": False,
                "candidate_count": 0, "endpoints_count": 0,
                "limits_reached": False, "limit_reasons": {},
            }
            return [], findings
        base_path = Path(decompiled_path)
        
        endpoints, raw_findings = await asyncio.to_thread(self._sync_map_apis, base_path)

        for item in raw_findings:
            if item["type"] == "sensitive_route_name":
                # A route name in a client does not demonstrate server-side
                # authorization behavior; keep this as an inventory lead.
                findings.append(Finding(
                    title=f"Review Sensitive-Looking Endpoint Path: {item['path']}",
                    description=f"Client source contains a path with a sensitive-looking name ('{item['path']}'). Names do not establish server-side privilege, authentication requirements or authorization failure; no request was sent.",
                    severity=Severity.INFO,
                    cwe_id="CWE-Unknown",
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=item["component"],
                    detection_method="APIMapper",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Ensure privileged endpoints enforce robust server-side RBAC and avoid hardcoding administrative routes in client binaries.",
                    file_path=item["file_path"], line_number=item.get("line_number")
                ))
            elif item["type"] == "staging_url":
                cwe = "CWE-489"
                findings.append(Finding(
                    title=f"Non-Production Staging/Dev Environment URL: {item['url']}",
                    description=f"Decompiled code contains a URL resembling a development/staging host ({item['url']}); build reachability, ownership, and non-production exposure are not established.",
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=item["component"],
                    detection_method="APIMapper",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Configure build variants (buildConfigField) to ensure non-production URLs are excluded from release packages.",
                    file_path=item["file_path"], line_number=item.get("line_number")
                ))
            elif item["type"] == "cleartext_url":
                cwe = "CWE-319"
                findings.append(Finding(
                    title=f"Hardcoded Cleartext HTTP URL: {item['url']}",
                    description=f"Code contains a literal HTTP URL ({item['url']}); runtime use, sensitive payloads, and effective platform cleartext policy were not tested.",
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=item["component"],
                    detection_method="APIMapper",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Migrate all network endpoints to HTTPS with modern TLS configurations.",
                    file_path=item["file_path"], line_number=item.get("line_number")
                ))

        logger.info(f"API mapping complete: {len(endpoints)} endpoints, {len(findings)} findings.")
        return endpoints, findings
