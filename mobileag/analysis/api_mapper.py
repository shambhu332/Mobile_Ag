import asyncio
import logging
import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)


def _mask_java_kotlin_comments(source: str) -> str:
    """Blank Java/Kotlin comments while preserving literals and line offsets."""
    chars = list(source)
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in "\r\n":
                chars[position] = " "

    index = 0
    while index < length:
        if source.startswith("//", index):
            end = index + 2
            while end < length and source[end] not in "\r\n":
                end += 1
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            index += 2
            depth = 1
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            blank(start, index)
            continue
        if source[index] in {'"', "'"}:
            quote = source[index]
            delimiter = quote * 3 if quote == '"' and source.startswith('"""', index) else quote
            index += len(delimiter)
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source.startswith(delimiter, index):
                    index += len(delimiter)
                    break
                else:
                    index += 1
            continue
        index += 1
    return "".join(chars)


def _mask_smali_comments(source: str) -> str:
    """Blank Smali # comments without touching quoted string constants."""
    chars = list(source)
    index = 0
    while index < len(source):
        if source[index] == '"':
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            continue
        if source[index] == "#":
            end = index + 1
            while end < len(source) and source[end] not in "\r\n":
                end += 1
            for position in range(index, end):
                chars[position] = " "
            index = end
            continue
        index += 1
    return "".join(chars)


def _mask_xml_comments(source: str) -> tuple[str, bool]:
    """Blank XML comments while preserving CDATA and source line offsets."""
    chars = list(source)
    index = 0
    malformed = False
    while index < len(source):
        if source.startswith("<![CDATA[", index):
            end = source.find("]]>", index + 9)
            if end < 0:
                malformed = True
                break
            index = end + 3
            continue
        if source.startswith("<!--", index):
            end = source.find("-->", index + 4)
            if end < 0:
                end = len(source)
                malformed = True
            else:
                end += 3
            for position in range(index, end):
                if chars[position] not in "\r\n":
                    chars[position] = " "
            index = end
            continue
        index += 1
    return "".join(chars), malformed


class APIMapper:
    """Agent for extracting API endpoints and identifying associated security issues."""

    def __init__(self, router: LLMRouter):
        """Initialize the API mapper with an LLM router."""
        self.router = router
        self.retrofit_pattern = re.compile(
            r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"]+)"\s*\)'
        )
        self.retrofit_http_start = re.compile(r"@HTTP\b")
        self.retrofit_http_method = re.compile(r'\bmethod\s*=\s*"([A-Z]+)"')
        self.retrofit_http_path = re.compile(r'\bpath\s*=\s*"([^"]+)"')
        self.MAX_RETROFIT_HTTP_ANNOTATION_CHARS = 4096
        self.url_pattern = re.compile(
            r'https?://(?:\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.-]+)'
            r'(?::\d+)?(?:/[a-zA-Z0-9._/?%&=+-]*)?', re.IGNORECASE
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
            opaque_id = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~-]{24,}$")
            short_mixed_case_id = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{8,23}$")
            uuid = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            email = re.compile(r"^[^/@\s]{1,64}@[^/@\s]+\.[^/@\s]+$")
            sensitive_segments = {
                "token", "access_token", "auth_token", "session", "sessionid",
                "session_id", "jwt", "reset", "verify", "password", "secret", "key",
                "api_key", "client_secret", "secret_key", "auth",
            }
            for segment in segments:
                decoded_segment = unquote(segment)
                if (redact_next or len(segment) > 128 or segment.isdigit()
                        or uuid.fullmatch(segment) or email.fullmatch(segment)
                        or opaque_id.fullmatch(segment) or opaque_id.fullmatch(decoded_segment)
                        or short_mixed_case_id.fullmatch(segment)
                        or short_mixed_case_id.fullmatch(decoded_segment)):
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

    def _retrofit_declarations(self, content: str, diagnostics: dict[str, int]):
        """Yield literal Retrofit declarations with bounded @HTTP parsing.

        The general annotation scanner advances past a bounded annotation span
        instead of running a backtracking expression from every @HTTP marker.
        This keeps malformed/decompiled source from causing quadratic scans.
        """
        for match, line_number in self._matches_with_line_numbers(self.retrofit_pattern, content):
            method, path = match.groups()
            yield method, path, line_number, False

        cursor = 0
        line_at_cursor = 1
        content_length = len(content)
        max_chars = self.MAX_RETROFIT_HTTP_ANNOTATION_CHARS
        while True:
            start_match = self.retrofit_http_start.search(content, cursor)
            if start_match is None:
                return
            start = start_match.start()
            start_line = line_at_cursor + content.count("\n", cursor, start)
            position = start_match.end()
            while position < content_length and content[position].isspace() and position - start <= 64:
                position += 1
            if position >= content_length or content[position] != "(":
                new_cursor = start_match.end()
                line_at_cursor += content.count("\n", cursor, new_cursor)
                cursor = new_cursor
                continue

            body_start = position + 1
            scan_limit = min(content_length, body_start + max_chars)
            depth = 1
            quote_char = ""
            escaped = False
            close = None
            for index in range(body_start, scan_limit):
                char = content[index]
                if quote_char:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote_char:
                        quote_char = ""
                    continue
                if char in {'"', "'"}:
                    quote_char = char
                elif char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        close = index
                        break

            if close is None:
                diagnostics["oversized_or_unclosed"] += 1
                new_cursor = scan_limit
            else:
                body = content[body_start:close]
                method_match = self.retrofit_http_method.search(body)
                path_match = self.retrofit_http_path.search(body)
                if method_match is None or path_match is None:
                    diagnostics["unmodeled"] += 1
                else:
                    yield method_match.group(1), path_match.group(1), start_line, True
                new_cursor = close + 1

            line_at_cursor += content.count("\n", cursor, new_cursor)
            cursor = new_cursor

    def _sync_map_apis(self, base_path: Path) -> tuple[list[dict], list[dict]]:
        """Synchronously scan source files for API definitions and URL references."""
        endpoints: list[dict] = []
        raw_findings: list[dict] = []
        seen_endpoint_urls: set[str] = set()
        deduplicated_endpoint_count = 0
        http_diagnostics = {"unmodeled": 0, "oversized_or_unclosed": 0}
        malformed_xml_comment_files = 0

        inventory = SourceInventory()
        for file_path, data in inventory.read(
                base_path, {".java", ".kt", ".smali", ".xml", ".json", ".js", ".mjs", ".dart"}):
            try:
                content = data.decode("utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                stem = file_path.stem
                if file_path.suffix.lower() in {".java", ".kt"}:
                    content = _mask_java_kotlin_comments(content)
                elif file_path.suffix.lower() == ".smali":
                    content = _mask_smali_comments(content)
                elif file_path.suffix.lower() == ".xml":
                    content, malformed_xml = _mask_xml_comments(content)
                    malformed_xml_comment_files += int(malformed_xml)
                
                # Extract literal Retrofit verb/path declarations. @HTTP is
                # parsed with a bounded quote-aware scanner to avoid repeated
                # long regex searches on malformed inputs.
                for method, path, line_number, is_http_annotation in self._retrofit_declarations(
                        content, http_diagnostics):
                    if len(endpoints) >= 5000:
                        inventory.record_limit('endpoint_count')
                        break
                    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
                                       "OPTIONS", "TRACE", "CONNECT"}:
                        if is_http_annotation:
                            http_diagnostics["unmodeled"] += 1
                        continue
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

                # Route-shaped literals are useful in Java/Kotlin too, where
                # they may be assembled outside Retrofit. Keep these as
                # UNKNOWN-method inventory candidates and deduplicate paths
                # already emitted from Retrofit declarations.
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
                # Source may serialize URLs with JSON/JavaScript escaped
                # slashes. Normalize only this local scan copy; line numbers
                # are unchanged because the replacement does not touch newlines.
                url_scan_content = content.replace("\\/", "/")
                for match, line_number in self._matches_with_line_numbers(self.url_pattern, url_scan_content):
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
                             unmodeled_retrofit_http_annotations=http_diagnostics["unmodeled"],
                             oversized_or_unclosed_retrofit_http_annotations=http_diagnostics[
                                 "oversized_or_unclosed"],
                             malformed_xml_comment_files=malformed_xml_comment_files,
                             limits={**inventory.coverage['limits'], 'endpoints':5000,'findings':500})
        if http_diagnostics["unmodeled"]:
            self.coverage["static_status"] = "partial"
            self.coverage.setdefault("limitations", []).append(
                "one or more Retrofit @HTTP declarations had non-literal or unsupported method/path values")
        if http_diagnostics["oversized_or_unclosed"]:
            self.coverage["static_status"] = "partial"
            self.coverage["limits_reached"] = True
            self.coverage.setdefault("limit_reasons", {})[
                "retrofit_http_annotation_chars"] = http_diagnostics["oversized_or_unclosed"]
        if malformed_xml_comment_files:
            self.coverage["static_status"] = "partial"
            self.coverage.setdefault("limitations", []).append(
                "one or more XML source files had an unclosed comment or CDATA section")
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
