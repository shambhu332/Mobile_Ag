"""Dynamic Mobile API Cataloger & OpenAPI 3.0 Exporter.

Aggregates intercepted HTTP/HTTPS traffic from mobile apps, discovers REST/GraphQL endpoints,
identifies shadow APIs, and synthesizes standard OpenAPI 3.0 specifications.
"""
from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from openapi_spec_validator import validate as validate_openapi_spec


_DYNAMIC_JSON_KEY_PATTERNS = (
    re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    re.compile(r"^[A-Za-z0-9_-]{24,}$"),
    re.compile(r"^[0-9]{5,}$"),
    re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$"),
    re.compile(r"^[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
)


def _looks_like_dynamic_json_key(value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in _DYNAMIC_JSON_KEY_PATTERNS)


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    response_status: int = 200
    response_body: Optional[str] = None


class MobileApiCataloger:
    """Catalogs mobile HTTP traffic into structured endpoints and OpenAPI specs."""

    def __init__(self, title: str = "Mobile App Backend APIs", version: str = "1.0.0"):
        self.title = title
        self.version = version
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.captured_requests: List[CapturedRequest] = []
        self.omitted_requests = 0
        self.unmodeled_requests = 0

    @staticmethod
    def _path_template(path: str) -> str:
        """Replace obvious opaque path identifiers without retaining sample values."""
        uuid_segment = re.compile(
            r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        # Redact token-shaped opaque IDs in exported route templates. This
        # deliberately errs on the side of parametrizing long mixed strings;
        # shorter or non-token-shaped identifiers remain unsupported.
        opaque_token_segment = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{24,}$")
        email_segment = re.compile(r"^[^/@\s]{1,64}@[^/@\s]+\.[^/@\s]+$")
        segments = path.split("/")
        identifier_index = 0
        for index, segment in enumerate(segments):
            if (re.fullmatch(r"\d+", segment) or uuid_segment.fullmatch(segment)
                    or opaque_token_segment.fullmatch(segment) or email_segment.fullmatch(segment)):
                identifier_index += 1
                segments[index] = f"{{id{identifier_index}}}"
        return "/".join(segments) or "/"

    @staticmethod
    def _json_schema(value: Any, depth: int = 0) -> Dict[str, Any]:
        """Infer a bounded shape only; never copy captured values to OpenAPI."""
        if depth >= 6:
            return {}
        if isinstance(value, dict):
            properties = {}
            redacted_dynamic_keys = False
            for key, item in list(value.items())[:100]:
                if isinstance(key, str) and len(key) <= 128:
                    if _looks_like_dynamic_json_key(key):
                        redacted_dynamic_keys = True
                        continue
                    properties[key] = MobileApiCataloger._json_schema(item, depth + 1)
            result: Dict[str, Any] = {"type": "object", "properties": properties,
                                      "additionalProperties": True}
            if len(value) > 100:
                result["x-mobileag-truncated-properties"] = True
            if redacted_dynamic_keys:
                result["x-mobileag-redacted-dynamic-keys"] = True
            return result
        if isinstance(value, list):
            schemas = [MobileApiCataloger._json_schema(item, depth + 1) for item in value[:12]]
            unique = {json.dumps(s, sort_keys=True) for s in schemas if s}
            item_schemas = [json.loads(s) for s in sorted(unique)]
            items = item_schemas[0] if len(item_schemas) == 1 else (
                {"oneOf": item_schemas} if item_schemas else {})
            return {"type": "array", "items": items}
        if value is None:
            return {"nullable": True}
        if isinstance(value, bool):
            return {"type": "boolean"}
        if isinstance(value, int):
            return {"type": "integer"}
        if isinstance(value, float):
            return {"type": "number"}
        if isinstance(value, str):
            return {"type": "string"}
        return {}

    @staticmethod
    def _parse_json_schema(body: Optional[str]) -> Optional[Dict[str, Any]]:
        if not isinstance(body, str) or len(body.encode("utf-8", errors="replace")) > 1024 * 1024:
            return None
        try:
            return MobileApiCataloger._json_schema(json.loads(body))
        except (ValueError, TypeError, RecursionError):
            return None

    @staticmethod
    def _merge_schemas(left: Optional[Dict[str, Any]], right: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if left is None:
            return right
        if right is None or left == right:
            return left
        if left.get("type") == right.get("type") == "object":
            properties = dict(left.get("properties", {}))
            for key, schema in right.get("properties", {}).items():
                properties[key] = MobileApiCataloger._merge_schemas(properties.get(key), schema)
            return {"type": "object", "properties": properties, "additionalProperties": True}
        variants = {}
        for schema in (left, right):
            for option in schema.get("oneOf", [schema]):
                variants[json.dumps(option, sort_keys=True)] = option
        return {"oneOf": [variants[key] for key in sorted(variants)]}

    def ingest_request(self, req: CapturedRequest) -> None:
        """Process and index an intercepted request."""
        if len(self.captured_requests) >= 10000:
            self.omitted_requests += 1
            return
        self.captured_requests.append(req)
        parsed = urlparse(req.url)
        path = self._path_template(parsed.path or "/")
        method = req.method.lower()
        if method not in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
            self.unmodeled_requests += 1
            return
        # Keep a normalized origin so same-path APIs on different hosts are
        # not silently collapsed. urlparse().netloc may contain userinfo; do
        # not export it.
        try:
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            hostname, port = None, None
        if parsed.scheme and hostname:
            host_literal = hostname
            try:
                ipaddress.IPv6Address(hostname.split("%", 1)[0])
                host_literal = f"[{hostname}]"
            except ValueError:
                pass
            server_url = f"{parsed.scheme}://{host_literal}"
        else:
            server_url = ""
        if port is not None:
            server_url += f":{port}"

        query_names = set(req.query_params)
        query_names.update(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        query_signature = tuple(sorted(name for name in query_names if isinstance(name, str)))
        key = f"{method}:{server_url}:{path}:{json.dumps(query_signature)}"
        if key not in self.endpoints:
            self.endpoints[key] = {
                "method": method,
                "path": path,
                "host": server_url,
                "headers": list(req.headers.keys()),
                "query_params": list(query_signature),
                "sample_statuses": [req.response_status],
                "has_body": req.body is not None,
                "request_schema": self._parse_json_schema(req.body),
                "response_schemas": {str(req.response_status): self._parse_json_schema(req.response_body)},
            }
        else:
            entry = self.endpoints[key]
            if req.response_status not in entry["sample_statuses"]:
                entry["sample_statuses"].append(req.response_status)
            entry["headers"] = sorted(set(entry["headers"]) | set(req.headers))
            entry["query_params"] = sorted(set(entry["query_params"]) | set(query_signature))
            entry["has_body"] = entry["has_body"] or req.body is not None
            entry["request_schema"] = self._merge_schemas(
                entry.get("request_schema"), self._parse_json_schema(req.body))
            status = str(req.response_status)
            entry.setdefault("response_schemas", {})[status] = self._merge_schemas(
                entry.get("response_schemas", {}).get(status), self._parse_json_schema(req.response_body))

    def export_openapi_json(self) -> Dict[str, Any]:
        """Convert cataloged endpoints into an OpenAPI 3.0 schema dictionary."""
        paths: Dict[str, Any] = {}

        for entry in self.endpoints.values():
            path_str = entry["path"]
            method_str = entry["method"]

            if path_str not in paths:
                paths[path_str] = {}

            parameters = []
            for path_parameter in re.findall(r"\{([^{}]+)\}", path_str):
                parameters.append({
                    "name": path_parameter,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                })
            for q in entry["query_params"]:
                parameters.append({
                    "name": q,
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string"},
                })

            operation = {
                "summary": f"Automated capture for {method_str.upper()} {path_str}",
                "parameters": parameters,
                "responses": {},
                "x-mobileag-inferred-from-capture": True,
            }
            for status in entry["sample_statuses"]:
                response: Dict[str, Any] = {"description": f"Observed response HTTP {status}"}
                schema = entry.get("response_schemas", {}).get(str(status))
                if schema:
                    response["content"] = {"application/json": {"schema": schema}}
                operation["responses"][str(status)] = response
            if entry.get("request_schema"):
                operation["requestBody"] = {
                    "required": False,
                    "content": {"application/json": {"schema": entry["request_schema"]}},
                }
            if entry.get("host"):
                operation["servers"] = [{"url": entry["host"]}]
            existing = paths[path_str].get(method_str)
            if existing is None:
                paths[path_str][method_str] = operation
            else:
                existing["parameters"] = list({
                    (p["name"], p["in"]): p
                    for p in existing["parameters"] + operation["parameters"]
                }.values())
                for status, response in operation["responses"].items():
                    prior = existing["responses"].get(status)
                    if prior and prior.get("content") and response.get("content"):
                        old_schema = prior["content"]["application/json"]["schema"]
                        new_schema = response["content"]["application/json"]["schema"]
                        prior["content"]["application/json"]["schema"] = self._merge_schemas(old_schema, new_schema)
                    else:
                        existing["responses"][status] = response
                if operation.get("requestBody"):
                    prior = existing.get("requestBody")
                    if prior:
                        old_schema = prior["content"]["application/json"]["schema"]
                        new_schema = operation["requestBody"]["content"]["application/json"]["schema"]
                        prior["content"]["application/json"]["schema"] = self._merge_schemas(old_schema, new_schema)
                    else:
                        existing["requestBody"] = operation["requestBody"]
                servers = {item["url"] for item in existing.get("servers", [])}
                servers.update(item["url"] for item in operation.get("servers", []))
                if servers:
                    existing["servers"] = [{"url": server} for server in sorted(servers)]

        document = {
            "openapi": "3.0.0",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": "Auto-generated by MobileAg Dynamic Traffic Auditor",
            },
            "paths": paths,
            "x-mobileag-capture-limits": {
                "maxRequests": 10000,
                "omittedRequests": self.omitted_requests,
                "unmodeledRequests": self.unmodeled_requests,
            },
        }
        # Do not silently emit a document that fails the normative OpenAPI
        # validator. Validation is local/offline and does not establish that
        # the inferred inventory is complete or reflects a server contract.
        validate_openapi_spec(document)
        return document

    def save_openapi(self, output_path: str) -> None:
        """Save OpenAPI specification to disk."""
        data = self.export_openapi_json()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def export_har_json(self) -> Dict[str, Any]:
        """Convert captured HTTP transactions into HAR 1.2 format."""
        from datetime import datetime, timezone
        from mobileag.security.privacy import redact

        entries = []
        for req in self.captured_requests:
            safe_headers = redact(req.headers)
            req_headers = [{"name": k, "value": str(v)} for k, v in safe_headers.items()]
            safe_query = redact(req.query_params)
            query_strings = [{"name": k, "value": str(v)} for k, v in safe_query.items()]
            safe_body = redact(req.body) if req.body is not None else None
            safe_response_body = redact(req.response_body) if req.response_body is not None else None

            post_data = None
            if safe_body is not None:
                content_type = req.headers.get("Content-Type", req.headers.get("content-type", "application/octet-stream"))
                post_data = {
                    "mimeType": content_type,
                    "text": safe_body,
                }

            res_content: Dict[str, Any] = {
                "size": len(safe_response_body.encode("utf-8")) if safe_response_body else 0,
                "mimeType": "application/json",
            }
            if safe_response_body is not None:
                res_content["text"] = safe_response_body

            entry: Dict[str, Any] = {
                "startedDateTime": datetime.now(timezone.utc).isoformat(),
                "time": 20,
                "request": {
                    "method": req.method.upper(),
                    "url": redact(req.url),
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": req_headers,
                    "queryString": query_strings,
                    "headersSize": -1,
                    "bodySize": len(safe_body.encode("utf-8")) if safe_body else 0,
                },
                "response": {
                    "status": req.response_status,
                    "statusText": "OK" if req.response_status < 400 else "Error",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "content": res_content,
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": res_content["size"],
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": 20,
                    "receive": 0,
                },
            }
            if post_data:
                entry["request"]["postData"] = post_data

            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "MobileAg Dynamic Traffic Auditor",
                    "version": self.version,
                },
                "pages": [],
                "entries": entries,
            }
        }

    def save_har(self, output_path: str) -> None:
        """Save captured traffic to HAR 1.2 JSON file."""
        data = self.export_har_json()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

