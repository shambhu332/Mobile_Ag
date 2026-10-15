"""Dynamic Mobile API Cataloger & OpenAPI 3.0 Exporter.

Aggregates intercepted HTTP/HTTPS traffic from mobile apps, discovers REST/GraphQL endpoints,
identifies shadow APIs, and synthesizes standard OpenAPI 3.0 specifications.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


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
    def _json_schema(value: Any, depth: int = 0) -> Dict[str, Any]:
        """Infer a bounded shape only; never copy captured values to OpenAPI."""
        if depth >= 6:
            return {}
        if isinstance(value, dict):
            properties = {}
            for key, item in list(value.items())[:100]:
                if isinstance(key, str) and len(key) <= 128:
                    properties[key] = MobileApiCataloger._json_schema(item, depth + 1)
            result: Dict[str, Any] = {"type": "object", "properties": properties,
                                      "additionalProperties": True}
            if len(value) > 100:
                result["x-mobileag-truncated-properties"] = True
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
        path = parsed.path or "/"
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
        server_url = f"{parsed.scheme}://{hostname}" if parsed.scheme and hostname else ""
        if port is not None:
            server_url += f":{port}"

        key = f"{method}:{server_url}:{path}"
        if key not in self.endpoints:
            self.endpoints[key] = {
                "method": method,
                "path": path,
                "host": server_url,
                "headers": list(req.headers.keys()),
                "query_params": list(req.query_params.keys()),
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
            entry["query_params"] = sorted(set(entry["query_params"]) | set(req.query_params))
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

        return {
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

