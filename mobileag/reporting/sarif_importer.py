"""Full-schema-validated, bounded, untrusted SARIF import projection.

The vendored OASIS SARIF v2.1.0 schema is applied offline before projecting a
small result subset. Imported results remain UNVERIFIED, and producer-supplied
properties/evidence are never trusted.
"""
from __future__ import annotations

import json
import hashlib
import math
from functools import lru_cache
from importlib import resources
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.security.privacy import redact

MAX_BYTES = 5 * 1024 * 1024
MAX_RUNS = 20
MAX_RESULTS = 5000
MAX_RULES = 1000
MAX_TEXT = 16_384
_SCHEMA_RESOURCE = "sarif-schema-2.1.0.json"


class SarifImportError(ValueError):
    """Rejected SARIF input with a safe, non-echoing diagnostic."""


@lru_cache(maxsize=1)
def _sarif_validator():
    """Load the vendored OASIS schema; never resolve schema URLs at runtime."""
    try:
        import jsonschema
        schema_resource = resources.files("mobileag").joinpath("data", _SCHEMA_RESOURCE)
        schema = json.loads(schema_resource.read_text(encoding="utf-8"))
        jsonschema.Draft7Validator.check_schema(schema)
        return jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
    except Exception:
        # A missing/corrupt bundled schema must block imports rather than silently
        # falling back to the former restricted hand-written projection checks.
        raise SarifImportError("The bundled SARIF schema is unavailable or invalid") from None


def _preflight_sarif_limits(document: dict[str, Any]) -> None:
    runs = document.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_RUNS:
        raise SarifImportError("SARIF must contain a bounded nonempty runs array")
    total_results = 0
    for run in runs:
        if not isinstance(run, dict):
            raise SarifImportError("SARIF run entry must be an object")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        rules = driver.get("rules", []) if isinstance(driver, dict) else []
        results = run.get("results", [])
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise SarifImportError("SARIF rule inventory exceeds limits")
        if not isinstance(results, list):
            raise SarifImportError("SARIF results must be an array")
        total_results += len(results)
        if total_results > MAX_RESULTS:
            raise SarifImportError("SARIF result inventory exceeds limits")
    try:
        first_error = next(_sarif_validator().iter_errors(document), None)
    except SarifImportError:
        raise
    except Exception:
        raise SarifImportError("SARIF schema validation failed") from None
    if first_error is not None:
        # Do not return schema-library messages; they may reproduce hostile input.
        raise SarifImportError("SARIF document does not conform to the OASIS 2.1.0 schema")


def validate_sarif_document(document: dict[str, Any]) -> None:
    """Validate a generated SARIF object against local limits and bundled schema."""
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise SarifImportError("Only SARIF version 2.1.0 is accepted")
    _bounded_object_size(document, [MAX_BYTES], set())
    _preflight_sarif_limits(document)


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _safe_relative_uri(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return ""
    candidate = value.replace("\\", "/")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return ""
    path = PurePosixPath(parsed.path)
    if (parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "\x00" in candidate
            or candidate.startswith("/") or any(part in {".", ".."} for part in path.parts)):
        return ""
    return candidate


def _bounded_object_size(value: Any, remaining: list[int], seen: set[int], depth: int = 0) -> int:
    """Preflight programmatic objects without serializing unbounded/cyclic data."""
    if depth > 64:
        raise SarifImportError("SARIF object nesting exceeds the import limit")
    if isinstance(value, str):
        try:
            size = len(value.encode("utf-8")) * 6 + 2
        except UnicodeEncodeError:
            raise SarifImportError("SARIF object contains invalid Unicode") from None
    elif value is None or isinstance(value, bool):
        size = 5
    elif isinstance(value, int):
        size = (abs(value).bit_length() * 30103) // 100000 + 2
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise SarifImportError("SARIF object is not finite JSON data")
        size = 32
    elif isinstance(value, (list, dict)):
        identity = id(value)
        if identity in seen:
            raise SarifImportError("SARIF object contains a cycle")
        seen.add(identity)
        if len(value) > 100_000:
            raise SarifImportError("SARIF object exceeds the import item limit")
        items = list(value.items()) if isinstance(value, dict) else value
        size = 2 + len(items)
        remaining[0] -= size
        if remaining[0] < 0:
            raise SarifImportError("SARIF input exceeds the import size limit")
        if isinstance(value, dict):
            for key, child in items:
                if not isinstance(key, str):
                    raise SarifImportError("SARIF object keys must be strings")
                size += _bounded_object_size(key, remaining, seen, depth + 1)
                size += _bounded_object_size(child, remaining, seen, depth + 1)
        else:
            for child in items:
                size += _bounded_object_size(child, remaining, seen, depth + 1)
        seen.remove(identity)
    else:
        raise SarifImportError("SARIF object contains a non-JSON value")
    if not isinstance(value, (list, dict)):
        remaining[0] -= size
        if remaining[0] < 0:
            raise SarifImportError("SARIF input exceeds the import size limit")
    return size


def import_sarif(value: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Import bounded SARIF results as explicitly untrusted MobileAg candidates."""
    if isinstance(value, dict):
        _bounded_object_size(value, [MAX_BYTES], set())
        raw_size = 0
        document = value
        source_bytes = json.dumps(value, ensure_ascii=True, allow_nan=False,
                                  sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        raw = value.encode("utf-8") if isinstance(value, str) else value
        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
            raise SarifImportError("SARIF input exceeds the import size limit")
        raw_size = len(raw)
        source_bytes = raw
        try:
            def unique_object(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON key")
                    result[key] = item
                return result
            document = json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid constant")))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise SarifImportError("SARIF input is not valid bounded JSON") from None
    if raw_size > MAX_BYTES:
        raise SarifImportError("SARIF input exceeds the import size limit")
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise SarifImportError("Only SARIF version 2.1.0 is accepted")
    _preflight_sarif_limits(document)
    runs = document.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_RUNS:
        raise SarifImportError("SARIF must contain a bounded nonempty runs array")

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    duplicates = 0
    dropped = 0
    total_results = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise SarifImportError("SARIF run entry must be an object")
        tool = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        if not isinstance(tool, dict):
            tool = {}
        tool_name = _text(tool.get("name"), 256) or "unknown"
        tool_version = _text(tool.get("version"), 128) or "unknown"
        rules = tool.get("rules", [])
        results = run.get("results", [])
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise SarifImportError("SARIF rule inventory exceeds limits")
        if not isinstance(results, list):
            raise SarifImportError("SARIF results must be an array")
        total_results += len(results)
        if total_results > MAX_RESULTS:
            raise SarifImportError("SARIF result inventory exceeds limits")
        rules_by_id = {item.get("id"): item for item in rules if isinstance(item, dict) and isinstance(item.get("id"), str)}
        for result in results:
            if not isinstance(result, dict):
                dropped += 1
                continue
            kind = result.get("kind")
            if isinstance(kind, str) and kind in {"pass", "notApplicable", "open"}:
                dropped += 1
                continue
            rule_id = _text(result.get("ruleId"), 256) or "SARIF-Unknown"
            rule = rules_by_id.get(rule_id, {})
            title = _text(rule.get("name")) or _text(rule.get("shortDescription", {}).get("text") if isinstance(rule.get("shortDescription"), dict) else "") or rule_id
            message_obj = result.get("message", {})
            description = _text(message_obj.get("text") if isinstance(message_obj, dict) else message_obj) or "Imported SARIF result; original details unavailable."
            level = result.get("level") if isinstance(result.get("level"), str) else ""
            severity = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.INFO}.get(level, Severity.INFO)
            file_path = ""
            line_number = None
            locations = result.get("locations", [])
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {})
                if isinstance(physical, dict):
                    artifact_location = physical.get("artifactLocation", {})
                    if isinstance(artifact_location, dict):
                        file_path = _safe_relative_uri(artifact_location.get("uri"))
                    region = physical.get("region", {})
                    if isinstance(region, dict) and type(region.get("startLine")) is int and region["startLine"] > 0:
                        line_number = region["startLine"]
            if locations and not file_path:
                dropped += 1
                continue
            key = (rule_id, file_path, line_number)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            properties = result.get("properties", {})
            imported_cwe = _text(properties.get("cwe") if isinstance(properties, dict) else "", 64)
            cwe_id = imported_cwe if imported_cwe.startswith("CWE-") else "CWE-Unknown"
            snippet = ""
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {})
                region = physical.get("region", {}) if isinstance(physical, dict) else {}
                snippet_obj = region.get("snippet", {}) if isinstance(region, dict) else {}
                snippet = _text(snippet_obj.get("text") if isinstance(snippet_obj, dict) else "", 4096)
            finding = Finding(
                title=title,
                description=description,
                severity=severity,
                cwe_id=cwe_id,
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet,
                detection_method="SARIFImport",
                status=FindingStatus.UNVERIFIED,
                metadata={"proof_state": "not_proven", "import": {
                    "format": "SARIF", "version": "2.1.0", "tool_name": tool_name,
                    "tool_version": tool_version, "run_index": run_index,
                    "source_sha256": source_sha256,
                    "source_trust": "untrusted_external_result",
                    "producer_properties_ignored": True,
                }},
            )
            findings.append(finding.model_dump(mode="json"))
    return redact({
        "schema_version": 1,
        "source_format": "SARIF 2.1.0",
        "source_sha256": source_sha256,
        "source_trust": "untrusted_external_results",
        "results_seen": total_results,
        "imported_candidates": len(findings),
        "duplicates_skipped": duplicates,
        "invalid_or_nonfinding_results_skipped": dropped,
        "findings": findings,
        "limitations": ["Imported results are UNVERIFIED and do not constitute MobileAg validation.",
                        "Full schema validation does not expand the bounded projection; producer properties and evidence are ignored.",
                        "SARIF status, severity, CWE, and location are external claims requiring review."],
    })
