"""Bounded, offline projection of a small MobSF Android static-report subset.

MobSF JSON is an external assertion, not MobileAg analysis evidence. This
adapter recognizes only code-analysis rule findings and manifest findings;
unknown report sections and producer claims are not promoted to verification.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any
from urllib.parse import urlsplit

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.security.privacy import redact

MAX_BYTES = 5 * 1024 * 1024
MAX_FINDINGS = 5000
MAX_TEXT = 16_384
MAX_RULES = 5000
MAX_LOCATION_ENTRIES = 20_000
_CWE = re.compile(r"^CWE-[0-9]{1,6}$")


class MobSFImportError(ValueError):
    """Rejected MobSF JSON input with non-echoing diagnostics."""


def _preflight_object(value: Any) -> int:
    """Bound programmatic JSON trees before canonical serialization."""
    remaining = [100_000]
    estimated = 0
    stack = [(value, 0)]
    seen: set[int] = set()
    while stack:
        item, depth = stack.pop()
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 64:
            raise MobSFImportError("MobSF report exceeds nesting or item limits")
        if isinstance(item, str):
            try:
                estimated += len(item.encode("utf-8")) + 2
            except UnicodeEncodeError:
                raise MobSFImportError("MobSF report contains invalid Unicode") from None
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            if isinstance(item, float) and not math.isfinite(item):
                raise MobSFImportError("MobSF report contains a non-finite number")
            estimated += ((abs(item).bit_length() * 30103) // 100000 + 2) if isinstance(item, int) else 32
        elif item is None or isinstance(item, bool):
            estimated += 5
        elif isinstance(item, dict):
            identity = id(item)
            if identity in seen:
                raise MobSFImportError("MobSF report object is cyclic or shared")
            seen.add(identity)
            estimated += 2 + len(item)
            for key, child in item.items():
                if not isinstance(key, str):
                    raise MobSFImportError("MobSF report object keys must be strings")
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            identity = id(item)
            if identity in seen:
                raise MobSFImportError("MobSF report object is cyclic or shared")
            seen.add(identity)
            estimated += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        else:
            raise MobSFImportError("MobSF report contains a non-JSON value")
        if estimated > MAX_BYTES:
            raise MobSFImportError("MobSF report exceeds the import size limit")
    return estimated


def _safe_text(value: Any, limit: int = MAX_TEXT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _safe_source_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    candidate = value.replace("\\", "/")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    raw_parts = candidate.split("/")
    if (parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
            or candidate.startswith("/") or re.match(r"^[A-Za-z]:", candidate)
            or "\x00" in candidate or any(part in {"", ".", ".."} for part in raw_parts)):
        return None
    return candidate


def _loads_bounded(value: str | bytes | dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, dict):
        _preflight_object(value)
        try:
            raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise MobSFImportError("MobSF report object is not bounded JSON data") from None
        if len(raw) > MAX_BYTES:
            raise MobSFImportError("MobSF report exceeds the import size limit")
        document = value
    else:
        raw = value.encode("utf-8") if isinstance(value, str) else value
        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
            raise MobSFImportError("MobSF report exceeds the import size limit")

        def unique_object(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result
        try:
            document = json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid constant")))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise MobSFImportError("MobSF input is not valid bounded JSON") from None
    if not isinstance(document, dict):
        raise MobSFImportError("MobSF report must be a JSON object")
    # Bound parsed JSON expansion before projection and reject numeric overflow.
    _preflight_object(document)
    return document, raw


def _severity(value: Any) -> Severity:
    if not isinstance(value, str):
        return Severity.INFO
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "warning": Severity.MEDIUM,
            "low": Severity.LOW}.get(value.strip().lower(), Severity.INFO)


def import_mobsf_json(value: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Project recognized MobSF Android static findings into unverified records."""
    document, raw = _loads_bounded(value)
    code_analysis = document.get("code_analysis")
    manifest_analysis = document.get("manifest_analysis")
    if not isinstance(code_analysis, dict) and not isinstance(manifest_analysis, dict):
        raise MobSFImportError("MobSF report has no recognized Android static-analysis sections")
    code_findings = code_analysis.get("findings", {}) if isinstance(code_analysis, dict) else {}
    manifest_findings = manifest_analysis.get("manifest_findings", []) if isinstance(manifest_analysis, dict) else []
    if not isinstance(code_findings, dict) or not isinstance(manifest_findings, list):
        raise MobSFImportError("MobSF static finding sections have unsupported shapes")
    if len(code_findings) > MAX_RULES or len(manifest_findings) > MAX_FINDINGS:
        raise MobSFImportError("MobSF finding inventory exceeds import limits")
    source_sha256 = hashlib.sha256(raw).hexdigest()
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    duplicates = dropped = locations_omitted = 0
    location_entries_projected = 0
    location_inventory_truncated = False

    def append_candidate(rule: str, title: str, description: str, severity: Any,
                         cwe: Any, path: str | None, line: int | None,
                         category: str, source_version: str) -> None:
        nonlocal duplicates, dropped
        if len(findings) >= MAX_FINDINGS:
            dropped += 1
            return
        rule = _safe_text(rule, 256) or "MobSF-Unknown"
        title = _safe_text(title, 512) or rule
        description = _safe_text(description) or "Imported MobSF result; original details unavailable."
        cwe_id = cwe if isinstance(cwe, str) and _CWE.fullmatch(cwe) else "CWE-Unknown"
        key = (rule, path or "", line)
        if key in seen:
            duplicates += 1
            return
        seen.add(key)
        finding = Finding(
            title=title, description=description, severity=_severity(severity),
            cwe_id=cwe_id, file_path=path or "", line_number=line, confidence=0.0,
            detection_method="MobSFImport", status=FindingStatus.UNVERIFIED,
            metadata={"proof_state": "not_proven", "import": {
                "format": "MobSF Android static JSON subset", "rule_id": rule,
                "category": category, "producer_version": source_version,
                "source_sha256": source_sha256,
                "source_trust": "untrusted_external_result",
                "producer_evidence_ignored": True,
            }},
        )
        findings.append(finding.model_dump(mode="json"))

    producer_version = _safe_text(document.get("mobsf_version"), 128) or "not_recorded"
    for rule_id, details in code_findings.items():
        if not isinstance(rule_id, str) or not isinstance(details, dict):
            dropped += 1
            continue
        metadata = details.get("metadata")
        if not isinstance(metadata, dict):
            dropped += 1
            continue
        severity_claim = metadata.get("severity")
        if isinstance(severity_claim, str) and severity_claim.strip().lower() in {"good", "secure", "suppressed"}:
            dropped += 1
            continue
        files = details.get("files", {})
        if not isinstance(files, dict):
            files = {}
        locations = []
        for file_index, (path_value, lines) in enumerate(files.items()):
            if file_index >= 100 or location_entries_projected >= MAX_LOCATION_ENTRIES:
                location_inventory_truncated = True
                break
            path = _safe_source_path(path_value)
            if path is None or not isinstance(lines, list):
                locations_omitted += 1
                continue
            for line in lines[:100]:
                if location_entries_projected >= MAX_LOCATION_ENTRIES:
                    location_inventory_truncated = True
                    break
                location_entries_projected += 1
                if type(line) is int and 1 <= line <= 10_000_000:
                    locations.append((path, line))
                else:
                    locations_omitted += 1
            if len(lines) > 100:
                location_inventory_truncated = True
            if location_inventory_truncated:
                break
        if not locations:
            locations = [(None, None)]
        for path, line in locations:
            append_candidate(rule_id, metadata.get("description") or rule_id,
                             details.get("description") or metadata.get("description"),
                             metadata.get("severity"), metadata.get("cwe"), path, line,
                             "code_analysis", producer_version)
        if location_inventory_truncated:
            break
    for index, item in enumerate(manifest_findings):
        if not isinstance(item, dict):
            dropped += 1
            continue
        severity = item.get("severity")
        if isinstance(severity, str) and severity.strip().lower() in {"secure", "good", "suppressed"}:
            dropped += 1
            continue
        rule = item.get("rule") or item.get("title") or f"manifest-{index + 1}"
        append_candidate(rule, item.get("title") or rule, item.get("description"), severity,
                         item.get("cwe"), None, None, "manifest_analysis", producer_version)

    result = {
        "schema_version": 1,
        "source_format": "MobSF Android static JSON (bounded subset)",
        "source_sha256": source_sha256,
        "source_trust": "untrusted_external_results",
        "producer_version": producer_version,
        "reported_package_name": _safe_text(document.get("package_name"), 256) or None,
        "producer_entries_seen": len(code_findings) + len(manifest_findings),
        "imported_candidates": len(findings),
        "duplicates_skipped": duplicates,
        "invalid_or_nonfinding_results_skipped": dropped,
        "source_locations_omitted": locations_omitted,
        "source_location_inventory_status": "truncated" if location_inventory_truncated else "within_limits",
        "findings": findings,
        "limitations": [
            "Only the recognized code_analysis.findings and manifest_analysis.manifest_findings subset is projected.",
            "MobSF producer severity, CWE, locations, and descriptions are external claims and are not verified by MobileAg.",
            "Unknown sections, producer evidence, analysis scores, and runtime claims are ignored.",
            "This standalone import does not modify scan history or bind imported results to a MobileAg artifact.",
        ],
    }
    return redact(result)
