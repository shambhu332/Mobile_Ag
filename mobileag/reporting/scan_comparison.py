"""Conservative read-only comparison of two immutable scan observations.

Comparison absence is never interpreted as a fix: analyzers, extraction, scope,
and artifact inputs can differ. Match keys deliberately require rule, CWE, file,
and sink line so vague title-only matches are not presented as retests.
"""
from __future__ import annotations

from collections import defaultdict, deque
from pathlib import PurePosixPath
import json


def _key(finding: dict) -> tuple | None:
    if not isinstance(finding, dict):
        return None
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    trace = metadata.get("source_sink_trace") if isinstance(metadata.get("source_sink_trace"), dict) else {}
    sink = trace.get("sink") if isinstance(trace.get("sink"), dict) else {}
    path = finding.get("file_path") or finding.get("file") or finding.get("source_file")
    line = sink.get("line") or finding.get("line_number") or finding.get("line")
    rule = (finding.get("rule_id") or finding.get("check_id")
            or metadata.get("rule_id") or metadata.get("check_id"))
    if not rule:
        detector = finding.get("detection_method")
        operation = sink.get("operation")
        rule = f"{detector}:{operation}" if isinstance(detector, str) and operation else detector
    cwe = finding.get("cwe_id") or finding.get("cwe")
    if not all(isinstance(v, str) and v.strip() for v in (path, rule, cwe)) or type(line) is not int or line < 1:
        return None
    raw_path = path.replace("\\", "/")
    normalized_path = PurePosixPath(raw_path)
    normalized = str(normalized_path)
    if (normalized in {".", ".."} or normalized_path.is_absolute()
            or any(part == ".." for part in normalized_path.parts)
            or (normalized_path.parts and normalized_path.parts[0].endswith(":"))):
        return None
    return (rule.strip(), cwe.strip(), normalized, line)


def _relocation_key(finding: dict) -> tuple | None:
    """Return a stringent review-only key for possible file moves.

    Requires the analyzer's package/import-qualified lexical method label and
    sink operation. This is not symbol resolution, a finding match, or a fix.
    """
    if not isinstance(finding, dict):
        return None
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    trace = metadata.get("source_sink_trace") if isinstance(metadata.get("source_sink_trace"), dict) else {}
    sink = trace.get("sink") if isinstance(trace.get("sink"), dict) else {}
    method = sink.get("source_qualified_method_identity")
    operation = sink.get("operation")
    rule = (finding.get("rule_id") or finding.get("check_id")
            or metadata.get("rule_id") or metadata.get("check_id"))
    if not rule:
        detector = finding.get("detection_method")
        rule = f"{detector}:{operation}" if isinstance(detector, str) and operation else detector
    cwe = finding.get("cwe_id") or finding.get("cwe")
    if (not isinstance(method, str) or not method or len(method) > 256
            or not isinstance(operation, str) or not operation or len(operation) > 128
            or not isinstance(rule, str) or not rule.strip()
            or not isinstance(cwe, str) or not cwe.strip()):
        return None
    return rule.strip(), cwe.strip(), method, operation


def compare_scans(baseline: dict, current: dict) -> dict:
    """Compare completed scans for the same package; never infer fixed status."""
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("Two scan documents are required")
    for scan in (baseline, current):
        if scan.get("status") not in {"completed", "complete", "success"}:
            raise ValueError("Only completed scans can be compared")
        if not isinstance(scan.get("scan_id"), str) or not scan["scan_id"]:
            raise ValueError("Scan identity is required")
    base_package = baseline.get("package_name")
    current_package = current.get("package_name")
    if not isinstance(base_package, str) or not base_package or base_package != current_package:
        raise ValueError("Scans must identify the same package")

    def collect(scan):
        grouped = defaultdict(deque)
        unmatchable = 0
        findings = scan.get("findings", [])
        if not isinstance(findings, list):
            findings = []
            unmatchable += 1
        for f in findings:
            identity = _key(f)
            if identity is None:
                unmatchable += 1
            else:
                grouped[identity].append(f)
        return grouped, unmatchable

    before, before_unmatchable = collect(baseline)
    after, after_unmatchable = collect(current)
    entries = []
    baseline_unmatched = []
    current_unmatched = []
    for key in sorted(set(before) | set(after)):
        old, new = before[key], after[key]
        while old and new:
            old.popleft(); new.popleft()
            entries.append({"rule_id": key[0], "cwe_id": key[1], "file": key[2],
                            "sink_line": key[3], "comparison": "observed_in_both",
                            "interpretation": "candidate_persists_retest_required"})
        while old:
            baseline_unmatched.append(old.popleft())
            entries.append({"rule_id": key[0], "cwe_id": key[1], "file": key[2],
                            "sink_line": key[3], "comparison": "not_observed_in_current",
                            "interpretation": "not_proof_of_fix"})
        while new:
            current_unmatched.append(new.popleft())
            entries.append({"rule_id": key[0], "cwe_id": key[1], "file": key[2],
                            "sink_line": key[3], "comparison": "new_in_current",
                            "interpretation": "candidate_requires_review"})
    def sha256(value):
        return (value if isinstance(value, str) and len(value) == 64
                and all(char in "0123456789abcdefABCDEF" for char in value) else None)

    baseline_hash = sha256(baseline.get("artifact_sha256"))
    current_hash = sha256(current.get("artifact_sha256"))
    artifact_changed = (baseline_hash != current_hash
                        if baseline_hash is not None and current_hash is not None
                        else None)

    # Retest absence is only interpretable alongside execution parity. Keep this
    # deliberately structural: matching labels do not prove analyzer equivalence.
    def parity(left, right):
        if (left is None or right is None or left == {} or right == {}
                or left == [] or right == []):
            return "unknown"
        try:
            encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            def bounded(value):
                chunks = []
                size = 0
                for chunk in encoder.iterencode(value):
                    size += len(chunk)
                    if size > 256_000:
                        return None
                    chunks.append(chunk)
                return "".join(chunks)
            a, b = bounded(left), bounded(right)
        except (TypeError, ValueError):
            return "unknown"
        # Comparison metadata is user/artifact derived; bound serialization work
        # so pathological nested coverage cannot inflate this read-only route.
        if a is None or b is None:
            return "unknown"
        return "same_recorded_value" if a == b else "different_recorded_value"

    def tools(scan):
        provenance = scan.get("artifact_provenance")
        return provenance.get("tools") if isinstance(provenance, dict) else None

    baseline_coverage = baseline.get("coverage")
    current_coverage = current.get("coverage")
    def relocation_groups(findings):
        groups = defaultdict(list)
        for finding in findings:
            identity = _relocation_key(finding)
            if identity is not None:
                groups[identity].append(finding)
        return groups

    old_moves = relocation_groups(baseline_unmatched)
    new_moves = relocation_groups(current_unmatched)
    relocation_leads = []
    for identity in sorted(set(old_moves) & set(new_moves)):
        old_group, new_group = old_moves[identity], new_moves[identity]
        if len(old_group) != 1 or len(new_group) != 1:
            continue
        old_path = _key(old_group[0])[2]
        new_path = _key(new_group[0])[2]
        if old_path == new_path:
            continue
        relocation_leads.append({
            "rule_id": identity[0], "cwe_id": identity[1],
            "sink_operation": identity[3], "method_identity": identity[2],
            "baseline_file": old_path, "current_file": new_path,
            "baseline_line": _key(old_group[0])[3], "current_line": _key(new_group[0])[3],
            "interpretation": "possible_file_move_manual_review_only_not_a_match_or_fix",
        })
    return {
        "schema_version": 1,
        "relation": {"baseline_scan_id": baseline["scan_id"], "current_scan_id": current["scan_id"],
                     "package_name": base_package,
                     "baseline_artifact_sha256": baseline_hash,
                     "current_artifact_sha256": current_hash,
                     "artifact_changed": artifact_changed,
                     "artifact_comparison_status": ("changed" if artifact_changed is True else
                                                    "same" if artifact_changed is False else "unknown")},
        "execution_parity": {
            "tool_versions": parity(tools(baseline), tools(current)),
            "coverage_records": parity(baseline_coverage, current_coverage),
            "interpretation": "recorded equality is not analyzer or coverage equivalence; unknown/different means absence is especially inconclusive",
        },
        "comparisons": entries,
        "relocation_leads": relocation_leads,
        "unmatchable": {"baseline_count": before_unmatchable, "current_count": after_unmatchable,
                        "status": "incomplete_if_nonzero"},
        "fixed_count": None,
        "limitations": [
            "This is a read-only location-key comparison, not an automatic fixed/retest verdict.",
            "Not observed in the current scan does not prove remediation; coverage, tool versions, extraction, and code movement may differ.",
            "Only exact rule/CWE/file/sink-line identities are matched; unmatched findings remain unmatchable.",
            "Analyst triage and independent verification are not inferred or transferred between scans.",
        ],
    }
