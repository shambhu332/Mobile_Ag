"""Intent Redirection and Sub-Intent Proxying Auditor.

Identifies patterns where an Android component extracts an untrusted Parcelable Intent
from caller extras and directly forwards it to startActivity() or sendBroadcast()
without validating the destination (CWE-926 / CWE-927).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.analysis.android_surface import mask_non_code, method_spans
from mobileag.reporting.finding import Finding, FindingStatus, Severity


class IntentRedirectionAuditor:
    """Detects unsafe Intent redirection and nested Intent proxying."""

    def __init__(self) -> None:
        self.coverage: Dict[str, Any] = {
            "static_status": "not_analyzed", "runtime_status": "not_tested",
            "proof_status": "not_proven", "exhaustive": False,
        }

    @staticmethod
    def _inventory() -> SourceInventory:
        return SourceInventory(max_entries=5000, max_file_bytes=2 * 1024 * 1024,
                               max_total_bytes=32 * 1024 * 1024)

    def _audit_content(self, content: str, path_str: str) -> List[Finding]:
        findings: List[Finding] = []
        code = mask_non_code(content)
        spans = list(method_spans(code))
        for method_name, offset, masked_scope in spans:
            body = content[offset:offset + len(masked_scope)]
            line_base = content.count("\n", 0, offset)
            findings.extend(self._audit_method_scope(body, path_str, method_name, line_base))
        return findings

    def _audit_method_scope(self, content: str, path_str: str,
                            method_name: str, line_base: int) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        extracted_intent_vars: dict[str, tuple[int, int]] = {}
        assignment_pattern = re.compile(r"(?<![=!<>])\b([A-Za-z_$][\w$]*)\s*=(?!=)")

        for idx, line in enumerate(lines, 1):
            extraction = self.EXTRA_INTENT_EXTRACTION_PATTERN.search(line)
            assignments = list(assignment_pattern.finditer(line))
            events: list[tuple[int, int, str, Any]] = []
            if extraction:
                events.append((extraction.start(), 0, "extract", extraction))
            for assignment in assignments:
                # The assignment which obtains the Parcelable is a source event,
                # not a kill of the value being introduced.
                if (extraction and assignment.group(1) == extraction.group(1)
                        and extraction.start() <= assignment.start() < extraction.end()):
                    continue
                events.append((assignment.start(), 1, "assign", assignment.group(1)))
            forward = self.START_ACTIVITY_FORWARD_PATTERN.search(line)
            if forward:
                events.append((forward.start(), 2, "sink", forward))

            for position, _order, kind, event in sorted(events, key=lambda item: (item[0], item[1])):
                if kind == "assign":
                    extracted_intent_vars.pop(event, None)
                    continue
                if kind == "extract":
                    extracted_intent_vars[event.group(1)] = (idx, position)
                    continue

                launched_var = event.group(1)
                source = extracted_intent_vars.get(launched_var)
                if source is None or (source[0] == idx and source[1] >= position):
                    continue
                extract_line = line_base + source[0]
                sink_line = line_base + idx
                findings.append(
                    Finding(
                        id=f"INTENT_REDIRECTION_{sink_line}",
                        title="Potential Intent Redirection Candidate",
                        description=(
                            f"Variable '{launched_var}' is syntactically assigned from an Intent Parcelable extra at "
                            f"line {extract_line} and passed to an Intent launch API at line {sink_line}. The candidate "
                            f"is bounded to lexical method '{method_name}', and recognized reassignments invalidate it. "
                            "This is not AST/control-flow analysis and does not resolve aliases, validation/allowlisting, "
                            "exported-component reachability, platform permissions, or security impact; review the full code path."
                        ),
                        severity=Severity.INFO,
                        status=FindingStatus.UNVERIFIED,
                        cwe_id="CWE-926",
                        file_path=path_str,
                        line_number=sink_line,
                        metadata={
                            "proof_state": "not_proven",
                            "analysis_kind": "intent_redirection_lexical_candidate",
                            "source_line": extract_line,
                            "method_scope": "bounded_lexical",
                            "method_name": method_name,
                            "reassignment_analysis": "linewise_bounded",
                            "validation": "not_resolved",
                            "component_reachability": "not_resolved",
                        },
                    )
                )
        return findings

    EXTRA_INTENT_EXTRACTION_PATTERN = re.compile(
        r"(?:Intent\s+)?([a-zA-Z0-9_]+)(?:\s*:\s*(?:android\.content\.)?Intent)?\s*=\s*"
        r"(?:(?:\(\s*(?:android\.content\.)?Intent\s*\)|\bas\s+(?:android\.content\.)?Intent)\s*)?"
        r"(?:[a-zA-Z0-9_().]+\.)?getParcelableExtra"
        r"(?:\s*<\s*(?:android\.content\.)?Intent\s*>)?"
        r"\s*\(\s*[\"'][^\"']+[\"']\s*(?:,\s*(?:Intent\.class|Intent::class\.java)\s*)?\)"
        r"(?:\s+as\s+(?:android\.content\.)?Intent)?"
    )

    START_ACTIVITY_FORWARD_PATTERN = re.compile(
        r"(?:startActivity|startActivities|startService|startForegroundService|sendBroadcast)\s*\(\s*([a-zA-Z0-9_]+)\s*\)"
    )

    def audit_file(self, file_path: str | Path) -> List[Finding]:
        """Audit a file for Intent redirection patterns."""
        inventory = self._inventory()
        path = Path(file_path)
        records = inventory.read(path.parent, names={path.name})
        candidate = next(records, None)
        records.close()
        self.coverage = dict(inventory.coverage)
        if candidate is None:
            return []
        _source_path, data = candidate
        return self._audit_content(data.decode("utf-8", errors="replace"), str(path))

    def audit_directory(self, source_dir: str | Path) -> List[Finding]:
        findings: List[Finding] = []
        inventory = self._inventory()
        for path, data in inventory.read(source_dir, {".java", ".kt"}):
            findings.extend(self._audit_content(data.decode("utf-8", errors="replace"), str(path)))
        self.coverage = dict(inventory.coverage)
        return findings
