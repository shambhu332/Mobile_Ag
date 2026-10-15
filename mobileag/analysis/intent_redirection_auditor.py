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
        lines = content.splitlines()
        extracted_intent_vars: dict[str, list[int]] = {}

        # Record extraction lines so a later declaration cannot create a
        # backwards-in-time source-to-sink candidate earlier in the file.
        for idx, line in enumerate(lines, 1):
            match = self.EXTRA_INTENT_EXTRACTION_PATTERN.search(line)
            if match:
                extracted_intent_vars.setdefault(match.group(1), []).append(idx)

        for idx, line in enumerate(lines, 1):
            forward_match = self.START_ACTIVITY_FORWARD_PATTERN.search(line)
            if not forward_match:
                continue
            launched_var = forward_match.group(1)
            source_lines = [line_no for line_no in extracted_intent_vars.get(launched_var, ()) if line_no < idx]
            if not source_lines:
                continue
            extract_line = max(source_lines)
            findings.append(
                Finding(
                    id=f"INTENT_REDIRECTION_{idx}",
                    title="Potential Intent Redirection Candidate",
                    description=(
                        f"Variable '{launched_var}' is syntactically assigned from an Intent Parcelable extra at "
                        f"line {extract_line} and passed to an Intent launch API at line {idx}. This bounded "
                        "lexical review does not resolve method scope, validation/allowlisting, exported-component "
                        "reachability, platform permissions, or security impact; review the full code path."
                    ),
                    severity=Severity.INFO,
                    status=FindingStatus.UNVERIFIED,
                    cwe_id="CWE-926",
                    file_path=path_str,
                    line_number=idx,
                    metadata={
                        "proof_state": "not_proven",
                        "analysis_kind": "intent_redirection_lexical_candidate",
                        "source_line": extract_line,
                        "method_scope": "not_resolved",
                        "validation": "not_resolved",
                        "component_reachability": "not_resolved",
                    },
                )
            )
        return findings

    EXTRA_INTENT_EXTRACTION_PATTERN = re.compile(
        r"(?:Intent\s+)?([a-zA-Z0-9_]+)\s*=\s*(?:[a-zA-Z0-9_().]+\.)?getParcelableExtra\s*\(\s*[\"'][^\"']+[\"']\s*(?:,\s*Intent\.class\s*)?\)"
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
