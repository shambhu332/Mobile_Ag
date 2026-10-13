"""Intent Redirection and Sub-Intent Proxying Auditor.

Identifies patterns where an Android component extracts an untrusted Parcelable Intent
from caller extras and directly forwards it to startActivity() or sendBroadcast()
without validating the destination (CWE-926 / CWE-927).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

from mobileag.reporting.finding import Finding, FindingStatus, Severity


class IntentRedirectionAuditor:
    """Detects unsafe Intent redirection and nested Intent proxying."""

    EXTRA_INTENT_EXTRACTION_PATTERN = re.compile(
        r"(?:Intent\s+)?([a-zA-Z0-9_]+)\s*=\s*(?:[a-zA-Z0-9_().]+\.)?getParcelableExtra\s*\(\s*[\"'][^\"']+[\"']\s*(?:,\s*Intent\.class\s*)?\)"
    )

    START_ACTIVITY_FORWARD_PATTERN = re.compile(
        r"(?:startActivity|startActivities|startService|startForegroundService|sendBroadcast)\s*\(\s*([a-zA-Z0-9_]+)\s*\)"
    )

    def audit_file(self, file_path: str | Path) -> List[Finding]:
        """Audit a file for Intent redirection patterns."""
        findings: List[Finding] = []
        path_str = str(file_path)

        try:
            with open(path_str, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return findings

        lines = content.splitlines()
        extracted_intent_vars: dict[str, int] = {}

        # First pass: find variables holding extracted Intents
        for idx, line in enumerate(lines, 1):
            match = self.EXTRA_INTENT_EXTRACTION_PATTERN.search(line)
            if match:
                var_name = match.group(1)
                extracted_intent_vars[var_name] = idx

        # Second pass: check if any extracted variable is launched
        for idx, line in enumerate(lines, 1):
            forward_match = self.START_ACTIVITY_FORWARD_PATTERN.search(line)
            if forward_match:
                launched_var = forward_match.group(1)
                if launched_var in extracted_intent_vars:
                    extract_line = extracted_intent_vars[launched_var]
                    findings.append(
                        Finding(
                            id=f"INTENT_REDIRECTION_{idx}",
                            title="Unsafe Intent Redirection (Nested Intent Launch)",
                            description=(
                                f"Variable '{launched_var}' extracted from Intent extra at line {extract_line} "
                                f"is directly forwarded to startActivity/sendBroadcast at line {idx} without "
                                "component verification. If this enclosing component is exported, an external attacker "
                                "can supply an Intent targeting private internal activities, services, or ContentProviders (CWE-926)."
                            ),
                            severity=Severity.HIGH,
                            status=FindingStatus.UNVERIFIED,
                            cwe_id="CWE-926",
                            file_path=path_str,
                            line_number=idx,
                        )
                    )

        return findings

    def audit_directory(self, source_dir: str | Path) -> List[Finding]:
        findings: List[Finding] = []
        for root, _, files in os.walk(source_dir):
            for file in files:
                if file.endswith((".java", ".kt")):
                    findings.extend(self.audit_file(os.path.join(root, file)))
        return findings
