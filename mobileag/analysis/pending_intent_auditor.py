"""PendingIntent Mutability & Security Auditor.

Audits PendingIntent creation calls across Java and Kotlin sources for missing
FLAG_IMMUTABLE and unsafe FLAG_MUTABLE configurations (CWE-927 / OWASP MASVS-CODE).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

from mobileag.reporting.finding import Finding, FindingStatus, Severity


class PendingIntentAuditor:
    """Audits PendingIntent factory invocations for mutability flags."""

    # Factory methods on PendingIntent
    FACTORY_METHODS = (
        "getActivity",
        "getActivities",
        "getBroadcast",
        "getService",
        "getForegroundService",
    )

    def __init__(self):
        self._factory_pattern = re.compile(
            r"PendingIntent\.(getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\((.*?)\)",
            re.DOTALL,
        )

    def audit_file(self, file_path: str | Path) -> List[Finding]:
        """Audit a single Java/Kotlin file for PendingIntent vulnerabilities."""
        findings: List[Finding] = []
        path_str = str(file_path)

        try:
            with open(path_str, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return findings

        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            if "PendingIntent." not in line:
                continue

            for method in self.FACTORY_METHODS:
                call_needle = f"PendingIntent.{method}"
                if call_needle in line:
                    flags_context = line
                    # Only look ahead if closing parenthesis is not on current line
                    if ")" not in line:
                        for lookahead in range(1, 4):
                            if idx - 1 + lookahead < len(lines):
                                flags_context += " " + lines[idx - 1 + lookahead]
                                if ")" in lines[idx - 1 + lookahead]:
                                    break

                    # Check for flags in arguments
                    has_immutable = "FLAG_IMMUTABLE" in flags_context
                    has_mutable = "FLAG_MUTABLE" in flags_context
                    has_zero_flag = re.search(r",\s*0\s*\)", flags_context) is not None

                    if not has_immutable and not has_mutable:
                        findings.append(
                            Finding(
                                id=f"PENDING_INTENT_MUTABLE_UNSPECIFIED_{idx}",
                                title=f"Missing PendingIntent Immutability Flag in {method}()",
                                description=(
                                    f"PendingIntent creation at line {idx} omits explicit mutability flags. "
                                    "On Android 12+ (API 31), apps targeting SDK 31+ must explicitly specify "
                                    "either FLAG_IMMUTABLE or FLAG_MUTABLE. Omission can allow malicious apps "
                                    "to mutate intent extras or alter component actions (CWE-927)."
                                ),
                                severity=Severity.MEDIUM,
                                status=FindingStatus.UNVERIFIED,
                                cwe_id="CWE-927",
                                file_path=path_str,
                                line_number=idx,
                            )
                        )
                    elif has_mutable and not has_immutable:
                        findings.append(
                            Finding(
                                id=f"PENDING_INTENT_EXPLICIT_MUTABLE_{idx}",
                                title=f"Potentially Unsafe FLAG_MUTABLE in PendingIntent.{method}()",
                                description=(
                                    f"PendingIntent at line {idx} explicitly uses PendingIntent.FLAG_MUTABLE. "
                                    "If this PendingIntent is passed to an untrusted application or third-party service, "
                                    "the recipient can modify the underlying Intent parameters to hijack authorization."
                                ),
                                severity=Severity.LOW,
                                status=FindingStatus.UNVERIFIED,
                                cwe_id="CWE-927",
                                file_path=path_str,
                                line_number=idx,
                            )
                        )

        return findings

    def audit_directory(self, source_dir: str | Path) -> List[Finding]:
        """Audit all source files in directory."""
        findings: List[Finding] = []
        for root, _, files in os.walk(source_dir):
            for file in files:
                if file.endswith((".java", ".kt")):
                    findings.extend(self.audit_file(os.path.join(root, file)))
        return findings
