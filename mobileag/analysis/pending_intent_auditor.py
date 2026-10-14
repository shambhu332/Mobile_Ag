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
            r"\bPendingIntent\s*\.\s*(getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\("
        )

    @staticmethod
    def _mask_comments_and_strings(source: str) -> str:
        """Mask lexical trivia while retaining offsets and newlines."""
        out = list(source)
        i = 0
        while i < len(source):
            if source.startswith("//", i):
                end = source.find("\n", i)
                end = len(source) if end < 0 else end
                for j in range(i, end): out[j] = " "
                i = end
            elif source.startswith("/*", i):
                end = source.find("*/", i + 2)
                end = len(source) if end < 0 else end + 2
                for j in range(i, end):
                    if source[j] not in "\r\n": out[j] = " "
                i = end
            elif source[i] in "\"'":
                quote = source[i]
                j = i + 1
                while j < len(source):
                    if source[j] == "\\": j += 2
                    elif source[j] == quote:
                        j += 1
                        break
                    else: j += 1
                for k in range(i, min(j, len(source))):
                    if source[k] not in "\r\n": out[k] = " "
                i = j
            else:
                i += 1
        return "".join(out)

    @staticmethod
    def _call_end(masked: str, open_paren: int) -> int | None:
        depth = 0
        for i in range(open_paren, len(masked)):
            if masked[i] == "(": depth += 1
            elif masked[i] == ")":
                depth -= 1
                if depth == 0: return i
        return None

    @staticmethod
    def _arguments(masked: str, start: int, end: int) -> list[str]:
        args, arg_start, depth = [], start + 1, 0
        for i in range(start + 1, end):
            if masked[i] in "([{": depth += 1
            elif masked[i] in ")]}": depth -= 1
            elif masked[i] == "," and depth == 0:
                args.append(masked[arg_start:i])
                arg_start = i + 1
        args.append(masked[arg_start:end])
        return args

    def audit_file(self, file_path: str | Path) -> List[Finding]:
        """Audit a single Java/Kotlin file for PendingIntent vulnerabilities."""
        findings: List[Finding] = []
        path_str = str(file_path)

        try:
            with open(path_str, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return findings

        masked = self._mask_comments_and_strings(content)
        for match in self._factory_pattern.finditer(masked):
            method = match.group(1)
            open_paren = match.end() - 1
            end = self._call_end(masked, open_paren)
            if end is None:
                continue
            args = self._arguments(masked, open_paren, end)
            final_flags = args[-1] if args else ""
            has_immutable = bool(re.search(r"\bFLAG_IMMUTABLE\b", final_flags))
            has_mutable = bool(re.search(r"\bFLAG_MUTABLE\b", final_flags))
            idx = content.count("\n", 0, match.start()) + 1

            if has_immutable and has_mutable:
                title = f"Conflicting PendingIntent mutability flags in {method}()"
                description = "The final flags expression includes both FLAG_IMMUTABLE and FLAG_MUTABLE; inspect the expression and platform behavior."
                severity = Severity.INFO
                finding_id = f"PENDING_INTENT_CONFLICTING_FLAGS_{idx}"
            elif not has_immutable and not has_mutable:
                title = f"Missing PendingIntent Mutability Flag in {method}()"
                description = (
                    f"PendingIntent creation at line {idx} has no explicit mutability flag in its final argument. "
                    "Apps targeting Android 12+ must specify mutability. Verify compile/target SDK and platform conditions; "
                    "this source pattern alone does not demonstrate that another app can mutate the token."
                )
                severity = Severity.MEDIUM
                finding_id = f"PENDING_INTENT_MUTABLE_UNSPECIFIED_{idx}"
            elif has_mutable and not has_immutable:
                title = f"Review Mutable PendingIntent in {method}()"
                description = (
                    f"PendingIntent at line {idx} explicitly uses FLAG_MUTABLE. Confirm that mutability is required "
                    "and that untrusted recipients cannot influence security-sensitive fill-in fields."
                )
                severity = Severity.LOW
                finding_id = f"PENDING_INTENT_EXPLICIT_MUTABLE_{idx}"
            else:
                continue
            findings.append(Finding(
                id=finding_id, title=title, description=description, severity=severity,
                status=FindingStatus.UNVERIFIED, cwe_id="CWE-927", file_path=path_str,
                line_number=idx,
            ))

        return findings

    def audit_directory(self, source_dir: str | Path) -> List[Finding]:
        """Audit all source files in directory."""
        findings: List[Finding] = []
        for root, _, files in os.walk(source_dir):
            for file in files:
                if file.endswith((".java", ".kt")):
                    findings.extend(self.audit_file(os.path.join(root, file)))
        return findings
