"""PendingIntent Mutability & Security Auditor.

Audits PendingIntent creation calls across Java and Kotlin sources for missing
FLAG_IMMUTABLE and unsafe FLAG_MUTABLE configurations (CWE-927 / OWASP MASVS-CODE).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.reporting.finding import Finding, FindingStatus, Severity


class PendingIntentAuditor:
    """Audits PendingIntent factory invocations for mutability flags."""

    def __init__(self):
        self.coverage: Dict[str, Any] = {
            "static_status": "not_analyzed", "runtime_status": "not_tested",
            "proof_status": "not_proven", "exhaustive": False,
            "target_sdk": None,
        }
        self._factory_pattern = re.compile(
            r"\bPendingIntent\s*\.\s*(getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\("
        )

    @staticmethod
    def _inventory() -> SourceInventory:
        return SourceInventory(max_entries=5000, max_file_bytes=2 * 1024 * 1024,
                               max_total_bytes=32 * 1024 * 1024)

    # Factory methods on PendingIntent
    FACTORY_METHODS = (
        "getActivity",
        "getActivities",
        "getBroadcast",
        "getService",
        "getForegroundService",
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

    @staticmethod
    def _constant_flag_aliases(masked: str) -> dict[str, str | None]:
        """Collect unique bounded Java final-int and Kotlin const-int expressions."""
        definitions: dict[str, list[str]] = {}
        java = re.compile(
            r"\b((?:(?:public|protected|private|static|final)\s+)*)(?:int|Integer)\s+"
            r"([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,512});"
        )
        kotlin = re.compile(
            r"\bconst\s+val\s+([A-Za-z_$][\w$]*)\s*:\s*Int\s*=\s*([^;\n]{1,512})"
        )
        for match in java.finditer(masked):
            if re.search(r"\bfinal\b", match.group(1)):
                definitions.setdefault(match.group(2), []).append(match.group(3).strip())
        for match in kotlin.finditer(masked):
            definitions.setdefault(match.group(1), []).append(match.group(2).strip())
        # `None` explicitly records an ambiguous duplicate declaration.
        return {name: values[0] if len(values) == 1 else None
                for name, values in definitions.items()}

    @classmethod
    def _resolve_flag_symbols(cls, expression: str, aliases: dict[str, str | None],
                              stack: tuple[str, ...] = ()) -> set[str] | None:
        """Resolve a literal/constant flag expression without evaluating code."""
        if len(stack) > 8 or not re.fullmatch(r"[\w.$|&~()+\-\s]+", expression):
            return None
        token_pattern = re.compile(
            r"(?P<flag>(?:[A-Za-z_$][\w$]*\.)*FLAG_[A-Z0-9_]+)"
            r"|(?P<number>0[xX][0-9A-Fa-f]+|\d+)"
            r"|(?P<identifier>[A-Za-z_$][\w$]*)"
            r"|(?P<operator>[|&~()+\-])|(?P<space>\s+)"
        )
        result: set[str] = set()
        cursor = 0
        for match in token_pattern.finditer(expression):
            if match.start() != cursor:
                return None
            cursor = match.end()
            if match.lastgroup == "flag":
                result.add(match.group())
            elif match.lastgroup == "identifier":
                name = match.group()
                if name in stack or name not in aliases or aliases[name] is None:
                    return None
                nested = cls._resolve_flag_symbols(aliases[name] or "", aliases, stack + (name,))
                if nested is None:
                    return None
                result.update(nested)
        return result if cursor == len(expression) else None

    def audit_file(self, file_path: str | Path, target_sdk: int | None = None) -> List[Finding]:
        """Audit a single Java/Kotlin file for PendingIntent vulnerabilities."""
        inventory = self._inventory()
        path = Path(file_path)
        records = inventory.read(path.parent, names={path.name})
        record = next(records, None)
        records.close()
        self.coverage = dict(inventory.coverage)
        self.coverage["target_sdk"] = target_sdk
        if record is None:
            return []
        _source_path, data = record
        return self._audit_content(data.decode("utf-8", errors="replace"), str(path), target_sdk)

    def _audit_content(self, content: str, path_str: str, target_sdk: int | None = None) -> List[Finding]:
        findings: List[Finding] = []
        masked = self._mask_comments_and_strings(content)
        aliases = self._constant_flag_aliases(masked)
        for match in self._factory_pattern.finditer(masked):
            method = match.group(1)
            open_paren = match.end() - 1
            end = self._call_end(masked, open_paren)
            if end is None:
                continue
            args = self._arguments(masked, open_paren, end)
            final_flags = args[-1] if args else ""
            resolved_flags = self._resolve_flag_symbols(final_flags, aliases)
            if resolved_flags is None:
                title = f"Unresolved PendingIntent Flags in {method}()"
                description = (
                    f"PendingIntent creation at line {content.count(chr(10), 0, match.start()) + 1} has a flags "
                    "expression that this bounded literal/constant resolver cannot determine. Review the final "
                    "argument and effective flags; this analyzer does not infer mutability from an unknown value."
                )
                idx = content.count("\n", 0, match.start()) + 1
                findings.append(Finding(
                    id=f"PENDING_INTENT_FLAGS_UNRESOLVED_{idx}",
                    title=title, description=description, severity=Severity.INFO,
                    status=FindingStatus.UNVERIFIED, cwe_id="CWE-Unknown", file_path=path_str,
                    line_number=idx,
                    metadata={"target_sdk": target_sdk, "review_kind": "flags_unresolved",
                              "flags_resolution": "not_resolved"},
                ))
                continue
            has_immutable = any(flag.endswith("FLAG_IMMUTABLE") for flag in resolved_flags)
            has_mutable = any(flag.endswith("FLAG_MUTABLE") for flag in resolved_flags)
            idx = content.count("\n", 0, match.start()) + 1

            if has_immutable and has_mutable:
                title = f"Conflicting PendingIntent mutability flags in {method}()"
                description = "The final flags expression includes both FLAG_IMMUTABLE and FLAG_MUTABLE; inspect the expression and platform behavior."
                severity = Severity.INFO
                finding_id = f"PENDING_INTENT_CONFLICTING_FLAGS_{idx}"
            elif not has_immutable and not has_mutable:
                title = f"Missing PendingIntent Mutability Flag in {method}()"
                if target_sdk is not None and target_sdk >= 31:
                    description = (
                        f"PendingIntent creation at line {idx} has no explicit mutability flag; the parsed manifest "
                        f"declares targetSdkVersion {target_sdk}. Android 12+ enforces explicit mutability for "
                        "apps targeting API 31+, typically by throwing IllegalArgumentException when this call executes. "
                        "This is a compatibility lead, not evidence that a mutable token was created or exploitable."
                    )
                    severity = Severity.INFO
                else:
                    sdk_context = (
                        f"The parsed manifest declares targetSdkVersion {target_sdk}; "
                        if target_sdk is not None else "The target SDK was unavailable; "
                    )
                    description = (
                        f"PendingIntent creation at line {idx} has no explicit mutability flag in its final argument. "
                        f"{sdk_context}verify runtime compatibility behavior and whether a token can be obtained by an "
                        "untrusted party. This source pattern alone does not demonstrate exploitability."
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
            compatibility_only = (
                not has_immutable and not has_mutable and target_sdk is not None and target_sdk >= 31
            )
            findings.append(Finding(
                id=finding_id, title=title, description=description, severity=severity,
                status=FindingStatus.UNVERIFIED, cwe_id="CWE-Unknown" if compatibility_only else "CWE-927", file_path=path_str,
                line_number=idx,
                metadata={"target_sdk": target_sdk,
                          "review_kind": "compatibility_lead" if compatibility_only else "mutability_review_candidate",
                          "flags_resolution": "literal_or_constant"},
            ))

        return findings

    def audit_directory(self, source_dir: str | Path, target_sdk: int | None = None) -> List[Finding]:
        """Audit all source files in directory."""
        findings: List[Finding] = []
        inventory = self._inventory()
        for path, data in inventory.read(source_dir, {".java", ".kt"}):
            findings.extend(self._audit_content(data.decode("utf-8", errors="replace"), str(path), target_sdk))
        self.coverage = dict(inventory.coverage)
        self.coverage["target_sdk"] = target_sdk
        return findings
