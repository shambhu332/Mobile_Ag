"""Straight-line Source-to-Sink Review Heuristic.

Traces untrusted input data flows (Intent extras, Deep Links, Content Resolvers)
through sequential variable assignments; inter-procedural and control-flow analysis are not implemented. Candidate flows are checked
until reaching critical sinks:
1. WebViews (loadUrl / evaluateJavascript) -> CWE-749 / CWE-79 (UXSS)
2. Databases (rawQuery / execSQL) -> CWE-89 (SQL Injection)
3. Intent Launchers (startActivity / startService) -> CWE-927 (Intent Redirection)
4. File Operations (new File / openFileOutput) -> CWE-22 (Path Traversal)
5. Command Execution (Runtime.exec / ProcessBuilder) -> CWE-78 (Command Injection)
6. Dynamic Class Loading (DexClassLoader / Class.forName) -> CWE-470
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mobileag.analysis.android_surface import mask_non_code, method_spans
from mobileag.analysis.source_syntax import call_sites
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Source regex patterns (extracts variable receiving untrusted data)
_SOURCE_PATTERNS = [
    (
        "INTENT_EXTRA",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_().]+\.)?(?:getStringExtra|getIntExtra|getBooleanExtra|getParcelableExtra|getSerializableExtra|getData|getDataString|getExtras|getCharSequenceExtra|getStringArrayListExtra)\s*\("""
        ),
    ),
    (
        "URI_QUERY_PARAM",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_().]+\.)?getQueryParameter\s*\("""
        ),
    ),
    (
        "INTENT_SOURCE",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_().]+\.)?getIntent\s*\("""
        ),
    ),
    (
        "CLIPBOARD_SOURCE",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_().]+\.)?(?:getPrimaryClip|getText)\s*\("""
        ),
    ),
    (
        "SHARED_PREFS_SOURCE",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_().]+\.)?getString\s*\("""
        ),
    ),
]

# Sink regex patterns
_SINK_SPECS = [
    {
        "type": "WEBVIEW_UXSS",
        "cwe": "CWE-749",
        "severity": Severity.HIGH,
        "title": "Untrusted Taint Flow to WebView Execution (UXSS)",
        "pattern": re.compile(r"""\b([a-zA-Z0-9_]+)\.(?:loadUrl|evaluateJavascript|postUrl)\s*\("""),
        "masvs": "MASVS-CODE-2",
        "remediation": "Validate target URLs against a strict whitelist of HTTPS domains before loading in WebViews.",
    },
    {
        "type": "SQLI",
        "cwe": "CWE-89",
        "severity": Severity.HIGH,
        "title": "Untrusted Taint Flow to Database Query (SQL Injection)",
        "pattern": re.compile(r"""\b(?:db|[a-zA-Z0-9_]*[dD]atabase|[a-zA-Z0-9_]*[dD]b|SQLiteDatabase|[a-zA-Z0-9_]+)\.(?:rawQuery|execSQL)\s*\("""),
        "masvs": "MASVS-CODE-2",
        "remediation": "Use parameterized queries with SQLiteQueryBuilder and bind selection arguments instead of string concatenation.",
    },
    {
        "type": "INTENT_REDIRECTION",
        "cwe": "CWE-927",
        "severity": Severity.HIGH,
        "title": "Untrusted Taint Flow to Intent Redirection (IPC Hijack)",
        "pattern": re.compile(r"""\b(?:startActivity|startActivityForResult|startService|startForegroundService|sendBroadcast|sendOrderedBroadcast)\s*\("""),
        "masvs": "MASVS-PLATFORM-1",
        "remediation": "Do not redirect arbitrary Intent objects from incoming extras. Validate component targets or check calling package identity.",
    },
    {
        "type": "PATH_TRAVERSAL",
        "cwe": "CWE-22",
        "severity": Severity.HIGH,
        "title": "Untrusted Taint Flow to File Operation (Path Traversal)",
        "pattern": re.compile(r"""\b(?:new\s+File|openFileOutput|openFileInput|new\s+FileInputStream|new\s+FileOutputStream|Files\.write|Files\.newInputStream|Files\.newOutputStream)\s*\("""),
        "masvs": "MASVS-STORAGE-2",
        "remediation": "Resolve the canonical target and enforce separator-aware directory containment, not a raw string prefix; constrain relative names and review symlink/TOCTOU behavior for the actual operation.",
    },
    {
        "type": "COMMAND_EXEC",
        "cwe": "CWE-78",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Taint Flow to System Command Execution",
        "pattern": re.compile(r"""\b(?:Runtime\.getRuntime\(\)\.exec|Runtime\.exec|new\s+ProcessBuilder|ProcessBuilder)\s*\("""),
        "masvs": "MASVS-CODE-4",
        "remediation": "Avoid invoking shell commands with dynamic user arguments. Utilize native Android system APIs.",
    },
    {
        "type": "DYNAMIC_CODE_LOADING",
        "cwe": "CWE-470",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Taint Flow to Dynamic Code Loading (DexClassLoader)",
        "pattern": re.compile(r"""\b(?:new\s+DexClassLoader|new\s+PathClassLoader|DexClassLoader|PathClassLoader)\s*\("""),
        "masvs": "MASVS-CODE-4",
        "remediation": "Do not instantiate dynamic class loaders using paths or URLs supplied from untrusted external sources.",
    },
    {
        "type": "UNSAFE_REFLECTION",
        "cwe": "CWE-470",
        "severity": Severity.HIGH,
        "title": "Untrusted Taint Flow to Dynamic Reflection Invocation",
        "pattern": re.compile(r"""\b([a-zA-Z0-9_]+)\.invoke\s*\("""),
        "masvs": "MASVS-CODE-4",
        "remediation": "Avoid invoking methods reflectively based on external or untrusted class/method names.",
    },
]

# Variable assignment pattern: varA = varB ...
_ASSIGN_RE = re.compile(r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?([^;\n]+);?""")

# Direct inline source call inside a sink
_INLINE_SOURCE_RE = re.compile(
    r"""(?:getStringExtra|getIntExtra|getParcelableExtra|getSerializableExtra|getData|getDataString|getQueryParameter|getIntent|getPrimaryClip)\s*\("""
)


@dataclass
class TaintTrace:
    source_var: str
    source_type: str
    source_line: int
    source_snippet: str
    tainted_vars: set[str] = field(default_factory=set)
    propagation_steps: list[str] = field(default_factory=list)


class TaintEngine:
    """Straight-line source-to-sink review heuristic; not an exploit verifier."""

    def __init__(self) -> None:
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}

    def analyze_source_content(self, content: str, file_path: str = "") -> list[Finding]:
        """Analyze a single Java/Kotlin file's source code for source-to-sink taint propagation."""
        findings: list[Finding] = []
        code = mask_non_code(content)
        scopes = list(method_spans(code))
        if not scopes:
            scopes = [("unscoped", 0, code)]
        for _name, scope_offset, body in scopes:
            # Nested methods have independent local bindings; do not also analyze
            # their contents using the enclosing method's values.
            body_chars = list(body)
            for _, nested_offset, nested_body in scopes:
                rel = nested_offset - scope_offset
                if 0 < rel and rel + len(nested_body) <= len(body):
                    for pos in range(rel, rel + len(nested_body)):
                        if body_chars[pos] != "\n":
                            body_chars[pos] = " "
            local_code = "".join(body_chars)
            bindings: dict[str, TaintTrace] = {}
            for offset, statement in self._statements(local_code):
                clean = statement.strip()
                if not clean:
                    continue
                line_idx = code.count("\n", 0, scope_offset + offset) + 1
                assignment = _ASSIGN_RE.search(statement)
                if assignment:
                    lhs, rhs = assignment.group(1), assignment.group(2)
                    previous = next((t for v, t in bindings.items() if re.search(rf"\b{re.escape(v)}\b", rhs)), None)
                    bindings.pop(lhs, None)  # A constant reassignment kills the earlier value.
                    source = next(((kind, pat.search(clean)) for kind, pat in _SOURCE_PATTERNS if pat.search(clean)), None)
                    if source:
                        bindings[lhs] = TaintTrace(lhs, source[0], line_idx, clean, {lhs}, [f"L{line_idx}: {lhs} from {source[0]}"])
                    elif previous:
                        bindings[lhs] = TaintTrace(previous.source_var, previous.source_type, previous.source_line,
                            previous.source_snippet, {lhs}, previous.propagation_steps + [f"L{line_idx}: {lhs} assigned"])
                for sink in _SINK_SPECS:
                    operation = sink["pattern"].pattern.removesuffix(r"\s*\(")
                    for call in call_sites(clean, operation):
                        # SQL bound selectionArgs are not query syntax. Likewise
                        # launch request codes and WebView header maps are not the
                        # launched Intent/loaded URL value.
                        relevant = call.code_args[:1] if sink["type"] in {"SQLI", "INTENT_REDIRECTION", "WEBVIEW_UXSS"} else call.code_args
                        context = " ".join(relevant)
                        trace = next((t for v, t in bindings.items() if re.search(rf"\b{re.escape(v)}\b", context)), None)
                        if trace is None and not _INLINE_SOURCE_RE.search(context):
                            continue
                        origin = f"{trace.source_var} ({trace.source_type}), line {trace.source_line}" if trace else "inline input source"
                        findings.append(Finding(
                            title=sink["title"], description=f"Potential flow from {origin} to {sink['type']}. "
                                "Straight-line lexical heuristic only: method calls, branch conditions, sanitization and external reachability require review; no exploit is established.",
                            severity=sink["severity"], confidence=0.5, cwe_id=sink["cwe"], cvss_score=0.0,
                            cvss_vector="", owasp_masvs=sink["masvs"], affected_component=file_path or "UnknownClass",
                            file_path=file_path, line_number=line_idx, code_snippet=clean[:1000],
                            detection_method="TaintEngine (straight-line heuristic)", status=FindingStatus.UNVERIFIED,
                            remediation=sink["remediation"],
                            metadata={"proof_state": "not_proven", "analysis_kind": "straight_line_lexical_flow",
                                      "control_flow": "not_implemented", "interprocedural_value_flow": "not_implemented"},
                        ))
        return findings

    @staticmethod
    def _statements(code):
        """Split logical lexical statements while retaining multiline call arguments."""
        start = 0
        stack = []
        for pos, char in enumerate(code):
            if char in "([":
                stack.append({"(": ")", "[": "]"}[char])
            elif char == "{" and stack:
                stack.append("}")
            elif char in ")]}":
                if stack and stack[-1] == char:
                    stack.pop()
                elif char == "}" and not stack:
                    yield start, code[start:pos]
                    start = pos + 1
            elif not stack and char in ";{\n":
                # Keep a simple wrapped assignment/expression, not a full AST.
                if char == "\n" and code[start:pos].rstrip().endswith(("=", "+", ".", ",")):
                    continue
                yield start, code[start:pos]
                start = pos + 1
        if start < len(code):
            yield start, code[start:]

    def analyze_directory(self, decompiled_dir: str) -> list[Finding]:
        """Recursively scan all Java and Kotlin source files in a decompiled APK directory."""
        all_findings: list[Finding] = []
        root_path = Path(decompiled_dir)

        inventory = SourceInventory()
        for file_path, data in inventory.read(root_path, {".java", ".kt"}):
            try:
                content = data.decode("utf-8", errors="replace")
                rel_path = str(file_path.relative_to(root_path))
                all_findings.extend(self.analyze_source_content(content, file_path=rel_path))
                if len(all_findings) >= 1000:
                    all_findings = all_findings[:1000]
                    inventory.coverage['limits_reached'] = True
                    break
            except Exception as e:
                logger.debug("Failed to analyze taint in %s: %s", file_path, e)
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             candidate_count=len(all_findings), limits={**inventory.coverage['limits'], 'findings':1000})
        return all_findings

    async def analyze_directory_async(self, decompiled_dir: str | Path) -> list[Finding]:
        """Asynchronously scan all Java and Kotlin source files in a decompiled APK directory."""
        return await asyncio.to_thread(self.analyze_directory, str(decompiled_dir))
