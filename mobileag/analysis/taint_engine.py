"""Bounded Java AST and lexical Source-to-Sink review heuristics.

Traces untrusted input data flows (Intent extras, Deep Links, Content Resolvers)
through parsed Java local flows when the optional Tree-sitter extra is installed,
plus lexical Java/Kotlin fallback and limited same-file method summaries. Full
inter-procedural Android call/control-flow analysis is not implemented. Candidate flows are checked
until reaching critical sinks:
1. WebView navigation and JavaScript evaluation -> CWE-829 / CWE-79 review candidates
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
from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Source regex patterns (extracts variable receiving untrusted data)
_SOURCE_PATTERNS = [
    (
        "INTENT_EXTRA",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_$().]+(?:\?\s*)?\s*\.\s*)?(?:getStringExtra|getIntExtra|getLongExtra|getFloatExtra|getDoubleExtra|getBooleanExtra|getByteArrayExtra|getStringArrayExtra|getStringArrayListExtra|getIntegerArrayListExtra|getParcelableExtra|getParcelableArrayExtra|getParcelableArrayListExtra|getSerializableExtra|getBundleExtra|getExtras|getCharSequenceExtra|getCharSequenceArrayExtra|getCharSequenceArrayListExtra)\s*\("""
        ),
    ),
    (
        "INTENT_EXTRA",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[A-Za-z_$][\w$]*(?:\?\s*)?\.|(?:this\.)?getIntent\(\)\.)getData(?:String)?\s*\(""",
            re.IGNORECASE,
        ),
    ),
    (
        "URI_QUERY_PARAM",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?P<receiver>[A-Za-z_$][\w$]*)\s*(?:\?\s*)?\.\s*getQueryParameter\s*\("""
        ),
    ),
    (
        "URI_COMPONENT",
        re.compile(
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?P<receiver>[A-Za-z_$][\w$]*)\s*(?:\?\s*)?\.\s*(?:getPath|getLastPathSegment|getHost|getAuthority|getFragment)\s*\(""",
            re.IGNORECASE,
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
            r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?(?:[a-zA-Z0-9_.$]+\.)?(?:getPrimaryClip|[a-zA-Z0-9_.$]*clip[a-zA-Z0-9_.$]*\.getText)\s*\(""",
            re.IGNORECASE,
        ),
    ),
]

# Sink regex patterns
_SINK_SPECS = [
    {
        "type": "WEBVIEW_NAVIGATION",
        "cwe": "CWE-829",
        "severity": Severity.HIGH,
        "title": "Potential Untrusted Input Flow to WebView Navigation",
        "pattern": re.compile(r"""\b([a-zA-Z0-9_]+)\.(?:loadUrl|postUrl)\s*\("""),
        "masvs": "MASVS-CODE-2",
        "remediation": "Treat externally supplied URLs as untrusted. Parse and validate the scheme and complete host against an exact allowlist before loading; verify the effective guard and impact before classifying this candidate as a vulnerability.",
    },
    {
        "type": "WEBVIEW_JAVASCRIPT",
        "cwe": "CWE-79",
        "severity": Severity.HIGH,
        "title": "Potential Untrusted Data Flow to WebView JavaScript Evaluation",
        "pattern": re.compile(r"""\b([a-zA-Z0-9_]+)\.evaluateJavascript\s*\("""),
        "masvs": "MASVS-CODE-2",
        "remediation": "Avoid concatenating untrusted data into JavaScript source. Use structured message APIs or context-appropriate encoding and verify the actual script context before asserting script injection.",
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
        "pattern": re.compile(r"""\b(?:new\s+File|File|openFileOutput|openFileInput|new\s+FileInputStream|new\s+FileOutputStream|Files\.write|Files\.newInputStream|Files\.newOutputStream)\s*\("""),
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
        "title": "Untrusted Taint Flow to Dynamic Reflection Target Selection",
        "pattern": re.compile(r"""\b(?:Class\.forName|[A-Za-z_$][\w$]*\.(?:loadClass|getMethod|getDeclaredMethod))\s*\("""),
        "masvs": "MASVS-CODE-4",
        "remediation": "Constrain class and method names used for reflective lookup to a fixed allowlist. Data arguments passed to Method.invoke do not establish that the selected method was attacker-controlled.",
    },
]

# Variable assignment pattern: varA = varB ...
_ASSIGN_RE = re.compile(r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?([^;]+);?""")

# Direct inline source call inside a sink
_INLINE_SOURCE_RE = re.compile(
    r"""(?<![\w$.])(?:this\.)?getIntent\s*\(\)""",
    re.IGNORECASE,
)
_INLINE_GETINTENT_ACCESSOR_RE = re.compile(
    r"(?<![\w$.])(?:this\.)?getIntent\s*\(\)\s*\.\s*"
    r"(?:getStringExtra|getIntExtra|getLongExtra|getFloatExtra|getDoubleExtra|getBooleanExtra|getByteArrayExtra|"
    r"getStringArrayExtra|getStringArrayListExtra|getIntegerArrayListExtra|getParcelableExtra|getParcelableArrayExtra|"
    r"getParcelableArrayListExtra|getSerializableExtra|getBundleExtra|getExtras|getCharSequenceExtra|"
    r"getCharSequenceArrayExtra|getCharSequenceArrayListExtra|getData(?:String)?)\s*\(", re.IGNORECASE)
_QUALIFIED_GETINTENT_RE = re.compile(
    r"(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*getIntent\s*\(\)", re.IGNORECASE)
_QUALIFIED_GETINTENT_ACCESSOR_RE = re.compile(
    r"(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*getIntent\s*\(\)\s*\.\s*"
    r"(?:getStringExtra|getIntExtra|getLongExtra|getFloatExtra|getDoubleExtra|getBooleanExtra|getByteArrayExtra|"
    r"getStringArrayExtra|getStringArrayListExtra|getIntegerArrayListExtra|getParcelableExtra|getParcelableArrayExtra|"
    r"getParcelableArrayListExtra|getSerializableExtra|getBundleExtra|getExtras|getCharSequenceExtra|"
    r"getCharSequenceArrayExtra|getCharSequenceArrayListExtra|getData(?:String)?)\s*\(", re.IGNORECASE)
_KOTLIN_SAFE_DOT = r"(?:\?\s*)?\."
_URI_QUERY_PARAMETER_CALL_RE = re.compile(rf"(?P<receiver>[A-Za-z_$][\w$]*)\s*{_KOTLIN_SAFE_DOT}\s*getQueryParameter\s*\(", re.IGNORECASE)
_URI_COMPONENT_CALL_RE = re.compile(rf"(?P<receiver>[A-Za-z_$][\w$]*)\s*{_KOTLIN_SAFE_DOT}\s*(?:getPath|getLastPathSegment|getHost|getAuthority|getFragment)\s*\(", re.IGNORECASE)
_INTENT_EXTRA_CALL_RE = re.compile(
    rf"(?P<receiver>[A-Za-z_$][\w$]*)\s*{_KOTLIN_SAFE_DOT}\s*(?:getStringExtra|getIntExtra|getLongExtra|getFloatExtra|getDoubleExtra|getBooleanExtra|getByteArrayExtra|getStringArrayExtra|getStringArrayListExtra|getIntegerArrayListExtra|getParcelableExtra|getParcelableArrayExtra|getParcelableArrayListExtra|getSerializableExtra|getBundleExtra|getExtras|getCharSequenceExtra|getCharSequenceArrayExtra|getCharSequenceArrayListExtra|getData(?:String)?)\s*\(",
    re.IGNORECASE,
)
_INLINE_INTENT_EXTRA_RE = re.compile(
    rf"(?P<receiver>[A-Za-z_$][\w$]*)\s*{_KOTLIN_SAFE_DOT}\s*(?:getStringExtra|getIntExtra|getLongExtra|getFloatExtra|getDoubleExtra|getBooleanExtra|getByteArrayExtra|getStringArrayExtra|getStringArrayListExtra|getIntegerArrayListExtra|getParcelableExtra|getParcelableArrayExtra|getParcelableArrayListExtra|getSerializableExtra|getBundleExtra|getExtras|getCharSequenceExtra|getCharSequenceArrayExtra|getCharSequenceArrayListExtra|getData(?:String)?)\s*\(",
    re.IGNORECASE,
)
_CLIPBOARD_CALL_RE = re.compile(
    r"(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*(?:getPrimaryClip|getText)\s*\(", re.IGNORECASE)


def _conditional_question_index(expression: str, rhs_start: int = -1) -> int | None:
    """Return the first Java-style ternary operator, excluding Kotlin `?.`/`?:`."""
    for match in re.finditer(r"\?", expression):
        index = match.start()
        previous = expression[index - 1] if index else ""
        following = expression[index + 1] if index + 1 < len(expression) else ""
        if previous == "." or following in {".", ":"}:
            continue
        if index > rhs_start and ":" in expression[index + 1:]:
            return index
    return None


def _conditional_result_expression(expression: str, rhs_start: int = -1) -> str:
    """Return only Java ternary result arms, excluding its selector condition."""
    question = _conditional_question_index(expression, rhs_start)
    if question is None:
        return expression
    nested_ternaries = 0
    paren_depth = bracket_depth = brace_depth = 0
    for index in range(question + 1, len(expression)):
        char = expression[index]
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif paren_depth == bracket_depth == brace_depth == 0:
            if char == "?" and (index == 0 or expression[index - 1] != "."):
                following = expression[index + 1] if index + 1 < len(expression) else ""
                if following not in {".", ":"}:
                    nested_ternaries += 1
            elif char == ":":
                if nested_ternaries:
                    nested_ternaries -= 1
                else:
                    return expression[question + 1:index] + " " + expression[index + 1:]
    return expression


@dataclass
class TaintTrace:
    source_var: str
    source_type: str
    source_line: int
    source_snippet: str
    tainted_vars: set[str] = field(default_factory=set)
    propagation_steps: list[str] = field(default_factory=list)


def _mask_nested_method_scopes(body: str, scope_offset: int, scopes: list[tuple[str, int, str]]) -> str:
    """Blank nested method bodies while preserving offsets and line numbers."""
    chars = list(body)
    for _, nested_offset, nested_body in scopes:
        rel = nested_offset - scope_offset
        if 0 < rel and rel + len(nested_body) <= len(body):
            for pos in range(rel, rel + len(nested_body)):
                if chars[pos] != "\n":
                    chars[pos] = " "
    return "".join(chars)


def _type_scopes(code: str) -> list[tuple[str, int, int]]:
    """Return lexical class-like type spans; this is not symbol resolution."""
    spans = []
    pattern = re.compile(r"\b(?:class|object|interface|enum|record)\s+([A-Za-z_$][\w$]*)[^;{}]*\{")
    for match in pattern.finditer(code):
        opening = match.end() - 1
        depth = 1
        end = opening + 1
        while end < len(code) and depth:
            if code[end] == "{":
                depth += 1
            elif code[end] == "}":
                depth -= 1
            end += 1
        if depth == 0:
            spans.append((match.group(1), match.start(), end))
    return spans


def _enclosing_type(offset: int, spans: list[tuple[str, int, int]]) -> str | None:
    containing = [item for item in spans if item[1] <= offset < item[2]]
    return min(containing, key=lambda item: item[2] - item[1])[0] if containing else None


def _enclosing_type_members(code: str, offset: int, type_spans: list[tuple[str, int, int]],
                            method_spans_list: list[tuple[str, int, str]]) -> str:
    containing = [item for item in type_spans if item[1] <= offset < item[2]]
    if not containing:
        return ""
    _, start, end = min(containing, key=lambda item: item[2] - item[1])
    return _mask_nested_method_scopes(code[start:end], start, method_spans_list)


def _declared_receiver_type(method_body: str, receiver: str) -> str | None:
    match = re.search(
        rf"(?:\b(?:final|var|val)\s+)?([A-Za-z_$][\w.$<>?\[\]]*)\s+{re.escape(receiver)}\b",
        method_body,
    )
    return match.group(1).split("<", 1)[0].rstrip("?[]").rsplit(".", 1)[-1] if match else None


def _intent_data_uri_names(code: str, intent_names: set[str] | None = None) -> set[str]:
    """Names assigned from an Intent data URI in this lexical method body.

    A variable's type being Uri is not sufficient evidence that its value came
    from an external link: Uri.parse(constants), resources and internal routes
    are common. Keep this source model narrow to Intent.getData()/data flows.
    """
    intent_receivers = (r"[A-Za-z_$][\w$]*" if intent_names is not None else
                        r"(?:[A-Za-z_$][\w$]*intent[A-Za-z0-9_$]*|intent)")
    java_pattern = re.compile(
        rf"\b(?:android\.net\.)?Uri\s+(?P<lhs>[A-Za-z_$][\w$]*)\s*=\s*(?:"
        rf"(?P<receiver>{intent_receivers})|(?:this\.)?getIntent\(\))\s*\.\s*getData\s*\(",
        re.IGNORECASE)
    names = {match.group("lhs") for match in java_pattern.finditer(code)
             if match.group("receiver") is None or intent_names is None
             or match.group("receiver") in intent_names}
    kotlin_pattern = re.compile(
        rf"\b(?:val|var)\s+(?P<lhs>[A-Za-z_$][\w$]*)\s*(?::\s*(?:android\.net\.)?Uri)?\s*=\s*"
        rf"(?P<receiver>{intent_receivers})\s*\??\.\s*(?:data|getData\(\))\b", re.IGNORECASE)
    names.update(match.group("lhs") for match in kotlin_pattern.finditer(code)
                 if intent_names is None or match.group("receiver") in intent_names)
    return names


def _mask_call_inputs(expression: str) -> str:
    """Remove unknown call names/arguments before direct variable matching.

    A tainted argument to an arbitrary method is not evidence that the method's
    return value is tainted (it may return a constant or validated value). Known
    same-file source-return summaries are handled separately at the sink.
    """
    chars = list(expression)
    for match in re.finditer(r"\b[A-Za-z_$][\w$]*\s*\(", expression):
        opening = expression.find("(", match.start())
        depth = 1
        closing = opening + 1
        while closing < len(expression) and depth:
            if expression[closing] == "(":
                depth += 1
            elif expression[closing] == ")":
                depth -= 1
            closing += 1
        if depth:
            continue
        for index in range(match.start(), opening):
            chars[index] = " "
        for index in range(opening + 1, closing - 1):
            chars[index] = " "
    return "".join(chars)


def _is_nested_in_call(expression: str, source_start: int) -> bool:
    """Whether a source call occurs inside another call's argument list."""
    for match in re.finditer(r"\b[A-Za-z_$][\w$]*\s*\(", expression):
        opening = expression.find("(", match.start())
        if match.start() == source_start or opening >= source_start:
            continue
        depth = 1
        closing = opening + 1
        while closing < len(expression) and depth:
            if expression[closing] == "(":
                depth += 1
            elif expression[closing] == ")":
                depth -= 1
            closing += 1
        if depth == 0 and opening < source_start < closing - 1:
            return True
    return False


def _has_modeled_get_intent(expression: str, activity_names: set[str]) -> bool:
    """Accept Activity.getIntent only for bare/this calls or typed Activities."""
    pattern = re.compile(
        r"(?<![\w$.])(?:this\.)?getIntent\s*\(\)"
        r"|(?P<receiver>(?!this\b)[A-Za-z_$][\w$]*)\s*\.\s*getIntent\s*\(\)", re.IGNORECASE)
    return any(match.group("receiver") is None or match.group("receiver") in activity_names
               for match in pattern.finditer(expression))


def _known_unrelated_sink_receiver(code: str, method_body: str, operation: str,
                                   compatible_types: set[str]) -> bool:
    """Reject a sink-name collision only when local type evidence proves it unrelated."""
    receiver_match = re.match(r"(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*", operation)
    if not receiver_match:
        return False
    receiver = re.escape(receiver_match.group("receiver"))
    declaration = re.search(
        rf"(?:\b(?:final|var|val)\s+)?(?P<type>[A-Za-z_$][\w.$<>?\[\]]*)\s+{receiver}\b",
        method_body,
    )
    if not declaration:
        return False
    declared_type = declaration.group("type").split("<", 1)[0].rstrip("?[]")
    simple_type = declared_type.rsplit(".", 1)[-1]
    if simple_type in compatible_types:
        return False
    bases: dict[str, set[str]] = {}
    for match in re.finditer(
        r"\bclass\s+([A-Za-z_$][\w$]*)\s*(?:<[^>{}]*>)?([^{}]*)\{",
        code,
    ):
        header = match.group(2)
        parents: set[str] = set()
        extends = re.search(r"\bextends\s+([A-Za-z_$][\w.$]*)", header)
        implements = re.search(r"\bimplements\s+([A-Za-z_$][\w.$]*(?:\s*,\s*[A-Za-z_$][\w.$]*)*)", header)
        if extends:
            parents.add(extends.group(1).rsplit(".", 1)[-1])
        if implements:
            parents.update(item.strip().rsplit(".", 1)[-1] for item in implements.group(1).split(","))
        bases[match.group(1)] = parents
    # No source-local definition means we cannot prove what an external type does.
    if simple_type not in bases:
        return False
    pending = [simple_type]
    visited = set()
    while pending:
        current = pending.pop()
        if current in compatible_types:
            return False
        if current in visited:
            continue
        visited.add(current)
        pending.extend(bases.get(current, set()))
    return True


class TaintEngine:
    """Bounded lexical source-to-sink heuristic; not an exploit verifier."""

    def __init__(self) -> None:
        self._java_ast = JavaAstTaintAnalyzer()
        self.ast_coverage = {"available": self._java_ast.available, "files_parsed": 0,
                             "parse_fallbacks": 0, "static_status": "not_analyzed"}
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}

    @staticmethod
    def _tainted_return_summaries(
        code: str,
    ) -> dict[str, tuple[str, int, str, int | tuple[int, ...] | None, int, str | None]]:
        """Find simple same-file methods returning an explicitly modeled source.

        This is a deliberately narrow summary, not a Java/Kotlin call graph. It
        handles direct returns and local aliases; overload resolution, fields,
        callbacks, branches and polymorphism remain outside this heuristic.
        """
        summaries: dict[str, tuple[str, int, str, int | tuple[int, ...] | None, int]] = {}
        direct_sources = {
            "INTENT_EXTRA": r"getStringExtra|getIntExtra|getLongExtra|getFloatExtra|getDoubleExtra|getBooleanExtra|getByteArrayExtra|getStringArrayExtra|getStringArrayListExtra|getIntegerArrayListExtra|getParcelableExtra|getParcelableArrayExtra|getParcelableArrayListExtra|getSerializableExtra|getBundleExtra|getExtras|getCharSequenceExtra|getCharSequenceArrayExtra|getCharSequenceArrayListExtra|(?:[A-Za-z_$][\w$]*|getIntent\(\))\.getData(?:String)?",
            "URI_QUERY_PARAM": r"[A-Za-z_$][\w$]*\.getQueryParameter",
            "URI_COMPONENT": r"[A-Za-z_$][\w$]*\.(?:getPath|getLastPathSegment|getHost|getAuthority|getFragment)",
            "SHARED_PREFS_SOURCE": r"(?:prefs|preferences|sharedPrefs|sharedPreferences)\s*\.\s*getString|getSharedPreferences\s*\([^)]*\)\s*\.\s*getString",
        }
        scopes = list(method_spans(code))
        type_scopes = _type_scopes(code)
        method_name_counts: dict[str, int] = {}
        method_owners: dict[str, str | None] = {}
        for method_name, _, _ in scopes:
            method_name_counts[method_name] = method_name_counts.get(method_name, 0) + 1
        for name, offset, body in scopes:
            # This table is keyed by name, while overload resolution depends
            # on receiver/type/argument signature. Do not publish an ambiguous
            # summary that could taint calls to a different overload (or class).
            if method_name_counts[name] != 1:
                continue
            method_owners[name] = _enclosing_type(offset, type_scopes)
            local_body = _mask_nested_method_scopes(body, offset, scopes)
            # Keep type-name evidence local to the method. File-global name
            # sets can incorrectly let a Uri declaration in one method turn
            # an unrelated same-named receiver in another method into a source.
            header = local_body.split("{", 1)[0]
            signature = re.search(rf"\b{re.escape(name)}\s*\(([^)]*)\)", header)
            uri_parameters: dict[str, int] = {}
            intent_parameters: dict[str, int] = {}
            parameter_indices: dict[str, int] = {}
            intent_names: set[str] = set(re.findall(
                r"\b(?:android\.content\.)?Intent\s+([A-Za-z_$][\w$]*)", local_body))
            activity_names = set(re.findall(
                r"\b(?:android\.(?:app|x\.fragment\.app)|androidx\.appcompat\.app)\.(?:Activity|FragmentActivity|ComponentActivity|AppCompatActivity)\s+([A-Za-z_$][\w$]*)|\b(?:Activity|FragmentActivity|ComponentActivity|AppCompatActivity)\s+([A-Za-z_$][\w$]*)",
                local_body))
            activity_names = {name for pair in activity_names for name in pair if name}
            parameter_count = 0
            if signature:
                raw_parameters = signature.group(1)
                parameters: list[str] = []
                start = depth = 0
                for pos, char in enumerate(raw_parameters):
                    if char in "<([":
                        depth += 1
                    elif char in ">)]":
                        depth = max(0, depth - 1)
                    elif char == "," and depth == 0:
                        parameters.append(raw_parameters[start:pos].strip())
                        start = pos + 1
                if raw_parameters[start:].strip():
                    parameters.append(raw_parameters[start:].strip())
                parameter_count = len(parameters)
                for index, parameter in enumerate(parameters):
                    java_name = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\[\])?\s*$", parameter)
                    kotlin_name = re.search(r"([A-Za-z_$][\w$]*)\s*:\s*[^=]+$", parameter)
                    named_parameter = kotlin_name or java_name
                    if named_parameter:
                        parameter_indices[named_parameter.group(1)] = index
                    java_uri = re.search(r"(?:android\.net\.)?Uri\s+([A-Za-z_$][\w$]*)\s*$", parameter)
                    kotlin_uri = re.search(r"([A-Za-z_$][\w$]*)\s*:\s*(?:android\.net\.)?Uri\b", parameter)
                    typed_uri = java_uri or kotlin_uri
                    if typed_uri:
                        uri_parameters[typed_uri.group(1)] = index
                    java_intent = re.search(r"(?:android\.content\.)?Intent\s+([A-Za-z_$][\w$]*)\s*$", parameter)
                    kotlin_intent = re.search(r"([A-Za-z_$][\w$]*)\s*:\s*(?:android\.content\.)?Intent\b", parameter)
                    typed_intent = java_intent or kotlin_intent
                    if typed_intent:
                        intent_parameters[typed_intent.group(1)] = index
                        intent_names.add(typed_intent.group(1))
            alias_binding_scopes: dict[str, list[tuple[int, tuple[str, int, str, int | tuple[int, ...] | None, int] | None]]] = {}
            uri_binding_scopes: dict[str, list[tuple[int, bool]]] = {}

            def parameter_flow(expression: str, line_number: int, source_text: str):
                has_conditional_result = _conditional_question_index(expression) is not None
                expression = _conditional_result_expression(expression)
                referenced = [(parameter_name, parameter_index)
                              for parameter_name, parameter_index in parameter_indices.items()
                              if re.search(rf"\b{re.escape(parameter_name)}\b", expression)]
                if has_conditional_result and referenced:
                    dependencies = tuple(sorted({index for _, index in referenced}))
                    dependency: int | tuple[int, ...] = dependencies[0] if len(dependencies) == 1 else dependencies
                    return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                            dependency, parameter_count)
                calls = list(re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", expression))
                if calls:
                    # These transformations preserve an input-dependent value;
                    # an arbitrary helper may instead return a constant or
                    # enforce a security policy and is deliberately not inferred.
                    if len(calls) != 1:
                        return None
                    call = calls[0]
                    method = call.group(1)
                    allowed_instance = {"toString", "trim", "strip", "substring", "concat",
                                        "replace", "replaceAll", "toLowerCase", "toUpperCase"}
                    allowed_static = method == "valueOf" and re.match(r"\s*String\s*\.\s*valueOf\s*\(", expression)
                    for parameter_name, parameter_index in referenced:
                        instance_call = (method in allowed_instance and
                                         re.match(rf"\s*{re.escape(parameter_name)}\s*\.\s*{method}\s*\(", expression))
                        static_call = allowed_static and re.fullmatch(
                            rf"\s*String\s*\.\s*valueOf\s*\(\s*{re.escape(parameter_name)}\s*\)\s*;?", expression)
                        if instance_call or static_call:
                            return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                                    parameter_index, parameter_count)
                    return None
                if expression.count("?") == 1 and expression.count(":") == 1:
                    condition, branches = expression.split("?", 1)
                    when_true, when_false = branches.split(":", 1)
                    result_parameters = [(parameter_name, parameter_index)
                                         for parameter_name, parameter_index in parameter_indices.items()
                                         if (re.search(rf"\b{re.escape(parameter_name)}\b", when_true)
                                             or re.search(rf"\b{re.escape(parameter_name)}\b", when_false))]
                    if len(result_parameters) > 1:
                        return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                                tuple(sorted(index for _, index in result_parameters)), parameter_count)
                    if result_parameters:
                        return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                                result_parameters[0][1], parameter_count)
                if len(referenced) > 1 and "+" in expression:
                    return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                            tuple(sorted(index for _, index in referenced)), parameter_count)
                for parameter_name, parameter_index in referenced:
                    if re.fullmatch(rf"\s*{re.escape(parameter_name)}\s*", expression) or "+" in expression:
                        return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                                parameter_index, parameter_count)
                return None

            def summarized_expression(expression: str, line_number: int, source_text: str):
                original_expression = expression
                expression = _conditional_result_expression(expression)
                inherited = [value for variable, value in aliases.items()
                             if re.search(rf"\b{re.escape(variable)}\b", expression)]
                direct_parameter = parameter_flow(original_expression, line_number, source_text)
                non_parameter_sources = [value for value in inherited
                                         if value[0] != "PARAMETER_PASSTHROUGH"]
                if non_parameter_sources:
                    return non_parameter_sources[0]
                parameter_indices_used: set[int] = set()
                for value in inherited:
                    if value[0] != "PARAMETER_PASSTHROUGH":
                        continue
                    dependency = value[3]
                    if isinstance(dependency, tuple):
                        parameter_indices_used.update(dependency)
                    elif dependency is not None:
                        parameter_indices_used.add(dependency)
                if direct_parameter:
                    dependency = direct_parameter[3]
                    if isinstance(dependency, tuple):
                        parameter_indices_used.update(dependency)
                    elif dependency is not None:
                        parameter_indices_used.add(dependency)
                if len(parameter_indices_used) > 1:
                    return ("PARAMETER_PASSTHROUGH", line_number, source_text,
                            tuple(sorted(parameter_indices_used)), parameter_count)
                if inherited:
                    return inherited[0]
                return direct_parameter

            for rel_offset, statement in TaintEngine._statements(local_body):
                line = code.count("\n", 0, offset + rel_offset) + 1
                statement_depth = local_body[:rel_offset].count("{") - local_body[:rel_offset].count("}")
                for variable, stack in list(uri_binding_scopes.items()):
                    while stack and stack[-1][0] > statement_depth:
                        stack.pop()
                    if not stack:
                        uri_binding_scopes.pop(variable, None)
                uri_names = {variable for variable, stack in uri_binding_scopes.items()
                             if stack and stack[-1][1]}
                for variable, stack in list(alias_binding_scopes.items()):
                    while stack and stack[-1][0] > statement_depth:
                        stack.pop()
                    if not stack:
                        alias_binding_scopes.pop(variable, None)
                aliases = {variable: stack[-1][1] for variable, stack in alias_binding_scopes.items()
                           if stack and stack[-1][1] is not None}
                assignment = _ASSIGN_RE.search(statement)
                if assignment:
                    lhs, rhs = assignment.group(1), assignment.group(2)
                    prefix = statement[:assignment.start(1)]
                    typed_uri = bool(re.search(r"(?:android\.net\.)?Uri\s+$", prefix)
                                     or re.search(r"\b(?:val|var)\s+[A-Za-z_$][\w$]*\s*:\s*(?:android\.net\.)?Uri\b", statement))
                    was_uri = lhs in uri_names
                    value_rhs = _conditional_result_expression(rhs)
                    alias_from_uri = any(re.search(rf"\b{re.escape(uri_name)}\b", value_rhs)
                                         for uri_name in uri_names if uri_name != lhs)
                    data_read = re.search(r"(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*getData\s*\(|\b(?:this\.)?getIntent\(\)\s*\.\s*getData\s*\(",
                                          value_rhs, re.IGNORECASE)
                    external_data = bool((was_uri or typed_uri) and data_read and
                                         (data_read.group("receiver") is None or data_read.group("receiver") in intent_names))
                    now_uri = (lhs in _intent_data_uri_names(f"val {lhs} = {value_rhs}", intent_names) or external_data
                               or ((was_uri or typed_uri) and alias_from_uri))
                    uri_stack = uri_binding_scopes.setdefault(lhs, [])
                    uri_declaration = typed_uri and bool(re.search(
                        r"(?:\b(?:val|var)\s+|(?:final\s+)?(?:android\.net\.)?Uri\s+)$", prefix))
                    bind_depth = statement_depth if uri_declaration or not uri_stack else uri_stack[-1][0]
                    if uri_stack and uri_stack[-1][0] == bind_depth:
                        uri_stack[-1] = (bind_depth, now_uri)
                    else:
                        uri_stack.append((bind_depth, now_uri))
                    uri_names = {variable for variable, entries in uri_binding_scopes.items()
                                 if entries and entries[-1][1]}
                    source_statement = statement
                    # In a Java conditional expression, sources in the
                    # condition control which value is selected but do not
                    # themselves become that value. Inspect only the result
                    # arms for assignment-source matches.
                    assignment_rhs_start = assignment.start(2) if assignment else -1
                    question_mark = _conditional_question_index(statement, assignment_rhs_start)
                    if question_mark is not None:
                        source_statement = statement[:assignment_rhs_start] + statement[question_mark + 1:]
                    source_match = next(((kind, pattern.search(source_statement))
                                         for kind, pattern in _SOURCE_PATTERNS if pattern.search(source_statement)), None)
                    if source_match:
                        kind, source_call = source_match
                        parameter_index = None
                        if kind == "INTENT_SOURCE" and not _has_modeled_get_intent(statement, activity_names):
                            source_match = None
                        if kind == "INTENT_EXTRA":
                            intent_call = _INTENT_EXTRA_CALL_RE.search(statement)
                            if intent_call:
                                receiver = intent_call.group("receiver")
                                if receiver in intent_parameters:
                                    parameter_index = intent_parameters[receiver]
                                elif not (receiver in aliases and aliases[receiver][0] == "INTENT_SOURCE"):
                                    source_match = None
                            elif not _has_modeled_get_intent(statement, activity_names):
                                source_match = None
                        if kind in {"URI_QUERY_PARAM", "URI_COMPONENT"}:
                            receiver = source_call.group("receiver")
                            if receiver not in uri_names:
                                if receiver not in uri_parameters:
                                    source_match = None
                                else:
                                    parameter_index = uri_parameters[receiver]
                        source_value = ((kind, line, statement.strip(), parameter_index, parameter_count)
                                        if source_match else None)
                    else:
                        source_value = summarized_expression(rhs, line, statement.strip())
                    alias_stack = alias_binding_scopes.setdefault(lhs, [])
                    prefix = statement[:assignment.start(1)]
                    is_declaration = bool(re.search(
                        r"(?:\b(?:val|var)\s+|(?:\b(?:final\s+)?[A-Za-z_$][\w.$<>?\[\]]*\s+))$", prefix))
                    bind_depth = statement_depth if is_declaration or not alias_stack else alias_stack[-1][0]
                    if alias_stack and alias_stack[-1][0] == bind_depth:
                        alias_stack[-1] = (bind_depth, source_value)
                    else:
                        alias_stack.append((bind_depth, source_value))
                    aliases = {variable: entries[-1][1] for variable, entries in alias_binding_scopes.items()
                               if entries and entries[-1][1] is not None}
                returned = re.search(r"\breturn\s+([^;]+)", statement)
                if not returned:
                    continue
                expression = returned.group(1)
                for kind, pattern in direct_sources.items():
                    match = re.search(rf"\b(?:{pattern})\s*\(", expression, re.I)
                    if match:
                        parameter_index = None
                        if kind == "INTENT_EXTRA":
                            intent_call = _INTENT_EXTRA_CALL_RE.search(expression)
                            if intent_call:
                                receiver = intent_call.group("receiver")
                                if receiver in intent_parameters:
                                    parameter_index = intent_parameters[receiver]
                                elif not (receiver in aliases and aliases[receiver][0] == "INTENT_SOURCE"):
                                    continue
                            elif not _has_modeled_get_intent(expression, activity_names):
                                continue
                        if kind == "URI_QUERY_PARAM":
                            uri_call = _URI_QUERY_PARAMETER_CALL_RE.search(expression)
                            if not uri_call:
                                continue
                            receiver = uri_call.group("receiver")
                            if receiver not in uri_names:
                                if receiver not in uri_parameters:
                                    continue
                                parameter_index = uri_parameters[receiver]
                        if kind == "URI_COMPONENT":
                            uri_call = _URI_COMPONENT_CALL_RE.search(expression)
                            if not uri_call:
                                continue
                            receiver = uri_call.group("receiver")
                            if receiver not in uri_names:
                                if receiver not in uri_parameters:
                                    continue
                                parameter_index = uri_parameters[receiver]
                        summaries[name] = (kind, line, statement.strip(), parameter_index, parameter_count)
                        break
                else:
                    parameter_summary = summarized_expression(expression, line, statement.strip())
                    if parameter_summary:
                        previous_summary = summaries.get(name)
                        if previous_summary and previous_summary[0] == "PARAMETER_PASSTHROUGH":
                            previous_dependency = previous_summary[3]
                            current_dependency = parameter_summary[3]
                            merged_dependencies = set(previous_dependency if isinstance(previous_dependency, tuple)
                                                      else (() if previous_dependency is None or previous_dependency == -1
                                                            else (previous_dependency,)))
                            merged_dependencies.update(current_dependency if isinstance(current_dependency, tuple)
                                                       else (() if current_dependency is None or current_dependency == -1
                                                             else (current_dependency,)))
                            parameter_summary = (
                                "PARAMETER_PASSTHROUGH", parameter_summary[1], parameter_summary[2],
                                tuple(sorted(merged_dependencies)) if len(merged_dependencies) > 1
                                else next(iter(merged_dependencies), parameter_summary[3]), parameter_count,
                            )
                        # A modeled source returned by any branch is a valid
                        # taint path; don't erase it with a later parameter-only
                        # return. Otherwise merge branch return dependencies.
                        if previous_summary is None or previous_summary[0] == "PARAMETER_PASSTHROUGH":
                            summaries[name] = parameter_summary
        return {name: (*summary, method_owners.get(name)) for name, summary in summaries.items()}

    @staticmethod
    def _external_intent_parameters(method_name: str, method_body: str) -> list[str]:
        """Return Intent parameter names for Android callback-shaped methods.

        This is a lexical callback signature model; it does not establish that
        the class overrides the framework callback or that its component is
        externally reachable. Those require symbol and manifest resolution.
        """
        callback_names = {"onNewIntent", "onReceive", "onActivityResult",
                          "onStartCommand", "onHandleIntent"}
        if method_name not in callback_names:
            return []
        header = method_body.split("{", 1)[0]
        signature = re.search(rf"\b{re.escape(method_name)}\s*\(([^)]*)\)", header)
        if not signature:
            return []
        result = []
        # The framework Intent is the third onActivityResult argument; receiver
        # and service callbacks also carry an Intent. A name/type check avoids
        # marking Bundle and primitive callback parameters as tainted.
        for parameter in signature.group(1).split(","):
            java = re.search(r"\bIntent\s+([A-Za-z_$][\w$]*)\b", parameter)
            kotlin = re.search(r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:android\.content\.)?Intent\b", parameter)
            match = java or kotlin
            if match:
                result.append(match.group(1))
        return result

    @staticmethod
    def _tainted_parameter_sink_summaries(
        code: str,
    ) -> dict[str, list[tuple[int, int, dict[str, Any], str, str | None]]]:
        """Summarize same-file methods that pass a parameter to a modeled sink.

        The summary is lexical and name-based. It intentionally emits only an
        unverified lead; overload resolution and path/guard analysis are absent.
        """
        summaries: dict[str, list[tuple[int, int, dict[str, Any], str, str | None]]] = {}
        scopes = list(method_spans(code))
        type_scopes = _type_scopes(code)
        method_name_counts: dict[str, int] = {}
        for method_name, _, _ in scopes:
            method_name_counts[method_name] = method_name_counts.get(method_name, 0) + 1
        for name, _offset, body in scopes:
            # Summaries are keyed by name rather than class/signature. Do not
            # merge sink behavior across overloads or same-named methods in
            # unrelated classes; unresolved calls remain unmodeled.
            if method_name_counts[name] != 1:
                continue
            header = body.split("{", 1)[0]
            signature = re.search(rf"\b{re.escape(name)}\s*\(([^)]*)\)", header)
            if not signature:
                continue
            raw_params = signature.group(1)
            params, start, depth = [], 0, 0
            for index, char in enumerate(raw_params):
                if char in "<([": depth += 1
                elif char in ">)]": depth = max(0, depth - 1)
                elif char == "," and depth == 0:
                    params.append(raw_params[start:index].strip()); start = index + 1
            tail = raw_params[start:].strip()
            if tail: params.append(tail)
            param_names = []
            for param in params:
                kotlin = re.match(r"(?:vararg\s+)?([A-Za-z_$][\w$]*)\s*:", param)
                java = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\[\])?\s*$", param)
                match = kotlin or java
                param_names.append(match.group(1) if match else "")
            for sink in _SINK_SPECS:
                operation = sink["pattern"].pattern.removesuffix(r"\s*\(")
                declaration = re.search(rf"\b{re.escape(name)}\s*\(", body)
                for call in call_sites(body, operation):
                    if declaration and call.offset == declaration.start():
                        continue
                    relevant = call.code_args[:1] if sink["type"] in {"SQLI", "INTENT_REDIRECTION", "WEBVIEW_NAVIGATION", "WEBVIEW_JAVASCRIPT"} else call.code_args
                    for param_index, param_name in enumerate(param_names):
                        if param_name and any(re.search(rf"\b{re.escape(param_name)}\b", arg) for arg in relevant):
                            summaries.setdefault(name, []).append((
                                param_index, len(params), sink,
                                call.code_args[0] if call.code_args else "",
                                _enclosing_type(_offset, type_scopes),
                            ))
        return summaries

    def analyze_source_content(self, content: str, file_path: str = "") -> list[Finding]:
        """Analyze a single Java/Kotlin file's source code for source-to-sink taint propagation."""
        findings: list[Finding] = []
        code = mask_non_code(content)
        tainted_returns = self._tainted_return_summaries(code)
        tainted_parameters = self._tainted_parameter_sink_summaries(code)
        scopes = list(method_spans(code))
        type_scopes = _type_scopes(code)
        if not scopes:
            scopes = [("unscoped", 0, code)]
        for _name, scope_offset, body in scopes:
            local_code = _mask_nested_method_scopes(body, scope_offset, scopes)
            # Method-local type evidence prevents arbitrary model objects that
            # happen to expose a similarly named method from becoming Android
            # Intent sources. This remains lexical and does not prove external
            # reachability of the Intent itself.
            intent_names = set(re.findall(r"\b(?:android\.content\.)?Intent\s+([A-Za-z_$][\w$]*)", local_code))
            intent_names.update(re.findall(
                r"\b(?:val|var)\s+([A-Za-z_$][\w$]*)\s*:\s*(?:android\.content\.)?Intent\b", local_code))
            intent_names.update(re.findall(
                r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:android\.content\.)?Intent\b", local_code))
            activity_matches = re.findall(
                r"\b(?:android\.(?:app|x\.fragment\.app)|androidx\.appcompat\.app)\.(?:Activity|FragmentActivity|ComponentActivity|AppCompatActivity)\s+([A-Za-z_$][\w$]*)|\b(?:Activity|FragmentActivity|ComponentActivity|AppCompatActivity)\s+([A-Za-z_$][\w$]*)",
                local_code)
            activity_names = {name for pair in activity_matches for name in pair if name}
            clipboard_names = set(re.findall(r"\b(?:android\.content\.)?ClipboardManager\s+([A-Za-z_$][\w$]*)", local_code))
            clipboard_names.update(re.findall(
                r"\b(?:val|var)\s+([A-Za-z_$][\w$]*)\s*:\s*(?:android\.content\.)?ClipboardManager\b", local_code))
            clipboard_names.update(re.findall(
                r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:android\.content\.)?ClipboardManager\b", local_code))
            # Track URI provenance with the same lexical shadowing model as
            # taint bindings. A flat set either survived safe reassignment or
            # lost an outer binding when a nested local shadowed its name.
            uri_binding_scopes: dict[str, list[tuple[int, bool]]] = {}
            # Nested methods have independent local bindings; do not also analyze
            # their contents using the enclosing method's values.
            binding_scopes: dict[str, list[tuple[int, TaintTrace | None]]] = {}
            depth_at = [0] * (len(local_code) + 1)
            current_depth = 0
            for char_index, char in enumerate(local_code):
                depth_at[char_index] = current_depth
                if char == "{":
                    current_depth += 1
                elif char == "}":
                    current_depth = max(0, current_depth - 1)
            depth_at[len(local_code)] = current_depth
            first_open = local_code.find("{")
            # Parameters belong to the method scope outside its body block,
            # so their binding depth must be the depth immediately before the
            # opening brace (otherwise the signature statement prunes them).
            method_depth = depth_at[first_open] if first_open >= 0 else 0

            def visible_bindings(depth: int) -> dict[str, TaintTrace]:
                visible: dict[str, TaintTrace] = {}
                for variable, stack in binding_scopes.items():
                    for binding_depth, trace in reversed(stack):
                        if binding_depth <= depth:
                            if trace is not None:
                                visible[variable] = trace
                            break
                return visible

            def lookup_binding(variable: str, depth: int) -> TaintTrace | None:
                for binding_depth, trace in reversed(binding_scopes.get(variable, [])):
                    if binding_depth <= depth:
                        return trace
                return None

            declaration_match = re.search(rf"\b{re.escape(_name)}\s*\(", body)
            declaration_name_offset = (scope_offset + declaration_match.start()) if declaration_match else None
            for parameter in self._external_intent_parameters(_name, body):
                callback_line_offset = declaration_name_offset if declaration_name_offset is not None else scope_offset
                line_idx = code.count("\n", 0, callback_line_offset) + 1
                binding_scopes[parameter] = [(method_depth, TaintTrace(
                    parameter, "ANDROID_CALLBACK_INTENT_PARAMETER", line_idx,
                    body.split("{", 1)[0].strip(), {parameter},
                    [f"L{line_idx}: {parameter} is a callback-shaped Intent parameter"],
                ))]
            for offset, statement in self._statements(local_code):
                statement_depth = depth_at[min(offset, len(local_code))]
                for variable, stack in list(binding_scopes.items()):
                    while stack and stack[-1][0] > statement_depth:
                        stack.pop()
                    if not stack:
                        binding_scopes.pop(variable, None)
                for variable, stack in list(uri_binding_scopes.items()):
                    while stack and stack[-1][0] > statement_depth:
                        stack.pop()
                    if not stack:
                        uri_binding_scopes.pop(variable, None)
                uri_names = {variable for variable, stack in uri_binding_scopes.items()
                             if stack and stack[-1][1]}
                clean = statement.strip()
                if not clean:
                    continue
                line_idx = code.count("\n", 0, scope_offset + offset) + 1
                assignment = _ASSIGN_RE.search(statement)
                if assignment:
                    uri_lhs, uri_rhs = assignment.group(1), assignment.group(2)
                    prefix = statement[:assignment.start(1)]
                    typed_uri = bool(re.search(r"(?:android\.net\.)?Uri\s+$", prefix)
                                     or re.search(r"\b(?:val|var)\s+[A-Za-z_$][\w$]*\s*:\s*(?:android\.net\.)?Uri\b", statement))
                    value_rhs = _conditional_result_expression(uri_rhs)
                    was_uri = uri_lhs in uri_names
                    alias_from_uri = any(re.search(rf"\b{re.escape(uri_name)}\b", value_rhs)
                                         for uri_name in uri_names if uri_name != uri_lhs)
                    data_read = re.search(r"(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*getData\s*\(|\b(?:this\.)?getIntent\(\)\s*\.\s*getData\s*\(",
                                          value_rhs, re.IGNORECASE)
                    intent_data_read = bool((was_uri or typed_uri) and data_read and
                                            (data_read.group("receiver") is None or data_read.group("receiver") in intent_names))
                    now_uri = (uri_lhs in _intent_data_uri_names(f"val {uri_lhs} = {value_rhs}", intent_names) or intent_data_read
                               or ((was_uri or typed_uri) and alias_from_uri))
                    uri_stack = uri_binding_scopes.setdefault(uri_lhs, [])
                    uri_declaration = typed_uri and bool(re.search(r"(?:\b(?:val|var)\s+|(?:final\s+)?(?:android\.net\.)?Uri\s+)$", prefix))
                    bind_depth = statement_depth if uri_declaration or not uri_stack else uri_stack[-1][0]
                    if uri_stack and uri_stack[-1][0] == bind_depth:
                        uri_stack[-1] = (bind_depth, now_uri)
                    else:
                        uri_stack.append((bind_depth, now_uri))
                    uri_names = {variable for variable, entries in uri_binding_scopes.items()
                                 if entries and entries[-1][1]}
                if assignment:
                    lhs, rhs = assignment.group(1), assignment.group(2)
                    visible_before = visible_bindings(statement_depth)
                    value_rhs = _conditional_result_expression(rhs)
                    previous = next((t for v, t in visible_before.items()
                                     if re.search(rf"\b{re.escape(v)}\b", value_rhs)), None)
                    prefix = statement[:assignment.start(1)]
                    is_declaration = bool(re.search(
                        r"(?:\b(?:val|var)\s+|(?:\b(?:final\s+)?[A-Za-z_$][\w.$<>?\[\]]*\s+))$",
                        prefix))
                    source_candidate = clean
                    assignment_rhs_start = assignment.start(2) if assignment else -1
                    question_mark = _conditional_question_index(statement, assignment_rhs_start)
                    if question_mark is not None:
                        source_candidate = (statement[:assignment_rhs_start]
                                            + statement[question_mark + 1:]).strip()
                    source = next(((kind, pat.search(source_candidate))
                                   for kind, pat in _SOURCE_PATTERNS if pat.search(source_candidate)), None)
                    if source and source[0] == "INTENT_SOURCE" and not _has_modeled_get_intent(clean, activity_names):
                        source = None
                    if source and source[0] == "INTENT_EXTRA":
                        intent_read = _INTENT_EXTRA_CALL_RE.search(clean)
                        if ((intent_read and intent_read.group("receiver") not in intent_names)
                                or (not intent_read and not _has_modeled_get_intent(clean, activity_names))):
                            source = None
                    if source and source[0] == "CLIPBOARD_SOURCE":
                        clipboard_read = _CLIPBOARD_CALL_RE.search(clean)
                        if clipboard_read and clipboard_read.group("receiver") not in clipboard_names:
                            source = None
                    if source and source[0] == "URI_QUERY_PARAM":
                        if source[1].group("receiver") not in uri_names:
                            source = None
                    if source and source[0] == "URI_COMPONENT":
                        if source[1].group("receiver") not in uri_names:
                            source = None
                    # `getString()` is ubiquitous (JSON, resources, SDK models,
                    # SharedPreferences). Treating every call as a taint source
                    # caused unrelated values to appear attacker-controlled.
                    # Keep this source limited to explicit preference receivers;
                    # this heuristic intentionally does not infer field types.
                    pref_call = re.search(
                        r"\b(?:prefs|preferences|sharedPrefs|sharedPreferences)\s*\.\s*getString\s*\(|"
                        r"\bgetSharedPreferences\s*\([^)]*\)\s*\.\s*getString\s*\(", clean, re.I)
                    if source is None and pref_call:
                        source = ("SHARED_PREFS_SOURCE", pref_call)
                    stack = binding_scopes.setdefault(lhs, [])
                    if is_declaration and (not stack or stack[-1][0] != statement_depth):
                        stack.append((statement_depth, None))
                    elif not stack:
                        stack.append((statement_depth, None))
                    if source:
                        stack[-1] = (stack[-1][0], TaintTrace(lhs, source[0], line_idx, clean, {lhs}, [f"L{line_idx}: {lhs} from {source[0]}"]))
                    elif previous:
                        stack[-1] = (stack[-1][0], TaintTrace(previous.source_var, previous.source_type, previous.source_line,
                            previous.source_snippet, {lhs}, previous.propagation_steps + [f"L{line_idx}: {lhs} assigned"]))
                    else:
                        stack[-1] = (stack[-1][0], None)  # A safe reassignment kills this binding.
                visible = visible_bindings(statement_depth)
                for sink in _SINK_SPECS:
                    operation = sink["pattern"].pattern.removesuffix(r"\s*\(")
                    for call in call_sites(clean, operation):
                        compatible_types = (
                            {"WebView"} if sink["type"] in {"WEBVIEW_NAVIGATION", "WEBVIEW_JAVASCRIPT"}
                            else {"SQLiteDatabase", "SupportSQLiteDatabase"}
                            if sink["type"] == "SQLI" else set()
                        )
                        if sink["type"] == "INTENT_REDIRECTION":
                            invoked_method = call.operation.rsplit(".", 1)[-1]
                            compatible_types = ({"Activity", "ActivityCompat"}
                                                if invoked_method == "startActivityForResult"
                                                else {"Context", "ContextWrapper", "Activity", "Service",
                                                      "Application", "ContextCompat"})
                        if sink["type"] == "UNSAFE_REFLECTION":
                            invoked_method = call.operation.rsplit(".", 1)[-1]
                            compatible_types = {"ClassLoader"} if invoked_method == "loadClass" else {"Class"}
                        sink_receiver = re.search(r"([A-Za-z_$][\w$]*)\s*\.\s*$", clean[:call.offset])
                        sink_operation = (f"{sink_receiver.group(1)}.{call.operation}"
                                          if sink_receiver else call.operation)
                        if (compatible_types and _known_unrelated_sink_receiver(
                                code, body, sink_operation, compatible_types)):
                            continue
                        # SQL bound selectionArgs are not query syntax. Likewise
                        # launch request codes and WebView header maps are not the
                        # launched Intent/loaded URL value.
                        relevant = call.code_args[:1] if sink["type"] in {"SQLI", "INTENT_REDIRECTION", "WEBVIEW_NAVIGATION", "WEBVIEW_JAVASCRIPT", "UNSAFE_REFLECTION"} else call.code_args
                        context = " ".join(relevant)
                        direct_value_context = _mask_call_inputs(context)
                        trace = next((t for v, t in visible.items()
                                      if re.search(rf"\b{re.escape(v)}\b", direct_value_context)), None)
                        helper = next((method for method in tainted_returns
                                       if re.search(rf"\b{re.escape(method)}\s*\(", context)), None)
                        helper_call_sites = (list(call_sites(context, rf"\b{re.escape(helper)}"))
                                             if helper else [])
                        if helper and tainted_returns[helper][5]:
                            summary_owner = tainted_returns[helper][5]
                            caller_type = _enclosing_type(scope_offset, type_scopes)
                            compatible_calls = []
                            for helper_call in helper_call_sites:
                                receiver_match = re.search(
                                    r"(?P<receiver>this|super|[A-Za-z_$][\w$]*)\s*\.\s*$",
                                    context[:helper_call.offset],
                                )
                                receiver_name = receiver_match.group("receiver") if receiver_match else None
                                if receiver_name in {"this", "super"}:
                                    if caller_type != summary_owner:
                                        continue
                                elif receiver_name and receiver_name != summary_owner:
                                    declared_type = _declared_receiver_type(body, receiver_name)
                                    if declared_type is None:
                                        declared_type = _declared_receiver_type(
                                            _enclosing_type_members(code, scope_offset, type_scopes, scopes),
                                            receiver_name,
                                        )
                                    if declared_type and declared_type != summary_owner:
                                        continue
                                compatible_calls.append(helper_call)
                            helper_call_sites = compatible_calls
                            if not helper_call_sites:
                                helper = None
                        if helper and (trace is None or tainted_returns[helper][3] is not None):
                                kind, source_line, source_snippet, parameter_index, parameter_count, _summary_owner = tainted_returns[helper]
                                if parameter_index is None:
                                    if trace is None:
                                        trace = TaintTrace(helper, kind, source_line, source_snippet,
                                                           {helper}, [f"L{source_line}: {helper} returns modeled source"])
                                else:
                                    for helper_call in helper_call_sites:
                                        if len(helper_call.code_args) != parameter_count:
                                            continue
                                        indices = (parameter_index if isinstance(parameter_index, tuple)
                                                   else range(parameter_count) if kind == "PARAMETER_PASSTHROUGH" and parameter_index == -1
                                                   else (parameter_index,))
                                        for argument_index in indices:
                                            if argument_index < 0 or argument_index >= len(helper_call.code_args):
                                                continue
                                            helper_arg = helper_call.code_args[argument_index]
                                            argument_trace = next((t for variable, t in visible.items()
                                                                   if re.search(rf"\b{re.escape(variable)}\b", helper_arg)), None)
                                            if argument_trace is not None:
                                                effective_kind = argument_trace.source_type if kind == "PARAMETER_PASSTHROUGH" else kind
                                                effective_line = argument_trace.source_line if kind == "PARAMETER_PASSTHROUGH" else source_line
                                                effective_snippet = argument_trace.source_snippet if kind == "PARAMETER_PASSTHROUGH" else source_snippet
                                                trace = TaintTrace(helper, effective_kind, effective_line, effective_snippet,
                                                                   {helper}, argument_trace.propagation_steps +
                                                                   [f"L{source_line}: {helper} returns modeled source from parameter {argument_index}"])
                                                break
                                        if trace is not None:
                                            break
                        inline_uri_call = _URI_QUERY_PARAMETER_CALL_RE.search(context)
                        valid_inline_uri = bool(inline_uri_call and inline_uri_call.group("receiver") in uri_names
                                                and not _is_nested_in_call(context, inline_uri_call.start()))
                        inline_component_call = _URI_COMPONENT_CALL_RE.search(context)
                        valid_inline_component = bool(inline_component_call and inline_component_call.group("receiver") in uri_names
                                                     and not _is_nested_in_call(context, inline_component_call.start()))
                        if valid_inline_uri:
                            trace = TaintTrace(inline_uri_call.group("receiver"), "URI_QUERY_PARAM", line_idx,
                                               clean, {inline_uri_call.group("receiver")},
                                               (trace.propagation_steps if trace else []) +
                                               [f"L{line_idx}: inline URI query parameter reaches {sink['type']}"])
                        elif valid_inline_component:
                            trace = TaintTrace(inline_component_call.group("receiver"), "URI_COMPONENT", line_idx,
                                               clean, {inline_component_call.group("receiver")},
                                               (trace.propagation_steps if trace else []) +
                                               [f"L{line_idx}: inline URI component reaches {sink['type']}"])
                        inline_intent_call = _INLINE_INTENT_EXTRA_RE.search(context)
                        valid_inline_intent = bool(inline_intent_call and inline_intent_call.group("receiver") in intent_names
                                                   and not _is_nested_in_call(context, inline_intent_call.start()))
                        inline_clipboard = _CLIPBOARD_CALL_RE.search(context)
                        valid_inline_clipboard = bool(inline_clipboard and inline_clipboard.group("receiver") in clipboard_names
                                                      and not _is_nested_in_call(context, inline_clipboard.start()))
                        generic_inline = _INLINE_SOURCE_RE.search(context)
                        valid_generic_inline = bool(generic_inline and not _is_nested_in_call(context, generic_inline.start()))
                        inline_intent_accessor = _INLINE_GETINTENT_ACCESSOR_RE.search(context)
                        qualified_intent_accessor = _QUALIFIED_GETINTENT_ACCESSOR_RE.search(context)
                        valid_qualified_accessor = bool(qualified_intent_accessor
                            and qualified_intent_accessor.group("receiver") in activity_names
                            and not _is_nested_in_call(context, qualified_intent_accessor.start()))
                        qualified_get_intent = _QUALIFIED_GETINTENT_RE.search(context)
                        valid_qualified_get_intent = bool(qualified_get_intent
                            and qualified_get_intent.group("receiver") in activity_names
                            and not _is_nested_in_call(context, qualified_get_intent.start()))
                        if ((inline_intent_accessor and not _is_nested_in_call(context, inline_intent_accessor.start()))
                                or valid_qualified_accessor):
                            source_var = qualified_intent_accessor.group("receiver") + ".getIntent()" if valid_qualified_accessor else "getIntent()"
                            trace = TaintTrace(source_var, "INTENT_EXTRA", line_idx, clean,
                                               {source_var}, [f"L{line_idx}: {source_var} accessor reaches {sink['type']}"])
                        elif valid_qualified_get_intent:
                            source_var = qualified_get_intent.group("receiver") + ".getIntent()"
                            trace = TaintTrace(source_var, "INTENT_SOURCE", line_idx, clean,
                                               {source_var}, [f"L{line_idx}: {source_var} reaches {sink['type']}"])
                        elif valid_generic_inline:
                            trace = TaintTrace("getIntent()", "INTENT_SOURCE", line_idx, clean,
                                               {"getIntent()"}, [f"L{line_idx}: getIntent() reaches {sink['type']}"])
                        if (trace is None and not valid_generic_inline and not valid_inline_intent
                                and not valid_qualified_get_intent and not valid_qualified_accessor
                                and not valid_inline_clipboard and not valid_inline_uri and not valid_inline_component):
                            continue
                        origin = f"{trace.source_var} ({trace.source_type}), line {trace.source_line}" if trace else "inline input source"
                        flow_kind = ("same_file_tainted_return_summary" if trace and trace.source_var in tainted_returns
                                     else "direct_callback_parameter" if trace and trace.source_type == "ANDROID_CALLBACK_INTENT_PARAMETER"
                                     else "intra_method_lexical_flow")
                        stored_preference = bool(trace and trace.source_type == "SHARED_PREFS_SOURCE")
                        finding_title = (f"Stored Preference Value Flow Candidate to {sink['type']}"
                                         if stored_preference else sink["title"])
                        finding_description = (f"Potential flow from {origin} to {sink['type']}. "
                            "Straight-line lexical heuristic only: method calls, branch conditions, sanitization and external reachability require review; no exploit is established.")
                        if stored_preference:
                            finding_description += " The value is app-persisted; who can write or modify it is not established, so attacker control is not proven."
                        findings.append(Finding(
                            title=finding_title, description=finding_description,
                            severity=Severity.INFO if stored_preference else sink["severity"], confidence=0.5, cwe_id=sink["cwe"], cvss_score=0.0,
                            cvss_vector="", owasp_masvs=sink["masvs"], affected_component=file_path or "UnknownClass",
                            file_path=file_path, line_number=line_idx, code_snippet=clean[:1000],
                            detection_method="TaintEngine (bounded lexical flow)", status=FindingStatus.UNVERIFIED,
                            remediation=sink["remediation"],
                            metadata={"proof_state": "not_proven", "analysis_kind": "bounded_lexical_flow",
                                      "source_kind": trace.source_type if trace else "inline_input_source",
                                      "source_control_status": "app_persisted_value_origin_not_established" if stored_preference else "modeled_source_not_reachability_proof",
                                      "source_reachability": "callback_signature_only" if trace and trace.source_type == "ANDROID_CALLBACK_INTENT_PARAMETER" else "not_established",
                                      "control_flow": "not_implemented",
                                      "interprocedural_value_flow": flow_kind},
                        ))

                # Propagate tainted arguments through same-file helper methods
                # whose parameter is lexically passed to a modeled sink.
                for helper, summaries in tainted_parameters.items():
                    for call in call_sites(clean, rf"\b{re.escape(helper)}"):
                        # `call_sites` is lexical and also sees a method's own
                        # declaration header. Do not treat that declaration as
                        # a call (which otherwise self-taints callback params).
                        clean_offset = statement.find(clean)
                        absolute_call = scope_offset + offset + max(clean_offset, 0) + call.offset
                        if absolute_call == declaration_name_offset:
                            continue
                        call_receiver = re.search(
                            r"(?P<receiver>this|super|[A-Za-z_$][\w$]*)\s*\.\s*$",
                            clean[:call.offset],
                        )
                        receiver_name = call_receiver.group("receiver") if call_receiver else None
                        caller_type = _enclosing_type(scope_offset, type_scopes)
                        for param_index, param_count, sink, _sink_arg, summary_owner in summaries:
                            if summary_owner and receiver_name:
                                if receiver_name in {"this", "super"}:
                                    if caller_type != summary_owner:
                                        continue
                                elif receiver_name != summary_owner:
                                    declared_type = _declared_receiver_type(body, receiver_name)
                                    if declared_type is None:
                                        type_members = _enclosing_type_members(
                                            code, scope_offset, type_scopes, scopes)
                                        declared_type = _declared_receiver_type(type_members, receiver_name)
                                    if declared_type and declared_type != summary_owner:
                                        continue
                            if len(call.code_args) != param_count or param_index >= len(call.code_args):
                                continue
                            arg = call.code_args[param_index]
                            trace = next((t for var, t in visible.items()
                                          if re.search(rf"\b{re.escape(var)}\b", arg)), None)
                            if trace is None:
                                continue
                            stored_preference = trace.source_type == "SHARED_PREFS_SOURCE"
                            helper_title = (f"Stored Preference Value Flow Candidate to {sink['type']}"
                                            if stored_preference else sink["title"])
                            findings.append(Finding(
                                title=helper_title,
                                description=(f"Potential same-file helper flow from {trace.source_var} "
                                             f"({trace.source_type}), line {trace.source_line}, through "
                                             f"{helper}() to {sink['type']}. Method resolution, guards, "
                                             "path conditions and external reachability are not analyzed; no exploit is established."
                                             + (" The preference value's writer/integrity is not established, so attacker control is unproven." if stored_preference else "")),
                                severity=Severity.INFO if stored_preference else sink["severity"], confidence=0.5, cwe_id=sink["cwe"],
                                cvss_score=0.0, cvss_vector="", owasp_masvs=sink["masvs"],
                                affected_component=file_path or "UnknownClass", file_path=file_path,
                                line_number=line_idx, code_snippet=clean[:1000],
                                detection_method="TaintEngine (same-file parameter summary)",
                                status=FindingStatus.UNVERIFIED, remediation=sink["remediation"],
                                metadata={"proof_state": "not_proven", "analysis_kind": "bounded_lexical_flow",
                                          "source_kind": trace.source_type,
                                          "source_control_status": "app_persisted_value_origin_not_established" if stored_preference else "modeled_source_not_reachability_proof",
                                          "source_reachability": "callback_signature_only" if trace.source_type == "ANDROID_CALLBACK_INTENT_PARAMETER" else "not_established",
                                          "control_flow": "not_implemented",
                                          "interprocedural_value_flow": "same_file_parameter_to_sink_summary"},
                            ))
        if file_path.lower().endswith(".java"):
            ast_findings = self._java_ast.analyze(content, file_path)
            if ast_findings is None:
                self.ast_coverage["parse_fallbacks"] += 1
                self.ast_coverage["static_status"] = "fallback_lexical"
            else:
                self.ast_coverage["files_parsed"] += 1
                self.ast_coverage["static_status"] = "analyzed_heuristically"
                known = {(f.cwe_id, f.file_path, f.line_number, f.title) for f in findings}
                for ast_finding in ast_findings:
                    key = (ast_finding.cwe_id, ast_finding.file_path, ast_finding.line_number, ast_finding.title)
                    if key not in known:
                        findings.append(ast_finding)
                        known.add(key)
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
                if char == "\n":
                    current = code[start:pos]
                    next_text = code[pos + 1:].lstrip()
                    conditional_count = sum(
                        1 for match in re.finditer(r"\?", current)
                        if (match.start() == 0 or current[match.start() - 1] != ".")
                        and match.start() + 1 < len(current)
                        and current[match.start() + 1] not in {".", ":"})
                    if (current.rstrip().endswith(("=", "+", ".", ","))
                            # Java/Kotlin commonly wrap a chained call after
                            # the receiver (``value\n .get...``). Preserve that
                            # expression as one lexical statement so the
                            # fallback can see the source and assignment.
                            or next_text.startswith((".", "?."))
                            or (next_text.startswith("?") and not next_text.startswith(("?.", "?:")))
                            or conditional_count > current.count(":")):
                        continue
                yield start, code[start:pos]
                start = pos + 1
        if start < len(code):
            yield start, code[start:]

    def analyze_directory(self, decompiled_dir: str) -> list[Finding]:
        """Recursively scan all Java and Kotlin source files in a decompiled APK directory."""
        all_findings: list[Finding] = []
        root_path = Path(decompiled_dir)
        self.ast_coverage.update(files_parsed=0, parse_fallbacks=0,
                                 static_status="not_analyzed")

        inventory = SourceInventory()
        analysis_failures: list[str] = []
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
                rel_path = str(file_path.relative_to(root_path)) if file_path.is_relative_to(root_path) else file_path.name
                analysis_failures.append(rel_path)
                logger.warning("Failed to analyze taint in %s (%s)", rel_path, type(e).__name__)
        self.coverage = dict(inventory.coverage)
        if analysis_failures:
            self.coverage["static_status"] = "partial"
            self.coverage["analysis_failures"] = len(analysis_failures)
            self.coverage["failed_source_files"] = analysis_failures[:100]
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             candidate_count=len(all_findings), java_ast=dict(self.ast_coverage),
                             limits={**inventory.coverage['limits'], 'findings':1000})
        return all_findings

    async def analyze_directory_async(self, decompiled_dir: str | Path) -> list[Finding]:
        """Asynchronously scan all Java and Kotlin source files in a decompiled APK directory."""
        return await asyncio.to_thread(self.analyze_directory, str(decompiled_dir))
