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

from mobileag.reporting.cvss import get_default_cvss_for_cwe
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
        "remediation": "Sanitize filenames using `new File(base, filename).getCanonicalPath()` and verify prefix equality against base directory.",
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
        pass

    def analyze_source_content(self, content: str, file_path: str = "") -> list[Finding]:
        """Analyze a single Java/Kotlin file's source code for source-to-sink taint propagation."""
        findings: list[Finding] = []
        lines = content.splitlines()

        # Conservative straight-line heuristic, not a control-flow or inter-procedural proof.
        bindings: dict[str, TaintTrace] = {}
        method_start = re.compile(r"(?:public|private|protected|fun|void)\s+.*?\([^;]*\)\s*\{")
        for line_idx, line in enumerate(lines, 1):
            if method_start.search(line):
                bindings.clear()
            if line.strip().startswith(("//", "/*", "*")):
                continue
            # Do not split on semicolons inside quoted strings.
            statements = re.split(r';(?=(?:[^"\\]*"[^"\\]*")*[^"\\]*$)', line)
            for statement in statements:
                clean = statement.strip()
                if not clean:
                    continue
                assignment = _ASSIGN_RE.search(clean)
                if assignment:
                    lhs, rhs = assignment.group(1), assignment.group(2)
                    previous = next((t for v,t in bindings.items() if re.search(rf"\b{re.escape(v)}\b", rhs)), None)
                    bindings.pop(lhs, None)  # Reassignment kills the previous value.
                    source = next(((kind, pat.search(clean)) for kind,pat in _SOURCE_PATTERNS if pat.search(clean)), None)
                    if source:
                        bindings[lhs] = TaintTrace(lhs, source[0], line_idx, clean, {lhs}, [f"L{line_idx}: {lhs} from {source[0]}"])
                    elif previous:
                        bindings[lhs] = TaintTrace(previous.source_var, previous.source_type, previous.source_line,
                            previous.source_snippet, {lhs}, previous.propagation_steps + [f"L{line_idx}: {lhs} assigned"])
                for sink in _SINK_SPECS:
                    match = sink["pattern"].search(clean)
                    if not match:
                        continue
                    context = clean[match.end():]
                    trace = next((t for v,t in bindings.items() if re.search(rf"\b{re.escape(v)}\b", context)), None)
                    if trace is None and not _INLINE_SOURCE_RE.search(context):
                        continue
                    score, vector = get_default_cvss_for_cwe(sink["cwe"])
                    origin = f"{trace.source_var} ({trace.source_type}), line {trace.source_line}" if trace else "inline input source"
                    findings.append(Finding(
                        title=sink["title"], description=f"Potential flow from {origin} to {sink['type']}. "
                            "Straight-line heuristic only: method calls, branch conditions, sanitization, and external reachability require review.",
                        severity=sink["severity"], confidence=0.5, cwe_id=sink["cwe"], cvss_score=score,
                        cvss_vector=vector, owasp_masvs=sink["masvs"], affected_component=file_path or "UnknownClass",
                        file_path=file_path, line_number=line_idx, code_snippet=clean,
                        detection_method="TaintEngine (straight-line heuristic)", status=FindingStatus.UNVERIFIED,
                        remediation=sink["remediation"],
                    ))

        return findings

    def analyze_directory(self, decompiled_dir: str) -> list[Finding]:
        """Recursively scan all Java and Kotlin source files in a decompiled APK directory."""
        all_findings: list[Finding] = []
        root_path = Path(decompiled_dir)

        if not root_path.exists():
            return all_findings

        for ext in ("*.java", "*.kt"):
            for file_path in root_path.rglob(ext):
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    rel_path = str(file_path.relative_to(root_path))
                    findings = self.analyze_source_content(content, file_path=rel_path)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.debug(f"Failed to analyze taint in {file_path}: {e}")

        return all_findings

    async def analyze_directory_async(self, decompiled_dir: str | Path) -> list[Finding]:
        """Asynchronously scan all Java and Kotlin source files in a decompiled APK directory."""
        return await asyncio.to_thread(self.analyze_directory, str(decompiled_dir))
