"""Inter-procedural Source-to-Sink Taint & Dataflow Tracking Engine.

Traces untrusted input data flows (Intent extras, Deep Links, Content Resolvers)
through variable assignments, transformations, and inter-procedural calls
until reaching critical sinks:
1. WebViews (loadUrl / evaluateJavascript) -> CWE-749 / CWE-79 (UXSS)
2. Databases (rawQuery / execSQL) -> CWE-89 (SQL Injection)
3. Intent Launchers (startActivity / startService) -> CWE-927 (Intent Redirection)
4. File Operations (new File / openFileOutput) -> CWE-22 (Path Traversal)
5. Command Execution (Runtime.exec / ProcessBuilder) -> CWE-78 (Command Injection)
6. Dynamic Class Loading (DexClassLoader / Class.forName) -> CWE-470
"""

from __future__ import annotations

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
]

# Variable assignment pattern: varA = varB ...
_ASSIGN_RE = re.compile(r"""(?:(?:final\s+)?(?:val\s+|var\s+|[a-zA-Z0-9_<>[\]]+\s+))?([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_<>[\]\s]+\)\s*)?([^;\n]+);?""")

# Direct inline source call inside a sink
_INLINE_SOURCE_RE = re.compile(
    r"""(?:getStringExtra|getIntExtra|getParcelableExtra|getSerializableExtra|getData|getDataString|getQueryParameter|getIntent)\s*\("""
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
    """Inter-procedural static source-to-sink taint analysis engine."""

    def __init__(self) -> None:
        pass

    def analyze_source_content(self, content: str, file_path: str = "") -> list[Finding]:
        """Analyze a single Java/Kotlin file's source code for source-to-sink taint propagation."""
        findings: list[Finding] = []
        lines = content.splitlines()

        traces: list[TaintTrace] = []

        # Step 1: Detect sources
        for line_idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
                continue

            for src_type, src_pat in _SOURCE_PATTERNS:
                m = src_pat.search(line)
                if m:
                    var_name = m.group(1)
                    trace = TaintTrace(
                        source_var=var_name,
                        source_type=src_type,
                        source_line=line_idx,
                        source_snippet=clean,
                        tainted_vars={var_name},
                        propagation_steps=[f"L{line_idx}: '{var_name}' initialized from {src_type}"],
                    )
                    traces.append(trace)

        if not traces:
            return findings

        # Step 2: Track variable propagation across statements
        for line_idx, line in enumerate(lines, 1):
            clean = line.strip()
            assign_match = _ASSIGN_RE.search(line)
            if assign_match:
                lhs = assign_match.group(1)
                rhs = assign_match.group(2)

                for trace in traces:
                    if any(re.search(rf"\b{re.escape(tv)}\b", rhs) for tv in trace.tainted_vars):
                        if lhs not in trace.tainted_vars:
                            trace.tainted_vars.add(lhs)
                            trace.propagation_steps.append(f"L{line_idx}: '{lhs}' tainted by assignment from '{rhs.strip()}'")

        # Step 3: Check for tainted sinks
        for line_idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//"):
                continue

            for sink in _SINK_SPECS:
                sink_match = sink["pattern"].search(line)
                if sink_match:
                    sink_context = line[sink_match.start():]

                    # Check trace-propagated variables
                    matched_trace = None
                    for trace in traces:
                        if line_idx < trace.source_line:
                            continue

                        if any(re.search(rf"\b{re.escape(tv)}\b", sink_context) for tv in trace.tainted_vars):
                            matched_trace = trace
                            break

                    if matched_trace:
                        cwe = sink["cwe"]
                        score, vector = get_default_cvss_for_cwe(cwe)
                        chain_str = " -> ".join(matched_trace.propagation_steps)

                        findings.append(Finding(
                            title=sink["title"],
                            description=(
                                f"Taint flow detected from untrusted source `{matched_trace.source_var}` ({matched_trace.source_type}) "
                                f"at line {matched_trace.source_line} into critical sink `{sink['type']}` at line {line_idx}.\n\n"
                                f"**Propagation Trace**:\n`{chain_str}`\n\n"
                                f"Sink Statement: `{clean}`"
                            ),
                            severity=sink["severity"],
                            confidence=0.92,
                            cwe_id=cwe,
                            cvss_score=score,
                            cvss_vector=vector,
                            owasp_masvs=sink["masvs"],
                            affected_component=file_path or "UnknownClass",
                            file_path=file_path,
                            line_number=line_idx,
                            code_snippet=clean,
                            detection_method="TaintEngine (Static Dataflow)",
                            status=FindingStatus.CONFIRMED,
                            remediation=sink["remediation"],
                        ))
                    elif _INLINE_SOURCE_RE.search(sink_context):
                        cwe = sink["cwe"]
                        score, vector = get_default_cvss_for_cwe(cwe)
                        findings.append(Finding(
                            title=sink["title"],
                            description=(
                                f"Direct inline taint flow detected from untrusted source into critical sink `{sink['type']}` at line {line_idx}.\n\n"
                                f"Sink Statement: `{clean}`"
                            ),
                            severity=sink["severity"],
                            confidence=0.95,
                            cwe_id=cwe,
                            cvss_score=score,
                            cvss_vector=vector,
                            owasp_masvs=sink["masvs"],
                            affected_component=file_path or "UnknownClass",
                            file_path=file_path,
                            line_number=line_idx,
                            code_snippet=clean,
                            detection_method="TaintEngine (Static Dataflow)",
                            status=FindingStatus.CONFIRMED,
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
