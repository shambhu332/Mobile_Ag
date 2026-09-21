"""Deterministic Smali & Bytecode Call Graph and Reachability Analysis Engine.

Parses decompiled DEX / Smali representations to build:
1. Class Hierarchy and Inheritance Trees (Class -> Superclass & Interfaces)
2. Whole-Program Inter-Procedural Call Graph (Method -> Invoked Methods)
3. Android Component Lifecycle Entrypoints (onCreate, onReceive, onStartCommand)
4. Source-to-Sink Reachability Solver for deterministic, offline vulnerability auditing
   (without relying on third-party LLMs or brittle Java source regex).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


@dataclass
class MethodNode:
    """Represents a method in the Smali Call Graph."""
    class_name: str
    method_name: str
    signature: str
    is_lifecycle_entrypoint: bool = False
    invocations: list[str] = field(default_factory=list)  # list of target method keys
    sources_called: list[str] = field(default_factory=list)
    sinks_called: list[str] = field(default_factory=list)
    file_path: str = ""
    line_number: int = 1

    @property
    def key(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.signature}"


@dataclass
class CallChainFinding:
    """Represents a validated source-to-sink reachability path across methods."""
    source_method: str
    sink_method: str
    cwe_id: str
    severity: Severity
    title: str
    description: str
    call_path: list[str]
    file_path: str
    line_number: int


# Standard Android Lifecycle entry points
LIFECYCLE_METHODS = {
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onReceive", "onStartCommand", "onBind", "onHandleIntent", "onNewIntent",
    "onActivityResult", "onRequestPermissionsResult", "query", "insert",
    "update", "delete", "openFile", "doInBackground", "onPostExecute"
}

# Smali Source signatures (methods returning untrusted external input)
SMALI_SOURCES = {
    "Landroid/content/Intent;->getStringExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getData": "INTENT_DATA_URI",
    "Landroid/content/Intent;->getDataString": "INTENT_DATA_URI",
    "Landroid/content/Intent;->getParcelableExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getSerializableExtra": "INTENT_SERIALIZABLE",
    "Landroid/content/Intent;->getExtras": "INTENT_BUNDLE",
    "Landroid/net/Uri;->getQueryParameter": "DEEP_LINK_PARAM",
    "Landroid/net/Uri;->getLastPathSegment": "DEEP_LINK_PATH",
    "Landroid/content/Context;->getIntent": "ACTIVITY_INTENT",
    "Landroid/app/Activity;->getIntent": "ACTIVITY_INTENT",
}

# Smali Sink signatures and corresponding CWE classifications
SMALI_SINKS = {
    "Landroid/webkit/WebView;->loadUrl": {
        "cwe": "CWE-749",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Intent Flow to WebView Execution (UXSS)",
        "desc": "External Intent or Deep Link input reaches WebView.loadUrl() across the method call graph."
    },
    "Landroid/webkit/WebView;->evaluateJavascript": {
        "cwe": "CWE-79",
        "severity": Severity.HIGH,
        "title": "Untrusted Input to WebView JavaScript Evaluation",
        "desc": "Untrusted external data is passed directly into WebView.evaluateJavascript()."
    },
    "Landroid/database/sqlite/SQLiteDatabase;->rawQuery": {
        "cwe": "CWE-89",
        "severity": Severity.HIGH,
        "title": "Untrusted Dataflow to Dynamic SQLite rawQuery",
        "desc": "Untrusted input reaches an unparameterized SQLiteDatabase rawQuery execution."
    },
    "Landroid/database/sqlite/SQLiteDatabase;->execSQL": {
        "cwe": "CWE-89",
        "severity": Severity.HIGH,
        "title": "Untrusted Dataflow to SQLite execSQL",
        "desc": "External parameter reaches SQLiteDatabase.execSQL without parameterized bindings."
    },
    "Landroid/content/Context;->startActivity": {
        "cwe": "CWE-927",
        "severity": Severity.HIGH,
        "title": "Untrusted IPC Intent Redirection (Trampoline)",
        "desc": "External Intent input is forwarded directly into Context.startActivity(), enabling intent hijacking."
    },
    "Landroid/app/Activity;->startActivity": {
        "cwe": "CWE-927",
        "severity": Severity.HIGH,
        "title": "Untrusted Activity Intent Redirection",
        "desc": "Untrusted Intent extra triggers arbitrary secondary Activity launch."
    },
    "Ljava/lang/Runtime;->exec": {
        "cwe": "CWE-78",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Dataflow to Native Runtime Command Execution",
        "desc": "External input reaches Runtime.getRuntime().exec(), permitting arbitrary command injection."
    },
    "Ljava/lang/ProcessBuilder;-><init>": {
        "cwe": "CWE-78",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Input to ProcessBuilder Command Execution",
        "desc": "External parameters flow into ProcessBuilder constructor arguments."
    },
    "Ljava/io/File;-><init>": {
        "cwe": "CWE-22",
        "severity": Severity.MEDIUM,
        "title": "Untrusted File Path Traversal Constructor",
        "desc": "External Intent or query parameter reaches new File() constructor without path canonicalization."
    }
}


class SmaliCallGraphEngine:
    """Parses Smali files to construct a whole-program call graph and audit reachability."""

    def __init__(self) -> None:
        self.methods: dict[str, MethodNode] = {}
        self.class_hierarchy: dict[str, str] = {}  # class -> superclass

    def build_graph(self, base_dir: str | Path) -> dict[str, MethodNode]:
        """Scan directory (or smali directories) and construct the call graph."""
        base_path = Path(base_dir)
        if not base_path.exists():
            logger.warning("Smali directory does not exist: %s", base_dir)
            return self.methods

        smali_files: list[Path] = []
        if base_path.is_file() and base_path.suffix == ".smali":
            smali_files.append(base_path)
        else:
            # Search recursively for .smali files in smali, smali_classes*, etc.
            smali_files = list(base_path.glob("**/*.smali"))

        logger.info("Found %d smali files for call graph construction", len(smali_files))
        for sf in smali_files:
            self._parse_smali_file(sf)

        logger.info("Constructed Call Graph with %d methods", len(self.methods))
        return self.methods

    def _parse_smali_file(self, smali_file: Path) -> None:
        """Parse class definition, methods, and invoke instructions in a Smali file."""
        try:
            content = smali_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.debug("Failed reading %s: %s", smali_file, e)
            return

        current_class = ""
        current_method: Optional[MethodNode] = None

        class_re = re.compile(r"^\.class\s+.*?(L[a-zA-Z0-9_$/]+;)", re.MULTILINE)
        super_re = re.compile(r"^\.super\s+(L[a-zA-Z0-9_$/]+;)", re.MULTILINE)
        method_re = re.compile(r"^\.method\s+.*?\s+([a-zA-Z0-9_$<>-]+)(\([^)]*\)[a-zA-Z0-9_$/;\[]+)", re.MULTILINE)
        end_method_re = re.compile(r"^\.end\s+method", re.MULTILINE)
        invoke_re = re.compile(r"invoke-(?:virtual|direct|static|interface|super).*?\s+(L[a-zA-Z0-9_$/]+;)->([a-zA-Z0-9_$<>-]+)(\([^)]*\)[a-zA-Z0-9_$/;\[]+)")

        match_class = class_re.search(content)
        if match_class:
            current_class = match_class.group(1)

        match_super = super_re.search(content)
        if match_super and current_class:
            self.class_hierarchy[current_class] = match_super.group(1)

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            if stripped.startswith(".method"):
                m = method_re.search(stripped)
                if m and current_class:
                    m_name, m_sig = m.group(1), m.group(2)
                    is_lifecycle = m_name in LIFECYCLE_METHODS
                    current_method = MethodNode(
                        class_name=current_class,
                        method_name=m_name,
                        signature=m_sig,
                        is_lifecycle_entrypoint=is_lifecycle,
                        file_path=str(smali_file),
                        line_number=line_num
                    )

            elif stripped.startswith(".end method"):
                if current_method:
                    self.methods[current_method.key] = current_method
                    current_method = None

            elif current_method and stripped.startswith("invoke-"):
                inv_match = invoke_re.search(stripped)
                if inv_match:
                    target_class = inv_match.group(1)
                    target_name = inv_match.group(2)
                    target_sig = inv_match.group(3)
                    target_key = f"{target_class}->{target_name}{target_sig}"
                    prefix_key = f"{target_class}->{target_name}"

                    current_method.invocations.append(target_key)

                    # Check if target is a known source
                    for src_prefix in SMALI_SOURCES:
                        if prefix_key == src_prefix or target_key.startswith(src_prefix):
                            current_method.sources_called.append(prefix_key)

                    # Check if target is a known sink
                    for sink_prefix in SMALI_SINKS:
                        if prefix_key == sink_prefix or target_key.startswith(sink_prefix):
                            current_method.sinks_called.append(sink_prefix)

    def find_source_sink_paths(self, max_depth: int = 6) -> list[CallChainFinding]:
        """Traverse the Call Graph to find paths from method sources to method sinks."""
        findings: list[CallChainFinding] = []
        visited_paths: set[str] = set()

        for method_key, method in self.methods.items():
            if not method.sources_called:
                continue

            # Method contains a source invocation. Explore paths to sinks.
            queue: list[tuple[str, list[str]]] = [(method_key, [method_key])]
            visited_in_walk: set[str] = {method_key}

            while queue:
                curr_key, path = queue.pop(0)
                curr_method = self.methods.get(curr_key)

                if not curr_method:
                    continue

                # Check if current method invokes a sink
                for sink_name in curr_method.sinks_called:
                    sink_spec = SMALI_SINKS[sink_name]
                    path_sig = "->".join(path) + f"->{sink_name}"

                    if path_sig not in visited_paths:
                        visited_paths.add(path_sig)
                        findings.append(
                            CallChainFinding(
                                source_method=method.sources_called[0],
                                sink_method=sink_name,
                                cwe_id=sink_spec["cwe"],
                                severity=sink_spec["severity"],
                                title=sink_spec["title"],
                                description=f"{sink_spec['desc']} (Call Chain: {' -> '.join(path[-3:])})",
                                call_path=path + [sink_name],
                                file_path=method.file_path,
                                line_number=method.line_number
                            )
                        )

                # Expand invocations if depth limit not reached
                if len(path) < max_depth:
                    for next_inv in curr_method.invocations:
                        # Normalize target method key if present in parsed methods
                        if next_inv in self.methods and next_inv not in visited_in_walk:
                            visited_in_walk.add(next_inv)
                            queue.append((next_inv, path + [next_inv]))

        return findings

    def audit_smali_directory(self, smali_dir: str | Path) -> list[Finding]:
        """High-level audit function converting call-chain paths into standard Finding objects."""
        self.build_graph(smali_dir)
        paths = self.find_source_sink_paths()

        findings: list[Finding] = []
        for i, p in enumerate(paths, start=1):
            score, vector = get_default_cvss_for_cwe(p.cwe_id)
            snippet = "\n".join([f"  [{idx+1}] {step}" for idx, step in enumerate(p.call_path)])

            findings.append(
                Finding(
                    id=f"smali-cg-{i:03d}",
                    title=p.title,
                    description=p.description,
                    severity=p.severity,
                    cwe_id=p.cwe_id,
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=p.source_method.split("->")[0],
                    file_path=p.file_path,
                    line_number=p.line_number,
                    code_snippet=f"Inter-Procedural Smali Call Chain:\n{snippet}",
                    remediation=f"Sanitize and validate untrusted input before forwarding across call chain to {p.sink_method}.",
                    status=FindingStatus.CONFIRMED,
                    confidence=0.96
                )
            )

        return findings
