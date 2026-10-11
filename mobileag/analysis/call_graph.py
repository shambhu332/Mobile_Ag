"""Bounded Smali call-path and local register-flow review heuristics.

Parses decompiled DEX / Smali representations to build:
1. Class Hierarchy and Inheritance Trees (Class -> Superclass & Interfaces)
2. Whole-Program Inter-Procedural Call Graph (Method -> Invoked Methods)
3. Android Component Lifecycle Entrypoints (onCreate, onReceive, onStartCommand)
4. Bounded source-API-containing-method to sink-API call-path inventory.
5. Same-method ``move-result*`` / ``move-object`` register flow candidates.

Cross-method register/argument flow, branch feasibility, dynamic dispatch and
effective manifest authorization are not resolved. Lifecycle names alone are
not externally reachable entrypoint proof.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.analysis.bounded_sources import SourceInventory

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
    instructions: list[tuple[int, str]] = field(default_factory=list, repr=False)

    @property
    def key(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.signature}"


@dataclass
class CallChainFinding:
    """Represents a syntactic call path; value-flow and authorization are unverified."""
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
    "Landroid/content/Intent;->getIntExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getLongExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getFloatExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getDoubleExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getBooleanExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getByteArrayExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getStringArrayExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getStringArrayListExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getIntegerArrayListExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getData": "INTENT_DATA_URI",
    "Landroid/content/Intent;->getDataString": "INTENT_DATA_URI",
    "Landroid/content/Intent;->getParcelableExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getParcelableArrayExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getParcelableArrayListExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getSerializableExtra": "INTENT_SERIALIZABLE",
    "Landroid/content/Intent;->getBundleExtra": "INTENT_BUNDLE",
    "Landroid/content/Intent;->getExtras": "INTENT_BUNDLE",
    "Landroid/content/Intent;->getCharSequenceExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getCharSequenceArrayExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getCharSequenceArrayListExtra": "INTENT_EXTRA",
    "Landroid/net/Uri;->getQueryParameter": "DEEP_LINK_PARAM",
    "Landroid/net/Uri;->getLastPathSegment": "DEEP_LINK_PATH",
    "Landroid/content/Context;->getIntent": "ACTIVITY_INTENT",
    "Landroid/app/Activity;->getIntent": "ACTIVITY_INTENT",
    "Landroid/content/ClipboardManager;->getPrimaryClip": "CLIPBOARD_DATA",
    "Landroid/content/ClipboardManager;->getText": "CLIPBOARD_DATA",
    "Landroid/content/SharedPreferences;->getString": "SHARED_PREFS_DATA",
    "Landroid/content/ContentResolver;->query": "CONTENT_RESOLVER_QUERY",
    "Landroid/telephony/TelephonyManager;->getDeviceId": "DEVICE_IMEI",
    "Landroid/telephony/TelephonyManager;->getImei": "DEVICE_IMEI",
    "Landroid/location/LocationManager;->getLastKnownLocation": "GEOLOCATION",
}

# Smali Sink signatures and corresponding CWE classifications
SMALI_SINKS = {
    "Landroid/webkit/WebView;->loadUrl": {
        "cwe": "CWE-829",
        "severity": Severity.HIGH,
        "title": "Potential Untrusted Input Flow to WebView Navigation",
        "desc": "A bounded Smali flow candidate reaches WebView.loadUrl(); URI trust validation, reachable external input, effective guards, and security impact are not established."
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
    },
    "Ldalvik/system/DexClassLoader;-><init>": {
        "cwe": "CWE-470",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Dynamic Code Execution via DexClassLoader",
        "desc": "External untrusted parameter reaches DexClassLoader constructor, enabling arbitrary code loading."
    },
    "Ldalvik/system/PathClassLoader;-><init>": {
        "cwe": "CWE-470",
        "severity": Severity.CRITICAL,
        "title": "Untrusted Dynamic Code Execution via PathClassLoader",
        "desc": "External untrusted parameter reaches PathClassLoader constructor, enabling arbitrary code loading."
    },
    "Ljava/lang/reflect/Method;->invoke": {
        "cwe": "CWE-470",
        "severity": Severity.HIGH,
        "title": "Untrusted Input Reaches Dynamic Reflection Invocation",
        "desc": "External untrusted data reaches Method.invoke(), allowing arbitrary reflection execution or sandbox bypass."
    },
    "Landroid/content/ContentResolver;->delete": {
        "cwe": "CWE-926",
        "severity": Severity.HIGH,
        "title": "Untrusted IPC Dataflow to ContentResolver Deletion",
        "desc": "Untrusted external parameter flows into ContentResolver.delete(), risking arbitrary data deletion."
    },
    "Landroid/content/ContentResolver;->update": {
        "cwe": "CWE-926",
        "severity": Severity.HIGH,
        "title": "Untrusted IPC Dataflow to ContentResolver Update",
        "desc": "Untrusted external parameter flows into ContentResolver.update(), risking database record tampering."
    },
}


def _invocation_registers(register_text: str) -> list[str]:
    """Expand regular and ``/range`` invoke register lists conservatively."""
    result: list[str] = []
    for token in register_text.split(","):
        token = token.strip()
        match = re.fullmatch(r"([vp])(\d+)\s*\.\.\s*([vp])(\d+)", token)
        if match:
            prefix, start, end_prefix, end = match.groups()
            first, last = int(start), int(end)
            if prefix == end_prefix and first <= last and last - first <= 255:
                result.extend(f"{prefix}{index}" for index in range(first, last + 1))
            continue
        if re.fullmatch(r"[vp]\d+", token):
            result.append(token)
    return result


class SmaliCallGraphEngine:
    """Parses Smali files to construct a whole-program call graph and audit reachability."""

    def __init__(self) -> None:
        self.methods: dict[str, MethodNode] = {}
        self.class_hierarchy: dict[str, str] = {}  # class -> superclass
        self.local_register_flows: list[dict[str, Any]] = []
        self.local_register_methods_skipped: list[str] = []
        self.local_register_analysis_warnings: list[str] = []
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}

    def build_graph(self, base_dir: str | Path) -> dict[str, MethodNode]:
        """Scan directory (or smali directories) and construct the call graph."""
        # One engine instance serves multiple scans; never reuse the previous artifact graph.
        self.methods.clear()
        self.class_hierarchy.clear()
        self.local_register_flows.clear()
        self.local_register_methods_skipped.clear()
        self.local_register_analysis_warnings.clear()
        base_path = Path(base_dir)
        if not base_path.exists():
            logger.warning("Smali directory does not exist: %s", base_dir)
            return self.methods

        inventory = SourceInventory(max_entries=5000, max_file_bytes=2*1024*1024,
                                    max_total_bytes=64*1024*1024)
        source_root = base_path.parent if base_path.is_file() else base_path
        names = {base_path.name} if base_path.is_file() else ()
        for sf, data in inventory.read(source_root, {".smali"}, names=names):
            self._parse_smali_file(sf, data.decode("utf-8", errors="ignore"))
            if len(self.methods) >= 100000:
                inventory.coverage['limits_reached'] = True
                break

        for method in self.methods.values():
            if len(method.instructions) > 20000:
                self.local_register_methods_skipped.append(method.key)
            else:
                self.local_register_flows.extend(self._analyze_local_register_flows(method))

        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             methods_analyzed=len(self.methods))
        logger.info("Constructed bounded call graph with %d methods", len(self.methods))

        self._resolve_synthetic_and_lambda_bridges()

        logger.info("Constructed Call Graph with %d methods", len(self.methods))
        return self.methods

    def _resolve_synthetic_and_lambda_bridges(self) -> None:
        """Resolve synthetic bridge methods (access$*) and lambdas to connect inter-procedural paths."""
        bridge_keys = [
            k for k, m in self.methods.items()
            if m.method_name.startswith("access$") or "lambda$" in m.method_name or "$$ExternalSynthetic" in m.class_name
        ][:1000]

        for b_key in bridge_keys:
            bridge_method = self.methods[b_key]
            # Find callers that invoke this bridge
            for caller in self.methods.values():
                if caller.key == b_key:
                    continue
                has_invocation = any(
                    inv == b_key or inv.startswith(f"{bridge_method.class_name}->{bridge_method.method_name}")
                    for inv in caller.invocations
                )
                if has_invocation:
                    # Propagate downstream targets, sources, and sinks from the bridge
                    for downstream in bridge_method.invocations:
                        if downstream not in caller.invocations:
                            caller.invocations.append(downstream)
                    for src in bridge_method.sources_called:
                        if src not in caller.sources_called:
                            caller.sources_called.append(src)
                    for snk in bridge_method.sinks_called:
                        if snk not in caller.sinks_called:
                            caller.sinks_called.append(snk)

    def _analyze_local_register_flows(self, method: MethodNode) -> list[dict[str, Any]]:
        """Run bounded, path-sensitive-to-branches intraprocedural register flow.

        This is a may-analysis over a small Smali CFG: conditional branches
        have both successors, unconditional gotos only their target, and
        returns/throws terminate. Register writes kill prior taint; modeled
        source results flow through move-result* and move-object. It does not
        model fields, arrays, sanitizers, interprocedural arguments, or switch
        payloads, and therefore emits candidates only.
        """
        instructions: list[tuple[int, str]] = []
        labels: dict[str, int] = {}
        for line_no, raw in method.instructions:
            stripped = raw.strip()
            label = re.fullmatch(r"(:[A-Za-z0-9_$.-]+)", stripped)
            if label:
                labels[label.group(1)] = len(instructions)
            elif stripped and not stripped.startswith(("#", ".")):
                instructions.append((line_no, stripped))
        if not instructions:
            return []

        successors: list[list[int]] = [[] for _ in instructions]

        def warn(message: str) -> None:
            if message not in self.local_register_analysis_warnings:
                self.local_register_analysis_warnings.append(message)

        for index, (_line, text) in enumerate(instructions):
            next_index = index + 1
            branch = re.match(r"goto(?:/\d+)?\s+(:[A-Za-z0-9_$.-]+)", text)
            conditional = re.match(r"if-[A-Za-z0-9/-]+\s+.*?,\s*(:[A-Za-z0-9_$.-]+)\s*$", text)
            if branch:
                target = labels.get(branch.group(1))
                if target is not None and target < len(instructions):
                    successors[index].append(target)
                else:
                    warn(f"unresolved goto target in {method.key} at line {_line}")
            elif conditional:
                target = labels.get(conditional.group(1))
                if target is not None and target < len(instructions):
                    successors[index].append(target)
                else:
                    warn(f"unresolved conditional target in {method.key} at line {_line}")
                if next_index < len(instructions):
                    successors[index].append(next_index)
            elif text.startswith("if-"):
                warn(f"unparsed conditional branch in {method.key} at line {_line}")
                if next_index < len(instructions):
                    successors[index].append(next_index)
            elif text.startswith("goto"):
                warn(f"unparsed goto in {method.key} at line {_line}")
            elif text.startswith(("packed-switch", "sparse-switch")):
                warn(f"unresolved switch targets in {method.key} at line {_line}")
                if next_index < len(instructions):
                    successors[index].append(next_index)
            elif text.startswith(("return", "throw")):
                pass
            elif next_index < len(instructions):
                successors[index].append(next_index)

        # Each state is (register -> source traces, pending invoke result).
        empty: tuple[dict[str, frozenset[tuple[str, int]]], frozenset[tuple[str, int]]] = ({}, frozenset())
        states: dict[int, tuple[dict[str, frozenset[tuple[str, int]]], frozenset[tuple[str, int]]]] = {0: empty}
        queue = [0]
        flows: list[dict[str, Any]] = []
        visited_steps = 0
        invoke_re = re.compile(r"invoke-[a-z/]+\s+\{([^}]+)\},\s*(L[a-zA-Z0-9_$/]+;)->([a-zA-Z0-9_$<>-]+)(\([^)]*\)[^\s]+)")
        invoke_args_re = re.compile(r"invoke-[a-z/]+\s+\{([^}]+)\}")
        write_re = re.compile(
            r"(?:const(?:-[a-z]+)?(?:/\w+)?|move-exception|new-instance|new-array|move(?:-wide)?(?:/\w+)?|"
            r"[as]get(?:-[a-z]+)?|array-length|instance-of|cmp[a-z]*|(?:neg|not)-[a-z]+|"
            r"(?:add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-[a-z0-9/]+)\s+([vp]\d+)(?:,|\s|$)"
        )
        while queue and visited_steps < 100000:
            index = queue.pop(0)
            visited_steps += 1
            line_no, text = instructions[index]
            incoming_regs, incoming_pending = states[index]
            registers = dict(incoming_regs)
            pending = incoming_pending
            move_result = re.match(r"move-result(?:-object|-wide)?\s+([vp]\d+)", text)
            move_alias = re.match(r"move-object(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)", text)
            if move_result:
                dest = move_result.group(1)
                if pending:
                    registers[dest] = pending
                else:
                    registers.pop(dest, None)
                pending = frozenset()
            elif move_alias:
                dest, src = move_alias.groups()
                if src in registers:
                    registers[dest] = registers[src]
                else:
                    registers.pop(dest, None)
                pending = frozenset()
            else:
                pending = frozenset()
                write = write_re.match(text)
                if write:
                    registers.pop(write.group(1), None)

                invoke = invoke_re.search(text)
                if invoke:
                    target_class, target_name, signature = invoke.group(2), invoke.group(3), invoke.group(4)
                    target_key = f"{target_class}->{target_name}"
                    source_kind = next((kind for prefix, kind in SMALI_SOURCES.items()
                                        if target_key == prefix or target_key.startswith(prefix)), None)
                    if source_kind:
                        pending = frozenset({(source_kind, line_no)})

                    sink = next((candidate for candidate in SMALI_SINKS
                                 if target_key == candidate or target_key.startswith(candidate)), None)
                    args_match = invoke_args_re.search(text)
                    args = _invocation_registers(args_match.group(1)) if args_match else []
                    if sink:
                        tainted = [(register, trace) for register in args for trace in registers.get(register, ())]
                        for register, trace in tainted:
                            flows.append({
                                "method": method.key, "file_path": method.file_path,
                                "source_kind": trace[0], "source_line": trace[1], "sink": sink,
                                "sink_line": line_no, "register": register,
                            })

            outgoing = (registers, pending)
            for successor in successors[index]:
                old = states.get(successor)
                if old is None:
                    states[successor] = (dict(registers), pending)
                    queue.append(successor)
                    continue
                old_regs, old_pending = old
                merged = {reg: frozenset(set(old_regs.get(reg, ())) | set(registers.get(reg, ())))
                          for reg in set(old_regs) | set(registers)}
                merged_pending = frozenset(set(old_pending) | set(pending))
                if merged != old_regs or merged_pending != old_pending:
                    states[successor] = (merged, merged_pending)
                    queue.append(successor)
        if queue:
            warn(f"register-flow worklist limit reached in {method.key}")
        return flows

    def _parse_smali_file(self, smali_file: Path, content: Optional[str] = None) -> None:
        """Parse class definition, methods, invoke instructions, and reflection in a Smali file."""
        if content is None:
            try:
                inventory = SourceInventory(max_file_bytes=2*1024*1024, max_total_bytes=2*1024*1024)
                records = inventory.read(smali_file.parent, {".smali"}, names={smali_file.name})
                _, data = next(records, (None, None))
                if data is None:
                    return
                content = data.decode("utf-8", errors="ignore")
            except Exception as e:
                logger.debug("Failed reading %s: %s", smali_file, e)
                return

        current_class = ""
        current_method: Optional[MethodNode] = None
        register_strings: dict[str, str] = {}
        last_reflected_method_name: Optional[str] = None

        class_re = re.compile(r"^\.class\s+.*?(L[a-zA-Z0-9_$/]+;)", re.MULTILINE)
        super_re = re.compile(r"^\.super\s+(L[a-zA-Z0-9_$/]+;)", re.MULTILINE)
        method_re = re.compile(r"^\.method\s+.*?\s+([a-zA-Z0-9_$<>-]+)(\([^)]*\)[a-zA-Z0-9_$/;\[]+)", re.MULTILINE)
        invoke_re = re.compile(r"invoke-(?:virtual|direct|static|interface|super).*?\s+(L[a-zA-Z0-9_$/]+;)->([a-zA-Z0-9_$<>-]+)(\([^)]*\)[a-zA-Z0-9_$/;\[]+)")
        const_str_re = re.compile(r'const-string(?:/jumbo)?\s+([vp]\d+),\s*"([^"]+)"')
        invoke_args_re = re.compile(r"invoke-[a-z/]+\s+\{([^}]+)\}")

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
                    register_strings.clear()
                    last_reflected_method_name = None

            elif stripped.startswith(".end method"):
                if current_method:
                    self.methods[current_method.key] = current_method
                    current_method = None
                    register_strings.clear()
                    last_reflected_method_name = None

            elif current_method:
                current_method.instructions.append((line_num, stripped))

                # Track string constants loaded into registers
                str_match = const_str_re.search(stripped)
                if str_match:
                    reg, val = str_match.group(1), str_match.group(2)
                    register_strings[reg] = val
                else:
                    register_write = re.match(
                        r"(?:const(?:-[a-z]+)?(?:/\w+)?|move-exception|new-instance|new-array|move(?:-wide)?(?:/\w+)?|"
                        r"[as]get(?:-[a-z]+)?|array-length|instance-of|cmp[a-z]*|"
                        r"(?:neg|not)-[a-z]+|(?:add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-[a-z0-9/]+)"
                        r"\s+([vp]\d+)(?:,|\s|$)", stripped
                    )
                    if register_write:
                        register_strings.pop(register_write.group(1), None)

                if stripped.startswith("invoke-"):
                    inv_match = invoke_re.search(stripped)
                    if inv_match:
                        target_class = inv_match.group(1)
                        target_name = inv_match.group(2)
                        target_sig = inv_match.group(3)
                        target_key = f"{target_class}->{target_name}{target_sig}"
                        prefix_key = f"{target_class}->{target_name}"

                        current_method.invocations.append(target_key)

                        # Check reflection resolution: Class.getMethod or getDeclaredMethod
                        if target_class == "Ljava/lang/Class;" and target_name in ("getMethod", "getDeclaredMethod"):
                            args_match = invoke_args_re.search(stripped)
                            if args_match:
                                regs = [r.strip() for r in args_match.group(1).split(",") if r.strip()]
                                # Typically: invoke-virtual {vClass, vMethodName, ...}
                                if len(regs) >= 2 and regs[1] in register_strings:
                                    last_reflected_method_name = register_strings[regs[1]]

                        # Check reflection invocation: Method.invoke
                        if target_class == "Ljava/lang/reflect/Method;" and target_name == "invoke":
                            # Register Method.invoke itself as sink
                            current_method.sinks_called.append("Ljava/lang/reflect/Method;->invoke")
                            if last_reflected_method_name:
                                # Resolve reflective call target into invocation list
                                ref_key = f"[Reflective]->{last_reflected_method_name}"
                                current_method.invocations.append(ref_key)
                                # If the reflected method name corresponds to a known sink, register that sink!
                                for sink_prefix in SMALI_SINKS:
                                    if sink_prefix.endswith(f"->{last_reflected_method_name}"):
                                        current_method.sinks_called.append(sink_prefix)

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
        truncated = False

        for method_key, method in self.methods.items():
            if len(findings) >= 1000:
                truncated = True
                break
            if not method.sources_called:
                continue

            # Method contains a source invocation. Explore paths to sinks.
            queue: list[tuple[str, list[str]]] = [(method_key, [method_key])]
            visited_in_walk: set[str] = {method_key}

            operations = 0
            while queue and operations < 10000 and len(findings) < 1000:
                operations += 1
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
                                description=(f"A method containing source API {method.sources_called[0]} has a syntactic call path to {sink_name}. "
                                             "Register/argument value flow, execution ordering, branch feasibility, parameterization, sanitization and external component authorization are not established. "
                                             f"This is a review lead, not source-to-sink proof. (Call Chain: {' -> '.join(path[-3:])})"),
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
                            if len(queue) >= 10000:
                                truncated = True
                                break

            if queue and operations >= 10000:
                truncated = True

        if truncated:
            self.coverage.update(static_status="partial", limits_reached=True)

        return findings

    def audit_smali_directory(self, smali_dir: str | Path) -> list[Finding]:
        """High-level audit function converting call-chain paths into standard Finding objects."""
        self.build_graph(smali_dir)
        paths = self.find_source_sink_paths()

        findings: list[Finding] = []
        for i, p in enumerate(paths, start=1):
            if i > 1000:
                self.coverage['limits_reached'] = True
                break
            snippet = "\n".join([f"  [{idx+1}] {step}" for idx, step in enumerate(p.call_path)])

            findings.append(
                Finding(
                    id=f"smali-cg-{i:03d}",
                    title=f"Review Smali call-path candidate: {p.cwe_id}",
                    description=p.description,
                    severity=Severity.INFO,
                    cwe_id=p.cwe_id,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=p.source_method.split("->")[0],
                    file_path=p.file_path,
                    line_number=p.line_number,
                    code_snippet=f"Inter-Procedural Smali Call Chain:\n{snippet}",
                    remediation=f"Sanitize and validate untrusted input before forwarding across call chain to {p.sink_method}.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.5,
                    detection_method="SmaliCallGraphEngine (call-path heuristic)",
                    metadata={"proof_state": "not_proven", "analysis_kind": "syntactic_call_path",
                              "register_dataflow": "not_implemented", "manifest_authorization": "not_resolved"}
                )
            )

        # These candidates have local register evidence, unlike the broader
        # syntactic call-path inventory above. They remain unverified because
        # branch feasibility, Android reachability, sanitizers, and sink impact
        # are not established by this bounded pass.
        seen_local: set[tuple[str, str, int, str]] = set()
        for flow in self.local_register_flows[:1000]:
            sink_spec = SMALI_SINKS[flow["sink"]]
            key = (flow["method"], flow["file_path"], flow["sink_line"], flow["sink"])
            if key in seen_local:
                continue
            seen_local.add(key)
            findings.append(Finding(
                title=f"Same-method Smali register-flow candidate: {sink_spec['cwe']}",
                description=(f"The bounded Smali pass tracked {flow['source_kind']} from line "
                             f"{flow['source_line']} into register {flow['register']} used by "
                             f"{flow['sink']} at line {flow['sink_line']} in the same method. "
                             "This is a CFG-based may-flow candidate; branch-condition feasibility, "
                             "sanitizers, component authorization, and security impact require validation."),
                severity=Severity.INFO, confidence=0.5, cwe_id=sink_spec["cwe"],
                cvss_score=0.0, cvss_vector="", affected_component=flow["method"].split("->", 1)[0],
                file_path=flow["file_path"], line_number=flow["sink_line"],
                code_snippet=(f"{flow['method']}\nsource line {flow['source_line']}: {flow['source_kind']}\n"
                              f"sink line {flow['sink_line']}: {flow['sink']} (register {flow['register']})"),
                remediation="Validate and constrain data at the actual trust boundary; use safe sink APIs and verify the runtime path.",
                status=FindingStatus.UNVERIFIED,
                detection_method="SmaliCallGraphEngine (bounded local register flow)",
                metadata={"proof_state": "not_proven", "analysis_kind": "smali_local_register_flow",
                          "register_dataflow": "same_method_move_result_and_move_object_only",
                          "control_flow": "cfg_may_analysis_condition_values_not_modeled",
                          "manifest_authorization": "not_resolved"},
            ))

        self.coverage.update(
            register_dataflow_status=("partial_bounded_cfg_may_analysis"
                                      if self.local_register_analysis_warnings or self.local_register_methods_skipped
                                      else "bounded_same_method_move_result_move_object_cfg_may_analysis"),
            local_register_flow_candidates=len(seen_local),
            local_register_methods_skipped=len(self.local_register_methods_skipped),
            skipped_method_keys=self.local_register_methods_skipped[:100],
            register_dataflow_warnings=self.local_register_analysis_warnings[:100],
            register_dataflow_limitations=[
                "conditional branches are both explored; condition feasibility and sanitizers are not modeled",
                "fields, arrays, arithmetic, casts, and cross-method argument flow are not modeled",
                "switch payload targets are not resolved",
                "component reachability and manifest authorization are not resolved",
            ],
        )
        if self.local_register_methods_skipped:
            self.coverage.update(static_status="partial", limits_reached=True)
        elif self.local_register_analysis_warnings:
            self.coverage.update(static_status="partial")

        return findings
