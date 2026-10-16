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
from collections import deque
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
    is_static: bool = False
    is_public: bool = False
    is_javascript_interface: bool = False
    javascript_interface_annotation_line: int | None = None
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

# Exact callback signatures whose Intent argument is supplied by Android as an
# external/event boundary. Name/signature alone does not prove component
# registration, export state, caller privileges, or runtime reachability.
LIFECYCLE_INTENT_CALLBACK_PARAMETERS = {
    ("onNewIntent", "(Landroid/content/Intent;)V"): (0, "Landroid/app/Activity;"),
    ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"): (1, "Landroid/content/BroadcastReceiver;"),
    ("onStartCommand", "(Landroid/content/Intent;II)I"): (0, "Landroid/app/Service;"),
    ("onHandleIntent", "(Landroid/content/Intent;)V"): (0, "Landroid/app/IntentService;"),
    ("onActivityResult", "(IILandroid/content/Intent;)V"): (2, "Landroid/app/Activity;"),
    ("onBind", "(Landroid/content/Intent;)Landroid/os/IBinder;"): (0, "Landroid/app/Service;"),
    ("onUnbind", "(Landroid/content/Intent;)Z"): (0, "Landroid/app/Service;"),
}

# Intent accessors are tainted only when their receiver came from an external
# boundary (Activity.getIntent or a bounded framework callback). Reading an
# internally constructed Intent is not itself external input.
SMALI_INTENT_DERIVED_KINDS = {
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
    "Landroid/content/Intent;->getParcelableExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getParcelableArrayExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getParcelableArrayListExtra": "INTENT_PARCELABLE",
    "Landroid/content/Intent;->getSerializableExtra": "INTENT_SERIALIZABLE",
    "Landroid/content/Intent;->getBundleExtra": "INTENT_BUNDLE",
    "Landroid/content/Intent;->getScheme": "INTENT_SCHEME",
    "Landroid/content/Intent;->getExtras": "INTENT_BUNDLE",
    "Landroid/content/Intent;->getCharSequenceExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getCharSequenceArrayExtra": "INTENT_EXTRA",
    "Landroid/content/Intent;->getCharSequenceArrayListExtra": "INTENT_EXTRA",
}

# Smali Source signatures (methods returning untrusted external input)
SMALI_SOURCES = {
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

# Accessors that only preserve taint from a known untrusted container/URI.
# These are deliberately not unconditional sources: ordinary internal Intents,
# Bundles, and Uris are not automatically attacker-controlled.
SMALI_DERIVED_SOURCES = {
    # Metadata read from an Intent is only considered untrusted when the
    # Intent receiver itself was sourced from an external/activity boundary.
    "Landroid/content/Intent;->getData",
    "Landroid/content/Intent;->getDataString",
    "Landroid/content/Intent;->getScheme",
    "Landroid/content/Intent;->getAction",
    "Landroid/content/Intent;->getType",
    "Landroid/content/Intent;->getClipData",
    "Landroid/content/ClipData;->getItemAt",
    "Landroid/content/ClipData$Item;->getUri",
    "Landroid/content/ClipData$Item;->getText",
    "Landroid/os/Bundle;->getString",
    "Landroid/os/Bundle;->getCharSequence",
    "Landroid/os/Bundle;->getInt",
    "Landroid/os/Bundle;->getLong",
    "Landroid/os/Bundle;->getBoolean",
    "Landroid/os/Bundle;->getByteArray",
    "Landroid/os/Bundle;->getStringArray",
    "Landroid/os/Bundle;->getStringArrayList",
    "Landroid/os/Bundle;->getParcelable",
    "Landroid/os/Bundle;->getSerializable",
    "Landroid/database/Cursor;->getString",
    "Landroid/database/Cursor;->getBlob",
    "Landroid/database/Cursor;->getShort",
    "Landroid/database/Cursor;->getInt",
    "Landroid/database/Cursor;->getLong",
    "Landroid/database/Cursor;->getFloat",
    "Landroid/database/Cursor;->getDouble",
    "Landroid/net/Uri;->getQueryParameter",
    "Landroid/net/Uri;->getLastPathSegment",
    "Landroid/net/Uri;->getPath",
    "Landroid/net/Uri;->getEncodedPath",
    "Landroid/net/Uri;->getQuery",
    "Landroid/net/Uri;->getFragment",
    "Landroid/net/Uri;->getAuthority",
    "Landroid/net/Uri;->getHost",
    "Landroid/net/Uri;->getScheme",
}

# External content is modeled only when the file/URI selector is already
# tainted. These are review candidates, not a claim that arbitrary app files
# are attacker-writable.
SMALI_EXTERNAL_URI_STREAMS = {
    "Landroid/content/ContentResolver;->openInputStream": 1,
    "Landroid/content/ContentResolver;->openFileDescriptor": 1,
    "Landroid/content/ContentResolver;->openAssetFileDescriptor": 1,
    "Landroid/content/ContentResolver;->openTypedAssetFileDescriptor": 1,
}
SMALI_EXTERNAL_PATH_READERS = {
    "Ljava/nio/file/Files;->readString": 0,
    "Ljava/nio/file/Files;->readAllBytes": 0,
    "Ljava/nio/file/Files;->newInputStream": 0,
    "Ljava/nio/file/Files;->newBufferedReader": 0,
}
SMALI_EXTERNAL_PATH_STREAM_CONSTRUCTORS = {
    "Ljava/io/FileInputStream;", "Ljava/io/FileReader;", "Ljava/io/RandomAccessFile;",
    "Ljava/util/Scanner;",
}
SMALI_PATH_OBJECT_CONSTRUCTORS = {"Ljava/io/File;"}
SMALI_STREAM_WRAPPER_CONSTRUCTORS = {
    "Ljava/io/InputStreamReader;", "Ljava/io/BufferedReader;",
    "Ljava/io/BufferedInputStream;", "Ljava/io/DataInputStream;",
    "Ljava/io/FilterInputStream;", "Ljava/io/SequenceInputStream;",
    "Landroid/os/ParcelFileDescriptor$AutoCloseInputStream;",
    "Ljava/util/Scanner;",
}
SMALI_BUFFER_READERS = {
    "Ljava/io/InputStream;", "Ljava/io/FileInputStream;", "Ljava/io/FilterInputStream;",
    "Ljava/io/BufferedInputStream;", "Ljava/io/DataInputStream;",
    "Ljava/io/Reader;", "Ljava/io/InputStreamReader;", "Ljava/io/FileReader;",
    "Ljava/io/BufferedReader;", "Ljava/io/RandomAccessFile;",
}
SMALI_CONTENT_LINE_READERS = {"Ljava/io/BufferedReader;", "Ljava/util/Scanner;"}
SMALI_STREAM_SOURCE_ACCESSORS = {
    "Landroid/content/res/AssetFileDescriptor;->createInputStream",
}

# Pure transformations preserve input taint; they are not sources on their
# own. Keep this list exact-owner/method to avoid matching app lookalikes.
SMALI_DERIVED_SOURCES.update(SMALI_INTENT_DERIVED_KINDS)

SMALI_TAINT_TRANSFORMS = {
    "Ljava/lang/String;->concat",
    "Ljava/lang/String;->valueOf",
    "Ljava/lang/String;->format",
    "Ljava/lang/String;->join",
    "Ljava/lang/String;->substring",
    "Ljava/lang/String;->trim",
    "Ljava/lang/String;->strip",
    "Ljava/lang/String;->stripLeading",
    "Ljava/lang/String;->stripTrailing",
    "Ljava/lang/String;->toLowerCase",
    "Ljava/lang/String;->toUpperCase",
    "Ljava/lang/String;->replace",
    "Ljava/lang/String;->replaceAll",
    "Ljava/lang/String;->replaceFirst",
    "Landroid/net/Uri;->toString",
    "Ljava/nio/file/Paths;->get",
    "Ljava/io/File;->toPath",
    "Ljava/lang/Integer;->toString",
    "Ljava/lang/Long;->toString",
    "Ljava/lang/Float;->toString",
    "Ljava/lang/Double;->toString",
    "Ljava/lang/Boolean;->toString",
    "Ljava/lang/Character;->toString",
}
SMALI_BUILDER_CONSTRUCTORS = {
    "Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V",
    "Ljava/lang/StringBuilder;-><init>(Ljava/lang/CharSequence;)V",
    "Ljava/lang/StringBuffer;-><init>(Ljava/lang/String;)V",
    "Ljava/lang/StringBuffer;-><init>(Ljava/lang/CharSequence;)V",
}
SMALI_BUILDER_MUTATORS = {
    "Ljava/lang/StringBuilder;->append",
    "Ljava/lang/StringBuffer;->append",
    "Ljava/lang/StringBuilder;->insert",
    "Ljava/lang/StringBuffer;->insert",
    "Ljava/lang/StringBuilder;->replace",
    "Ljava/lang/StringBuffer;->replace",
    "Ljava/lang/StringBuilder;->delete",
    "Ljava/lang/StringBuffer;->delete",
    "Ljava/lang/StringBuilder;->deleteCharAt",
    "Ljava/lang/StringBuffer;->deleteCharAt",
    "Ljava/lang/StringBuilder;->reverse",
    "Ljava/lang/StringBuffer;->reverse",
    "Ljava/lang/StringBuilder;->setCharAt",
    "Ljava/lang/StringBuffer;->setCharAt",
    "Ljava/lang/StringBuilder;->setLength",
    "Ljava/lang/StringBuffer;->setLength",
}
SMALI_BUILDER_TO_STRING = {
    "Ljava/lang/StringBuilder;->toString",
    "Ljava/lang/StringBuffer;->toString",
}

# Smali Sink signatures and corresponding CWE classifications
SMALI_SINKS = {
    "Landroid/webkit/WebView;->loadUrl": {
        "cwe": "CWE-829",
        "severity": Severity.HIGH,
        "title": "Potential Untrusted Input Flow to WebView Navigation",
        "desc": "A bounded Smali flow candidate reaches WebView.loadUrl(); URI trust validation, reachable external input, effective guards, and security impact are not established."
    },
    "Landroid/webkit/WebView;->loadData": {
        "cwe": "CWE-79",
        "severity": Severity.HIGH,
        "title": "Untrusted Data Reaches WebView HTML Loading",
        "desc": "A bounded Smali flow candidate reaches WebView.loadData(); HTML context, sanitization, reachability, and impact require review."
    },
    "Landroid/webkit/WebView;->loadDataWithBaseURL": {
        "cwe": "CWE-79",
        "severity": Severity.HIGH,
        "title": "Untrusted Data Reaches WebView HTML Loading With a Base URL",
        "desc": "A bounded Smali flow candidate reaches WebView.loadDataWithBaseURL(); HTML context, base-origin behavior, sanitization, reachability, and impact require review."
    },
    "Landroid/webkit/WebView;->postUrl": {
        "cwe": "CWE-829",
        "severity": Severity.HIGH,
        "title": "Untrusted Input Reaches WebView POST Navigation",
        "desc": "A bounded Smali flow candidate reaches WebView.postUrl(); destination trust, payload handling, reachability, and impact require review."
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
    "Landroid/app/PendingIntent;->send": {
        "cwe": "CWE-927",
        "severity": Severity.HIGH,
        "title": "Untrusted PendingIntent Forwarding / Execution",
        "desc": "Untrusted input reaches PendingIntent.send(), enabling unauthorized invocation of caller-granted privileges."
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


def _parameter_descriptors(signature: str) -> list[tuple[int, int]] | None:
    """Return (parameter index, register width), or None for malformed descriptors."""
    if not signature.startswith("(") or ")" not in signature:
        return None
    body = signature[1:signature.index(")")]
    params: list[tuple[int, int]] = []
    index = 0
    while index < len(body):
        while index < len(body) and body[index] == "[":
            index += 1
        if index >= len(body):
            return None
        if body[index] == "L":
            end = body.find(";", index)
            if end < 0:
                return None
            index = end + 1
            width = 1
        elif body[index] in "ZBCSIFJD":
            width = 2 if body[index] in "JD" and (index == 0 or body[index - 1] != "[") else 1
            index += 1
        else:
            return None
        params.append((len(params), width))
    return params


def _parameter_argument_registers(signature: str, is_static: bool, actuals: list[str]) -> list[tuple[str, str]]:
    """Map narrow/wide invoke argument words to callee p-register aliases."""
    descriptors = _parameter_descriptors(signature)
    if descriptors is None:
        return []
    actual_index = 0 if is_static else 1  # Non-static invokes include receiver as word zero.
    formal_index = 0 if is_static else 1  # Non-static p0 is `this`.
    if not is_static and not actuals:
        return []
    mapped: list[tuple[str, str]] = []
    for _parameter_index, width in descriptors:
        if actual_index + width > len(actuals):
            return []
        mapped.append((f"p{formal_index}", actuals[actual_index]))
        actual_index += width
        formal_index += width
    if actual_index != len(actuals):
        return []
    return mapped


class SmaliCallGraphEngine:
    """Parses Smali files to construct a whole-program call graph and audit reachability."""

    def __init__(self) -> None:
        self.methods: dict[str, MethodNode] = {}
        self.class_hierarchy: dict[str, str] = {}  # class -> superclass
        self.local_register_flows: list[dict[str, Any]] = []
        self.local_register_methods_skipped: list[str] = []
        self.local_register_analysis_warnings: list[str] = []
        self.MAX_INTERPROCEDURAL_METHOD_RUNS = 100_000
        self.MAX_INTERPROCEDURAL_TAINT_FACTS = 100_000
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
                inventory.record_limit('smali_method_count')
                break

        parameter_taints: dict[str, dict[str, set[tuple[str, int, str, str]]]] = {}
        static_field_taints: dict[str, set[tuple[str, int, str, str]]] = {}
        static_field_readers: dict[str, set[str]] = {}
        method_return_taints: dict[str, set[tuple[str, int, str, str]]] = {}
        return_callers: dict[str, set[str]] = {}
        worklist = deque(self.methods)
        queued = set(self.methods)
        interprocedural_runs = 0
        taint_facts = 0
        parameter_taint_facts = 0
        interprocedural_limited = False
        seen_flows: set[tuple[Any, ...]] = set()
        lifecycle_intent_seed_methods: set[str] = set()
        while worklist and interprocedural_runs < self.MAX_INTERPROCEDURAL_METHOD_RUNS:
            method_key = worklist.popleft()
            queued.discard(method_key)
            method = self.methods[method_key]
            interprocedural_runs += 1
            if len(method.instructions) > 20000:
                if method.key not in self.local_register_methods_skipped:
                    self.local_register_methods_skipped.append(method.key)
                continue
            initial = {
                register: set(traces)
                for register, traces in parameter_taints.get(method_key, {}).items()
            }
            lifecycle_callback = LIFECYCLE_INTENT_CALLBACK_PARAMETERS.get(
                (method.method_name, method.signature)
            )
            descriptors = _parameter_descriptors(method.signature)
            if (lifecycle_callback is not None and descriptors is not None
                    and not method.is_static
                    and self._inherits_from(method.class_name, lifecycle_callback[1])):
                lifecycle_intent_index = lifecycle_callback[0]
                formal_index = 0 if method.is_static else 1
                for parameter_index, width in descriptors:
                    if parameter_index == lifecycle_intent_index:
                        source_trace = (
                            "LIFECYCLE_INTENT_PARAMETER", method.line_number,
                            method.key, method.file_path,
                        )
                        initial.setdefault(f"p{formal_index}", set()).add(source_trace)
                        lifecycle_intent_seed_methods.add(method.key)
                        break
                    formal_index += width
            if method.is_public and method.is_javascript_interface:
                descriptors = _parameter_descriptors(method.signature) or []
                formal_index = 0 if method.is_static else 1
                for _parameter_index, width in descriptors:
                    source_trace = (
                        "WEBVIEW_JAVASCRIPT_INTERFACE_PARAMETER",
                        method.javascript_interface_annotation_line or method.line_number,
                        method.key,
                        method.file_path,
                    )
                    initial.setdefault(f"p{formal_index}", set()).add(source_trace)
                    formal_index += width
            initial = {register: frozenset(traces) for register, traces in initial.items()}
            flows, argument_flows, field_writes, field_reads, return_flows, called_methods = self._analyze_local_register_flows(
                method, initial, static_field_taints, method_return_taints,
            )
            for field_key in field_reads:
                static_field_readers.setdefault(field_key, set()).add(method_key)
            for callee_key in called_methods:
                return_callers.setdefault(callee_key, set()).add(method_key)
            for flow in flows:
                flow_key = (flow["method"], flow["sink_line"], flow["sink"],
                            flow["source_method"], flow["source_line"], flow["source_file"])
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    if len(self.local_register_flows) < 10_000:
                        self.local_register_flows.append(flow)
                    else:
                        interprocedural_limited = True
                        break
            for target_key, formal_register, trace in argument_flows:
                if target_key not in self.methods:
                    continue
                target_params = parameter_taints.setdefault(target_key, {})
                traces = target_params.setdefault(formal_register, set())
                if trace in traces:
                    continue
                if taint_facts >= self.MAX_INTERPROCEDURAL_TAINT_FACTS:
                    interprocedural_limited = True
                    break
                traces.add(trace)
                taint_facts += 1
                parameter_taint_facts += 1
                if target_key not in queued:
                    worklist.append(target_key)
                    queued.add(target_key)

            for field_key, trace in field_writes:
                traces = static_field_taints.setdefault(field_key, set())
                if trace in traces:
                    continue
                if taint_facts >= self.MAX_INTERPROCEDURAL_TAINT_FACTS:
                    interprocedural_limited = True
                    break
                traces.add(trace)
                taint_facts += 1
                for reader_key in static_field_readers.get(field_key, ()):
                    if reader_key not in queued:
                        worklist.append(reader_key)
                        queued.add(reader_key)

            return_traces = method_return_taints.setdefault(method_key, set())
            for trace in return_flows:
                if trace in return_traces:
                    continue
                if taint_facts >= self.MAX_INTERPROCEDURAL_TAINT_FACTS:
                    interprocedural_limited = True
                    break
                return_traces.add(trace)
                taint_facts += 1
                for caller_key in return_callers.get(method_key, ()):
                    if caller_key not in queued:
                        worklist.append(caller_key)
                        queued.add(caller_key)

        if worklist:
            interprocedural_limited = True

        self.coverage = dict(inventory.coverage)
        self.coverage.update(
            runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
            methods_analyzed=len(self.methods), interprocedural_method_runs=interprocedural_runs,
            interprocedural_parameter_taint_facts=parameter_taint_facts,
            interprocedural_static_field_taint_facts=sum(len(v) for v in static_field_taints.values()),
            interprocedural_return_taint_facts=sum(len(v) for v in method_return_taints.values()),
            lifecycle_intent_parameter_seed_methods=len(lifecycle_intent_seed_methods),
            interprocedural_flow_status=("partial" if interprocedural_limited
                                         else "bounded_arguments_static_fields_and_returns"),
        )
        if interprocedural_limited:
            self.coverage.update(static_status="partial", limits_reached=True)
        logger.info("Constructed bounded call graph with %d methods", len(self.methods))

        self._resolve_synthetic_and_lambda_bridges()

        logger.info("Constructed Call Graph with %d methods", len(self.methods))
        return self.methods

    def _inherits_from(self, class_name: str, expected_base: str) -> bool:
        """Resolve the parsed Smali superclass chain to a known Android callback base."""
        current = class_name
        seen: set[str] = set()
        while current and current not in seen:
            if current == expected_base:
                return True
            seen.add(current)
            current = self.class_hierarchy.get(current, "")
        return False

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

    def _analyze_local_register_flows(
        self,
        method: MethodNode,
        initial_taints: dict[str, frozenset[tuple[str, int, str, str]]] | None = None,
        initial_static_field_taints: dict[str, set[tuple[str, int, str, str]]] | None = None,
        callee_return_taints: dict[str, set[tuple[str, int, str, str]]] | None = None,
    ) -> tuple[list[dict[str, Any]], list[tuple[str, str, tuple[str, int, str, str]]],
               list[tuple[str, tuple[str, int, str, str]]], set[str],
               set[tuple[str, int, str, str]], set[str]]:
        """Run bounded CFG register may-flow with exact-signature arg propagation.

        This is a may-analysis over a small Smali CFG: conditional branches
        have both successors, unconditional gotos only their target, and
        returns/throws terminate. Register writes kill prior taint; modeled
        source results flow through move-result* and move-object. Tainted actual
        arguments may seed matching callee p-registers, while bounded static-field,
        method-return, and array-element summaries propagate values. Packed/sparse
        switch payload targets are traversed, with unresolved or over-limit payloads
        marking coverage partial. Instance fields, sanitizers, and dynamic dispatch
        are not modeled. Results are candidates only.
        """
        instructions: list[tuple[int, str]] = []
        labels: dict[str, int] = {}
        switch_payloads: dict[str, tuple[list[str], bool]] = {}
        payload_label: str | None = None
        payload_kind: str | None = None
        pending_label: str | None = None
        payload_targets: list[str] = []
        payload_invalid = False
        for _line, raw in method.instructions:
            stripped = raw.strip()
            if payload_kind:
                end_directive = ".end " + payload_kind[1:]
                if stripped == end_directive:
                    if payload_label:
                        switch_payloads[payload_label] = (payload_targets[:10000], payload_invalid)
                    payload_label = None
                    payload_kind = None
                    payload_targets = []
                    payload_invalid = False
                elif payload_kind == ".packed-switch":
                    if not stripped or stripped.startswith("#"):
                        continue
                    target = re.fullmatch(r"(:[A-Za-z0-9_$.-]+)", stripped)
                    if target:
                        if len(payload_targets) < 10000:
                            payload_targets.append(target.group(1))
                        else:
                            payload_invalid = True
                    else:
                        payload_invalid = True
                else:
                    if not stripped or stripped.startswith("#"):
                        continue
                    target = re.fullmatch(
                        r"[+-]?(?:0x[0-9A-Fa-f]+|[0-9]+)\s*->\s*(:[A-Za-z0-9_$.-]+)",
                        stripped,
                    )
                    if target:
                        if len(payload_targets) < 10000:
                            payload_targets.append(target.group(1))
                        else:
                            payload_invalid = True
                    else:
                        payload_invalid = True
                continue
            label = re.fullmatch(r"(:[A-Za-z0-9_$.-]+)", stripped)
            if label:
                pending_label = label.group(1)
            elif stripped in {".packed-switch", ".sparse-switch"} or stripped.startswith((".packed-switch ", ".sparse-switch ")):
                payload_label = pending_label
                payload_kind = stripped.split()[0]
                payload_targets = []
                payload_invalid = False
                pending_label = None
            elif stripped and not stripped.startswith(("#", ".")):
                pending_label = None
        inside_switch_payload = False
        for line_no, raw in method.instructions:
            stripped = raw.strip()
            if inside_switch_payload:
                if stripped in {".end packed-switch", ".end sparse-switch"}:
                    inside_switch_payload = False
                continue
            if stripped.startswith((".packed-switch ", ".sparse-switch ")):
                inside_switch_payload = True
                continue
            label = re.fullmatch(r"(:[A-Za-z0-9_$.-]+)", stripped)
            if label:
                labels[label.group(1)] = len(instructions)
            elif stripped and not stripped.startswith(("#", ".")):
                instructions.append((line_no, stripped))
        if not instructions:
            return [], []

        successors: list[list[int]] = [[] for _ in instructions]

        def warn(message: str) -> None:
            if message not in self.local_register_analysis_warnings:
                self.local_register_analysis_warnings.append(message)

        def clear_register_tracking(register: str) -> None:
            registers.pop(register, None)
            registers.pop(f"@array:{register}", None)
            registers.pop(f"@builder:{register}", None)
            registers.pop(f"@returned:{register}", None)

        def clear_wide_high_word(register: str) -> None:
            match = re.fullmatch(r"([vp])(\d+)", register)
            if match:
                clear_register_tracking(f"{match.group(1)}{int(match.group(2)) + 1}")

        for index, (_line, text) in enumerate(instructions):
            next_index = index + 1
            branch = re.match(r"goto(?:/\d+)?\s+(:[A-Za-z0-9_$.-]+)", text)
            conditional = re.match(r"if-[A-Za-z0-9/-]+\s+.*?,\s*(:[A-Za-z0-9_$.-]+)\s*$", text)
            switch = re.match(r"(?:packed|sparse)-switch\s+[vp]\d+,\s*(:[A-Za-z0-9_$.-]+)", text)
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
            elif switch:
                payload = switch_payloads.get(switch.group(1))
                if payload is None:
                    warn(f"unresolved switch payload in {method.key} at line {_line}")
                else:
                    payload_targets, invalid = payload
                    if invalid:
                        warn(f"malformed or over-limit switch payload in {method.key} at line {_line}")
                    for target_label in payload_targets:
                        target = labels.get(target_label)
                        if target is not None and target < len(instructions):
                            successors[index].append(target)
                        else:
                            warn(f"unresolved switch case target in {method.key} at line {_line}")
                if next_index < len(instructions):
                    successors[index].append(next_index)
            elif text.startswith(("packed-switch", "sparse-switch")):
                warn(f"unparsed switch instruction in {method.key} at line {_line}")
                if next_index < len(instructions):
                    successors[index].append(next_index)
            elif text.startswith(("return", "throw")):
                pass
            elif next_index < len(instructions):
                successors[index].append(next_index)

        # Each state is (register -> source traces, pending invoke result).
        empty = (dict(initial_taints or {}), frozenset())
        states = {0: empty}
        queue = [0]
        flows: list[dict[str, Any]] = []
        argument_flows: set[tuple[str, str, tuple[str, int, str, str]]] = set()
        static_field_writes: set[tuple[str, tuple[str, int, str, str]]] = set()
        static_field_reads: set[str] = set()
        return_flows: set[tuple[str, int, str, str]] = set()
        called_methods: set[str] = set()
        visited_steps = 0
        invoke_re = re.compile(r"invoke-[a-z/]+\s+\{([^}]+)\},\s*(L[a-zA-Z0-9_$/]+;)->([a-zA-Z0-9_$<>-]+)(\([^)]*\)[^\s]+)")
        invoke_args_re = re.compile(r"invoke-[a-z/]+\s+\{([^}]+)\}")
        static_get_re = re.compile(r"sget(?:-[a-z]+)?\s+([vp]\d+),\s*(L[^;]+;->[A-Za-z0-9_$]+:[^\s]+)")
        static_put_re = re.compile(r"sput(?:-[a-z]+)?\s+([vp]\d+),\s*(L[^;]+;->[A-Za-z0-9_$]+:[^\s]+)")
        return_value_re = re.compile(r"return(?:-object|-wide)?\s+([vp]\d+)")
        write_re = re.compile(
            r"(?:const(?:-[a-z0-9]+)*(?:/\w+)?|move-exception|new-instance|new-array|move(?:-wide)?(?:/\w+)?|"
            r"iget(?:-[a-z0-9/]+)?|[as]get(?:-[a-z]+)?|array-length|instance-of|cmp[a-z]*|(?:neg|not)-[a-z]+|"
            r"(?:int|long|float|double)-to-(?:int|long|float|double|byte|char|short)|"
            r"(?:rsub|add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-[a-z0-9/]+)\s+([vp]\d+)(?:,|\s|$)"
        )
        while queue and visited_steps < 100000:
            index = queue.pop(0)
            visited_steps += 1
            line_no, text = instructions[index]
            incoming_regs, incoming_pending = states[index]
            registers = dict(incoming_regs)
            pending = incoming_pending
            move_result = re.match(r"move-result(?:-object|-wide)?\s+([vp]\d+)", text)
            move_alias = re.match(r"move(?:-object|-wide)?(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)", text)
            array_get = re.match(r"aget(?:-[a-z]+)?\s+([vp]\d+),\s*([vp]\d+),\s*[vp]\d+", text)
            array_put = re.match(r"aput(?:-[a-z]+)?\s+([vp]\d+),\s*([vp]\d+),\s*[vp]\d+", text)
            fill_array_data = re.match(r"fill-array-data\s+([vp]\d+),", text)
            filled_new_array = re.match(r"filled-new-array(?:/range)?\s+\{([^}]*)\}", text)
            instance_get = re.match(r"iget(?:-[a-z0-9/]+)?\s+([vp]\d+),", text)
            instance_put = re.match(r"iput(?:-[a-z0-9/]+)?\s+([vp]\d+),", text)
            static_get = static_get_re.match(text)
            static_put = static_put_re.match(text)
            return_value = return_value_re.match(text)
            if not move_result:
                registers.pop("@pending_return", None)
                registers.pop("@pending_builder", None)
                registers.pop("@pending_array_elements", None)
            if static_get:
                dest, field_key = static_get.groups()
                static_field_reads.add(field_key)
                registers.pop(f"@array:{dest}", None)
                registers.pop(f"@returned:{dest}", None)
                registers.pop(f"@builder:{dest}", None)
                traces = (initial_static_field_taints or {}).get(field_key, ())
                if traces:
                    registers[dest] = frozenset(traces)
                else:
                    registers.pop(dest, None)
                if text.startswith("sget-wide"):
                    clear_wide_high_word(dest)
                pending = frozenset()
            elif move_result:
                dest = move_result.group(1)
                registers.pop(f"@array:{dest}", None)
                registers.pop(f"@builder:{dest}", None)
                return_taints = registers.pop("@pending_return", frozenset())
                builder_taints = registers.pop("@pending_builder", frozenset())
                registers.pop(f"@returned:{dest}", None)
                if pending:
                    registers[dest] = pending
                else:
                    registers.pop(dest, None)
                pending_array_taints = registers.pop("@pending_array_elements", frozenset())
                if pending_array_taints:
                    registers[f"@array:{dest}"] = pending_array_taints
                if return_taints:
                    registers[f"@returned:{dest}"] = return_taints
                if builder_taints:
                    registers[f"@builder:{dest}"] = builder_taints
                if text.startswith("move-result-wide"):
                    clear_wide_high_word(dest)
                pending = frozenset()
            elif move_alias:
                dest, src = move_alias.groups()
                wide_alias = text.startswith("move-wide")
                source_traces = set(registers.get(src, ()))
                if wide_alias:
                    source_match = re.fullmatch(r"([vp])(\d+)", src)
                    if source_match:
                        source_traces.update(registers.get(
                            f"{source_match.group(1)}{int(source_match.group(2)) + 1}", ()
                        ))
                    clear_register_tracking(dest)
                    clear_wide_high_word(dest)
                if source_traces:
                    registers[dest] = frozenset(source_traces)
                else:
                    registers.pop(dest, None)
                if wide_alias:
                    clear_wide_high_word(dest)
                # Keep a bounded may-taint summary for array aliases separate
                # from object-register taint (so passing an array itself to a
                # sink does not imply its elements are tainted).
                array_key = f"@array:{src}"
                dest_array_key = f"@array:{dest}"
                if text.startswith("move-object") and array_key in registers:
                    registers[dest_array_key] = registers[array_key]
                else:
                    registers.pop(dest_array_key, None)
                builder_key = f"@builder:{src}"
                dest_builder_key = f"@builder:{dest}"
                if text.startswith("move-object") and builder_key in registers:
                    registers[dest_builder_key] = registers[builder_key]
                else:
                    registers.pop(dest_builder_key, None)
                returned_key = f"@returned:{src}"
                dest_returned_key = f"@returned:{dest}"
                if returned_key in registers:
                    registers[dest_returned_key] = registers[returned_key]
                else:
                    registers.pop(dest_returned_key, None)
                pending = frozenset()
            elif array_get:
                dest, array_register = array_get.groups()
                registers.pop(f"@array:{dest}", None)
                registers.pop(f"@builder:{dest}", None)
                registers.pop(f"@returned:{dest}", None)
                traces = registers.get(f"@array:{array_register}", registers.get(array_register, ()))
                if traces:
                    registers[dest] = traces
                else:
                    registers.pop(dest, None)
                if text.startswith("aget-wide"):
                    clear_wide_high_word(dest)
                pending = frozenset()
            else:
                pending = frozenset()
                registers.pop("@pending_return", None)
                if instance_get:
                    warn(f"instance field read value is not modeled in {method.key} at line {line_no}")
                if instance_put:
                    warn(f"instance field write value is not modeled in {method.key} at line {line_no}")
                if fill_array_data:
                    # The payload is static data and replaces this array's
                    # contents; don't retain element taint from earlier writes.
                    # Register aliases/object identity are not modeled, so the
                    # method still receives partial-coverage status.
                    registers.pop(f"@array:{fill_array_data.group(1)}", None)
                    warn(f"fill-array-data payload/index effects are not modeled in {method.key} at line {line_no}")
                if filled_new_array:
                    element_traces = frozenset(
                        trace for register in _invocation_registers(filled_new_array.group(1))
                        for trace in registers.get(register, ())
                    )
                    if element_traces:
                        registers["@pending_array_elements"] = element_traces
                if return_value:
                    return_flows.update(registers.get(return_value.group(1), ()))
                arithmetic = re.match(
                    r"(?:rsub|add|sub|mul|div|rem|and|or|xor|shl|shr|ushr|neg|not)-[a-z0-9]+(?:/2addr|/lit\d+)?\s+.+",
                    text,
                )
                conversion = re.match(
                    r"(?:int|long|float|double)-to-(?:int|long|float|double|byte|char|short)\s+([vp]\d+),\s*([vp]\d+)",
                    text,
                )
                arithmetic_traces: set[tuple[str, int, str, str]] = set()
                if arithmetic:
                    operands = re.findall(r"[vp]\d+", text)
                    source_registers = operands if "/2addr" in text.split(None, 1)[0] else operands[1:]
                    for source_register in source_registers:
                        arithmetic_traces.update(registers.get(source_register, ()))
                if conversion:
                    arithmetic_traces.update(registers.get(conversion.group(2), ()))
                write = write_re.match(text)
                unknown_register_write = re.match(r"[A-Za-z][A-Za-z0-9/-]*\s+([vp]\d+)\s*,", text)
                if (unknown_register_write and not write and not array_put and not instance_put
                        and not static_put and not fill_array_data
                        and not text.startswith(("if-", "check-cast", "packed-switch", "sparse-switch"))):
                    warn(f"unmodeled register-write form in {method.key} at line {line_no}")
                    unknown_dest = unknown_register_write.group(1)
                    registers.pop(unknown_dest, None)
                    registers.pop(f"@array:{unknown_dest}", None)
                    registers.pop(f"@builder:{unknown_dest}", None)
                    registers.pop(f"@returned:{unknown_dest}", None)
                if write:
                    destination = write.group(1)
                    registers.pop(destination, None)
                    registers.pop(f"@array:{destination}", None)
                    registers.pop(f"@builder:{destination}", None)
                    registers.pop(f"@returned:{destination}", None)
                    opcode = text.split(None, 1)[0]
                    wide_write = (
                        opcode.startswith(("const-wide", "move-wide", "move-result-wide",
                                           "iget-wide", "sget-wide", "aget-wide"))
                        or re.match(r"(?:int|long|float|double)-to-(?:long|double)$", opcode)
                        or re.match(r"(?:add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-(?:long|double)(?:/2addr|/lit\d+)?$", opcode)
                    )
                    if wide_write:
                        clear_wide_high_word(destination)
                    if arithmetic_traces:
                        registers[destination] = frozenset(arithmetic_traces)

                if array_put:
                    value_register, array_register = array_put.groups()
                    value_traces = registers.get(value_register, ())
                    if value_traces:
                        array_key = f"@array:{array_register}"
                        registers[array_key] = frozenset(
                            set(registers.get(array_key, ())) | set(value_traces)
                        )

                if static_put:
                    value_register, field_key = static_put.groups()
                    for trace in registers.get(value_register, ()):
                        static_field_writes.add((field_key, trace))

                invoke = invoke_re.search(text)
                if text.startswith("invoke-") and not invoke:
                    warn(f"unmodeled invoke form in {method.key} at line {line_no}")
                if invoke:
                    target_class, target_name, signature = invoke.group(2), invoke.group(3), invoke.group(4)
                    target_key = f"{target_class}->{target_name}"
                    args_match = invoke_args_re.search(text)
                    args = _invocation_registers(args_match.group(1)) if args_match else []
                    # Match the complete owner + method name. Prefix matching
                    # misclassified lookalikes such as getStringExtraCompat as
                    # Android framework sources/sinks.
                    source_kind = SMALI_SOURCES.get(target_key)
                    if source_kind:
                        pending = frozenset({(source_kind, line_no, method.key, method.file_path)})
                    elif target_key in SMALI_DERIVED_SOURCES and args:
                        receiver_traces = registers.get(args[0], ())
                        if target_key in {
                            "Landroid/content/Intent;->getData",
                            "Landroid/content/Intent;->getDataString",
                        }:
                            pending = frozenset((
                                "INTENT_DATA_URI", line_no, trace[2], trace[3]
                            ) for trace in receiver_traces)
                        elif target_key in SMALI_INTENT_DERIVED_KINDS:
                            derived_kind = SMALI_INTENT_DERIVED_KINDS[target_key]
                            pending = frozenset((
                                derived_kind, line_no, trace[2], trace[3]
                            ) for trace in receiver_traces)
                        else:
                            pending = frozenset(receiver_traces)
                    elif target_key in SMALI_TAINT_TRANSFORMS:
                        pending = frozenset(
                            trace for register in args for trace in registers.get(register, ())
                        )
                    elif target_key in SMALI_BUILDER_TO_STRING and args:
                        pending = frozenset(registers.get(f"@builder:{args[0]}", ()))
                    if target_key in SMALI_STREAM_SOURCE_ACCESSORS and args:
                        pending = frozenset(registers.get(args[0], ()))

                    external_uri_index = SMALI_EXTERNAL_URI_STREAMS.get(target_key)
                    if external_uri_index is not None and len(args) > external_uri_index:
                        if registers.get(args[external_uri_index]):
                            pending = frozenset({(
                                "EXTERNAL_FILE_CONTENT_CANDIDATE", line_no,
                                method.key, method.file_path,
                            )})

                    external_path_index = SMALI_EXTERNAL_PATH_READERS.get(target_key)
                    if external_path_index is not None and len(args) > external_path_index:
                        if registers.get(args[external_path_index]):
                            pending = frozenset({(
                                "EXTERNAL_FILE_CONTENT_CANDIDATE", line_no,
                                method.key, method.file_path,
                            )})
                            if target_key.endswith("->readAllBytes"):
                                registers["@pending_array_elements"] = pending

                    if target_name == "<init>" and args:
                        if target_class in SMALI_EXTERNAL_PATH_STREAM_CONSTRUCTORS:
                            path_traces = frozenset(trace for register in args[1:]
                                                    for trace in registers.get(register, ()))
                            if path_traces:
                                registers[args[0]] = frozenset({(
                                    "EXTERNAL_FILE_CONTENT_CANDIDATE", line_no,
                                    method.key, method.file_path,
                                )})
                        elif target_class in SMALI_PATH_OBJECT_CONSTRUCTORS:
                            path_traces = frozenset(trace for register in args[1:]
                                                    for trace in registers.get(register, ()))
                            if path_traces:
                                registers[args[0]] = path_traces
                            else:
                                registers.pop(args[0], None)
                        elif target_class in SMALI_STREAM_WRAPPER_CONSTRUCTORS:
                            wrapped_traces = frozenset(trace for register in args[1:]
                                                       for trace in registers.get(register, ()))
                            if wrapped_traces:
                                registers[args[0]] = wrapped_traces

                    receiver_traces = frozenset(registers.get(args[0], ())) if args else frozenset()
                    if receiver_traces and target_class in SMALI_BUFFER_READERS:
                        if target_name == "read" and len(args) > 1 and "[" in signature:
                            array_key = f"@array:{args[1]}"
                            registers[array_key] = frozenset(
                                set(registers.get(array_key, ())) | set(receiver_traces)
                            )
                            pending = frozenset()
                        elif target_name == "read" and signature.startswith("()I"):
                            # InputStream.read() and Reader.read() return one
                            # byte/character directly instead of filling an
                            # array. Keep the return tainted so subsequent
                            # scalar/string operations remain visible.
                            pending = receiver_traces
                        elif target_name in {"readLine", "readText"}:
                            pending = receiver_traces
                        elif target_name == "readAllBytes":
                            pending = receiver_traces
                            registers["@pending_array_elements"] = receiver_traces
                    if receiver_traces and target_class in SMALI_CONTENT_LINE_READERS and target_name in {
                        "next", "nextLine", "nextInt", "nextLong", "nextFloat", "nextDouble",
                    }:
                        pending = receiver_traces

                    exact_target_key = f"{target_class}->{target_name}{signature}"
                    tainted_arguments = any(registers.get(register) for register in args)
                    modeled_invocation_summary = (
                        target_key in SMALI_SOURCES
                        or target_key in SMALI_DERIVED_SOURCES
                        or target_key in SMALI_TAINT_TRANSFORMS
                        or target_key in SMALI_BUILDER_TO_STRING
                        or target_key in SMALI_BUILDER_MUTATORS
                        or exact_target_key in SMALI_BUILDER_CONSTRUCTORS
                        or target_key in SMALI_STREAM_SOURCE_ACCESSORS
                        or target_key in SMALI_EXTERNAL_URI_STREAMS
                        or target_key in SMALI_EXTERNAL_PATH_READERS
                        or (target_name == "<init>" and target_class in (
                            SMALI_EXTERNAL_PATH_STREAM_CONSTRUCTORS
                            | SMALI_PATH_OBJECT_CONSTRUCTORS
                            | SMALI_STREAM_WRAPPER_CONSTRUCTORS
                        ))
                        or (target_class in SMALI_BUFFER_READERS and target_name in {
                            "read", "readLine", "readText", "readAllBytes",
                        })
                        or (target_class in SMALI_CONTENT_LINE_READERS and target_name in {
                            "next", "nextLine", "nextInt", "nextLong", "nextFloat", "nextDouble",
                        })
                        or target_key in SMALI_SINKS
                        or exact_target_key in self.methods
                    )
                    if tainted_arguments and not modeled_invocation_summary:
                        warn(f"tainted arguments passed to an unmodeled invocation in {method.key} at line {line_no}")
                    if exact_target_key in SMALI_BUILDER_CONSTRUCTORS and len(args) > 1:
                        builder_key = f"@builder:{args[0]}"
                        constructor_traces = frozenset(
                            trace for register in args[1:] for trace in registers.get(register, ())
                        )
                        if constructor_traces:
                            registers[builder_key] = constructor_traces

                    if target_key in SMALI_BUILDER_MUTATORS and args:
                        builder_key = f"@builder:{args[0]}"
                        builder_traces = set(registers.get(builder_key, ()))
                        for register in args[1:]:
                            builder_traces.update(registers.get(register, ()))
                        if builder_traces:
                            builder_summary = frozenset(builder_traces)
                            registers[builder_key] = builder_summary
                            if signature.split(")", 1)[-1] in {
                                "Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;",
                            }:
                                registers["@pending_builder"] = builder_summary

                    sink = target_key if target_key in SMALI_SINKS else None
                    if sink:
                        tainted = [(register, trace) for register in args for trace in registers.get(register, ())]
                        for register, trace in tainted:
                            flows.append({
                                "method": method.key, "file_path": method.file_path,
                                "source_kind": trace[0], "source_line": trace[1], "sink": sink,
                                "source_method": trace[2], "source_file": trace[3],
                                "sink_line": line_no, "register": register,
                                "via_interprocedural_return": trace in registers.get(f"@returned:{register}", ()),
                            })
                    target_signature = invoke.group(4)
                    exact_target_key = f"{target_class}->{target_name}{target_signature}"
                    target_method = self.methods.get(exact_target_key)
                    if target_method:
                        called_methods.add(exact_target_key)
                        if (not source_kind and target_key not in SMALI_DERIVED_SOURCES
                                and target_key not in SMALI_TAINT_TRANSFORMS
                                and target_key not in SMALI_BUILDER_MUTATORS
                                and target_key not in SMALI_BUILDER_TO_STRING):
                            pending = frozenset((callee_return_taints or {}).get(exact_target_key, ()))
                            if pending:
                                registers["@pending_return"] = pending
                    if target_method and args:
                        for formal_register, actual_register in _parameter_argument_registers(
                            target_signature, target_method.is_static, args,
                        ):
                            for trace in registers.get(actual_register, ()):
                                argument_flows.add((exact_target_key, formal_register, trace))

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
        return (flows, sorted(argument_flows), sorted(static_field_writes), static_field_reads,
                return_flows, called_methods)

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
                        is_static=" static " in f" {stripped} ",
                        is_public=" public " in f" {stripped} ",
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
                if re.match(
                    r"\.annotation\s+(?:runtime|system|build)\s+Landroid/webkit/JavascriptInterface;",
                    stripped,
                ):
                    current_method.is_javascript_interface = True
                    current_method.javascript_interface_annotation_line = line_num

                # Track string constants loaded into registers
                str_match = const_str_re.search(stripped)
                if str_match:
                    reg, val = str_match.group(1), str_match.group(2)
                    register_strings[reg] = val
                else:
                    register_write = re.match(
                        r"(?:const(?:-[a-z]+)?(?:/\w+)?|move-exception|new-instance|new-array|move(?:-wide)?(?:/\w+)?|"
                        r"iget(?:-[a-z0-9/]+)?|[as]get(?:-[a-z]+)?|array-length|instance-of|cmp[a-z]*|"
                        r"(?:neg|not)-[a-z]+|(?:rsub|add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-[a-z0-9/]+)"
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
                        if prefix_key in SMALI_SOURCES:
                            current_method.sources_called.append(prefix_key)

                        # Check if target is a known sink
                        if prefix_key in SMALI_SINKS:
                            current_method.sinks_called.append(prefix_key)

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
        seen_local: set[tuple[str, str, int, str, str, int]] = set()
        for flow in self.local_register_flows[:1000]:
            sink_spec = SMALI_SINKS[flow["sink"]]
            key = (flow["method"], flow["file_path"], flow["sink_line"], flow["sink"],
                   flow["source_method"], flow["source_line"])
            if key in seen_local:
                continue
            seen_local.add(key)
            is_cross_method = (flow["source_method"] != flow["method"]
                               or flow.get("via_interprocedural_return", False))
            analysis_kind = ("smali_interprocedural_register_flow" if is_cross_method
                             else "smali_local_register_flow")
            flow_scope = ("across supported exact-signature calls, static fields, or method returns"
                          if is_cross_method else "within the same method")
            source_context_note = (
                " The JavascriptInterface annotation does not prove the object is registered with a WebView, "
                "JavaScript is enabled, or the calling frame/content is attacker-controlled."
                if flow["source_kind"] == "WEBVIEW_JAVASCRIPT_INTERFACE_PARAMETER" else ""
            )
            findings.append(Finding(
                title=f"{'Interprocedural' if is_cross_method else 'Same-method'} Smali register-flow candidate: {sink_spec['cwe']}",
                description=(f"The bounded Smali pass tracked {flow['source_kind']} from "
                             f"{flow['source_file']}:{flow['source_line']} in {flow['source_method']} "
                             f"into register {flow['register']} used by {flow['sink']} at "
                             f"{flow['file_path']}:{flow['sink_line']} in {flow['method']} {flow_scope}. "
                             "This is a bounded CFG may-flow candidate using exact-signature argument and tainted "
                             "register-return summaries, primitive moves/arithmetic, supported String transforms, "
                             "local StringBuilder/StringBuffer constructor/mutation/toString summaries, exact static-field names, and "
                             "imprecise array-element summaries. "
                             "dynamic dispatch, instance/heap identity, array indexes, sanitizers, branch "
                             "feasibility, component authorization, and security impact remain unresolved. "
                             f"{source_context_note}"),
                severity=Severity.INFO, confidence=0.5, cwe_id=sink_spec["cwe"],
                cvss_score=0.0, cvss_vector="", affected_component=flow["method"].split("->", 1)[0],
                file_path=flow["file_path"], line_number=flow["sink_line"],
                code_snippet=(f"{flow['method']}\nsource line {flow['source_line']}: {flow['source_kind']}\n"
                              f"sink line {flow['sink_line']}: {flow['sink']} (register {flow['register']})"),
                remediation="Validate and constrain data at the actual trust boundary; use safe sink APIs and verify the runtime path.",
                status=FindingStatus.UNVERIFIED,
                detection_method="SmaliCallGraphEngine (bounded register may-flow)",
                metadata={"proof_state": "not_proven", "analysis_kind": analysis_kind,
                          "source_file": flow["source_file"], "source_line": flow["source_line"],
                          "source_method": flow["source_method"], "source_kind": flow["source_kind"],
                          "register_dataflow": "same_method_moves_arithmetic_string_transforms_builder_mutations_array_elements_static_fields_exact_signature_arguments_and_returns",
                          "control_flow": "cfg_may_analysis_condition_values_not_modeled",
                          "manifest_authorization": "not_resolved"},
            ))

        self.coverage.update(
            register_dataflow_status=("partial_bounded_cfg_register_may_analysis"
                                      if self.local_register_analysis_warnings or self.local_register_methods_skipped
                                      else "bounded_same_method_and_interprocedural_register_cfg_may_analysis"),
            local_register_flow_candidates=len(seen_local),
            local_register_methods_skipped=len(self.local_register_methods_skipped),
            skipped_method_keys=self.local_register_methods_skipped[:100],
            register_dataflow_warnings=self.local_register_analysis_warnings[:100],
            register_dataflow_limitations=[
                "conditional branches are both explored; condition feasibility and sanitizers are not modeled",
                "instance fields, precise array indexes/objects, casts, returned heap side effects, builder identity across fields/calls, and polymorphic dispatch are not modeled",
                "unresolved or over-limit switch payloads mark coverage partial",
                "component reachability and manifest authorization are not resolved",
                "JavascriptInterface annotation does not prove registration, JavaScript enablement, frame origin, target SDK, or a loaded untrusted page",
            ],
        )
        if self.local_register_methods_skipped:
            self.coverage.update(static_status="partial", limits_reached=True)
        elif self.local_register_analysis_warnings:
            self.coverage.update(static_status="partial")

        return findings
