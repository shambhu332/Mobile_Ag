"""Optional Tree-sitter Java source-to-sink candidate analysis.

This is a bounded, path-insensitive local data-flow pass. It improves syntax
and argument-boundary handling over regex-only scanning, but it is not Android
call-graph, control-flow, sanitizer, or exploit verification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.analysis.source_syntax import numeric_sql_concatenation

MAX_PARSE_ERROR_NODE_VISITS = 100_000
MAX_TYPE_IDENTITY_NODE_VISITS = 100_000


@dataclass(frozen=True)
class Trace:
    kind: str
    line: int
    source: str


class JavaAstTaintAnalyzer:
    def __init__(self):
        self.last_failure_reason: str | None = None
        self.last_parse_error_node_count: int | None = None
        self.last_parse_error_count_status = "not_measured"
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_java
            self._parser = Parser(Language(tree_sitter_java.language()))
            self.available = True
        except (ImportError, AttributeError, TypeError):
            self._parser = None
            self.available = False

    def analyze(self, content: str, file_path: str = "") -> list[Finding] | None:
        """Return AST candidates; None means unavailable or parse errors (fallback)."""
        self.last_parse_error_node_count = None
        self.last_parse_error_count_status = "not_measured"
        if not self.available:
            self.last_failure_reason = "parser_unavailable"
            return None
        raw = content.encode("utf-8", errors="replace")
        try:
            tree = self._parser.parse(raw)
        except Exception:
            self.last_failure_reason = "parser_exception"
            return None
        if tree.root_node.has_error:
            self.last_failure_reason = "syntax_error"
            pending = [tree.root_node]
            visited = 0
            error_nodes = 0
            truncated = False
            while pending and visited < MAX_PARSE_ERROR_NODE_VISITS:
                node = pending.pop()
                visited += 1
                if node.is_error or node.is_missing:
                    error_nodes += 1
                children = node.children
                available = MAX_PARSE_ERROR_NODE_VISITS - visited - len(pending)
                if len(children) > available:
                    pending.extend(children[:max(0, available)])
                    truncated = True
                    break
                pending.extend(children)
            self.last_parse_error_node_count = error_nodes
            self.last_parse_error_count_status = "measured" if not truncated and not pending else "incomplete_visit_limit"
            return None
        self.last_failure_reason = None
        findings: list[Finding] = []
        qualified_identities: dict[str, str] = {}
        class_bases: dict[str, set[str]] = {}
        for match in re.finditer(
            r"\bclass\s+([A-Za-z_$][\w$]*)\s*(?:<[^>{}]*>)?([^{}]*)\{",
            content,
        ):
            header = match.group(2)
            parents: set[str] = set()
            extends = re.search(r"\bextends\s+([A-Za-z_$][\w.$]*)", header)
            implements = re.search(r"\bimplements\s+([A-Za-z_$][\w.$]*(?:\s*,\s*[A-Za-z_$][\w.$]*)*)", header)
            if extends:
                parents.add(extends.group(1).rsplit(".", 1)[-1])
            if implements:
                parents.update(item.strip().rsplit(".", 1)[-1] for item in implements.group(1).split(","))
            class_bases[match.group(1)] = parents

        def is_known_unrelated_sink_type(type_name: str, compatible_types: set[str]) -> bool:
            simple = type_name.split("<", 1)[0].rstrip("?[]").rsplit(".", 1)[-1]
            if simple in compatible_types or simple not in class_bases:
                return False
            visited: set[str] = set()
            pending = [simple]
            while pending:
                current = pending.pop()
                if current in compatible_types:
                    return False
                if current in visited:
                    continue
                visited.add(current)
                pending.extend(class_bases.get(current, set()))
            return True

        def method_receiver_types(method_node) -> dict[str, str]:
            result: dict[str, str] = {}
            pending = list(method_node.named_children)
            while pending:
                current = pending.pop()
                if current.type in {"method_declaration", "class_declaration", "interface_declaration",
                                    "enum_declaration", "record_declaration", "lambda_expression",
                                    "object_creation_expression"}:
                    continue
                if current.type == "formal_parameter":
                    type_node = current.child_by_field_name("type")
                    name_node = current.child_by_field_name("name")
                    if type_node and name_node:
                        result[text(name_node)] = text(type_node)
                elif current.type == "local_variable_declaration":
                    type_node = current.child_by_field_name("type")
                    if type_node:
                        for declarator in current.named_children:
                            if declarator.type == "variable_declarator":
                                name_node = declarator.child_by_field_name("name")
                                if name_node:
                                    result[text(name_node)] = text(type_node)
                pending.extend(current.named_children)
            return result
        direct_sources = {
            "getStringExtra": "INTENT_EXTRA", "getIntExtra": "INTENT_EXTRA",
            "getLongExtra": "INTENT_EXTRA", "getFloatExtra": "INTENT_EXTRA",
            "getDoubleExtra": "INTENT_EXTRA", "getBooleanExtra": "INTENT_EXTRA",
            "getByteArrayExtra": "INTENT_EXTRA", "getStringArrayExtra": "INTENT_EXTRA",
            "getStringArrayListExtra": "INTENT_EXTRA", "getIntegerArrayListExtra": "INTENT_EXTRA",
            "getParcelableExtra": "INTENT_EXTRA", "getParcelableArrayExtra": "INTENT_EXTRA",
            "getParcelableArrayListExtra": "INTENT_EXTRA", "getSerializableExtra": "INTENT_EXTRA",
            "getBundleExtra": "INTENT_EXTRA", "getExtras": "INTENT_EXTRA",
            "getCharSequenceExtra": "INTENT_EXTRA", "getCharSequenceArrayExtra": "INTENT_EXTRA",
            "getCharSequenceArrayListExtra": "INTENT_EXTRA",
            "getIntent": "INTENT_SOURCE",
            "getPrimaryClip": "CLIPBOARD_SOURCE",
        }
        sink_methods = {
            "loadUrl": ("CWE-829", Severity.HIGH, "Potential Untrusted Input Flow to WebView Navigation", "MASVS-CODE-2"),
            "evaluateJavascript": ("CWE-79", Severity.HIGH, "Potential Untrusted Data Flow to WebView JavaScript Evaluation", "MASVS-CODE-2"),
            "postUrl": ("CWE-829", Severity.HIGH, "Potential Untrusted Input Flow to WebView Navigation", "MASVS-CODE-2"),
            "rawQuery": ("CWE-89", Severity.HIGH, "Untrusted Taint Flow to Database Query (SQL Injection)", "MASVS-CODE-2"),
            "execSQL": ("CWE-89", Severity.HIGH, "Untrusted Taint Flow to Database Query (SQL Injection)", "MASVS-CODE-2"),
            "startActivity": ("CWE-927", Severity.HIGH, "Untrusted Taint Flow to Intent Redirection (IPC Hijack)", "MASVS-PLATFORM-1"),
            "startActivityForResult": ("CWE-927", Severity.HIGH, "Untrusted Taint Flow to Intent Redirection (IPC Hijack)", "MASVS-PLATFORM-1"),
            "startService": ("CWE-927", Severity.HIGH, "Untrusted Taint Flow to Intent Redirection (IPC Hijack)", "MASVS-PLATFORM-1"),
            "startForegroundService": ("CWE-927", Severity.HIGH, "Untrusted Taint Flow to Intent Redirection (IPC Hijack)", "MASVS-PLATFORM-1"),
            "sendBroadcast": ("CWE-927", Severity.HIGH, "Untrusted Taint Flow to Intent Redirection (IPC Hijack)", "MASVS-PLATFORM-1"),
            "sendOrderedBroadcast": ("CWE-927", Severity.HIGH, "Untrusted Taint Flow to Intent Redirection (IPC Hijack)", "MASVS-PLATFORM-1"),
            "exec": ("CWE-78", Severity.CRITICAL, "Untrusted Taint Flow to System Command Execution", "MASVS-CODE-4"),
            "forName": ("CWE-470", Severity.HIGH, "Untrusted Taint Flow to Dynamic Reflection Target Selection", "MASVS-CODE-4"),
            "loadClass": ("CWE-470", Severity.HIGH, "Untrusted Taint Flow to Dynamic Reflection Target Selection", "MASVS-CODE-4"),
            "getMethod": ("CWE-470", Severity.HIGH, "Untrusted Taint Flow to Dynamic Reflection Target Selection", "MASVS-CODE-4"),
            "getDeclaredMethod": ("CWE-470", Severity.HIGH, "Untrusted Taint Flow to Dynamic Reflection Target Selection", "MASVS-CODE-4"),
        }
        remediation = {
            "CWE-829": "Treat externally supplied URLs as untrusted. Parse and validate scheme and complete host against an exact allowlist before loading; verify effective guards and impact.",
            "CWE-79": "Avoid concatenating untrusted data into JavaScript source. Use structured messaging or context-appropriate encoding and verify the script context.",
            "CWE-89": "Use parameterized SQL with bind arguments; never concatenate untrusted query syntax.",
            "CWE-927": "Validate the destination and authority of forwarded Intents before launching or broadcasting.",
            "CWE-78": "Avoid dynamic command execution; use platform APIs and fixed argument structures.",
            "CWE-470": "Avoid reflection or class loading selected from untrusted names; use a fixed allowlist.",
            "CWE-22": "Canonicalize paths and enforce separator-aware containment within the intended directory.",
        }

        def text(node) -> str:
            return raw[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

        package_name = ""
        imports: dict[str, set[str]] = {}
        wildcard_import = False
        for declaration in tree.root_node.named_children:
            if declaration.type == "package_declaration" and declaration.named_children:
                package_name = text(declaration.named_children[0]).strip()
            elif declaration.type == "import_declaration":
                value = text(declaration).strip().removeprefix("import").removesuffix(";").strip()
                if value.startswith("static "):
                    continue
                if value.endswith(".*"):
                    wildcard_import = True
                elif "." in value:
                    imports.setdefault(value.rsplit(".", 1)[-1], set()).add(value)

        declared_type_names: dict[str, set[str]] = {}
        declared_type_counts: dict[str, int] = {}
        top_level_nodes = tree.root_node.named_children
        if len(top_level_nodes) > MAX_TYPE_IDENTITY_NODE_VISITS:
            # Do not make a partial type index look definitive.
            top_level_nodes = []
        for current in top_level_nodes:
            if current.type in {"class_declaration", "interface_declaration", "enum_declaration",
                                "record_declaration", "annotation_type_declaration"}:
                declared_name = current.child_by_field_name("name")
                if declared_name is not None:
                    simple_name = text(declared_name)
                    declared_type_counts[simple_name] = declared_type_counts.get(simple_name, 0) + 1
                    declared_type_names.setdefault(simple_name, set()).add(
                        f"{package_name}.{simple_name}" if package_name else simple_name)
        if len(top_level_nodes) == 0 and len(tree.root_node.named_children) > MAX_TYPE_IDENTITY_NODE_VISITS:
            declared_type_names = {}
            declared_type_counts = {}

        primitives = {"boolean", "byte", "short", "int", "long", "char", "float", "double"}
        java_lang = {"String", "Object", "Boolean", "Byte", "Short", "Integer", "Long", "Character",
                     "Float", "Double", "Number", "Class", "Throwable", "Exception", "RuntimeException",
                     "Void", "Enum", "Iterable", "Comparable", "StringBuilder", "Math", "System"}

        def qualify_type(type_name: str) -> str | None:
            """Qualify only unambiguous non-generic type names, not semantic symbols."""
            value = re.sub(r"\s+", "", type_name)
            match = re.fullmatch(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)(?:\[\])*", value)
            if not match:
                return None
            base = match.group(1)
            suffix = value[len(base):]
            if base in primitives or "." in base:
                return base + suffix
            imported_types = imports.get(base, set())
            if len(imported_types) == 1:
                return next(iter(imported_types)) + suffix
            if len(imported_types) > 1:
                return None
            local_types = declared_type_names.get(base, set())
            if len(local_types) == 1 and declared_type_counts.get(base) == 1:
                return next(iter(local_types)) + suffix
            if local_types:
                return None
            if base in java_lang:
                return "java.lang." + base + suffix
            if wildcard_import:
                return None
            return f"{package_name}.{base}{suffix}" if package_name else base + suffix

        def method_name(node) -> str:
            name = node.child_by_field_name("name")
            return text(name) if name else ""

        intent_getters = set(direct_sources) - {"getIntent", "getPrimaryClip"}

        def trace_for(node, env: dict[str, Trace | None], uri_names: set[str],
                      intent_names: set[str], clipboard_names: set[str]) -> Trace | None:
            if node is None:
                return None
            if node.type == "identifier":
                return env.get(text(node))
            if node.type == "ternary_expression":
                # Only the values of the two result arms can reach the
                # expression result. A tainted condition that merely selects
                # between fixed values must not taint the selected value.
                consequence = node.child_by_field_name("consequence")
                alternative = node.child_by_field_name("alternative")
                return (trace_for(consequence, env, uri_names, intent_names, clipboard_names)
                        or trace_for(alternative, env, uri_names, intent_names, clipboard_names))
            if node.type == "method_invocation":
                name = method_name(node)
                if name in direct_sources:
                    obj = node.child_by_field_name("object")
                    if name in intent_getters:
                        if obj is None or text(obj) not in intent_names:
                            return None
                    elif name == "getPrimaryClip" and (obj is None or text(obj) not in clipboard_names):
                        return None
                    elif name == "getIntent" and obj is not None and text(obj) not in {"this", "super"}:
                        return None
                    return Trace(direct_sources[name], node.start_point.row + 1, text(node)[:300])
                obj = node.child_by_field_name("object")
                if name == "getQueryParameter" and obj is not None:
                    receiver = text(obj)
                    base = env.get(receiver)
                    if ((receiver in uri_names and base is not None and base.kind == "INTENT_EXTRA")
                            or ("getdata()" in receiver.lower() and "intent" in receiver.lower())):
                        return Trace("URI_QUERY_PARAM", node.start_point.row + 1, text(node)[:300])
                if name in {"getPath", "getLastPathSegment", "getHost", "getAuthority", "getFragment"} and obj is not None:
                    receiver = text(obj)
                    base = env.get(receiver)
                    if ((receiver in uri_names and base is not None and base.kind == "INTENT_EXTRA")
                            or ("getdata()" in receiver.lower() and "intent" in receiver.lower())):
                        return Trace("URI_COMPONENT", node.start_point.row + 1, text(node)[:300])
                if name == "getText" and obj is not None and text(obj) in clipboard_names:
                    return Trace("CLIPBOARD_SOURCE", node.start_point.row + 1, text(node)[:300])
                if name in {"getData", "getDataString"} and obj is not None:
                    receiver = text(obj).lower()
                    if text(obj) in intent_names or receiver == "getintent()":
                        return Trace("INTENT_EXTRA", node.start_point.row + 1, text(node)[:300])
                if name == "getString" and obj is not None and text(obj).split(".")[-1] in {
                    "prefs", "preferences", "sharedPrefs", "sharedPreferences"
                }:
                    return Trace("SHARED_PREFS_SOURCE", node.start_point.row + 1, text(node)[:300])
                if name == "toString" and obj is not None:
                    return trace_for(obj, env, uri_names, intent_names, clipboard_names)
                if name == "valueOf":
                    args = args_of(node)
                    return trace_for(args[0], env, uri_names, intent_names, clipboard_names) if args else None
                # Unknown call arguments are not automatically the call's
                # return value. Source methods were handled above; summaries
                # remain a bounded lexical-engine responsibility.
                return None
            for child in node.named_children:
                found = trace_for(child, env, uri_names, intent_names, clipboard_names)
                if found:
                    return found
            return None

        def args_of(node):
            args = node.child_by_field_name("arguments")
            return list(args.named_children) if args else []

        def directly_declared(block_node) -> set[str]:
            names: set[str] = set()
            for child in block_node.named_children:
                if child.type != "local_variable_declaration":
                    continue
                for declarator in child.named_children:
                    if declarator.type == "variable_declarator":
                        name_node = declarator.child_by_field_name("name")
                        if name_node:
                            names.add(text(name_node))
            return names

        def merge_path_insensitive(before: Trace | None, after: Trace | None) -> Trace | None:
            # A branch may assign a tainted value on only some paths. Preserve
            # that possibility; a safe assignment on one path cannot prove the
            # variable safe after the branch.
            return after if before is None else before if after is None else before

        def emit(node, trace: Trace, sink_name: str, current_method: str,
                 current_method_identity: str | None):
            cwe, severity, title, masvs = sink_methods[sink_name]
            stored_preference = trace.kind == "SHARED_PREFS_SOURCE"
            if stored_preference:
                title = f"Stored Preference Value Flow Candidate to {sink_name}"
            line = node.start_point.row + 1
            line_text = content.splitlines()[line - 1].strip() if line <= len(content.splitlines()) else text(node)[:500]
            description = (f"A Tree-sitter Java AST pass found a local candidate flow from "
                           f"{trace.kind} at line {trace.line} to {sink_name} at line {line}. "
                           "The pass is path-insensitive; Android reachability, guards, framework semantics, "
                           "and exploit impact require manual validation.")
            if stored_preference:
                description += " The value is app-persisted; who can write or modify it is not established, so attacker control is not proven."
            findings.append(Finding(
                title=title,
                description=description,
                severity=Severity.INFO if stored_preference else severity, confidence=0.5, cwe_id=cwe, cvss_score=0.0,
                owasp_masvs=masvs, affected_component=file_path or "UnknownClass",
                file_path=file_path, line_number=line, code_snippet=line_text[:1000],
                detection_method="JavaAstTaintAnalyzer (Tree-sitter)", status=FindingStatus.UNVERIFIED,
                remediation=remediation[cwe],
                metadata={"proof_state": "not_proven", "analysis_kind": "java_ast_local_flow",
                          "source_kind": trace.kind,
                          "source_sink_trace": {
                              "source": {"kind": trace.kind, "line": trace.line, "method": current_method,
                                         "method_identity": current_method_identity,
                                         "source_qualified_method_identity": qualified_identities.get(current_method_identity),
                                         "source_qualified_identity_kind": "package_import_and_same_source_type_lexical_canonicalization_only" if current_method_identity in qualified_identities else "not_available",
                                         "method_identity_kind": "tree_sitter_lexical_owner_signature" if current_method_identity else "not_available"},
                              "sink": {"operation": sink_name, "line": line, "method": current_method,
                                       "method_identity": current_method_identity,
                                       "source_qualified_method_identity": qualified_identities.get(current_method_identity),
                                       "source_qualified_identity_kind": "package_import_and_same_source_type_lexical_canonicalization_only" if current_method_identity in qualified_identities else "not_available",
                                       "method_identity_kind": "tree_sitter_lexical_owner_signature" if current_method_identity else "not_available"},
                              "guards": "not_resolved", "runtime_verified": False,
                          },
                          "source_control_status": "app_persisted_value_origin_not_established" if stored_preference else "modeled_source_not_reachability_proof",
                          "source_reachability": "callback_signature_only" if trace.kind == "ANDROID_CALLBACK_INTENT_PARAMETER" else "not_established",
                          "control_flow": "path_insensitive",
                          "interprocedural_value_flow": "direct_callback_parameter" if trace.kind == "ANDROID_CALLBACK_INTENT_PARAMETER" else "not_resolved"},
            ))

        def method_uri_names(method_node) -> set[str]:
            names: set[str] = set()
            pending = list(method_node.named_children)
            while pending:
                current = pending.pop()
                # A local/anonymous class, nested method, or lambda has its
                # own lexical locals and must not contribute receiver types to
                # the enclosing method's source checks.
                if current.type in {"method_declaration", "class_declaration", "interface_declaration",
                                    "enum_declaration", "record_declaration", "lambda_expression",
                                    "object_creation_expression"}:
                    continue
                if current.type == "formal_parameter":
                    type_node = current.child_by_field_name("type")
                    name_node = current.child_by_field_name("name")
                    if type_node and name_node and text(type_node).endswith("Uri"):
                        names.add(text(name_node))
                elif current.type == "local_variable_declaration":
                    type_node = current.child_by_field_name("type")
                    if type_node and text(type_node).endswith("Uri"):
                        for declarator in current.named_children:
                            if declarator.type == "variable_declarator":
                                name_node = declarator.child_by_field_name("name")
                                if name_node:
                                    names.add(text(name_node))
                pending.extend(current.named_children)
            return names

        def method_intent_names(method_node) -> set[str]:
            names: set[str] = set()
            pending = list(method_node.named_children)
            while pending:
                current = pending.pop()
                if current.type in {"method_declaration", "class_declaration", "interface_declaration",
                                    "enum_declaration", "record_declaration", "lambda_expression",
                                    "object_creation_expression"}:
                    continue
                if current.type == "formal_parameter":
                    type_node = current.child_by_field_name("type")
                    name_node = current.child_by_field_name("name")
                    if type_node and name_node and text(type_node).split("<", 1)[0].rstrip("?[]").rsplit(".", 1)[-1] == "Intent":
                        names.add(text(name_node))
                elif current.type == "local_variable_declaration":
                    type_node = current.child_by_field_name("type")
                    if type_node and text(type_node).split("<", 1)[0].rstrip("?[]").rsplit(".", 1)[-1] == "Intent":
                        for declarator in current.named_children:
                            if declarator.type == "variable_declarator":
                                name_node = declarator.child_by_field_name("name")
                                if name_node:
                                    names.add(text(name_node))
                pending.extend(current.named_children)
            return names

        def method_clipboard_names(method_node) -> set[str]:
            names: set[str] = set()
            pending = list(method_node.named_children)
            while pending:
                current = pending.pop()
                if current.type in {"method_declaration", "class_declaration", "interface_declaration",
                                    "enum_declaration", "record_declaration", "lambda_expression",
                                    "object_creation_expression"}:
                    continue
                if current.type == "formal_parameter":
                    type_node = current.child_by_field_name("type")
                    name_node = current.child_by_field_name("name")
                    if type_node and name_node and text(type_node).endswith("ClipboardManager"):
                        names.add(text(name_node))
                elif current.type == "local_variable_declaration":
                    type_node = current.child_by_field_name("type")
                    if type_node and text(type_node).endswith("ClipboardManager"):
                        for declarator in current.named_children:
                            if declarator.type == "variable_declarator":
                                name_node = declarator.child_by_field_name("name")
                                if name_node:
                                    names.add(text(name_node))
                pending.extend(current.named_children)
            return names

        def walk(node, env: dict[str, Trace | None], current_method: str = "",
                 uri_names: set[str] | None = None, intent_names: set[str] | None = None,
                 clipboard_names: set[str] | None = None,
                 receiver_types: dict[str, str] | None = None,
                 current_method_identity: str | None = None,
                 current_owner: str = ""):
            if node.type in {"class_declaration", "interface_declaration", "enum_declaration",
                             "record_declaration", "annotation_type_declaration"}:
                owner_node = node.child_by_field_name("name")
                if owner_node:
                    owner_name = text(owner_node)
                    current_owner = f"{current_owner}.{owner_name}" if current_owner else owner_name
            # Seed only known framework callback-shaped Intent parameters. The
            # callback override and manifest exposure are not validated here.
            if node.type == "method_declaration":
                current_method = method_name(node)
                parameters = node.child_by_field_name("parameters")
                parameter_types = []
                if parameters is not None:
                    for parameter in parameters.named_children:
                        type_node = parameter.child_by_field_name("type")
                        if type_node is None:
                            # Unknown parameter syntax: withhold the identity rather
                            # than collapsing an overload to an imprecise signature.
                            parameter_types = []
                            break
                        parameter_types.append(" ".join(text(type_node).split()))
                candidate_identity = (
                    f"{current_owner or '<file>'}#{current_method}({','.join(parameter_types)})"
                    if parameters is not None and (not parameters.named_children or parameter_types)
                    else None
                )
                current_method_identity = candidate_identity if candidate_identity and len(candidate_identity) <= 256 else None
                if current_method_identity:
                    canonical_parameters = [qualify_type(item) for item in parameter_types]
                    if all(item is not None for item in canonical_parameters):
                        owner = f"{package_name}.{current_owner}" if package_name and current_owner else current_owner
                        canonical = f"{owner or '<file>'}#{current_method}({','.join(canonical_parameters)})"
                        if len(canonical) <= 256:
                            qualified_identities[current_method_identity] = canonical
                env = dict(env)
                uri_names = method_uri_names(node)
                intent_names = method_intent_names(node)
                clipboard_names = method_clipboard_names(node)
                receiver_types = method_receiver_types(node)
                params = node.child_by_field_name("parameters")
                callback_names = {"onNewIntent", "onReceive", "onActivityResult", "onStartCommand", "onHandleIntent"}
                if current_method in callback_names and params:
                    for param in params.named_children:
                        ptype = param.child_by_field_name("type")
                        pname = param.child_by_field_name("name")
                        if ptype and pname and text(ptype).split("<", 1)[0].rstrip("?[]").rsplit(".", 1)[-1] == "Intent":
                            env[text(pname)] = Trace("ANDROID_CALLBACK_INTENT_PARAMETER", param.start_point.row + 1, text(param))
            uri_names = uri_names or set()
            intent_names = intent_names or set()
            clipboard_names = clipboard_names or set()
            receiver_types = receiver_types or {}
            if node.type == "block":
                before = dict(env)
                branch = dict(env)
                for child in node.named_children:
                    walk(child, branch, current_method, uri_names, intent_names, clipboard_names,
                         receiver_types, current_method_identity, current_owner)
                local_names = directly_declared(node)
                for name, previous in before.items():
                    if name not in local_names and name in branch:
                        env[name] = merge_path_insensitive(previous, branch[name])
                return
            if node.type == "local_variable_declaration":
                for declarator in node.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    name_node = declarator.child_by_field_name("name")
                    value = declarator.child_by_field_name("value")
                    if name_node:
                        env[text(name_node)] = trace_for(value, env, uri_names, intent_names, clipboard_names)
                    if value:
                        walk(value, env, current_method, uri_names, intent_names, clipboard_names,
                             receiver_types, current_method_identity, current_owner)
                return
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and left.type == "identifier":
                    env[text(left)] = trace_for(right, env, uri_names, intent_names, clipboard_names)
                if right:
                    walk(right, env, current_method, uri_names, intent_names, clipboard_names,
                         receiver_types, current_method_identity, current_owner)
                return
            if node.type == "method_invocation":
                name = method_name(node)
                if name in sink_methods:
                    compatible_types = (
                        {"WebView"} if name in {"loadUrl", "evaluateJavascript", "postUrl"}
                        else {"SQLiteDatabase", "SupportSQLiteDatabase"}
                        if name in {"rawQuery", "execSQL"}
                        else ({"Activity", "ActivityCompat"} if name == "startActivityForResult"
                              else {"Context", "ContextWrapper", "Activity", "Service",
                                    "Application", "ContextCompat"})
                        if name in {"startActivity", "startActivityForResult", "startService",
                                    "startForegroundService", "sendBroadcast", "sendOrderedBroadcast"}
                        else ({"ClassLoader"} if name == "loadClass" else {"Class"})
                        if name in {"forName", "loadClass", "getMethod", "getDeclaredMethod"}
                        else set()
                    )
                    if compatible_types:
                        receiver = node.child_by_field_name("object")
                        receiver_name = text(receiver) if receiver and receiver.type == "identifier" else ""
                        receiver_type = receiver_types.get(receiver_name)
                        if receiver_type and is_known_unrelated_sink_type(receiver_type, compatible_types):
                            return
                    args = args_of(node)
                    relevant = args[:1] if name in {"loadUrl", "evaluateJavascript", "postUrl", "rawQuery", "execSQL", "startActivity", "startActivityForResult", "startService", "startForegroundService", "sendBroadcast", "sendOrderedBroadcast", "exec", "forName", "loadClass", "getMethod", "getDeclaredMethod"} else args
                    if name in {"rawQuery", "execSQL"} and args and numeric_sql_concatenation(text(args[0]), content):
                        return
                    trace = next((candidate for arg in relevant if (candidate := trace_for(arg, env, uri_names, intent_names, clipboard_names))), None)
                    if trace:
                        emit(node, trace, name, current_method, current_method_identity)
                for child in node.named_children:
                    walk(child, env, current_method, uri_names, intent_names, clipboard_names,
                         receiver_types, current_method_identity, current_owner)
                return
            for child in node.named_children:
                walk(child, env, current_method, uri_names, intent_names, clipboard_names,
                     receiver_types, current_method_identity, current_owner)

        walk(tree.root_node, {})
        return findings
