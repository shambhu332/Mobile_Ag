"""Scope-aware code reviewer for Android Java and Kotlin source files.

Combines lightweight lexical method-block scoping with pattern review
to identify complex logic and configuration vulnerabilities:
1. Intent Redirection (CWE-927 / CWE-940)
2. PendingIntent Mutability (CWE-926)
3. Android 13+ Unprotected Dynamic Receivers (CWE-926)
4. Broken Custom TrustManager & HostnameVerifier (CWE-295 / CWE-297)
5. Biometric Authentication Bypass (CWE-287)
6. WebView, SQLi, and Data Storage Flaws
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, Optional

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.android_surface import mask_non_code, method_spans
from mobileag.analysis.source_syntax import call_sites, literal_flag_bits
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)


class MethodBlock:
    """Represents a method scope parsed from decompiled source code."""

    def __init__(self, name: str, start_line: int, end_line: int, body: str):
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.body = body


class CodeReviewer:
    """Scope-aware code reviewer auditing Android Java/Kotlin source trees."""

    def __init__(self, router: Optional[LLMRouter] = None):
        self.router = router
        self.coverage = {"static_status":"not_analyzed", "runtime_status":"not_tested",
                         "proof_status":"not_proven", "exhaustive":False}

        # ── Standard Single/Multi-Line Rules ──
        self.basic_rules = [
            (
                "WebView AllowFileAccess Enabled",
                re.compile(r"setAllowFileAccess\(\s*true\s*\)", re.IGNORECASE),
                "CWE-669",
                Severity.INFO,
                "Review WebView local-file access. The setting alone does not demonstrate disclosure; assess platform/API behavior, whether untrusted content executes, and which sensitive files are actually reachable. Prefer WebViewAssetLoader or a narrowly scoped content provider."
            ),
            (
                "WebView Exposed JavascriptInterface",
                re.compile(r"addJavascriptInterface\(", re.IGNORECASE),
                "CWE-749",
                Severity.INFO,
                "Review the JavaScript bridge. Registration alone is not proof of exposure: inspect annotated methods, Android/API compatibility, loaded origins, and whether untrusted content can invoke sensitive app functionality. Prefer origin-restricted messaging APIs where possible."
            ),
            (
                "SQL Injection (Concatenated Queries)",
                re.compile(r"(?:rawQuery|execSQL)\([^,]+\+.*", re.IGNORECASE),
                "CWE-89",
                Severity.HIGH,
                "Use parameterized queries with selectionArgs placeholders instead of raw dynamic concatenation."
            ),
            (
                "File-Open Path Review Candidate",
                re.compile(r"openFile\([^)]*\)", re.IGNORECASE),
                "CWE-Unknown",
                Severity.INFO,
                "An openFile method or call is present. This pattern alone does not establish attacker-controlled paths, traversal, sensitive-file access, or external reachability. Trace the exact URI/path into filesystem operations and verify separator-aware canonical containment and guards before assigning CWE-22."
            ),
            (
                "Sensitive Data Logcat Exposure",
                re.compile(r"Log\.[deiv]\(.*?(password|token|key|secret|credential).*?\)", re.IGNORECASE),
                "CWE-532",
                Severity.LOW,
                "Strip sensitive log statements in production builds using ProGuard/R8 rules."
            ),
            (
                "Insecure SharedPreferences Mode",
                re.compile(r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", re.IGNORECASE),
                "CWE-276",
                Severity.HIGH,
                "Use MODE_PRIVATE or EncryptedSharedPreferences to prevent cross-app file access."
            ),
        ]

        # ── Scope & Intent Detection Patterns ──
        self.intent_extract_pattern = re.compile(
            r"""(?:Intent|Parcelable)\s+([a-zA-Z0-9_]+)\s*=\s*(?:\([a-zA-Z0-9_]+\)\s*)?(?:[a-zA-Z0-9_().]+?\.)?(?:getParcelableExtra|getExtras)\(""",
            re.IGNORECASE
        )
        self.intent_sink_pattern = re.compile(
            r"""(?:startActivity|startService|sendBroadcast|startActivityForResult)\s*\(\s*([a-zA-Z0-9_]+)""",
            re.IGNORECASE
        )

        # ── Biometric Authentication Patterns ──
        self.biometric_auth_call = re.compile(
            r"""(?:[a-zA-Z0-9_]+\.)?authenticate\s*\(([^)]+)\)""",
            re.MULTILINE
        )

    @staticmethod
    def _extract_method_blocks(content: str) -> list[MethodBlock]:
        """Extract method blocks using bracket depth counting."""
        code = mask_non_code(content)
        return [MethodBlock(name, code.count("\n", 0, offset) + 1,
                            code.count("\n", 0, offset + len(body)) + 1, body)
                for name, offset, body in method_spans(code)]

    def _audit_intent_redirection(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Identify untrusted incoming intent extraction forwarded directly to execution sinks."""
        findings = []
        method_blocks = self._extract_method_blocks(content)

        for block in method_blocks:
            extracted_vars = set()
            for m in self.intent_extract_pattern.finditer(block.body):
                var_name = m.group(1)
                if var_name:
                    extracted_vars.add(var_name)

            for m in self.intent_sink_pattern.finditer(block.body):
                sink_arg = m.group(1)
                if sink_arg in extracted_vars:
                    cwe = "CWE-927"
                    findings.append({
                        "title": f"Review incoming Intent forwarding in {stem}.{block.name}()",
                        "description": (
                            f"Method '{block.name}' extracts a Parcelable/Intent '{sink_arg}' from an incoming Intent "
                            f"and a component-launch call mentions the same variable in this lexical method scope. "
                            "Variable mutation, dominating validation, external component access, destination privileges and platform hardening are unresolved; no proxy access was demonstrated."
                        ),
                        "severity": Severity.HIGH,
                        "cwe": cwe,
                        "component": stem,
                        "file_path": rel_path,
                        "line_number": block.start_line,
                        "snippet": f"Sink: {m.group(0)}(...) forwarding untrusted '{sink_arg}'",
                        "remediation": "Validate target ComponentName/Action against a strict allowlist before launching forwarded Intents."
                    })

        return findings

    @staticmethod
    def _call_review(source, call, rel_path, stem, title, description, cwe="CWE-926"):
        return {
            "title": f"{title} in {stem}", "description": description,
            "severity": Severity.INFO, "cwe": cwe, "component": stem,
            "file_path": rel_path, "line_number": source.count("\n", 0, call.offset) + 1,
            "snippet": source[call.offset:call.end][:500],
            "remediation": "Review the effective flags, intended recipients, component permissions and actual attacker-controlled impact before changing legitimate functionality.",
        }

    def _audit_pending_intent_mutability(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Review the actual fourth argument, including multiline/nested calls.

        Mutable capabilities can be intentional. Missing mutability is also a
        target-SDK-dependent compatibility issue, never automatic exploit proof.
        """
        findings = []
        symbols = {"FLAG_IMMUTABLE": 0x04000000, "FLAG_MUTABLE": 0x02000000,
                   "FLAG_UPDATE_CURRENT": 0x08000000, "FLAG_CANCEL_CURRENT": 0x10000000,
                   "FLAG_NO_CREATE": 0x20000000, "FLAG_ONE_SHOT": 0x40000000,
                   "FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT": 0x01000000}
        pattern = r"\bPendingIntent\.(?:getActivity|getActivities|getBroadcast|getService|getForegroundService)"
        for call in call_sites(content, pattern):
            if len(call.args) not in (4, 5):
                continue
            bits, complete = literal_flag_bits(call.code_args[3], symbols)
            if bits & symbols["FLAG_IMMUTABLE"] and not bits & symbols["FLAG_MUTABLE"]:
                continue
            if bits & symbols["FLAG_MUTABLE"]:
                title = "Review mutable PendingIntent capability"
                description = ("An explicit mutable PendingIntent flag is present. Mutable capabilities can be required for legitimate features; review the enclosed Intent's explicit destination, fill-in fields, URI grants, who obtains the token, and current OS/target-SDK restrictions. No recipient access or privilege escalation was demonstrated.")
            elif complete:
                title = "Review missing PendingIntent mutability declaration"
                description = ("The literal flags contain neither FLAG_IMMUTABLE nor FLAG_MUTABLE. Apps targeting Android 12/API 31 or higher must declare mutability; behavior on older targets differs. Neither a reachable crash nor recipient-controlled mutation has been demonstrated.")
            else:
                title = "Review unresolved PendingIntent flags"
                description = ("The flags expression cannot be resolved by this literal-only review. Trace its effective value and recipient access; missing mutability or exploitability is not established.")
            findings.append(self._call_review(content, call, rel_path, stem, title, description))
        return findings

    def _audit_dynamic_receivers(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Review overload-specific export flags, not incidental digits in a line."""
        findings = []
        symbols = {"RECEIVER_EXPORTED": 2, "RECEIVER_NOT_EXPORTED": 4,
                   "RECEIVER_VISIBLE_TO_INSTANT_APPS": 1}
        pattern = r"\b(?:ContextCompat\.)?registerReceiver"
        for call in call_sites(content, pattern):
            compat = call.operation.startswith("ContextCompat.")
            receiver_index = 1 if compat else 0
            if len(call.code_args) <= receiver_index or call.code_args[receiver_index] == "null":
                continue  # Sticky-broadcast query without registering a receiver.
            flag_count = (4, 6) if compat else (3, 5)
            no_flag_count = (3, 5) if compat else (2, 4)
            if len(call.args) in flag_count:
                bits, complete = literal_flag_bits(call.code_args[-1], symbols)
                if bits & 4 and not bits & 2:
                    continue
                if bits & 2:
                    title = "Review exported runtime receiver"
                    description = ("RECEIVER_EXPORTED is present. This may be intentional; review the effective broadcast permission, protected system actions, sender identity and sensitive operations. No unauthorized broadcast impact was demonstrated.")
                else:
                    title = "Review missing runtime receiver export declaration" if complete else "Review unresolved runtime receiver flags"
                    description = ("Export behavior is absent from the literal flags or unresolved. Apps targeting Android 14/API 34 or higher must specify export behavior for non-system broadcasts; system-only registrations are an exception. Review target SDK, actual actions and overload semantics; exposure or a reachable crash is not established.")
            elif len(call.args) in no_flag_count:
                title = "Review missing runtime receiver export declaration"
                description = ("The selected overload has no export-flags argument. Apps targeting Android 14/API 34 or higher require explicit export behavior for non-system broadcasts; system-only registrations are an exception. Sender permissions, action provenance, reachability and impact remain untested.")
            else:
                continue
            findings.append(self._call_review(content, call, rel_path, stem, title, description))
        return findings

    def _audit_trust_managers_and_verifiers(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Identify empty X509TrustManager methods or permissive HostnameVerifier verify() implementations."""
        findings = []
        content = mask_non_code(content)

        # Check TrustManager checkServerTrusted empty body
        trust_manager_match = re.search(
            r"void\s+(checkServerTrusted|checkClientTrusted)\s*\([^)]*\)\s*\{(.*?)\}",
            content,
            re.DOTALL
        )
        if trust_manager_match:
            body = trust_manager_match.group(2).strip()
            # Clean comments
            clean_body = mask_non_code(body).strip()
            if not clean_body or clean_body == ";" or clean_body.startswith("return;"):
                cwe = "CWE-295"
                findings.append({
                    "title": f"Insecure Empty TrustManager Implementation in {stem}",
                    "description": (
                        f"Method '{trust_manager_match.group(1)}' has an empty body and performs no certificate validation. "
                        "Review whether this implementation is installed on an active TLS path and whether an untrusted researcher-controlled certificate is accepted; traffic interception is not demonstrated."
                    ),
                    "severity": Severity.CRITICAL,
                    "cwe": cwe,
                    "component": stem,
                    "file_path": rel_path,
                    "line_number": 1,
                    "snippet": f"{trust_manager_match.group(1)}() {{ ... }}",
                    "remediation": "Rely on standard system trust anchors or implement strict certificate pinning."
                })

        # Check HostnameVerifier returning true
        hostname_verifier_match = re.search(
            r"boolean\s+verify\s*\([^)]*String[^)]*SSLSession[^)]*\)\s*\{(.*?)\}",
            content,
            re.DOTALL
        )
        if hostname_verifier_match:
            body = hostname_verifier_match.group(1).strip()
            clean_body = mask_non_code(body).strip()
            if clean_body == "return true;" or clean_body == "return (true);":
                cwe = "CWE-297"
                findings.append({
                    "title": f"Permissive HostnameVerifier (Allow All) in {stem}",
                    "description": (
                        "Custom HostnameVerifier.verify() unconditionally returns true without verifying that the certificate's "
                        "Common Name (CN) or Subject Alternative Names (SAN) match the connecting host."
                    ),
                    "severity": Severity.CRITICAL,
                    "cwe": cwe,
                    "component": stem,
                    "file_path": rel_path,
                    "line_number": 1,
                    "snippet": "boolean verify(...) { return true; }",
                    "remediation": "Use OkHttp's default HostnameVerifier or implement standard domain verification."
                })

        return findings

    def _audit_biometric_auth(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Identify BiometricPrompt.authenticate() calls made without a CryptoObject."""
        findings = []
        content = mask_non_code(content)
        if "BiometricPrompt" not in content:
            return findings

        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            match = self.biometric_auth_call.search(line)
            if match:
                args = [a.strip() for a in match.group(1).split(",")]
                # If only 1 argument (PromptInfo) or first argument is null, no CryptoObject is bound
                if len(args) == 1 or args[0] in ("null", "PromptInfo"):
                    cwe = "CWE-287"
                    findings.append({
                        "title": f"Review biometric authentication without cryptographic binding in {stem}",
                        "description": (
                            "BiometricPrompt.authenticate() is invoked without binding to a BiometricPrompt.CryptoObject. "
                            "This can be an intentional UI authentication flow. Review whether a sensitive cryptographic operation requires user authentication; root/hooks are not ordinary-app bypass proof."
                        ),
                        "severity": Severity.MEDIUM,
                        "cwe": cwe,
                        "component": stem,
                        "file_path": rel_path,
                        "line_number": idx,
                        "snippet": line.strip(),
                        "remediation": "Bind BiometricPrompt.authenticate() with a Cipher initialized from Android Keystore (CryptoObject)."
                    })

        return findings

    def _sync_scan_source(self, base_path: Path) -> list[dict[str, Any]]:
        """Synchronously scan source files with pattern and scope-aware rules."""
        findings: list[dict[str, Any]] = []

        inventory = SourceInventory()
        for file_path, data in inventory.read(base_path, {".java", ".kt"}):
            try:
                content = data.decode("utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                stem = file_path.stem
                lines = mask_non_code(content).splitlines()
                original_lines = content.splitlines()

                # 1. Standard rules
                for line_num, line in enumerate(lines, 1):
                    if len(findings) >= 1000:
                        inventory.coverage['limits_reached'] = True
                        break
                    for name, pattern, cwe, sev, rem in self.basic_rules:
                        if pattern.search(line):
                            if name.startswith("WebView") or name == "File-Open Path Review Candidate":
                                description = rem
                            else:
                                description = f"Identified code pattern for {name}."
                            findings.append({
                                "title": f"Potential {name}",
                                "description": description,
                                "severity": sev,
                                "cwe": cwe,
                                "component": stem,
                                "file_path": rel_path,
                                "line_number": line_num,
                                "snippet": original_lines[line_num - 1].strip(),
                                "remediation": rem
                            })
                            if len(findings) >= 1000:
                                inventory.coverage['limits_reached'] = True
                                break

                # 2. Lexical method-scope review, not an AST/control-flow proof
                for audit in (self._audit_intent_redirection, self._audit_pending_intent_mutability,
                              self._audit_dynamic_receivers, self._audit_trust_managers_and_verifiers,
                              self._audit_biometric_auth, self._audit_keystore_specs):
                    findings.extend(audit(content, rel_path, stem)[:max(0, 1000-len(findings))])
                    if len(findings) >= 1000:
                        inventory.coverage['limits_reached'] = True
                        break

            except Exception as e:
                logger.debug(f"Could not inspect file {file_path}: {e}")

            if len(findings) >= 1000:
                break
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status='not_tested',proof_status='not_proven',exhaustive=False,
                             candidate_count=len(findings),limits={**inventory.coverage['limits'],'findings':1000})
        return findings

    def _audit_keystore_specs(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Identify Android Keystore keys generated without user authentication binding."""
        findings = []
        content = mask_non_code(content)
        if "KeyGenParameterSpec" not in content:
            return findings

        builder_matches = re.finditer(r"KeyGenParameterSpec\.Builder\s*\([^)]+\)(.*?)\.build\(\)", content, re.DOTALL)
        for m in builder_matches:
            block = m.group(1)
            if not re.search(r"\bsetUserAuthenticationRequired\s*\(\s*true\s*\)", block):
                cwe = "CWE-305"
                findings.append({
                    "title": f"Review Keystore key user-authentication policy in {stem}",
                    "description": (
                        "A cryptographic key is generated in Android Keystore without enforcing "
                        "`setUserAuthenticationRequired(true)`. Keys generated without this parameter "
                        "may be intentionally used by background operations. Other ordinary apps do not gain access to this app UID's keys from this setting alone. Review the intended security policy and a reachable sensitive operation; unauthorized key use is not demonstrated."
                    ),
                    "severity": Severity.MEDIUM,
                    "cwe": cwe,
                    "component": stem,
                    "file_path": rel_path,
                    "line_number": 1,
                    "snippet": f"KeyGenParameterSpec.Builder(...){block[:100]}....build()",
                    "remediation": "Call `.setUserAuthenticationRequired(true)` and `.setInvalidatedByBiometricEnrollment(true)` when building KeyGenParameterSpec."
                })
        return findings

    def extract_intent_extras(self, content: str) -> list[str]:
        """Extract Intent extra keys used by components to guide dynamic fuzzing."""
        extras = set()
        pattern = re.compile(r"""(?:getStringExtra|getIntExtra|getBooleanExtra|getParcelableExtra|getSerializableExtra|hasExtra)\s*\(\s*["']([a-zA-Z0-9_.-]+)["']""")
        for m in pattern.finditer(content):
            extras.add(m.group(1))
        return list(extras)


    async def review(self, decompiled_path: str, manifest_data: dict[str, Any]) -> list[Finding]:
        """Review decompiled source code for vulnerabilities and return Finding models."""
        logger.info(f"Starting scope-aware code review in: {decompiled_path}")
        base_path = Path(decompiled_path)

        raw_findings = await asyncio.to_thread(self._sync_scan_source, base_path)
        findings: list[Finding] = []

        for item in raw_findings:
            cwe = item["cwe"]
            findings.append(Finding(
                title=item["title"],
                description=item["description"],
                # These rules are lexical indicators, not demonstrated attacker
                # impact. Keep all candidates informational until a separate
                # verification step establishes exploitability.
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component=item.get("component", "SourceCode"),
                detection_method="CodeReviewer",
                status=FindingStatus.UNVERIFIED,
                remediation=item.get("remediation", ""),
                file_path=item["file_path"],
                line_number=item.get("line_number"),
                code_snippet=item.get("snippet", ""),
                metadata={"proof_state": "not_proven", "analysis_kind": "bounded_lexical_candidate",
                          "limitations": ["not an AST or full dataflow/guard analysis", "external authorization, effective runtime values and attacker impact require validation"]}
            ))

        logger.info(f"Scope-aware code review completed: {len(findings)} findings.")
        return findings
