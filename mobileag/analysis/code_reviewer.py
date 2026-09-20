"""Scope-aware code reviewer for Android Java and Kotlin source files.

Combines lightweight lexical AST / method-block scoping with static taint analysis
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
from mobileag.reporting.cvss import get_default_cvss_for_cwe

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

        # ── Standard Single/Multi-Line Rules ──
        self.basic_rules = [
            (
                "WebView AllowFileAccess Enabled",
                re.compile(r"setAllowFileAccess\(\s*true\s*\)", re.IGNORECASE),
                "CWE-276",
                Severity.HIGH,
                "Disable file access in WebViews (setAllowFileAccess(false)) to prevent local file exfiltration."
            ),
            (
                "WebView Exposed JavascriptInterface",
                re.compile(r"addJavascriptInterface\(", re.IGNORECASE),
                "CWE-749",
                Severity.HIGH,
                "Ensure targetSdkVersion >= 17, annotate exposed methods with @JavascriptInterface, or migrate to WebMessagePorts."
            ),
            (
                "SQL Injection (Concatenated Queries)",
                re.compile(r"(?:rawQuery|execSQL)\([^,]+\+.*", re.IGNORECASE),
                "CWE-89",
                Severity.HIGH,
                "Use parameterized queries with selectionArgs placeholders instead of raw dynamic concatenation."
            ),
            (
                "Content Provider Path Traversal",
                re.compile(r"openFile\([^)]*\)", re.IGNORECASE),
                "CWE-22",
                Severity.HIGH,
                "Canonicalize and validate URI path segments using File.getCanonicalPath() against an allowed directory base."
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

        # ── PendingIntent Mutability Patterns ──
        self.pending_intent_call = re.compile(
            r"""PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)\s*\(([^)]+)\)""",
            re.MULTILINE
        )

        # ── Dynamic Receiver Patterns ──
        self.register_receiver_call = re.compile(
            r"""registerReceiver\s*\(([^;]+)\)""",
            re.MULTILINE
        )

        # ── Biometric Authentication Patterns ──
        self.biometric_auth_call = re.compile(
            r"""(?:[a-zA-Z0-9_]+\.)?authenticate\s*\(([^)]+)\)""",
            re.MULTILINE
        )

    @staticmethod
    def _extract_method_blocks(content: str) -> list[MethodBlock]:
        """Extract method blocks using bracket depth counting."""
        blocks: list[MethodBlock] = []
        lines = content.splitlines()

        method_sig_pattern = re.compile(r"(?:public|protected|private|static|fun)\s+.*?([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\{")

        for idx, line in enumerate(lines):
            match = method_sig_pattern.search(line)
            if match:
                method_name = match.group(1)
                start_line = idx + 1
                brace_depth = 0
                body_lines = []

                for sub_idx in range(idx, len(lines)):
                    cur_line = lines[sub_idx]
                    body_lines.append(cur_line)
                    brace_depth += cur_line.count("{") - cur_line.count("}")

                    if brace_depth <= 0 and sub_idx > idx:
                        end_line = sub_idx + 1
                        blocks.append(MethodBlock(method_name, start_line, end_line, "\n".join(body_lines)))
                        break

        return blocks

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
                        "title": f"Intent Redirection Vulnerability in {stem}.{block.name}()",
                        "description": (
                            f"Method '{block.name}' extracts a Parcelable/Intent '{sink_arg}' from an incoming Intent "
                            f"and forwards it directly to a start component sink without validation. "
                            "This allows external apps to use this component as a proxy to access private internal components."
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

    def _audit_pending_intent_mutability(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Flag PendingIntent creation missing FLAG_IMMUTABLE or FLAG_MUTABLE."""
        findings = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            for match in self.pending_intent_call.finditer(line):
                args_str = match.group(2)
                args = [a.strip() for a in args_str.split(",")]

                if len(args) >= 4:
                    flags_arg = args[-1]
                    has_immutable = "FLAG_IMMUTABLE" in flags_arg or "0x04000000" in flags_arg or "67108864" in flags_arg
                    has_mutable = "FLAG_MUTABLE" in flags_arg or "0x02000000" in flags_arg or "33554432" in flags_arg

                    if not (has_immutable or has_mutable):
                        cwe = "CWE-926"
                        findings.append({
                            "title": f"Missing PendingIntent Mutability Flag in {stem}",
                            "description": (
                                f"PendingIntent.{match.group(1)}() invocation does not declare FLAG_IMMUTABLE or FLAG_MUTABLE. "
                                "On Android 12 (API 31)+, omitting explicit mutability flags can cause runtime crashes or "
                                "allow malicious recipients to mutate intent extras."
                            ),
                            "severity": Severity.MEDIUM,
                            "cwe": cwe,
                            "component": stem,
                            "file_path": rel_path,
                            "line_number": idx,
                            "snippet": line.strip(),
                            "remediation": "Explicitly include PendingIntent.FLAG_IMMUTABLE in the flags argument."
                        })

        return findings

    def _audit_dynamic_receivers(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Flag registerReceiver calls on Android 13+ missing RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED."""
        findings = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            if "registerReceiver(" in line:
                has_exported_flag = "RECEIVER_EXPORTED" in line or "RECEIVER_NOT_EXPORTED" in line or "2" in line or "4" in line
                if not has_exported_flag:
                    cwe = "CWE-926"
                    findings.append({
                        "title": f"Unspecified Export Flag on Dynamic BroadcastReceiver in {stem}",
                        "description": (
                            "registerReceiver() is called without explicitly specifying Context.RECEIVER_EXPORTED or "
                            "Context.RECEIVER_NOT_EXPORTED. On Android 13 (API 33)+, this can lead to runtime crashes "
                            "or unintentional broadcast exposure."
                        ),
                        "severity": Severity.MEDIUM,
                        "cwe": cwe,
                        "component": stem,
                        "file_path": rel_path,
                        "line_number": idx,
                        "snippet": line.strip(),
                        "remediation": "Pass Context.RECEIVER_NOT_EXPORTED or Context.RECEIVER_EXPORTED in registerReceiver()."
                    })

        return findings

    def _audit_trust_managers_and_verifiers(self, content: str, rel_path: str, stem: str) -> list[dict[str, Any]]:
        """Identify empty X509TrustManager methods or permissive HostnameVerifier verify() implementations."""
        findings = []

        # Check TrustManager checkServerTrusted empty body
        trust_manager_match = re.search(
            r"void\s+(checkServerTrusted|checkClientTrusted)\s*\([^)]*\)\s*\{(.*?)\}",
            content,
            re.DOTALL
        )
        if trust_manager_match:
            body = trust_manager_match.group(2).strip()
            # Clean comments
            clean_body = re.sub(r"//.*|/\*.*?\*/", "", body, flags=re.DOTALL).strip()
            if not clean_body or clean_body == ";" or clean_body.startswith("return;"):
                cwe = "CWE-295"
                findings.append({
                    "title": f"Insecure Empty TrustManager Implementation in {stem}",
                    "description": (
                        f"Method '{trust_manager_match.group(1)}' has an empty body and performs no certificate validation. "
                        "This completely disables TLS certificate validation, exposing network traffic to MitM interception."
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
            clean_body = re.sub(r"//.*|/\*.*?\*/", "", body, flags=re.DOTALL).strip()
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
                        "title": f"Biometric Authentication Without Cryptographic Binding in {stem}",
                        "description": (
                            "BiometricPrompt.authenticate() is invoked without binding to a BiometricPrompt.CryptoObject. "
                            "Authentication relies solely on a boolean callback in userland, which is susceptible to runtime hooking."
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

        for file_path in base_path.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in {".java", ".kt"}:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                stem = file_path.stem
                lines = content.splitlines()

                # 1. Standard rules
                for line_num, line in enumerate(lines, 1):
                    for name, pattern, cwe, sev, rem in self.basic_rules:
                        if pattern.search(line):
                            findings.append({
                                "title": f"Potential {name}",
                                "description": f"Identified code pattern for {name}.",
                                "severity": sev,
                                "cwe": cwe,
                                "component": stem,
                                "file_path": rel_path,
                                "line_number": line_num,
                                "snippet": line.strip(),
                                "remediation": rem
                            })

                # 2. Scope-aware AST / Method analysis
                findings.extend(self._audit_intent_redirection(content, rel_path, stem))
                findings.extend(self._audit_pending_intent_mutability(content, rel_path, stem))
                findings.extend(self._audit_dynamic_receivers(content, rel_path, stem))
                findings.extend(self._audit_trust_managers_and_verifiers(content, rel_path, stem))
                findings.extend(self._audit_biometric_auth(content, rel_path, stem))

            except Exception as e:
                logger.debug(f"Could not inspect file {file_path}: {e}")

        return findings

    async def review(self, decompiled_path: str, manifest_data: dict[str, Any]) -> list[Finding]:
        """Review decompiled source code for vulnerabilities and return Finding models."""
        logger.info(f"Starting scope-aware code review in: {decompiled_path}")
        base_path = Path(decompiled_path)

        raw_findings = await asyncio.to_thread(self._sync_scan_source, base_path)
        findings: list[Finding] = []

        for item in raw_findings:
            cwe = item["cwe"]
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component=item.get("component", "SourceCode"),
                detection_method="CodeReviewer",
                status=FindingStatus.UNVERIFIED,
                remediation=item.get("remediation", ""),
                file_path=item["file_path"],
                line_number=item.get("line_number"),
                code_snippet=item.get("snippet", "")
            ))

        logger.info(f"Scope-aware code review completed: {len(findings)} findings.")
        return findings
