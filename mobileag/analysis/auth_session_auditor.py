from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

if TYPE_CHECKING:
    from mobileag.dast.adb_manager import ADBManager

logger = logging.getLogger(__name__)

class AuthSessionAuditor:
    """
    Authentication & Session Security Tester for MobileAg.
    Provides lexical review candidates; draft live collection is disabled.
    """

    def __init__(self):
        # Patterns mapped to (CWE ID, Severity, Description)
        self.static_patterns = {
            "hardcoded_credentials": (
                re.compile(r'(?i)(password|passwd|pwd|secret|api_key|client_secret)\s*=\s*["\'][^"\']+["\']'),
                798,
                Severity.HIGH,
                "Credential-shaped assignment found; its purpose and validity require review."
            ),
            "oauth_client_secret": (
                re.compile(r'(?i)(client_secret|clientsecret)\s*=\s*["\'][a-zA-Z0-9_\-]+["\']'),
                798,
                Severity.HIGH,
                "OAuth client secret embedded in source code."
            ),
            "jwt_tokens": (
                re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*'),
                347,
                Severity.MEDIUM,
                "JWT-shaped literal found; this does not establish server-side signature validation behavior."
            ),
            "firebase_auth": (
                re.compile(r'FirebaseAuth\.getInstance\(\)\.signIn'),
                522,
                Severity.LOW,
                "Firebase Auth token handling found; manual review required to ensure secure storage."
            ),
            "shared_prefs_unencrypted": (
                re.compile(r'(?i)put(String|Text)\s*\(\s*["\'].*(password|pin|secret|auth).*["\']'),
                256,
                Severity.HIGH,
                "Potential unencrypted password/secret stored in SharedPreferences."
            ),
            "webview_save_password": (
                re.compile(r'setSavePassword\s*\(\s*true\s*\)'),
                312,
                Severity.MEDIUM,
                "Insecure WebView credential caching enabled (setSavePassword(true))."
            ),
            "empty_trust_callback": (
                # Look for common trusting trust managers
                re.compile(r'check(Client|Server)Trusted\s*\(\s*X509Certificate\[\]\s+[a-zA-Z0-9_]+,\s*String\s+[a-zA-Z0-9_]+\s*\)\s*\{\s*\}'),
                295,
                Severity.HIGH,
                "Empty certificate trust callback found; verify the active validation path, not pinning presence."
            ),
            "device_credential_fallback": (
                re.compile(r'setDeviceCredentialAllowed\s*\(\s*true\s*\)'),
                287,
                Severity.MEDIUM,
                "Device-credential fallback configured; this may be intended and is not an authentication bypass."
            ),
            "session_timeout_configuration": (
                re.compile(r'setMaxInactiveInterval\s*\(\s*-?[0-9]+\s*\)'),
                613,
                Severity.MEDIUM,
                "Explicit session timeout configuration found, ensure adequate timing limit."
            ),
            "oauth_redirect_uri": (
                re.compile(r'redirect_uri\s*=\s*'),
                601,
                Severity.LOW,
                "OAuth redirect URI parameter found; verify validation prevents open redirects."
            ),
            "token_in_logs": (
                re.compile(r'(?i)Log\.[vdiwe]\s*\([^,]+,\s*[^)]*(token|password|secret|session)[^)]*\)'),
                532,
                Severity.MEDIUM,
                "A logging call mentions authentication-related names; actual sensitive output is unverified."
            ),
        }

    async def audit_source(self, decompiled_dir: str | Path) -> list[Finding]:
        return (await self.analyze(decompiled_dir))["findings"]

    async def analyze(self, decompiled_dir):
        return await asyncio.to_thread(self._review, decompiled_dir)

    def _review(self, directory):
        inventory = SourceInventory()
        findings = []
        # Retain literal values for review but discard comments with stable lines.
        tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|<!--[\s\S]*?-->')
        for file_path, data in inventory.read(directory, {'.java', '.kt', '.xml', '.smali'}):
            source = data.decode('utf-8', errors='replace')
            content = tokens.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0])
                                 if m[0].startswith(('//', '/*', '<!--')) else m[0], source)
            for line_idx, line in enumerate(content.splitlines()):
                for issue_id, (pattern, cwe, _, description) in self.static_patterns.items():
                    if pattern.search(line):
                        if len(findings) >= 500:
                            inventory.record_limit('auth_candidate_count')
                            continue
                        findings.append(Finding(
                            title=f"Authentication/session review: {issue_id}",
                            description=description + " Lexical review only; attacker control and impact are not established.",
                            severity=Severity.INFO, cwe_id=f"CWE-{cwe}",
                            affected_component=file_path.name,
                            detection_method="AuthSessionAuditor (static lexical scan)",
                            status=FindingStatus.UNVERIFIED,
                            remediation="Review effective server validation, credential lifecycle and storage access with synthetic positive/negative controls.",
                            file_path=str(file_path), line_number=line_idx + 1,
                            # Do not retain source values as durable evidence.
                            code_snippet="", confidence=0.4,
                            metadata={"proof_state": "not_proven", "automatic_exploit_proof": False},
                        ))
        coverage = inventory.coverage
        if coverage['limits_reached']:
            coverage['static_status'] = 'partial'
        coverage['candidate_count'] = len(findings)
        coverage['limitations'] = ['bounded lexical patterns, not AST or dataflow',
                                   'backend password policy, token validation and session behavior not tested']
        return {"findings": findings, "coverage": coverage}

    async def audit_live_auth(self, serial: str, package_name: str, adb: ADBManager) -> list[Finding]:
        """Do not collect device-wide secrets through an unscoped draft API.

        Use the approved storage/logging workflows with selected device/package,
        synthetic fixtures and privilege-labelled evidence instead.
        """
        raise PermissionError("Live auth auditing requires the scoped assessment workflow; this draft API is disabled")
