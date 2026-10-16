"""Read-only ADB provider diagnostics, restricted to server-approved synthetic fixtures.

Shell access is not ordinary-app authorization proof. Never retain returned rows.
"""
from __future__ import annotations
import json
import inspect
import os
import re
from urllib.parse import urlsplit, unquote
from typing import Any, Optional
from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.finding import Finding, FindingStatus, Severity


class ProviderAuditor:
    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    @staticmethod
    def _check_scope_guard(guard) -> None:
        if not callable(guard):
            raise PermissionError('Provider diagnostic scope guard is required')
        try:
            allowed = guard()
        except Exception as exc:
            raise PermissionError('Provider diagnostic scope guard denied access') from exc
        if inspect.isawaitable(allowed):
            close = getattr(allowed, 'close', None)
            if callable(close):
                close()
            raise PermissionError('Provider diagnostic scope guard must be synchronous')
        if allowed is False:
            raise PermissionError('Provider diagnostic scope guard denied access')

    def approved_uris(self, serial: str, package_name: str) -> list[str]:
        """Configuration is operator-owned, not supplied by an APK or HTTP request."""
        if serial not in os.getenv('MOBILEAG_ALLOWED_DEVICES', '').split(','):
            raise PermissionError('Provider diagnostic device is not approved')
        try:
            raw = os.getenv('MOBILEAG_PROVIDER_FIXTURES', '[]')
            if len(raw) > 16384:
                raise ValueError()
            entries = json.loads(raw)
            if not isinstance(entries, list) or len(entries) > 100:
                raise ValueError()
            uris = []
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'package_name', 'uri'}:
                    raise ValueError()
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+', entry['package_name']):
                    raise ValueError()
                uri = entry['uri']; p = urlsplit(uri)
                if (p.scheme != 'content' or not re.fullmatch(r'[A-Za-z0-9_.-]+', p.netloc)
                    or p.query or p.fragment or p.path in ('', '/')
                    or any(part in ('.', '..') for part in unquote(p.path).split('/'))):
                    raise ValueError()
                if entry['package_name'] == package_name:
                    uris.append(uri)
            return uris
        except (ValueError, TypeError, KeyError):
            raise PermissionError('Invalid provider fixture configuration') from None

    async def audit_provider_uri(self, serial: str, package_name: str, uri: str, guard=None) -> list[Finding]:
        self._check_scope_guard(guard)
        if uri not in self.approved_uris(serial, package_name):
            raise PermissionError('Exact synthetic provider fixture is not approved')
        code, stdout, stderr = await self.adb._exec_cmd(
            ['-s', serial, 'shell', 'content', 'query', '--uri', uri], timeout=4.0)
        self._check_scope_guard(guard)
        # No SQL mutations or raw-row evidence collection. A successful shell
        # read says nothing about an ordinary application's permission checks.
        if code != 0 or b'Row:' not in stdout:
            return []
        return [Finding(
            title=f'ADB shell provider fixture read: {uri}',
            description='The approved synthetic fixture returned a row to ADB shell. Ordinary-app access, permission enforcement and confidentiality impact are not established.',
            severity=Severity.INFO, confidence=0.4, cwe_id='CWE-926',
            cvss_score=0.0, cvss_vector='', affected_component=uri,
            file_path=uri, line_number=1, code_snippet='Row contents intentionally not retained',
            detection_method='ProviderAuditor (ADB diagnostic)', status=FindingStatus.UNVERIFIED,
            remediation='Validate expected permissions using an ordinary-app caller and controlled fixture before changing provider exposure.')]

    async def audit_providers(self, serial: str, package_name: str, authorities: list[str], guard=None) -> tuple[list[dict[str, Any]], list[Finding]]:
        self._check_scope_guard(guard)
        approved = self.approved_uris(serial, package_name)
        if len(authorities) > 30 or any(not any(urlsplit(u).netloc == a for u in approved) for a in authorities):
            raise PermissionError('Provider authority has no approved synthetic fixture')
        results, findings = [], []
        for uri in approved:
            if urlsplit(uri).netloc not in authorities:
                continue
            current = await self.audit_provider_uri(serial, package_name, uri, guard=guard)
            results.append({'authority': urlsplit(uri).netloc, 'uri': uri, 'findings_count': len(current)})
            findings.extend(current)
        return results, findings

    def create_fuzzer(self) -> Any:
        """Create a ContentProviderFuzzer bound to the active ADB runner."""
        from mobileag.dast.provider_fuzzer import ContentProviderFuzzer
        return ContentProviderFuzzer(adb_path=getattr(self.adb, "adb_path", None))

