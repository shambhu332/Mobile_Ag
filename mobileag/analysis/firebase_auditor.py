"""Offline Firebase configuration review; no database reads, listing or signup.

Configuration and lexical candidates do not establish a rules defect. Use the
approved replay workflow or owner-provided emulator rules tests for validation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import plistlib
import re
from pathlib import Path
from typing import Any, Optional

from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
_FIREBASE_DB_URL_RE = re.compile(
    r"https://([a-zA-Z0-9_-]+)\.firebaseio\.com"
)
_FIREBASE_STORAGE_BUCKET_RE = re.compile(
    r"([a-zA-Z0-9_-]+)\.appspot\.com"
)
_FIREBASE_API_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
_FCM_SERVER_KEY_RE = re.compile(
    r"(?:AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})"
)
_FIREBASE_PROJECT_ID_RE = re.compile(
    r'"project_id"\s*:\s*"([a-zA-Z0-9_-]+)"'
)


class FirebaseAuditor:
    """Audits Firebase backend configuration extracted from mobile apps."""

    def __init__(self) -> None:
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested"}

    # ------------------------------------------------------------------
    # 1. Static Configuration Extraction
    # ------------------------------------------------------------------

    async def extract_config(self, decompiled_dir):
        inventory = SourceInventory()
        result = await asyncio.to_thread(self._extract, [decompiled_dir], inventory)
        self.coverage = inventory.coverage
        return result

    def _extract(self, directories, inventory):
        config = {"project_id": None, "api_keys": [], "database_urls": [],
                  "storage_buckets": [], "fcm_server_keys": [], "source_files": []}
        seen_roots = set()
        for directory in directories:
            if not directory:
                continue
            root = Path(directory)
            identity = str(root.absolute())
            if identity in seen_roots:
                continue
            seen_roots.add(identity)
            for path, data in inventory.read(root, {'.xml', '.java', '.kt', '.json', '.plist'}):
                content = data.decode('utf-8', errors='replace')
                if path.name in {'google-services.json', 'GoogleService-Info.plist'}:
                    try:
                        if path.name == 'google-services.json':
                            parsed = json.loads(content)
                            project = parsed.get('project_info', {})
                            config['project_id'] = project.get('project_id') or config['project_id']
                            for key, field in [('firebase_url', 'database_urls'), ('storage_bucket', 'storage_buckets')]:
                                if isinstance(project.get(key), str):
                                    config[field].append(project[key])
                            for client in parsed.get('client', []):
                                for key in client.get('api_key', []):
                                    if isinstance(key.get('current_key'), str):
                                        config['api_keys'].append(key['current_key'])
                        else:
                            parsed = plistlib.loads(data)
                            config['project_id'] = parsed.get('PROJECT_ID') or config['project_id']
                            for key, field in [('DATABASE_URL', 'database_urls'), ('STORAGE_BUCKET', 'storage_buckets'), ('API_KEY', 'api_keys')]:
                                if isinstance(parsed.get(key), str):
                                    config[field].append(parsed[key])
                        config['source_files'].append(str(path))
                    except (ValueError, TypeError, AttributeError, KeyError, plistlib.InvalidFileException):
                        inventory.record_skip('configuration_parse_error')
                for field, pattern in [('database_urls', _FIREBASE_DB_URL_RE),
                                       ('storage_buckets', _FIREBASE_STORAGE_BUCKET_RE),
                                       ('api_keys', _FIREBASE_API_KEY_RE),
                                       ('fcm_server_keys', _FCM_SERVER_KEY_RE)]:
                    for match in pattern.finditer(content):
                        if len(config[field]) >= 500:
                            inventory.record_limit('firebase_value_count')
                            break
                        if match[0] not in config[field]:
                            config[field].append(match[0])
                if not config['project_id']:
                    match = _FIREBASE_PROJECT_ID_RE.search(content)
                    if match:
                        config['project_id'] = match[1]
        for key in ('api_keys', 'database_urls', 'storage_buckets', 'fcm_server_keys', 'source_files'):
            config[key] = list(dict.fromkeys(config[key]))[:500]
        if inventory.coverage['limits_reached'] or inventory.coverage['source_files_skipped']:
            inventory.coverage['static_status'] = 'partial'
        return config

    async def analyze(self, source_dir, resource_dir=''):
        inventory = SourceInventory()
        config = await asyncio.to_thread(self._extract, [source_dir, resource_dir], inventory)
        findings = self._audit_fcm_keys(config['fcm_server_keys'])
        if config['database_urls']:
            findings.extend(await self.audit_realtime_db(config.get('project_id') or 'unknown'))
        if config['storage_buckets']:
            findings.extend(await self.audit_storage_bucket('discovered'))
        # Return counts only. Configuration/credential values never enter scan state.
        coverage = inventory.coverage
        coverage['candidate_count'] = len(findings)
        coverage['inventory_counts'] = {key: len(config[key]) for key in ('database_urls', 'storage_buckets', 'api_keys', 'fcm_server_keys')}
        coverage['limitations'] = ['configuration inventory only; Firebase rules and key privileges not tested',
                                   'public API-key presence is not an authentication vulnerability']
        self.coverage = coverage
        return {'findings': findings, 'coverage': coverage}

    @staticmethod
    def _reject_live(allow_network):
        if allow_network:
            raise PermissionError("Use the approved replay workflow with a synthetic Firebase fixture; bulk reads, listing and sign-up probes are disabled")

    @staticmethod
    def _candidate(title, description, cwe="CWE-284"):
        return Finding(title=title, description=description,
                       severity=Severity.INFO, cwe_id=cwe, confidence=0.4,
                       detection_method="FirebaseAuditor (static inventory)",
                       status=FindingStatus.UNVERIFIED,
                       remediation="Review owner-provided rules using synthetic emulator fixtures and positive/negative controls.",
                       metadata={"proof_state": "not_proven", "automatic_exploit_proof": False})

    async def audit_realtime_db(self, project_id: str, api_key=None, *, allow_network=False):
        self._reject_live(allow_network)
        return [self._candidate("Review Firebase database authorization",
            "Firebase configuration was discovered. Database existence, access rules and sensitive data exposure have not been tested.")]

    async def audit_storage_bucket(self, bucket: str, *, allow_network=False):
        self._reject_live(allow_network)
        return [self._candidate("Review Firebase storage authorization",
            "A bucket identifier was discovered. Public listing, object access and security impact have not been tested.")]

    async def audit_auth_api(self, api_key: str, *, allow_network=False):
        self._reject_live(allow_network)
        # A Firebase API key is normally a public identifier, not auth bypass.
        return []

    def _audit_fcm_keys(self, fcm_keys):
        return [self._candidate("Review embedded server-key-shaped material",
            "A server-key-shaped value was discovered. Validity, privileges and impact remain unverified; no notifications were sent.",
            "CWE-798")] if fcm_keys else []

    async def full_audit(self, decompiled_dir, *, allow_network=False):
        self._reject_live(allow_network)
        return (await self.analyze(decompiled_dir))["findings"]
