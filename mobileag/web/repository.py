"""Local transactional metadata and scan-scoped analyst decisions.

Raw originals stay immutable on disk. SQLite is the authoritative mutable record;
legacy dashboard files are imported on first access. This is not a tenant service.
"""
from __future__ import annotations
import json
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from mobileag.security.privacy import redact
from mobileag.reporting.validation import bind_confirmation
from mobileag.reporting.artifact_writer import preflight_bounded_structure

MAX_SCAN_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_DASHBOARD_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_PERSISTED_INPUT_BYTES = 32 * 1024 * 1024
MAX_PERSISTED_NODES = 250_000
MAX_PERSISTED_DEPTH = 64
MAX_SETTINGS_BYTES = 4 * 1024
MAX_POLICY_BYTES = 256 * 1024


def _bounded_redacted_json(value: dict, *, label: str, output_limit: int) -> tuple[dict, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    preflight_bounded_structure(
        value, max_bytes=MAX_PERSISTED_INPUT_BYTES,
        max_nodes=MAX_PERSISTED_NODES, max_depth=MAX_PERSISTED_DEPTH,
        label=label,
    )
    redacted_value = redact(value)
    raw = json.dumps(redacted_value, allow_nan=False, default=str, indent=2)
    if len(raw.encode("utf-8")) > output_limit:
        raise ValueError(f"{label} exceeds the storage size limit")
    return redacted_value, raw


def _bounded_config_json(value: dict, *, label: str, output_limit: int) -> str:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    preflight_bounded_structure(
        value, max_bytes=512 * 1024, max_nodes=4_096, max_depth=16, label=label,
    )
    try:
        raw = json.dumps(value, allow_nan=False, separators=(',', ':'))
    except (TypeError, ValueError, RecursionError):
        raise ValueError(f"{label} is not valid JSON data") from None
    if len(raw.encode('utf-8')) > output_limit:
        raise ValueError(f"{label} exceeds the storage size limit")
    return raw


def private_write(path: Path, value: dict) -> None:
    _, raw = _bounded_redacted_json(
        value, label="Dashboard snapshot", output_limit=MAX_DASHBOARD_SNAPSHOT_BYTES,
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)



class ScanRepository:
    def __init__(self, output: Path):
        self.output = output
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = output / '.mobileag.sqlite3'
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, created TEXT NOT NULL,
                    status TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS scan_created ON scans(created DESC, id);
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                    at TEXT NOT NULL, verdict TEXT NOT NULL, notes TEXT NOT NULL,
                    revision INTEGER NOT NULL, actor TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policies (id INTEGER PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tombstones (id TEXT PRIMARY KEY, at TEXT NOT NULL, sha256 TEXT);
                CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS test_plans (
                    scan_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, document TEXT NOT NULL
                );
            ''')
            db.execute('BEGIN IMMEDIATE')
            if 'evidence' not in {row['name'] for row in db.execute('PRAGMA table_info(decisions)')}:
                db.execute('ALTER TABLE decisions ADD COLUMN evidence TEXT')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def save(self, scan: dict) -> dict:
        if not isinstance(scan, dict):
            raise ValueError("Scan document must be an object")
        scan = dict(scan)
        sid = scan['scan_id']
        scan.setdefault('revision', 0)
        scan, raw = _bounded_redacted_json(
            scan, label="Scan document", output_limit=MAX_SCAN_DOCUMENT_BYTES,
        )
        with self.connection() as db:
            # Worker snapshots must not overwrite a newer analyst revision.
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT revision,document FROM scans WHERE id=?', (sid,)).fetchone()
            if old and old['revision'] > scan['revision']:
                return json.loads(old['document'])
            db.execute('INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?)',
                       (sid, scan.get('created_at', ''), scan.get('status', 'unknown'),
                        scan['revision'], raw))
        return scan

    def get(self, sid: str) -> dict | None:
        with self.connection() as db:
            row = db.execute('SELECT document FROM scans WHERE id=?', (sid,)).fetchone()
        return json.loads(row['document']) if row else None

    def page(self, offset=0, limit=25):
        with self.connection() as db:
            total = db.execute('SELECT count(*) FROM scans').fetchone()[0]
            rows = db.execute('SELECT document FROM scans ORDER BY created DESC,id DESC LIMIT ? OFFSET ?',
                              (limit, offset)).fetchall()
        return [json.loads(r['document']) for r in rows], total

    def triage(self, sid, fid, verdict, notes, expected_revision, evidence=None):
        if (not isinstance(sid, str) or len(sid) > 128
                or not isinstance(fid, str) or len(fid) > 256
                or verdict not in {'CONFIRMED', 'FALSE_POSITIVE', 'DUPLICATE', 'UNVERIFIED'}
                or not isinstance(notes, str) or len(notes) > 10_000):
            raise ValueError('Invalid or oversized triage input')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT document,revision FROM scans WHERE id=?', (sid,)).fetchone()
            if not row:
                raise KeyError('Scan not found')
            scan = json.loads(row['document'])
            if expected_revision is not None and row['revision'] != expected_revision:
                raise ValueError('Scan changed; reload before saving this decision')
            if scan.get('status') in {'running', 'queued', 'cancelling'}:
                raise ValueError('Wait for the scan to finish before triage')
            matches = [f for f in scan.get('findings', []) if f.get('id') == fid]
            if len(matches) != 1:
                raise KeyError('Finding not found or not uniquely identified')
            proof=bind_confirmation(evidence,scan) if verdict=='CONFIRMED' else None
            revision = row['revision'] + 1
            now = datetime.now(timezone.utc).isoformat()
            f = matches[0]
            f.update(status=verdict, validation_notes=redact(notes), validated_at=now)
            if proof is not None:f["validation_evidence"]=redact(proof)
            elif isinstance(f.get("validation_evidence"),dict):f["validation_evidence"]["active"]=False
            scan['revision'] = revision
            scan, raw_scan = _bounded_redacted_json(
                scan, label="Scan document", output_limit=MAX_SCAN_DOCUMENT_BYTES,
            )
            db.execute('UPDATE scans SET revision=?,document=? WHERE id=?',
                       (revision, raw_scan, sid))
            raw_evidence = json.dumps(redact(proof), allow_nan=False) if proof else None
            db.execute('INSERT INTO decisions(scan_id,finding_id,at,verdict,notes,revision,actor,evidence) VALUES(?,?,?,?,?,?,?,?)',
                       (sid, fid, now, verdict, redact(notes), revision, 'local-operator', raw_evidence))
        return scan

    def history(self, sid):
        with self.connection() as db:
            rows=[dict(r) for r in db.execute('SELECT finding_id,at,verdict,notes,revision,actor,evidence FROM decisions WHERE scan_id=? ORDER BY id', (sid,))]
            for row in rows:row['evidence']=json.loads(row['evidence']) if row['evidence'] else None
            return rows

    def get_test_plan(self, sid):
        with self.connection() as db:
            row = db.execute('SELECT document FROM test_plans WHERE scan_id=?', (sid,)).fetchone()
        return json.loads(row['document']) if row else None

    def save_test_plan(self, sid, document, expected_revision):
        """Optimistically persist a bounded plan tied to the exact scan artifact."""
        if not isinstance(document, dict):
            raise ValueError('Test plan must be an object')
        preflight_bounded_structure(
            document, max_bytes=512 * 1024, max_nodes=10_000,
            max_depth=32, label='Test plan',
        )
        try:
            raw = json.dumps(redact(document), allow_nan=False, separators=(',', ':'))
        except (TypeError, ValueError, RecursionError):
            raise ValueError('Test plan is not valid JSON data') from None
        if len(raw.encode('utf-8')) > 128 * 1024:
            raise ValueError('Test-plan size limit exceeded')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            scan_row = db.execute('SELECT status,document FROM scans WHERE id=?', (sid,)).fetchone()
            if not scan_row:
                raise KeyError('Scan not found')
            scan = json.loads(scan_row['document'])
            if scan_row['status'] not in {'completed', 'complete', 'success'}:
                raise ValueError('A test plan can only bind to a completed scan')
            current_provenance = scan.get('artifact_provenance')
            current_provenance = current_provenance if isinstance(current_provenance, dict) else {}
            artifact_hash = scan.get('artifact_sha256') or current_provenance.get('sha256')
            binding = document.get('scope', {})
            if (document.get('scan_id') != sid or binding.get('package_name') != scan.get('package_name')
                    or binding.get('artifact_sha256') != artifact_hash):
                raise ValueError('Test-plan scope does not match this scan artifact')
            retest_id = document.get('retest_of_scan_id')
            baseline_binding = None
            if retest_id:
                prior_row = db.execute('SELECT status,document FROM scans WHERE id=?', (retest_id,)).fetchone()
                if not prior_row:
                    raise ValueError('Retest baseline must be an existing scan')
                prior = json.loads(prior_row['document'])
                if prior_row['status'] not in {'completed', 'complete', 'success'} or prior.get('package_name') != scan.get('package_name'):
                    raise ValueError('Retest baseline must be a completed scan for the same package')
                prior_provenance = prior.get('artifact_provenance')
                prior_provenance = prior_provenance if isinstance(prior_provenance, dict) else {}
                prior_hash = prior.get('artifact_sha256') or prior_provenance.get('sha256')
                if not isinstance(prior_hash, str) or not re.fullmatch(r'[A-Fa-f0-9]{64}', prior_hash):
                    raise ValueError('Retest baseline must have a valid artifact SHA-256')
                prior_info = prior.get('app_info') if isinstance(prior.get('app_info'), dict) else {}
                baseline_binding = {
                    'scan_id': retest_id,
                    'package_name': prior.get('package_name'),
                    'artifact_sha256': prior_hash.lower(),
                    'app_version': prior.get('version') or prior_info.get('version_name'),
                }
            old = db.execute('SELECT revision FROM test_plans WHERE scan_id=?', (sid,)).fetchone()
            if old:
                if expected_revision is None or expected_revision != old['revision']:
                    raise ValueError('Test plan changed; reload before saving')
                revision = old['revision'] + 1
            else:
                if expected_revision is not None:
                    raise ValueError('Test plan does not exist; reload before saving')
                revision = 0
            document = dict(document, plan_revision=revision, retest_baseline_binding=baseline_binding)
            raw = json.dumps(redact(document), allow_nan=False, separators=(',', ':'))
            if len(raw.encode('utf-8')) > 128 * 1024:
                raise ValueError('Test-plan size limit exceeded')
            db.execute('INSERT OR REPLACE INTO test_plans VALUES(?,?,?)', (sid, revision, raw))
        return document

    def remove(self, sid):
        with self.connection() as db:
            db.execute('DELETE FROM scans WHERE id=?', (sid,))
            db.execute('DELETE FROM test_plans WHERE scan_id=?', (sid,))
            # Keep the minimal decision history; it contains redacted notes, not raw originals.

    def get_settings(self):
        with self.connection() as db:
            row = db.execute('SELECT document FROM settings WHERE id=1').fetchone()
        return json.loads(row[0]) if row else {}

    def save_settings(self, settings):
        raw = _bounded_config_json(settings, label="Settings", output_limit=MAX_SETTINGS_BYTES)
        with self.connection() as db:
            db.execute('INSERT OR REPLACE INTO settings VALUES(1,?)', (raw,))

    def get_policy(self):
        with self.connection() as db:
            row = db.execute('SELECT document FROM policies WHERE id=1').fetchone()
        return json.loads(row[0]) if row else None

    def save_policy(self, policy):
        raw = _bounded_config_json(policy, label="Scope policy", output_limit=MAX_POLICY_BYTES)
        with self.connection() as db:
            db.execute('INSERT OR REPLACE INTO policies VALUES(1,?)',(raw,))

    def purged(self, sid):
        with self.connection() as db:
            return bool(db.execute('SELECT 1 FROM tombstones WHERE id=?',(sid,)).fetchone())

    def purge(self, sid, sha256, revision):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT revision,status FROM scans WHERE id=?',(sid,)).fetchone()
            if not row or row['revision'] != revision or row['status'] in {'running','queued','cancelling'}:
                raise ValueError('Scan changed; preview again')
            db.execute('DELETE FROM scans WHERE id=?',(sid,))
            db.execute('DELETE FROM decisions WHERE scan_id=?',(sid,))
            db.execute('DELETE FROM test_plans WHERE scan_id=?',(sid,))
            db.execute('INSERT OR REPLACE INTO tombstones VALUES(?,?,?)',
                       (sid,datetime.now(timezone.utc).isoformat(),sha256))
