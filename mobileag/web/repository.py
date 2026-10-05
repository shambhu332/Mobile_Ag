"""Local transactional metadata and scan-scoped analyst decisions.

Raw originals stay immutable on disk. SQLite is the authoritative mutable record;
legacy dashboard files are imported on first access. This is not a tenant service.
"""
from __future__ import annotations
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from mobileag.security.privacy import redact


def private_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(redact(value), out, indent=2, default=str)
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
            ''')

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
        scan = redact(scan)
        sid = scan['scan_id']
        scan.setdefault('revision', 0)
        with self.connection() as db:
            # Worker snapshots must not overwrite a newer analyst revision.
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT revision,document FROM scans WHERE id=?', (sid,)).fetchone()
            if old and old['revision'] > scan['revision']:
                return json.loads(old['document'])
            db.execute('INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?)',
                       (sid, scan.get('created_at', ''), scan.get('status', 'unknown'),
                        scan['revision'], json.dumps(scan, default=str)))
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

    def triage(self, sid, fid, verdict, notes, expected_revision):
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
            revision = row['revision'] + 1
            now = datetime.now(timezone.utc).isoformat()
            f = matches[0]
            f.update(status=verdict, validation_notes=redact(notes), validated_at=now)
            scan['revision'] = revision
            db.execute('UPDATE scans SET revision=?,document=? WHERE id=?',
                       (revision, json.dumps(redact(scan)), sid))
            db.execute('INSERT INTO decisions(scan_id,finding_id,at,verdict,notes,revision,actor) VALUES(?,?,?,?,?,?,?)',
                       (sid, fid, now, verdict, redact(notes), revision, 'local-operator'))
        return scan

    def history(self, sid):
        with self.connection() as db:
            return [dict(r) for r in db.execute('SELECT finding_id,at,verdict,notes,revision,actor FROM decisions WHERE scan_id=? ORDER BY id', (sid,))]

    def remove(self, sid):
        with self.connection() as db:
            db.execute('DELETE FROM scans WHERE id=?', (sid,))
            # Keep the minimal decision history; it contains redacted notes, not raw originals.

    def get_settings(self):
        with self.connection() as db:
            row = db.execute('SELECT document FROM settings WHERE id=1').fetchone()
        return json.loads(row[0]) if row else {}

    def save_settings(self, settings):
        with self.connection() as db:
            db.execute('INSERT OR REPLACE INTO settings VALUES(1,?)', (json.dumps(settings),))

    def get_policy(self):
        with self.connection() as db:
            row = db.execute('SELECT document FROM policies WHERE id=1').fetchone()
        return json.loads(row[0]) if row else None

    def save_policy(self, policy):
        with self.connection() as db:
            db.execute('INSERT OR REPLACE INTO policies VALUES(1,?)',(json.dumps(policy),))

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
            db.execute('INSERT OR REPLACE INTO tombstones VALUES(?,?,?)',
                       (sid,datetime.now(timezone.utc).isoformat(),sha256))
