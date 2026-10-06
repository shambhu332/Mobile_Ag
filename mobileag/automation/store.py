"""Private CAS run state; no resumption of device input on server restart."""
import json
import os
import re
import sqlite3
from pathlib import Path
from contextlib import contextmanager

class Conflict(ValueError): pass

class RunStore:
    def __init__(self, output: Path):
        self.root = output/'automation'
        if self.root.is_symlink(): raise ValueError('Unsafe automation directory')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path = self.root/'.runs.sqlite3'
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);os.close(fd)
        with self.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, serial TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL)')
    @contextmanager
    def connection(self):
        db=sqlite3.connect(self.path,timeout=5)
        try:
            yield db;db.commit()
        except BaseException:
            db.rollback();raise
        finally:db.close()
    def get(self,rid):
        if not re.fullmatch(r'auto_[a-f0-9]{32}',rid): raise ValueError('Invalid automation identifier')
        with self.connection() as db:
            row=db.execute('SELECT document FROM runs WHERE id=?',(rid,)).fetchone()
        if not row: raise KeyError(rid)
        return json.loads(row[0])
    def list(self):
        with self.connection() as db:
            rows=db.execute('SELECT document FROM runs ORDER BY rowid DESC LIMIT 100').fetchall()
        return [{'id':d['id'],'status':d['status'],'revision':d['revision'],'package_name':d['package_name'],'steps':len(d['steps'])} for (raw,) in rows for d in [json.loads(raw)]]
    def save(self,doc,expected=None):
        raw=json.dumps(doc,allow_nan=False)
        if len(raw.encode())>1024*1024:raise ValueError('Run document limit exceeded')
        with self.connection() as db:
            if expected is None:
                if db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]>=100:raise Conflict('Run retention limit: export/archive through an operator-managed backup')
                db.execute('INSERT INTO runs VALUES(?,?,?,?,?)',(doc['id'],doc['serial'],doc['status'],doc['revision'],raw))
            else:
                changed=db.execute('UPDATE runs SET status=?,revision=?,document=? WHERE id=? AND revision=?',(doc['status'],doc['revision'],raw,doc['id'],expected)).rowcount
                if not changed:raise Conflict('Run changed; reload before approval')
    def claim(self,rid,revision):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT document,revision,status FROM runs WHERE id=?',(rid,)).fetchone()
            if not row:raise KeyError(rid)
            if row[1]!=revision or row[2] not in {'awaiting_review','paused','completed','interrupted'}:raise Conflict('Run changed or is active')
            doc=json.loads(row[0])
            if db.execute("SELECT id FROM runs WHERE serial=? AND status IN ('running','discovering') AND id!=?",(doc['serial'],rid)).fetchone():raise Conflict('Another run controls this device')
            doc.update(status='running',revision=revision+1,cancel_requested=False)
            db.execute('UPDATE runs SET status=?,revision=?,document=? WHERE id=?',('running',doc['revision'],json.dumps(doc),rid))
            return doc
    def recover(self):
        for item in self.list():
            doc=self.get(item['id'])
            if doc['status'] in {'running','discovering'}:
                previous=doc['revision'];doc.update(status='interrupted',revision=previous+1,reason='Restarted; device actions were not resumed')
                self.save(doc,previous)
