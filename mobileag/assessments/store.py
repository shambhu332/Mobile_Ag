"""Bounded private assessment state, independent of scan metadata."""
import json
import re
from mobileag.web.repository import ScanRepository

class AssessmentStore:
    def __init__(self,output):
        self.repository=ScanRepository(output)
        with self.repository.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,document TEXT NOT NULL)')
    def get(self,rid):
        if not re.fullmatch(r'assess_[a-f0-9]{32}',rid):raise KeyError('Unknown assessment')
        with self.repository.connection() as db:row=db.execute('SELECT document FROM assessments WHERE id=?',(rid,)).fetchone()
        if not row:raise KeyError('Unknown assessment')
        return json.loads(row[0])
    def save(self,doc):
        data=json.dumps(doc,allow_nan=False)
        if len(data.encode())>128*1024:raise ValueError('Assessment evidence limit')
        with self.repository.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT id FROM assessments WHERE id=?',(doc['id'],)).fetchone() and db.execute('SELECT count(*) FROM assessments').fetchone()[0]>=100:raise ValueError('Assessment retention limit')
            db.execute('INSERT OR REPLACE INTO assessments VALUES(?,?)',(doc['id'],data))
    def list(self):
        with self.repository.connection() as db:rows=db.execute('SELECT document FROM assessments ORDER BY rowid DESC LIMIT 100').fetchall()
        return [{k:d[k] for k in ('id','status','package_name','artifact_sha256')} for r in rows for d in [json.loads(r[0])]]
    def recover(self):
        for item in self.list():
            doc=self.get(item['id'])
            if doc['status']=='running':
                doc.update(status='interrupted',reason='Restarted; re-approve a new assessment, never resume live actions');self.save(doc)
