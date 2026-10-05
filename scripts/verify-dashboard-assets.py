"""Verify pinned runtime asset hashes and reject remote script/style dependencies."""
import hashlib,json,re
from pathlib import Path
root=Path(__file__).resolve().parents[1]/'mobileag/web'
for entry in json.loads((root/'static/vendor/manifest.json').read_text()):
    assert hashlib.sha256((root/'static/vendor'/entry['file']).read_bytes()).hexdigest()==entry['sha256'],entry['file']
html=(root/'templates/index.html').read_text()
assert not re.search(r'(?:src|href)=["\']https?://',html)
scripts=re.findall(r'<script[^>]+src=["\'](/static/[^"\']+)["\']',html)
for script in scripts:
    assert (root/script.lstrip('/')).is_file(),script
assert scripts.index('/static/session-actions.js') < scripts.index('/static/workspace.js') < scripts.index('/static/findings.js') < scripts.index('/static/dashboard.js') < scripts.index('/static/workflow.js')
print('Local dashboard asset and ordered module checks passed')
