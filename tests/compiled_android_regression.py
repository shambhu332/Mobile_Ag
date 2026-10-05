"""Opt-in real JADX/APKTool/sandbox test; no devices, keys or cloud requests.

Requires java, a trusted APKTool 3 JAR, JADX, bubblewrap and user systemd.
Produces a minimal compiled binary manifest/DEX fixture, not a production corpus.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
from config.settings import Settings
from mobileag.web.jobs import isolated_analysis

async def run(args):
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mobileag-compiled-fixture-') as tmp:
        root = Path(tmp)
        project = root / 'project'
        shutil.copytree(Path(__file__).parent / 'fixtures/compiled_android', project)
        apk = root / 'synthetic.apk'
        env = {**os.environ, 'HOME': str(root)}
        build = subprocess.run(['java', '-jar', args.apktool_jar, 'b', str(project), '-p', str(root/'framework'), '-o', str(apk)], env=env, capture_output=True, text=True, timeout=120)
        (out/'build.log').write_text(build.stdout + build.stderr)
        assert build.returncode == 0, build.stderr
        async def progress(*unused): pass
        start = time.monotonic()
        state = await isolated_analysis(apk, root/'analysis', 'scan_compiled_fixture', Settings(_env_file=None, offline=True), progress)
        duration = time.monotonic()-start
        assert not state.get('errors'), state.get('errors')
        assert state['package_name'] == 'org.mobileag.validation.fixture'
        manifest = state['manifest_data']
        assert manifest['version_name'] == '1.0-synthetic' and manifest['target_sdk'] == '35'
        assert state['coverage']['java_files'] >= 1 and state['coverage']['smali_files'] >= 1
        candidates = state.get('filtered_findings', [])
        assert all(f['status'] == 'UNVERIFIED' for f in candidates)
        exported = [f for f in candidates if 'Exported' in f['title']]
        assert all(f['severity'] == 'INFO' and f['cvss_score'] == 0 for f in exported)
        shutil.copyfile(apk, out/'synthetic.apk')
        report = {'python':platform.python_version(), 'os':platform.platform(), 'jadx':subprocess.check_output(['jadx','--version'],text=True).strip(), 'apktool':subprocess.check_output(['java','-jar',args.apktool_jar,'--version'],text=True).strip(), 'sha256':hashlib.sha256(apk.read_bytes()).hexdigest(), 'analysis_seconds':round(duration,3), 'manifest_version':manifest['version_name'], 'target_sdk':manifest['target_sdk'], 'coverage':state['coverage'], 'candidates':[{'title':f['title'],'status':f['status'],'severity':f['severity']} for f in candidates], 'limits':'One minimal compiled synthetic Android fixture. Not production-corpus performance, device exploitation, iOS runtime coverage or release certification.'}
        (out/'compiled-android.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))

if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output',required=True)
    p.add_argument('--apktool-jar',default='/snap/apktool/current/apktool.jar')
    asyncio.run(run(p.parse_args()))
