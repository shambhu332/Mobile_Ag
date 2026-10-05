"""Opt-in actual namespace/cgroup and synthetic static-worker regression.

Run using the project Python: python tests/sandbox_process_regression.py --output DIR
Requires bubblewrap and an ordinary-user systemd manager. No device/cloud tests.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
import zipfile
from config.settings import Settings
from mobileag.web.jobs import sandbox_command, resource_command, manager_environment, isolated_analysis

async def run(out):
    with tempfile.TemporaryDirectory(prefix='mobileag-process-regression-') as temporary:
        root=Path(temporary);work=root/'work';work.mkdir();archive=root/'selected';archive.write_text('immutable synthetic input')
        code="import os,socket,pathlib,json; p=pathlib.Path; c={'home_hidden':not p('/home').exists(),'passwd_hidden':not p('/etc/passwd').exists(),'loopback_only':list(socket.if_nameindex())==[(1,'lo')],'provider_key_absent':not os.getenv('OPENAI_API_KEY')};\ntry:p('/input.archive').write_text('bad')\nexcept OSError:c['input_readonly']=True\nelse:c['input_readonly']=False\np('/work/proof').write_text('ok');c['workspace_writable']=True;print(json.dumps(c))"
        result=subprocess.run(sandbox_command(work,archive)[:-3]+['/usr/bin/python','-c',code],env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=15)
        assert result.returncode==0,result.stderr
        namespace=json.loads(result.stdout);assert all(namespace.values()) and archive.read_text()=='immutable synthetic input'
        sid='proof-'+uuid.uuid4().hex
        process=subprocess.Popen(resource_command(['/usr/bin/sleep','10'],sid),env=manager_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                result=subprocess.run(['systemctl','--user','show','mobileag-'+sid+'.scope','-p','MemoryMax','-p','MemorySwapMax','-p','TasksMax','-p','CPUQuotaPerSecUSec'],env=manager_environment(),capture_output=True,text=True)
                if 'TasksMax=128' in result.stdout:break
                time.sleep(.1)
            props=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
            assert props.get('MemoryMax')=='3221225472' and props.get('MemorySwapMax')=='536870912' and props.get('TasksMax')=='128' and props.get('CPUQuotaPerSecUSec')=='1s',props
        finally:
            subprocess.run(['systemctl','--user','stop','mobileag-'+sid+'.scope'],env=manager_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            process.wait(timeout=5)
        ipa=root/'synthetic.ipa'
        with zipfile.ZipFile(ipa,'w') as z:
            z.writestr('Payload/App.app/Info.plist',plistlib.dumps({'CFBundleExecutable':'Actual','CFBundleIdentifier':'org.example.synthetic','CFBundleShortVersionString':'1.0-synthetic','NSAppTransportSecurity':{'NSAllowsArbitraryLoads':True}}))
            z.writestr('Payload/App.app/Actual',struct.pack('<8I',0xfeedfacf,0x100000c,0,2,0,0,0x200000,0)+b'___stack_chk_fail objc_release')
        async def progress(*args):pass
        state=await isolated_analysis(ipa,root/'output','scan_'+uuid.uuid4().hex,Settings(_env_file=None,offline=True),progress)
        assert not state.get('errors') and state['filtered_findings']
        assert all(f['status']=='UNVERIFIED' for f in state['filtered_findings'])
        assert state['coverage']['runtime']=='not_assessed'
        out.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(ipa,out/'synthetic.ipa');(out/'synthetic.ipa').chmod(0o600)
        # A ZIP with plaintext manifest is not a legitimate compiled APK. Real
        # tool failure must stay incomplete instead of returning a clean audit.
        apk=root/'invalid-compiled.apk'
        with zipfile.ZipFile(apk,'w') as z:z.writestr('AndroidManifest.xml','<manifest package="org.example.synthetic"/>')
        negative=await isolated_analysis(apk,root/'output','scan_'+uuid.uuid4().hex,Settings(_env_file=None,offline=True),progress)
        assert negative.get('errors'), 'Malformed compiled archive must not be a clean success'
        report={'namespace':namespace,'aggregate_limits':props,'python':platform.python_version(),'host_os':platform.platform(),
                'synthetic_ipa_sha256':hashlib.sha256(ipa.read_bytes()).hexdigest(),'candidate_count':len(state['filtered_findings']),
                'candidate_statuses':sorted({f['status'] for f in state['filtered_findings']}),'coverage':state['coverage'],
                'invalid_apk_incomplete':bool(negative.get('errors')),
                'limits':'Synthetic header/ZIP fixtures, not a compiled production IPA/APK, ordinary-app exploit, or real-device assessment'}
        (out/'sandbox-results.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    asyncio.run(run(Path(args.output).resolve()))
