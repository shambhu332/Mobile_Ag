"""Opt-in owned-device smoke: explicit serial, only our compiled fixture.

No root/su/hooking, log clearing, arbitrary package inventory or application data
access. Refuses to overwrite an existing fixture package. Removes only its own
new installation. Shell/old emulator observations are NOT ordinary-app proof.
"""
import argparse
import asyncio
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from mobileag.dast.adb_manager import ADBManager

PACKAGE = 'org.mobileag.validation.fixture'

async def run(args):
    out = Path(args.output).resolve()
    compiled = json.loads((out/'compiled-android.json').read_text())
    apk = out/'synthetic.apk'
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == compiled['sha256']
    adb = ADBManager()
    code, stdout, stderr = await adb._exec_cmd(['-s',args.serial,'get-state'])
    assert code == 0 and stdout.strip() == b'device', 'Selected device is not connected'
    code, present, stderr = await adb._exec_cmd(['-s',args.serial,'shell','pm','path',PACKAGE])
    assert not present.strip(), 'Refusing to replace an existing package'
    details = await adb._get_device_details(args.serial)
    fingerprint = await adb._getprop(args.serial,'ro.build.fingerprint')
    _, identity, _ = await adb._exec_cmd(['-s',args.serial,'shell','id'])
    install_attempted = False
    report = {'device':asdict(details),'fingerprint':fingerprint,'shell_identity':identity.decode().strip(),'unsigned_fixture_sha256':compiled['sha256'],'scope':PACKAGE,'ordinary_app_exploit_proof':False,'limitations':'Synthetic install/launch smoke on explicitly selected device. ADB shell privileges and emulator age are recorded, not proof of app authorization or production readiness.'}
    try:
        with tempfile.TemporaryDirectory(prefix='mobileag-signing-') as tmp:
            root=Path(tmp);key=root/'ephemeral.jks';signed=root/'signed.apk'
            env={**os.environ,'FIXTURE_SIGNING_PASS':secrets.token_urlsafe(24)}
            subprocess.run(['keytool','-genkeypair','-keystore',str(key),'-storepass:env','FIXTURE_SIGNING_PASS','-keypass:env','FIXTURE_SIGNING_PASS','-alias','fixture','-keyalg','RSA','-keysize','2048','-validity','1','-dname','CN=Synthetic MobileAg Fixture'],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            subprocess.run(['apksigner','sign','--ks',str(key),'--ks-pass','env:FIXTURE_SIGNING_PASS','--key-pass','env:FIXTURE_SIGNING_PASS','--out',str(signed),str(apk)],env=env,check=True,timeout=30)
            subprocess.run(['apksigner','verify',str(signed)],check=True,timeout=10)
            report['signed_fixture_sha256']=hashlib.sha256(signed.read_bytes()).hexdigest()
            # Only this known permission-free fixture; no auto-grants.
            install_attempted=True
            report['install']=await adb.install_apk(args.serial,signed,grant_permissions=False)
            assert report['install']['status']=='success',report['install']
            report['launch']=await adb.launch_activity(args.serial,PACKAGE+'/.MainActivity')
            assert report['launch']['status']=='success' and 'Error:' not in report['launch']['output'],report['launch']
            code, pid, _=await adb._exec_cmd(['-s',args.serial,'shell','pidof',PACKAGE])
            report['running']=code==0 and bool(pid.strip())
            assert report['running']
    finally:
        if install_attempted:
            # An ADB timeout may still have installed the package on-device.
            _, present, _ = await adb._exec_cmd(['-s',args.serial,'shell','pm','path',PACKAGE])
            if present.strip():
                code, stdout, stderr=await adb._exec_cmd(['-s',args.serial,'uninstall',PACKAGE],timeout=30)
                report['cleanup']=code==0 and b'Success' in stdout
                assert report['cleanup'],stderr.decode(errors='replace')
            else:
                report['cleanup']=True
        (out/'genymotion-results.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--serial',required=True);p.add_argument('--output',required=True)
    asyncio.run(run(p.parse_args()))
