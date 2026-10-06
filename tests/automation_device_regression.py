"""Opt-in real Android fixture navigation: explicit serial, no existing package overwrite.

Build/sign permission-free researcher fixture; install, discover, approve one
navigation-only button, observe graph transition, export structural evidence,
uninstall own fixture. No app secrets, roots, hooks, network or log clearing.
Requires trusted APKTool JAR, java/keytool/apksigner, Android ADB shell permissions.
"""
import argparse
import asyncio
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
from mobileag.dast.adb_manager import ADBManager
from mobileag.automation.android import AndroidDriver
from mobileag.automation.engine import AutomationService
from mobileag.automation.models import CreateRun,ExecuteRun

PACKAGE='org.mobileag.validation.navigation'

async def run(args):
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True,mode=0o700)
    adb=ADBManager();attempted=False;runid=None;report={'package':PACKAGE,'serial':args.serial,'ordinary_app_exploit_proof':False}
    code,state,_=await adb._exec_cmd(['-s',args.serial,'get-state'])
    assert code==0 and state.strip()==b'device','Explicit device must already be connected'
    code,present,_=await adb._exec_cmd(['-s',args.serial,'shell','pm','path',PACKAGE])
    assert code in {0,1} and not present.strip(),'Refusing to overwrite an existing package or unknown state'
    details=await adb._get_device_details(args.serial)
    report.update(device=asdict(details),fingerprint=await adb._getprop(args.serial,'ro.build.fingerprint'),version='1.0-synthetic')
    with tempfile.TemporaryDirectory(prefix='mobileag-navigation-fixture-') as tmp:
        root=Path(tmp);project=root/'project';shutil.copytree(Path(__file__).parent/'fixtures/navigation_android',project)
        apk=root/'unsigned.apk';signed=root/'signed.apk';key=root/'ephemeral.jks'
        env={**os.environ,'HOME':str(root),'FIXTURE_KEY_PASS':secrets.token_urlsafe(24)}
        build=subprocess.run(['java','-jar',args.apktool_jar,'b',str(project),'-p',str(root/'framework'),'-o',str(apk)],env=env,capture_output=True,text=True,timeout=120)
        (out/'navigation-build.txt').write_text(build.stdout+build.stderr);assert build.returncode==0
        subprocess.run(['keytool','-genkeypair','-keystore',str(key),'-storepass:env','FIXTURE_KEY_PASS','-keypass:env','FIXTURE_KEY_PASS','-alias','fixture','-keyalg','RSA','-keysize','2048','-validity','1','-dname','CN=Synthetic Navigation Fixture'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30)
        subprocess.run(['apksigner','sign','--ks',str(key),'--ks-pass','env:FIXTURE_KEY_PASS','--key-pass','env:FIXTURE_KEY_PASS','--out',str(signed),str(apk)],env=env,check=True,timeout=30)
        subprocess.run(['apksigner','verify',str(signed)],check=True,timeout=10)
        report['apk_sha256']=hashlib.sha256(signed.read_bytes()).hexdigest();shutil.copyfile(signed,out/'navigation-synthetic.apk')
        try:
            attempted=True
            # Explicit longer fixture harness timeout, not an implicit production retry.
            code,stdout,_=await adb._exec_cmd(['-s',args.serial,'install',str(signed)],timeout=90)
            report['install_acknowledged']=code==0 and b'Success' in stdout
            assert report['install_acknowledged'],'Fixture install timeout/failure'
            result=await adb.launch_activity(args.serial,PACKAGE+'/.MainActivity')
            report['launch_acknowledged']=result['status']=='success';assert report['launch_acknowledged']
            await asyncio.sleep(2)
            os.environ['MOBILEAG_ALLOWED_DEVICES']=args.serial
            policy={'devices':[args.serial],'packages':[PACKAGE],'actions':['automation_observe','automation_execute'],'origins':[],'methods':['GET']}
            async def no_network(*a,**k):raise AssertionError('No network authorized in fixture harness')
            service=AutomationService(lambda:root/'output',lambda:policy,lambda token:token=='synthetic-fixture-only',lambda serial,package:AndroidDriver(adb,serial,package),transport=no_network)
            doc=await service.create(CreateRun(serial=args.serial,package_name=PACKAGE,component=PACKAGE+'/.MainActivity',environment='synthetic',dedicated_account_confirmed=True,dedicated_device_confirmed=True,max_steps=1,max_requests=0),'synthetic-fixture-only')
            runid=doc['id'];report['initial_status']=doc['status']
            (out/'initial-run.json').write_text(json.dumps(doc,indent=2))
            assert doc['status']=='awaiting_review','Scoped hierarchy could not be observed'
            candidates=[a for a in doc['actions'] if a['label']=='Profile' and not a['blocked_reason']]
            assert len(candidates)==1,'Expected unique safe fixture Profile control; see initial-run.json'
            action=candidates[0]
            await service.execute(runid,ExecuteRun(revision=doc['revision'],confirmation=runid,approved_action_ids=[action['id']]),'synthetic-fixture-only')
            await service.tasks[runid]
            doc=service.store().get(runid);final=service.get_report(runid)
            report.update(final_status=doc['status'],steps=len(doc['steps']),screens=len(doc['screens']),executed=final['executive_summary']['executed'])
            (out/'device-automation-report.json').write_text(json.dumps(final,indent=2))
            report['navigation_observed']=len(doc['steps'])==1 and len(doc['edges'])==1 and doc['edges'][0]['from']!=doc['edges'][0]['to']
            assert report['navigation_observed'],'Navigation transition was not demonstrated'
        finally:
            if attempted:
                code,stdout,stderr=await adb._exec_cmd(['-s',args.serial,'uninstall',PACKAGE],timeout=60)
                _,present,_=await adb._exec_cmd(['-s',args.serial,'shell','pm','path',PACKAGE])
                report['cleanup_confirmed']=code==0 and b'Success' in stdout and not present.strip()
            report['limitations']='One synthetic navigation-only fixture on recorded emulator/build/shell. Not current ordinary-app exploitation, own production app coverage, iOS, payment/auth workflows or readiness certification.'
            (out/'device-results.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--serial',required=True);p.add_argument('--output',required=True);p.add_argument('--apktool-jar',default='/snap/apktool/current/apktool.jar')
    asyncio.run(run(p.parse_args()))
