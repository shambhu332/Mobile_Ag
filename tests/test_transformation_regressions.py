"""Synthetic controls for persisted scope, session, retention and real sandbox."""
import asyncio
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from config.settings import Settings

web=importlib.import_module('mobileag.web.app')

@pytest.fixture
def client():
    return TestClient(web.app,headers={'Authorization':'Bearer '+web.app.state.auth_token})

def scan(sid='scan_fixture',status='completed'):
    return {'scan_id':sid,'status':status,'revision':0,'artifact_sha256':'synthetic','findings':[], 'created_at':'2026-10-05'}

def test_no_scope_is_static_only(client):
    with web.repository().connection() as db:db.execute('DELETE FROM policies')
    assert client.post('/api/dast/root',json={'serial':'emulator-5554'}).status_code==403
    assert client.get('/api/settings').status_code==200

def test_scope_never_expands_environment(client,monkeypatch):
    value={'devices':['outside-device'],'packages':['org.example'],'origins':[],'methods':['GET'],'actions':['screenshot']}
    assert client.post('/api/scope',json=value).status_code==422
    value['devices']=['emulator-5554'];value['origins']=['https://outside.example']
    assert client.post('/api/scope',json=value).status_code==422
    value['origins']=[]
    assert client.post('/api/scope',json=value).status_code==200
    assert web.repository().get_policy()==value
    assert client.post('/api/dast/root',json={'serial':'emulator-5554'}).status_code==403
    assert client.post('/api/dast/storage',json={'serial':'emulator-5554','package_name':'org.example'}).status_code==403

def test_package_and_component_scope(client):
    assert client.post('/api/dast/crawl',json={'serial':'emulator-5554','package_name':'outside.app'}).status_code==403
    assert client.post('/api/dast/fuzz',json={'serial':'emulator-5554','package_name':'org.example','activities':['outside.app/Main']}).status_code==403
    assert client.post('/api/dast/deeplink',json={'serial':'emulator-5554','uri':'test://'}).status_code==403

def test_replay_method_policy(client,monkeypatch):
    monkeypatch.setenv('MOBILEAG_ALLOWED_ORIGINS','https://owned.example')
    value={'devices':[],'packages':[],'origins':['https://owned.example'],'methods':['GET'],'actions':[]}
    assert client.post('/api/scope',json=value).status_code==200
    call=AsyncMock(return_value={'status_code':200,'body':'synthetic','headers':{}});monkeypatch.setattr(web,'scoped_request',call)
    assert client.post('/api/apis/test',json={'url':'https://owned.example/a','method':'DELETE'}).status_code==403
    call.assert_not_called()
    assert client.post('/api/apis/test',json={'url':'https://owned.example/a','method':'GET'}).status_code==200
    call.assert_awaited_once()

def test_session_expiration_rotation_and_logout(client,monkeypatch,capsys):
    monkeypatch.setattr(web.app.state,'auth_token',web.app.state.auth_token)
    monkeypatch.setattr(web.app.state,'session_deadline',time.monotonic()+100)
    old=web.app.state.auth_token
    result=client.post('/api/session/rotate');assert result.status_code==200
    new=result.json()['token'];assert new!=old
    assert client.get('/api/settings').status_code==401
    client.headers['Authorization']='Bearer '+new
    assert client.get('/api/settings').status_code==200
    monkeypatch.setattr(web.app.state,'session_deadline',time.monotonic()-1)
    assert client.get('/api/settings').status_code==401
    monkeypatch.setattr(web.app.state,'session_deadline',time.monotonic()+100)
    assert client.post('/api/session/logout').status_code==200
    assert client.get('/api/settings').status_code==401
    # Do not persist the terminal reconnect token in any evidence.
    assert 'after logout' in capsys.readouterr().out


def test_isolated_worker_tree_measurement_enforces_bounded_no_follow_inventory(tmp_path):
    from mobileag.web.jobs import _measure_tree

    root = tmp_path / "worker"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "result.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="entry budget"):
        _measure_tree(root, max_entries=1)

    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic", encoding="utf-8")
    (root / "linked.txt").symlink_to(outside)
    with pytest.raises(RuntimeError, match="symlink"):
        _measure_tree(root, reject_skipped=True)


def test_isolated_worker_tree_measurement_counts_regular_file_bytes(tmp_path):
    from mobileag.web.jobs import _measure_tree

    root = tmp_path / "worker"
    root.mkdir()
    (root / "one").write_bytes(b"123")
    (root / "two").write_bytes(b"45")

    assert _measure_tree(root) == (5, 2)

def test_retention_confirm_revision_original_and_tombstone(client):
    document=scan();web.repository().save(document)
    original=web.UPLOAD_DIR/'original.apk';original.write_bytes(b'preserve')
    directory=web.OUTPUT_DIR/document['scan_id'];directory.mkdir();(directory/'dashboard.json').write_text(json.dumps(document))
    assert client.get('/api/scans/scan_fixture/retention').json()['allowed'] is True
    assert client.post('/api/scans/scan_fixture/purge',json={'confirmation':'wrong','revision':0}).status_code==409
    assert client.post('/api/scans/scan_fixture/purge',json={'confirmation':'scan_fixture','revision':1}).status_code==409
    assert client.post('/api/scans/scan_fixture/purge',json={'confirmation':'scan_fixture','revision':0}).status_code==200
    assert original.read_bytes()==b'preserve' and not directory.exists()
    # A stale preserved legacy snapshot cannot resurrect a purged record.
    directory.mkdir();(directory/'dashboard.json').write_text(json.dumps(document))
    assert client.get('/api/scans/scan_fixture').status_code==404
    web.repository_import_legacy();assert web.repository().get('scan_fixture') is None

def test_retention_rejects_symlink_and_active_job(client,tmp_path):
    document=scan(status='running');web.repository().save(document)
    assert client.post('/api/scans/scan_fixture/purge',json={'confirmation':'scan_fixture','revision':0}).status_code==409
    document['status']='completed';web.repository().save(document)
    outside=tmp_path/'outside';outside.mkdir();(outside/'untouched').write_text('original')
    (web.OUTPUT_DIR/'scan_fixture').symlink_to(outside,target_is_directory=True)
    assert client.post('/api/scans/scan_fixture/purge',json={'confirmation':'scan_fixture','revision':0}).status_code==409
    assert (outside/'untouched').read_text()=='original'

@pytest.mark.asyncio
async def test_restart_recovery_is_not_automatic_execution():
    web.repository().save(scan(status='running'))
    await web.recover_interrupted_jobs()
    result=web.repository().get('scan_fixture')
    assert result['status']=='interrupted'
    assert 'No device action' in result['errors'][0]

def test_assets_offline_and_csp(client):
    assert client.get('/static/vendor/lucide.js').status_code==200
    anonymous=TestClient(web.app)
    assert anonymous.get('/static/accessibility.css').status_code==200
    assert anonymous.get('/api/scope').status_code==401
    response=anonymous.get('/')
    assert 'https://unpkg.com' not in response.headers['content-security-policy']
    assert 'script-src \'self\'' in response.headers['content-security-policy']
    assert 'https://' not in response.text

@pytest.mark.skipif(not shutil.which('bwrap'),reason='Linux bubblewrap not installed')
def test_real_namespace_controls(tmp_path,monkeypatch):
    from mobileag.web.jobs import sandbox_command
    source=tmp_path/'input';source.write_text('readonly')
    work=tmp_path/'work';work.mkdir()
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-must-not-inherit')
    command=sandbox_command(work,source)[:-3]+['/usr/bin/python','-c',
        "import os,socket,pathlib,json; p=pathlib.Path; assert not p('/home/shambhu').exists(); assert not p('/etc/passwd').exists(); assert not os.getenv('OPENAI_API_KEY'); p('/work/proof').write_text('ok');\ntry: p('/input.archive').write_text('bad')\nexcept OSError: pass\nelse: raise AssertionError('input writable')\nassert list(socket.if_nameindex()) == [(1,'lo')]; print(json.dumps({'home_hidden':True,'input_readonly':True,'only_loopback_interface':True,'no_provider_key':True}))"]
    result=subprocess.run(command,env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)['home_hidden'] is True
    assert source.read_text()=='readonly' and (work/'proof').read_text()=='ok'

@pytest.mark.skipif(not shutil.which('bwrap'),reason='Linux bubblewrap not installed')
@pytest.mark.asyncio
async def test_real_worker_timeout_and_cancellation(tmp_path,monkeypatch):
    import mobileag.web.jobs as jobs
    # CI user managers vary: timeout test isolates namespace supervisor only.
    monkeypatch.setattr(jobs,'resource_command',lambda command,sid:command)
    original=jobs.sandbox_command
    monkeypatch.setattr(jobs,'sandbox_command',lambda work,file:original(work,file)[:-3]+['/usr/bin/python','-c','import time;time.sleep(60)'])
    artifact=tmp_path/'input';artifact.write_bytes(b'synthetic')
    async def progress(*args):pass
    with pytest.raises(TimeoutError):
        await jobs.isolated_analysis(artifact,tmp_path/'output','timeout',Settings(_env_file=None),progress,timeout=.5)
    assert not jobs.PROCESSES and not list((tmp_path/'output').glob('.job-*'))
    task=asyncio.create_task(jobs.isolated_analysis(artifact,tmp_path/'output','cancel',Settings(_env_file=None),progress,timeout=10))
    while 'cancel' not in jobs.PROCESSES:await asyncio.sleep(.01)
    jobs.CANCELLED.add('cancel')
    with pytest.raises(RuntimeError,match='cancelled'):await task
    assert not jobs.PROCESSES and not list((tmp_path/'output').glob('.job-*'))

@pytest.mark.asyncio
async def test_incomplete_worker_preserves_candidates(monkeypatch):
    sid='scan_partial';web.ACTIVE_SCANS[sid]=scan(sid,status='running')
    monkeypatch.setattr(web,'validate_archive',lambda path:'android')
    monkeypatch.setattr(web,'isolated_analysis',AsyncMock(return_value={'errors':['synthetic tool incomplete'], 'filtered_findings':[{'id':'lead','title':'Synthetic candidate','description':'synthetic','severity':'LOW','status':'CONFIRMED'}], 'coverage':{'phase':'incomplete'}}))
    request=web.RunScanRequest(apk_path=str(web.UPLOAD_DIR/'synthetic.apk'),output_dir=str(web.OUTPUT_DIR))
    await web.live_scan_telemetry_worker(sid,'synthetic',request)
    result=web.repository().get(sid)
    assert result['status']=='partial' and result['findings'][0]['status']=='UNVERIFIED'
    assert result['coverage']=={'phase':'incomplete'}

@pytest.mark.asyncio
async def test_concurrent_job_reservations_never_exceed_capacity():
    import zipfile
    from fastapi import BackgroundTasks, HTTPException
    artifact=web.UPLOAD_DIR/'synthetic.apk'
    with zipfile.ZipFile(artifact,'w') as archive:
        archive.writestr('AndroidManifest.xml','<manifest package="org.example"/>')
    # Call the real submission boundary concurrently, but do not run background
    # parsing or device operations. Reservations remain active for this control.
    results=await asyncio.gather(*(web.trigger_scan(web.RunScanRequest(apk_path=str(artifact)),BackgroundTasks()) for _ in range(3)),return_exceptions=True)
    assert sum(isinstance(result,dict) for result in results)==2
    assert sum(isinstance(result,HTTPException) and result.status_code==429 for result in results)==1
    assert len(web.ACTIVE_SCANS)==2

@pytest.mark.asyncio
async def test_expired_socket_cannot_receive_broadcast(monkeypatch):
    connection=AsyncMock();manager=web.ConnectionManager()
    manager.active_connections.append(connection);manager.sessions[connection]=web.app.state.auth_token
    monkeypatch.setattr(web.app.state,'session_deadline',time.monotonic()-1)
    await manager.broadcast({'type':'synthetic','message':'private evidence'})
    connection.send_json.assert_not_awaited();connection.close.assert_awaited_once_with(code=1008)
    assert not manager.active_connections and not manager.sessions

@pytest.mark.asyncio
async def test_root_observation_never_invokes_su():
    from mobileag.dast.adb_manager import ADBManager
    from unittest.mock import AsyncMock
    manager = ADBManager()
    manager._exec_cmd = AsyncMock(return_value=(0, b'uid=2000(shell)', b''))
    assert not await manager._check_root('owned-device')
    manager._exec_cmd.assert_awaited_once_with(['-s', 'owned-device', 'shell', 'id'], timeout=2.0)

@pytest.mark.asyncio
async def test_launch_rejects_zero_exit_android_error():
    from mobileag.dast.adb_manager import ADBManager
    from unittest.mock import AsyncMock
    manager = ADBManager()
    manager._exec_cmd = AsyncMock(return_value=(0, b'Error type 3\nError: Activity class does not exist.', b''))
    assert (await manager.launch_activity('owned-device', 'org.example/.Main'))['status'] == 'failed'

def test_dependency_constraints_have_no_local_artifact_references():
    from pathlib import Path
    snapshot = (Path(__file__).resolve().parents[1]/'requirements/validated-python314.txt').read_text()
    assert 'file:' not in snapshot and ' @ ' not in snapshot
    assert not any(line.lower().startswith('mobileag') for line in snapshot.splitlines() if not line.startswith('#'))
