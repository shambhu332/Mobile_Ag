"""Killable offline static jobs in a mount/PID/network namespace.

Fail closed without Linux bubblewrap. Only selected input, runtime, source modules
and job workspace are mounted; no dashboard DB, home, environment keys or ADB.
"""
import asyncio
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile

PROCESSES = {}
CANCELLED = set()
MAX_DISK = 512*1024*1024


def sandbox_command(work, artifact):
    binary = shutil.which('bwrap')
    if not binary:
        raise RuntimeError('Offline sandbox requires Linux bubblewrap; no unsafe fallback')
    source = Path(__file__).resolve().parents[2]
    command = [binary, '--die-with-parent', '--unshare-all', '--new-session',
               '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin',
               '--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
               '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
               '--dir','/app', '--ro-bind',str(source/'mobileag'),'/app/mobileag',
               '--ro-bind',str(source/'config'),'/app/config',
               '--ro-bind',str(artifact),'/input.archive', '--bind',str(work),'/work', '--chdir','/work']
    prefix = Path(sys.prefix).resolve()
    if not str(prefix).startswith('/usr'):
        command += ['--ro-bind',str(prefix),str(prefix)]
    # Minimal runtime configuration; never bind /etc wholesale or the repository root.
    for path in ['/etc/ld.so.cache','/etc/fonts','/etc/ssl/certs','/etc/java-openjdk','/etc/java17-openjdk','/etc/java11-openjdk','/etc/java21-openjdk']:
        if Path(path).exists():
            command += ['--ro-bind',path,path]
    jar = Path(os.environ.get('MOBILEAG_SANDBOX_APKTOOL_JAR','/snap/apktool/current/apktool.jar'))
    if jar.is_file():
        command += ['--ro-bind',str(jar.resolve()),'/tools/apktool.jar']
    command += ['--clearenv']
    for key,value in {'PATH':'/usr/bin:/bin','PYTHONPATH':'/app','PYTHONDONTWRITEBYTECODE':'1','HOME':'/tmp','LANG':'C.UTF-8','JAVA_TOOL_OPTIONS':'-Xmx768m -Xms64m -XX:+UseSerialGC'}.items():
        command += ['--setenv',key,value]
    command += [sys.executable,'-m','mobileag.core.isolated_worker']
    return command

def resource_command(command, sid):
    runner=shutil.which('systemd-run')
    if not runner:
        raise RuntimeError('Static jobs require a systemd user manager for aggregate memory/PID limits')
    return [runner,'--user','--scope','--quiet','--unit=mobileag-'+sid,
            '-p','MemoryMax=3G','-p','MemorySwapMax=512M','-p','TasksMax=128',
            '-p','CPUQuota=100%', *command]


def manager_environment():
    return {'PATH':'/usr/bin:/bin','XDG_RUNTIME_DIR':f'/run/user/{os.getuid()}',
            'DBUS_SESSION_BUS_ADDRESS':f'unix:path=/run/user/{os.getuid()}/bus'}

async def isolated_analysis(artifact, output, sid, settings, progress, timeout=360):
    output = Path(output)
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Separate transient writable workspace. Final evidence moves only after process exit.
    work = Path(tempfile.mkdtemp(prefix='.job-',dir=output))
    process = None
    try:
        public = {k:getattr(settings,k) for k in ('entropy_threshold','enable_deep_taint','enable_reachability_filter','enable_consensus_voting')}
        jar = Path(os.environ.get('MOBILEAG_SANDBOX_APKTOOL_JAR','/snap/apktool/current/apktool.jar'))
        apktool = '/usr/bin/apktool'
        if jar.is_file():
            wrapper = work/'apktool.sh'
            wrapper.write_text('#!/bin/sh\nexec /usr/bin/java -jar /tools/apktool.jar "$@"\n')
            wrapper.chmod(0o700)
            apktool = '/work/apktool.sh'
        (work/'request.json').write_text(json.dumps({'settings':public,'scan_id':sid,'apktool':apktool}))
        process = await asyncio.create_subprocess_exec(*resource_command(sandbox_command(work,artifact),sid),env=manager_environment(),
                   stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,start_new_session=True,limit=8192)
        PROCESSES[sid] = process
        async def consume():
            while line := await process.stdout.readline():
                try:
                    event = json.loads(line)
                    if isinstance(event,dict) and 'progress' in event:
                        await progress(event.get('stage','Analysis'),event.get('message',''),event['progress'])
                except (ValueError,TypeError):
                    continue
        async def watch():
            while process.returncode is None:
                if sid in CANCELLED:
                    raise RuntimeError('Scan cancelled by operator')
                size, count = 0, 0
                for root, dirs, files in os.walk(work,followlinks=False):
                    for name in files:
                        file = Path(root)/name
                        if not file.is_symlink():
                            size += file.stat().st_size
                        count += 1
                        if size > MAX_DISK or count > 30000:
                            raise RuntimeError('Worker output budget exceeded')
                await asyncio.sleep(.25)
        reader, watcher = asyncio.create_task(consume()), asyncio.create_task(watch())
        try:
            async with asyncio.timeout(timeout):
                done, _ = await asyncio.wait([reader,watcher],return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                await process.wait()
        finally:
            watcher.cancel(); reader.cancel()
            await asyncio.gather(watcher,reader,return_exceptions=True)
        result = work/'result.json'
        if sid in CANCELLED:
            raise RuntimeError('Scan cancelled by operator')
        if process.returncode or not result.is_file() or result.stat().st_size > 16*1024*1024:
            raise RuntimeError('Isolated worker failed; check sandbox and tool readiness')
        state = json.loads(result.read_text())
        if not isinstance(state,dict):
            raise RuntimeError('Invalid isolated worker result')
        evidence = work/sid
        if evidence.is_dir() and not evidence.is_symlink():
            # Never follow a worker-created symlink into operator files.
            for root, dirs, files in os.walk(evidence,followlinks=False):
                for name in dirs+files:
                    if (Path(root)/name).is_symlink():
                        raise RuntimeError('Worker returned unsupported symlink evidence')
            destination = output/sid
            if destination.exists():
                raise RuntimeError('Evidence destination already exists')
            evidence.rename(destination)
        state['output_dir'] = str(output/sid)
        return state
    finally:
        if process and process.returncode is None:
            try:
                os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
        if process:
            ctl=shutil.which('systemctl')
            if ctl:
                cleanup=await asyncio.create_subprocess_exec(ctl,'--user','stop','mobileag-'+sid+'.scope',env=manager_environment(),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
                try:
                    await asyncio.wait_for(cleanup.wait(),timeout=5)
                except TimeoutError:
                    cleanup.kill();await cleanup.wait()
        PROCESSES.pop(sid,None)
        CANCELLED.discard(sid)
        shutil.rmtree(work,ignore_errors=True)
