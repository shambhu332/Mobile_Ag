"""Fail-closed, cancellable namespace runner for the two CLI-only adapters."""
import asyncio
import json
import os
from pathlib import Path
import signal
import tempfile
import uuid
from fastapi import HTTPException
from mobileag.web.jobs import sandbox_command,resource_command,manager_environment,_measure_tree,_read_worker_result,MAX_DISK


async def local_tool(operation,artifact,request):
    from mobileag.web.app import require_current_session
    if getattr(request.app.state,'studio_job_active',False):
        raise HTTPException(409,'One offline import/analysis adapter job may run at a time')
    require_current_session(request)
    request.app.state.studio_job_active=True
    process=None
    try:
        with tempfile.TemporaryDirectory(prefix='mobileag-studio-job-') as folder:
            work=Path(folder)
            (work/'request.json').write_text(json.dumps({'operation':operation}))
            try:
                command=sandbox_command(work,Path(artifact).resolve())
                command[-1]='mobileag.studio.worker'
                command=resource_command(command,'studio-'+uuid.uuid4().hex)
                process=await asyncio.create_subprocess_exec(*command,env=manager_environment(),
                    stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,start_new_session=True)
                async with asyncio.timeout(360):
                    while process.returncode is None:
                        require_current_session(request)
                        size,_=await asyncio.to_thread(_measure_tree,work)
                        if size>MAX_DISK:raise RuntimeError('Workspace disk budget exceeded')
                        try:await asyncio.wait_for(process.wait(),timeout=.5)
                        except asyncio.TimeoutError:continue
                require_current_session(request)
                if process.returncode!=0:raise RuntimeError('Offline worker failed')
                return await asyncio.to_thread(_read_worker_result,work/'result.json')
            except (OSError,RuntimeError,TimeoutError):
                raise HTTPException(503,'Offline adapter unavailable, failed, or exceeded resource limits; inspect worker readiness. No unsafe fallback.') from None
            finally:
                if process is not None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    await process.wait()
    finally:request.app.state.studio_job_active=False
