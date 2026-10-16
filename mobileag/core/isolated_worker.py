"""Offline static worker protocol. Never imports dashboard state or credentials."""
import asyncio
import json
import os
from pathlib import Path
import resource
import tempfile
from config.settings import Settings
from mobileag.security.archives import validate_archive
from mobileag.security.privacy import redact

MAX_RESULT_BYTES = 16 * 1024 * 1024


def _write_result(path: str | Path, value) -> None:
    """Publish bounded worker JSON atomically without following result links."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    try:
        encoder = json.JSONEncoder(default=str, ensure_ascii=True, allow_nan=False,
                                   separators=(",", ":"))
        with os.fdopen(fd, "wb") as stream:
            written = 0
            for chunk in encoder.iterencode(redact(value)):
                encoded = chunk.encode("utf-8")
                written += len(encoded)
                if written > MAX_RESULT_BYTES:
                    raise ValueError("Worker result exceeds output size limit")
                stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

async def main():
    resource.setrlimit(resource.RLIMIT_AS, (4*1024**3, 4*1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256*1024*1024, 256*1024*1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 310))
    request = json.loads(Path('/work/request.json').read_text())
    settings = Settings(_env_file=None, **request['settings'], offline=True,
                        approved_llm_providers=[], OUTPUT_DIR='/work',
                        JADX_PATH='/usr/bin/jadx', APKTOOL_PATH=request['apktool'])
    async def progress(stage, message, pct, finding=None):
        print(json.dumps({'stage':str(stage)[:256], 'message':str(redact(message))[:1024],
                          'progress':min(int(pct),99)}), flush=True)
    sid = request['scan_id']
    try:
        if validate_archive('/input.archive') == 'ios':
            from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer
            from mobileag.core.state import create_initial_state
            result = await asyncio.to_thread(IOSSecurityAnalyzer().audit_ipa, '/input.archive', Path('/work')/sid/'ios_extract')
            state = create_initial_state(sid, '/input.archive', '/work/'+sid)
            state.update(package_name=result['package_name'] or result['app_name'], app_version=result['version'], filtered_findings=[f.model_dump(mode='json') for f in result['findings']], coverage=result['coverage'], errors=result['errors'])
        else:
            from mobileag.core.orchestrator import Orchestrator
            state = await Orchestrator(settings).scan('/input.archive', output_dir='/work', scan_id=sid, progress_callback=progress)
        import sys,platform
        state['execution_environment']={'python':sys.version.split()[0],'os':platform.platform(),'worker':'bubblewrap','network':'denied','device_access':'not_mounted'}
        for finding in state.get('filtered_findings', []):
            finding['status'] = 'UNVERIFIED'
        _write_result('/work/result.json', state)
    except Exception:
        _write_result('/work/result.json', {'errors':['Isolated analysis failed; check tool readiness and archive format']})

if __name__ == '__main__':
    asyncio.run(main())
