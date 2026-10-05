import asyncio, tempfile, pathlib, shutil, subprocess, json
from unittest.mock import AsyncMock, patch
from mobileag.knowledge.qdrant_store import PatternMemory
from mobileag.reporting.finding import Finding
from mobileag.llm.consensus import ConsensusVoter
from mobileag.core.orchestrator import Orchestrator
from mobileag.core.state import create_initial_state
from mobileag.ingestion.manifest_parser import ManifestParser
out={}
async def main():
    mem=object.__new__(PatternMemory);mem._connected=True;mem.client=AsyncMock();mem.collection_name='synthetic'
    try: await mem.store_finding(Finding(title='Synthetic',description='Synthetic'),[0.0]*384)
    except Exception as e:out['qdrant_store_exception']=f'{type(e).__name__}: {e}'
    voter=ConsensusVoter(None)
    out['string_false_vote']=voter._parse_vote('synthetic','{"vulnerable":"false"}').vulnerable
    with tempfile.TemporaryDirectory() as td:
        root=pathlib.Path(td); smali=root/'apktool_out';java=root/'jadx_out';smali.mkdir();java.mkdir()
        (smali/'Probe.smali').write_text('synthetic')
        manifest=smali/'AndroidManifest.xml';manifest.write_text('<manifest package="synthetic" xmlns:android="http://schemas.android.com/apk/res/android"><application><activity android:name=".Main"><intent-filter><data android:scheme="test" android:host="route"/></intent-filter></activity></application></manifest>')
        obj=object.__new__(Orchestrator)
        obj._extractor=AsyncMock();obj._extractor.extract.return_value={'apktool_dir':str(smali),'jadx_dir':str(java),'manifest_path':str(manifest),'package_name':'synthetic'}
        obj._manifest_parser=ManifestParser()
        from unittest.mock import MagicMock
        obj._framework_detector=MagicMock();obj._framework_detector.detect.return_value={}
        obj._packer_detector=MagicMock();obj._obfuscation_analyzer=MagicMock()
        state=await obj._run_ingestion(create_initial_state('s','synthetic.apk',td))
        out['analysis_root_smali_count']=len(list(pathlib.Path(state['decompiled_path']).rglob('*.smali')))
        out['parser_deep_link']=state['deep_links'][0]
        out['worker_deep_link_value']=state['deep_links'][0].get('uri','')
asyncio.run(main())
with tempfile.TemporaryDirectory() as td:
    root=pathlib.Path(td)
    for name in ['pyproject.toml','README.md']:shutil.copy(name,root/name)
    for name in ['mobileag','config','tests']:shutil.copytree(name,root/name,ignore=shutil.ignore_patterns('__pycache__'))
    for name in ['data','uploads','output']: (root/name).mkdir()
    p=subprocess.run(['python','-m','pip','wheel','--no-deps','--no-build-isolation','.', '-w','/tmp/mobileag-review-20261005/wheels'],cwd=root,capture_output=True,text=True)
    out['wheel_returncode']=p.returncode
    pathlib.Path('/tmp/mobileag-review-20261005/packaging.txt').write_text(p.stdout+p.stderr)
print(json.dumps(out,indent=2))
