"""Authenticated UI capability discovery and bounded CLI import/report adapters.

No shell runner, arbitrary filesystem selector, credential writer or scope bypass.
"""
from __future__ import annotations
import asyncio
import json
import tempfile
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import Response
from mobileag.security.privacy import redact

UPLOAD_LIMITS = {
    '/api/studio/taint/source-archive': 128 * 1024 * 1024,
    '/api/studio/compare/apks': 128 * 1024 * 1024,
    '/api/studio/import/sarif': 16 * 1024 * 1024,
    '/api/studio/import/mobsf': 16 * 1024 * 1024,
    '/api/studio/inventory/aab': 128 * 1024 * 1024,
}
DISABLED = {
    '/api/findings/{finding_id}/feedback': 'Legacy unscoped triage is retired. Use scan-scoped feedback.',
    '/api/dast/logcat/clear': 'Disabled by backend: preserve original device logs.',
    '/api/dast/frida': 'Disabled by backend: hook deployment and bypasses are retired.',
    '/api/frida/presets/{script_type}': 'Disabled by backend: runtime hook previews are retired.',
}


def group(path):
    if path.startswith('/api/studio/import') or '/inventory/' in path:return 'Imports & inventory'
    if path.startswith('/api/assessments'):return 'Guided assessments'
    if path.startswith('/api/automation'):return 'Automation'
    if '/api-capture/' in path or path.startswith('/api/apis') or path=='/api/dast/traffic/audit':return 'API & traffic'
    if path.startswith('/api/dast'):return 'Device diagnostics'
    if path in {'/api/scope','/api/settings','/api/readiness','/api/preflight','/api/status','/api/agents','/api/graph/status'}:return 'Configuration'
    if '/source' in path or '/taint/' in path or path.startswith('/api/analysis'):return 'Source & taint'
    if '/feedback' in path or '/decisions' in path or '/test-plan' in path or '/poc' in path or path=='/api/copilot':return 'Evidence & plans'
    if any(v in path for v in ('/sarif','/cyclonedx','/spdx','/openapi','/har','/report')):return 'Reports & exports'
    return 'Scans & comparison'


def effect(path, method):
    if path in DISABLED:return 'disabled'
    if path.endswith('/purge'):return 'destructive'
    if path=='/api/scope' and method!='GET':return 'changes authorization policy'
    if path.startswith('/api/assessments') and method=='POST' and path.count('/')==2:return 'starts selected static, API, device and optional model stages'
    if path.startswith('/api/dast/') and '/api-capture/' not in path and path!='/api/dast/traffic/audit':return 'explicit device access; shell/root may be device-wide'
    if path.startswith('/api/apis/') or path.endswith('/api-capture/start'):return 'scoped network or proxy operation'
    if path.startswith('/api/automation') and method!='GET':return 'approved automation state/device/API operation'
    if path in {'/api/graph/status','/api/preflight','/api/readiness'} or path.endswith('/graph'):return 'explicit environment or graph probe'
    if method!='GET':return 'local computation or persisted state change'
    return 'read or export local evidence'


def catalog(app):
    from copy import deepcopy
    spec=deepcopy(app.openapi())
    models=spec.get('components',{}).get('schemas',{})
    if 'ExecuteRun' in models:
        models['ExecuteRun']['properties']['confirmation']['description']='Type the exact automation run ID (rid). Only the listed action IDs and API case IDs are approved.'
    if 'Assessment' in models:
        models['Assessment']['properties']['llm_provider']['description']='Optional server-approved provider ID. Only aggregate counts/status are sent; explicit metadata-egress consent is required.'
    operations=[]
    for path, methods in spec['paths'].items():
        if not path.startswith('/api/') or path=='/api/studio/catalog':continue
        for method, op in methods.items():
            if method not in {'get','post','put','delete','patch'}:continue
            operations.append({'id':method.upper()+' '+path,'method':method.upper(),'path':path,
                'title':op.get('summary',path),'description':op.get('description',''),
                'group':group(path),'effect':effect(path,method.upper()),'disabled_reason':DISABLED.get(path),
                'parameters':deepcopy(op.get('parameters',[])), 'requestBody':deepcopy(op.get('requestBody',{}))})
    # Open dict APIs still get explicit useful controls; server remains authoritative.
    for op in operations:
        if op['method']=='POST' and op['path']=='/api/scope':
            op['requestBody']={'required':True,'content':{'application/json':{'schema':{'type':'object','required':['devices','packages','origins','methods','actions'],'properties':{k:{'type':'array','items':{'type':'string'},'maxItems':100} for k in ['devices','packages','origins','methods','actions']}}}}}
        if op['method']=='POST' and op['path']=='/api/settings':
            op['requestBody']={'required':True,'content':{'application/json':{'schema':{'type':'object','properties':{'entropy_threshold':{'type':'number','minimum':0,'maximum':8},**{k:{'type':'boolean'} for k in ['enable_deep_taint','enable_reachability_filter','enable_consensus_voting']},'offline':{'type':'boolean','const':True}}}}}}
    return {'operations':operations,'schemas':spec.get('components',{}).get('schemas',{}),
            'workflow':'Select operation → enter exact parameters → review → approve → execute. No auto execution.',
            'boundaries':['Browser does not grant server scope.','Retired backend operations remain disabled.',
                'Provider keys/models and environment ceilings are server-managed, never written by this UI.',
                'Web static workers remain offline; CLI cloud source review and OSV egress are not enabled in the browser.',
                'File inputs use browser-selected uploads, output uses downloads; no arbitrary host filesystem access.'],
            'cli_mapping':[
                {'command':'scan / ios','ui':'New assessment + Reports & exports','status':'offline browser equivalent; CLI cloud/advisory flags intentionally unavailable'},
                {'command':'diff','ui':'Scans & comparison','status':'stored scan comparison or isolated two-APK comparison'},
                {'command':'taint','ui':'Source & taint','status':'source snippet, isolated uploaded-source archive, or APK scan taint; no arbitrary host directory access'},
                {'command':'import-sarif','ui':'Imports & inventory','status':'same bounded importer; download candidate projection'},
                {'command':'import-mobsf-json','ui':'Imports & inventory','status':'same bounded importer; download candidate projection'},
                {'command':'inventory-aab','ui':'Imports & inventory','status':'same bounded inventory; temporary upload removed'},
                {'command':'dashboard api','ui':'Advanced tools','status':'authenticated parameter forms and result downloads'},
                {'command':'web','ui':'server lifecycle','status':'launch/host/token environment remain terminal-managed'},
                {'command':'dast','ui':'Device diagnostics / Guided assessments','status':'legacy full suite stays disabled; scoped individual actions available'}]}


async def bounded_file(file, limit):
    data=bytearray()
    try:
        while chunk:=await file.read(65536):
            if len(data)+len(chunk)>limit:raise HTTPException(413,'Input exceeds this operation size limit')
            data.extend(chunk)
        return bytes(data)
    finally:await file.close()


async def stage_upload(file,path,limit):
    total=0
    with path.open('xb') as output:
        path.chmod(0o600)
        while chunk:=await file.read(65536):
            total+=len(chunk)
            if total>limit:raise HTTPException(413,'Uploaded input exceeds the operation size limit')
            output.write(chunk)


def build_router(app):
    router=APIRouter(prefix='/api/studio',tags=['Browser workflow adapters'])
    @router.get('/catalog')
    async def capabilities():
        return catalog(app)

    @router.post('/import/sarif',summary='Import SARIF candidates')
    async def sarif(request:Request,file:UploadFile=File(...)):
        """Validate a selected SARIF file offline; return unverified candidates without changing stored scans."""
        from mobileag.reporting.sarif_importer import import_sarif,MAX_BYTES,SarifImportError
        from mobileag.web.app import require_current_session
        raw=await bounded_file(file,min(MAX_BYTES,UPLOAD_LIMITS['/api/studio/import/sarif']))
        try:result=await asyncio.to_thread(import_sarif,raw)
        except SarifImportError:raise HTTPException(422,'Invalid or unsupported bounded SARIF input') from None
        require_current_session(request)
        return redact(result)

    @router.post('/import/mobsf',summary='Import MobSF JSON candidates')
    async def mobsf(request:Request,file:UploadFile=File(...)):
        """Import a bounded Android static-report subset; no MobSF server is contacted."""
        from mobileag.reporting.mobsf_importer import import_mobsf_json,MAX_BYTES,MobSFImportError
        from mobileag.web.app import require_current_session
        raw=await bounded_file(file,min(MAX_BYTES,UPLOAD_LIMITS['/api/studio/import/mobsf']))
        try:result=await asyncio.to_thread(import_mobsf_json,raw)
        except MobSFImportError:raise HTTPException(422,'Invalid or unsupported bounded MobSF input') from None
        require_current_session(request)
        return redact(result)

    @router.post('/inventory/aab',summary='Inventory an Android App Bundle')
    async def aab(request:Request,file:UploadFile=File(...)):
        """Inventory only: no APK generation, manifest protobuf decoding, extraction or execution."""
        from mobileag.ingestion.aab_inventory import inventory_android_app_bundle
        from mobileag.web.app import require_current_session
        # tempfile owns its path, never the untrusted client filename. It is removed after use.
        total=0
        try:
            with tempfile.TemporaryDirectory(prefix='mobileag-aab-') as directory:
                path=Path(directory)/'input.aab'
                with path.open('xb') as out:
                    path.chmod(0o600)
                    while chunk:=await file.read(65536):
                        total+=len(chunk)
                        if total>UPLOAD_LIMITS['/api/studio/inventory/aab']:raise HTTPException(413,'AAB size limit exceeded')
                        out.write(chunk)
                try:result=await asyncio.to_thread(inventory_android_app_bundle,path)
                except (OSError,ValueError):raise HTTPException(422,'Invalid or unsupported bounded AAB input') from None
                require_current_session(request)
                return redact(result)
        finally:await file.close()

    @router.post('/taint/source-archive',summary='Analyze uploaded source directory ZIP')
    async def source_archive(request:Request,file:UploadFile=File(...)):
        """Offline Java/Kotlin directory taint in an isolated worker. Up to 1000 files, 2 MiB/file, 32 MiB source total. No host paths or cloud review."""
        from mobileag.studio.jobs import local_tool
        try:
            with tempfile.TemporaryDirectory(prefix='mobileag-source-upload-') as folder:
                path=Path(folder)/'source.zip'
                await stage_upload(file,path,128*1024*1024)
                return await local_tool('taint',path,request)
        finally:await file.close()

    @router.post('/compare/apks',summary='Compare two uploaded APK versions')
    async def compare_apks(request:Request,old_file:UploadFile=File(...),new_file:UploadFile=File(...)):
        """Runs the CLI VersionDiff engine inside the offline namespace/resource boundary. Select old/new APKs, combined size below 128 MiB. Not a fix-verification claim."""
        import zipfile
        from mobileag.studio.jobs import local_tool
        from mobileag.security.archives import validate_archive
        try:
            with tempfile.TemporaryDirectory(prefix='mobileag-diff-upload-') as folder:
                root=Path(folder)
                for upload,name in [(old_file,'old.apk'),(new_file,'new.apk')]:
                    path=root/name
                    await stage_upload(upload,path,128*1024*1024)
                    try:platform=await asyncio.to_thread(validate_archive,path)
                    except ValueError:raise HTTPException(422,'Both inputs must be valid bounded APK archives') from None
                    if platform!='android':raise HTTPException(422,'Both inputs must be Android APK archives')
                if sum((root/name).stat().st_size for name in ('old.apk','new.apk'))>128*1024*1024-4096:
                    raise HTTPException(413,'Combined APK upload must be below 128 MiB')
                archive=root/'pair.zip'
                def pack():
                    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_STORED) as output:
                        for name in ('old.apk','new.apk'):output.write(root/name,name)
                await asyncio.to_thread(pack)
                return await local_tool('diff',archive,request)
        finally:
            await old_file.close();await new_file.close()

    @router.get('/scans/{scan_id}/report',summary='Download JSON or Markdown report')
    async def report(scan_id:str,format:Literal['json','markdown']='json'):
        """Export the normalized stored scan; a report is not independent exploit verification."""
        from mobileag.web.app import get_scan_details
        scan=await get_scan_details(scan_id)
        if format=='json':content=json.dumps(scan,indent=2,ensure_ascii=True);mime='application/json';extension='json'
        else:
            # Encode untrusted strings as JSON within an indented code block, not executable HTML/links.
            content='# MobileAg evidence report\n\nStored observations only. No independent exploit verification.\n\n'
            content+='\n'.join('    '+line for line in json.dumps(scan,indent=2,ensure_ascii=True).splitlines())+'\n'
            mime='text/markdown';extension='md'
        return Response(content,media_type=mime,headers={'Content-Disposition':f'attachment; filename="{scan_id}.{extension}"'})
    return router
