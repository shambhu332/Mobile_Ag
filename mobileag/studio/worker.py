"""Offline subprocess entry point for uploaded-source taint and two-APK diff.

Invoked only inside the existing namespace + aggregate resource boundary.
"""
from pathlib import Path
import asyncio
import hashlib
import platform
from importlib.metadata import version, PackageNotFoundError
import json
import os
import zipfile


def execute(operation, artifact, work):
    from mobileag.security.archives import _validated_members, validate_archive
    from mobileag.security.privacy import redact
    from mobileag.reporting.artifact_writer import write_private_artifact
    work=Path(work);artifact=Path(artifact)
    with artifact.open("rb") as stream:
        input_sha256=hashlib.file_digest(stream,"sha256").hexdigest()
    names=_validated_members(artifact)
    if operation=='taint':
        from mobileag.analysis.taint_engine import TaintEngine
        root=work/'sources';root.mkdir(mode=0o700)
        selected=sorted(name for name in names if Path(name).suffix.lower() in {'.java','.kt'})
        if not selected:raise ValueError('No Java/Kotlin source files in archive')
        if len(selected)>1000:raise ValueError('Source archive exceeds 1000 source files')
        total=0
        with zipfile.ZipFile(artifact) as archive:
            for name in selected:
                info=archive.getinfo(name);total+=info.file_size
                if info.file_size>2*1024*1024 or total>32*1024*1024:raise ValueError('Source byte budget exceeded')
                path=root/name
                path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with archive.open(info) as src,path.open('xb') as dst:
                    count=0
                    while chunk:=src.read(65536):
                        count+=len(chunk)
                        if count>info.file_size:raise ValueError('Archive entry size changed')
                        dst.write(chunk)
        engine=TaintEngine();findings=engine.analyze_directory(str(root))
        result={'findings':[f.model_dump(mode='json') for f in findings], 'coverage':engine.coverage,
                'selected_source_files':len(selected),'non_source_members':len(names)-len(selected),
                'runtime_status':'not_tested','proof_status':'not_proven','operation':'uploaded_source_taint'}
    elif operation=='diff':
        from config.settings import Settings
        from mobileag.diffing.version_diff import VersionDiff
        if names!={'old.apk','new.apk'}:raise ValueError('Expected exactly two staged APKs')
        with zipfile.ZipFile(artifact) as archive:
            for name in ('old.apk','new.apk'):
                path=work/name
                with archive.open(name) as src,path.open('xb') as dst:
                    count=0
                    while chunk:=src.read(65536):
                        count+=len(chunk)
                        if count>128*1024*1024:raise ValueError('APK size limit exceeded')
                        dst.write(chunk)
                if validate_archive(path)!='android':raise ValueError('Expected two Android APKs')
        apktool='/usr/bin/apktool'
        if Path('/tools/apktool.jar').is_file():
            wrapper=work/'apktool.sh';wrapper.write_text('#!/bin/sh\nexec /usr/bin/java -jar /tools/apktool.jar "$@"\n');wrapper.chmod(0o700);apktool=str(wrapper)
        settings=Settings(offline=True,JADX_PATH='/usr/bin/jadx',APKTOOL_PATH=apktool)
        engine=VersionDiff(settings)
        extract=engine._extractor.extract
        provenance={}
        async def recorded_extract(path, output):
            extracted=await extract(path, output)
            provenance[Path(path).name]=extracted.get('artifact_provenance', {})
            return extracted
        engine._extractor.extract=recorded_extract
        result=asyncio.run(engine.diff(str(work/'old.apk'),str(work/'new.apk'),str(work/'diff')))
        result['artifact_provenance']=provenance
        result.update(runtime_status='not_tested',proof_status='not_proven',operation='uploaded_apk_diff',
                      limitations=['Bounded offline version comparison; absence of a candidate is not proof of a fix.'])
    else:raise ValueError('Unknown offline operation')
    from mobileag import __version__
    packages={}
    for name in ('tree-sitter','tree-sitter-java','tree-sitter-kotlin'):
        try:packages[name]=version(name)
        except PackageNotFoundError:packages[name]='not_installed'
    result['adapter_provenance']={'input_sha256':input_sha256,'input_size_bytes':artifact.stat().st_size,
        'mobileag_version':__version__,'python_version':platform.python_version(),'parser_packages':packages,
        'mode':'offline_static_only'}
    write_private_artifact(work/'result.json',json.dumps(redact(result),ensure_ascii=True,allow_nan=False),16*1024*1024)


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024*1024,128*1024*1024))
    os.umask(0o077)
    operation=json.loads(Path('/work/request.json').read_text())['operation']
    execute(operation,'/input.archive','/work')


if __name__=='__main__':main()
