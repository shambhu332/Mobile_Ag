"""Opt-in real isolated SAST + owned loopback API/model fixture; no devices/cloud.

Only our permission-free navigation fixture is accepted by expected package/hash
scope. Real parser failures remain incomplete, never a fabricated passed scan.
"""
import argparse,asyncio,hashlib,json,os,shutil,tempfile,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

async def run(args):
    assert hashlib.sha256(Path(args.apk).read_bytes()).hexdigest()=='678c3906158acdff220c8b116166c019f2adb323548545562b2537b4bb5043ee','Only the recorded synthetic fixture is in this harness scope'
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=True)
    seen={'api':0,'model':0,'metadata_only':False}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen['api']+=1
            self.send_response(200 if self.headers.get('Authorization')=='Bearer synthetic-owned-account' else 401)
            self.end_headers();self.wfile.write(b'{"data":{"id":"synthetic-owned-id"}}')
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            seen['model']+=1
            prompt=json.loads(body['messages'][1]['content'])
            seen['metadata_only']=set(prompt)=={'static_status','static_candidate_counts','static_confirmed','api_cases_executed','dast_screens_observed','production_readiness'}
            self.send_response(200);self.end_headers();self.wfile.write(b'{"choices":[{"message":{"content":"Synthetic local advice: review actual coverage; no production score."}}]}')
        def log_message(self,*a):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin=f'http://127.0.0.1:{server.server_port}'
    try:
        with tempfile.TemporaryDirectory(prefix='mobileag-guided-fixture-') as temporary:
            root=Path(temporary)
            os.environ.update(MOBILEAG_DATA_DIR=str(root),MOBILEAG_API_TOKEN='synthetic-local-guided-key',OFFLINE='true',APPROVED_LLM_PROVIDERS='[]',
                MOBILEAG_ALLOWED_DEVICES='',MOBILEAG_ALLOWED_CONNECT='',MOBILEAG_ALLOWED_ORIGINS=origin,MOBILEAG_ALLOW_PRIVATE_TARGETS='1',
                MOBILEAG_LLM_ALLOWED_PROVIDERS='local_openai',MOBILEAG_LLM_LOCAL_OPENAI_MODEL='synthetic-loopback-model',
                MOBILEAG_LLM_LOCAL_OPENAI_ORIGIN=origin,MOBILEAG_LLM_LOCAL_ORIGINS=origin,MOBILEAG_LOCAL_LLM_KEY='')
            from mobileag.web.app import assessment_service,app,UPLOAD_DIR,repository
            from mobileag.assessments.models import Assessment
            apk=UPLOAD_DIR/'synthetic-fixture.apk';shutil.copyfile(args.apk,apk)
            sha=hashlib.sha256(apk.read_bytes()).hexdigest()
            service=assessment_service()
            req=Assessment(apk_path=str(apk),package_name='org.mobileag.validation.navigation',scope={'devices':[],'packages':['org.mobileag.validation.navigation'],
                'origins':[origin],'methods':['GET'],'actions':[]},authorized=True,scope_change_confirmed=True,confirmation='START SCOPED TESTS',
                api=True,captures=[{'method':'GET','url':origin+'/owned-profile','protected':True,'response_status':200,'read_only_confirmed':True}],
                api_authorization='Bearer synthetic-owned-account',dedicated_account_confirmed=True,llm_provider='local_openai',llm_metadata_egress_confirmed=True)
            doc=await service.create(req,app.state.auth_token);await service.tasks[doc['id']];doc=service.report(doc['id'])
            (output/'assessment-report.json').write_text(json.dumps(doc,indent=2))
            scan=repository().get(doc['scan_id']) if doc['scan_id'] else {}
            (output/'static-scan.json').write_text(json.dumps(scan,indent=2))
            result={'artifact_sha256':sha,'package':'org.mobileag.validation.navigation','assessment_status':doc['status'],
                'stages':{k:v['status'] for k,v in doc['stages'].items()},'requests':seen,'coverage':scan.get('coverage'),
                'execution_environment':scan.get('execution_environment'),'device_operations':0,'commercial_provider_calls':0,
                'boundary':'Real namespace/cgroup/parser and loopback transport integration only; no production app/device exploitation proof.'}
            (output/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
            assert doc['status']=='completed' and seen['api']==2 and seen['model']==1 and seen['metadata_only'], 'Fixture failed or incomplete; inspect evidence'
    finally:server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--apk',required=True);p.add_argument('--output',required=True);asyncio.run(run(p.parse_args()))
