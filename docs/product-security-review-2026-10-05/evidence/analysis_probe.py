"""Synthetic filter, triage identity and input-shape checks; no external requests."""
import asyncio,importlib,json,os,tempfile
from pathlib import Path
from unittest.mock import AsyncMock
OUT=Path(__file__).resolve().parent;root=Path(tempfile.mkdtemp(prefix='mobileag-analysis-review-'))
os.environ.update(OFFLINE='true',MOBILEAG_DATA_DIR=str(root),MOBILEAG_API_TOKEN='synthetic-review-only')
from config.settings import Settings
from mobileag.llm.router import LLMRouter
from mobileag.analysis.secret_scanner import SecretScanner
from mobileag.filters.pipeline import FilterPipeline
from mobileag.filters.sanitizer_check import SanitizerFilter
from fastapi.testclient import TestClient
async def run():
 s=Settings(_env_file=None,offline=True);r=LLMRouter(s)
 for i in range(6):(root/f'Reference{i}.java').write_text('Example value;')
 src=root/'Example.java';base='class Example { Object c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }'
 results={}
 for name,text in [('baseline',base),('irrelevant_comment',base+' // ? Base64.encode SecureRandom')]:
  src.write_text(text);fs=await SecretScanner(r).scan(str(root));kept=await FilterPipeline(r,settings=s).filter_findings(fs,str(root))
  results[name]={'raw':len(fs),'retained':len(kept),'confidence':fs[0].confidence,'scores':fs[0].filter_scores}
 # file-path boundary lead: not asserting a sample can control this argument.
 outside=root/'host-synthetic.txt';outside.write_text('SYNTHETIC_OUTSIDE_ANALYSIS_ROOT')
 analysis=root/'analysis';analysis.mkdir()
 results['context_path_lead']={'outside_root_read':SanitizerFilter(r)._get_code_context(str(outside),1,str(analysis))=='SYNTHETIC_OUTSIDE_ANALYSIS_ROOT','attacker_control_demonstrated':False}
 return results
results=asyncio.run(run())
async def crawler_probe():
 from mobileag.dast.ui_crawler import UICrawler
 adb=type('FakeADB',(),{'_exec_cmd':AsyncMock(return_value=(0,b'',b''))})()
 crawler=UICrawler(adb)
 crawler.dump_ui_hierarchy=AsyncMock(return_value='<hierarchy><node package="org.example.unrelated" text="Allow" content-desc="" class="android.widget.Button" clickable="true" bounds="[10,10][50,50]" /></hierarchy>')
 report=await crawler.crawl_app('synthetic-device','org.example.intended',max_steps=1,step_delay=0)
 return {'reported_package':report['package_name'],'foreground_fixture_package':'org.example.unrelated','device_commands':[c.args[0] for c in adb._exec_cmd.call_args_list],'real_device_commands':0}
results['crawler']=asyncio.run(crawler_probe())
m=importlib.import_module('mobileag.web.app');c=TestClient(m.app,base_url='http://127.0.0.1',raise_server_exceptions=False);h={'Authorization':'Bearer synthetic-review-only'}
m.ACTIVE_SCANS.clear()
for sid in ('ios-a','ios-b'):m.ACTIVE_SCANS[sid]={'findings':[{'id':'ios-ats-001','status':'UNVERIFIED'}]}
r=c.post('/api/findings/ios-ats-001/feedback',headers=h,json={'verdict':'FALSE_POSITIVE'})
results['cross_scan_triage']={'status_code':r.status_code,'statuses':{k:v['findings'][0]['status'] for k,v in m.ACTIVE_SCANS.items()}}
results['traffic_malformed']=dict(status=c.post('/api/dast/traffic/audit',headers=h,json={'transactions':[{'url':5,'request_headers':[]}]}).status_code)
results['settings_offline_returned']='offline' in c.get('/api/settings',headers=h).json()
(OUT/'analysis-results.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
