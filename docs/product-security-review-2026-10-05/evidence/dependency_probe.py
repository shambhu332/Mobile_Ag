"""Query public OSV for public installed package names/versions only, no source/secrets."""
import json,urllib.request,datetime
from pathlib import Path
out=Path(__file__).resolve().parent
packages=[p for p in json.loads((out/'python-dependencies.json').read_text()) if p['name'].lower()!='mobileag']
queries=[{'package':{'name':p['name'],'ecosystem':'PyPI'},'version':p['version']} for p in packages]
result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'endpoint':'https://api.osv.dev/v1/querybatch','packages':len(packages)}
try:
 req=urllib.request.Request(result['endpoint'],json.dumps({'queries':queries}).encode(),{'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r: data=json.load(r)
 result['results']=[dict(**p,**r) for p,r in zip(packages,data['results'])]
 result['pagination_pending']=any(r.get('next_page_token') for r in data['results'])
 result['matches']=[r for r in result['results'] if r.get('vulns')]
except Exception as e:result['error']=str(e)
(out/'dependency-osv.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:v for k,v in result.items() if k!='results'},indent=2))
