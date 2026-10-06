"""Factory-wired router: no importing app globals or auth test-mode switches."""
from fastapi import APIRouter, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse
from fastapi.responses import Response
from mobileag.automation.models import CreateRun, ExecuteRun, ImportCaptures, Contract
from mobileag.automation.store import Conflict
from mobileag.automation.engine import RunCancelled
from mobileag.automation.report import layout_svg
from pydantic import Field
import json

class Revision(Contract):revision:int=Field(ge=0)

class PrivateValidationRoute(APIRoute):
    def get_route_handler(self):
        original=super().get_route_handler()
        async def handler(request):
            try:return await original(request)
            except RequestValidationError:
                # Pydantic's default error includes input values, potentially an
                # entire payload carrying the ephemeral Authorization header.
                return JSONResponse({'detail':'Invalid automation fields; check required values, confirmations and limits'},status_code=422)
        return handler

def build_router(service,token):
    router=APIRouter(prefix='/api/automation',tags=['Authorized automation'],route_class=PrivateValidationRoute)
    async def call(fn,*args):
        try:return await fn(*args)
        except RunCancelled:raise HTTPException(409,"Run was stopped")
        except PermissionError:raise HTTPException(403,'Automation target/action is outside current authorization')
        except Conflict as e:raise HTTPException(409,str(e))
        except ValueError as e:raise HTTPException(422,str(e))
        except KeyError:raise HTTPException(404,'Automation run not found')
    def document(rid):
        try:return service().store().get(rid)
        except (KeyError,ValueError):raise HTTPException(404,'Automation run not found')
    @router.get('/capabilities')
    async def capabilities():
        return {'platforms':['android'],'execution':'explicitly approved bounded navigation + read-only API cases',
            'defaults':'observe/map only; no device selected implicitly',
            'limits':{'steps':30,'requests':10,'wall_seconds_per_batch':120,'concurrent_devices':2},
            'raw_screenshots':False,'layout_evidence':'text/pixel-free structural SVG',
            'unsupported':['native iOS','automatic TLS interception','credential/form filling','write API mutation','ownership without paired account fixtures','manual accessibility certification','production score']}
    @router.get('/runs')
    async def runs():return service().store().list()
    @router.post('/runs')
    async def create(req:CreateRun):return await call(service().create,req,token())
    @router.get('/runs/{rid}')
    async def get(rid:str):return document(rid)
    @router.post('/runs/{rid}/observe')
    async def observe(rid:str,req:Revision):return await call(service().observe,rid,req.revision,token())
    @router.post('/runs/{rid}/execute')
    async def execute(rid:str,req:ExecuteRun):return await call(service().execute,rid,req,token())
    @router.post('/runs/{rid}/cancel')
    async def cancel(rid:str):
        try:return service().cancel(rid)
        except (KeyError,ValueError):raise HTTPException(409,'Run is unavailable or not active')
    @router.post('/runs/{rid}/captures')
    async def captures(rid:str,req:ImportCaptures):
        s=service();doc=document(rid)
        try:
            s.guard(doc,token())
            if doc['revision']!=req.revision or doc['status'] in {'running','discovering'}:raise Conflict('Run changed or active')
            # Re-import after restart refreshes memory-only URLs without rewriting evidence.
            current={c['id'] for c in doc['captures']}
            from mobileag.automation.android import digest
            refreshed={digest(c.method+' '+c.url):c.url for c in req.captures if digest(c.method+' '+c.url) in current}
            for c in req.captures:
                if digest(c.method+' '+c.url) in refreshed:
                    temp={**doc,'captures':[],'tests':[],'correlations':[]};s.captures(temp,[c])
            added=s.captures(doc,[c for c in req.captures if digest(c.method+' '+c.url) not in current])
            s.persist(doc);s.targets.setdefault(rid,{}).update({**refreshed,**dict(added)})
            return doc
        except PermissionError:raise HTTPException(403,'Capture scope denied')
        except Conflict as e:raise HTTPException(409,str(e))
        except ValueError as e:raise HTTPException(422,str(e))
    @router.get('/runs/{rid}/report')
    async def final_report(rid:str):
        document(rid);return service().get_report(rid)
    @router.get('/runs/{rid}/export')
    async def export(rid:str):
        document(rid);return Response(json.dumps(service().get_report(rid),indent=2),media_type='application/json',headers={'Content-Disposition':f'attachment; filename="{rid}-report.json"'})
    @router.get('/runs/{rid}/screens/{sid}/layout')
    async def layout(rid:str,sid:str):
        doc=document(rid);snapshot=next((x for x in doc['screens'] if x['id']==sid),None)
        if not snapshot:raise HTTPException(404,'Screen not found')
        return Response(layout_svg(snapshot),media_type='image/svg+xml')
    return router
