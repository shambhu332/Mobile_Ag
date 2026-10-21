from fastapi import APIRouter,HTTPException,Request
from mobileag.assessments.models import Assessment
from mobileag.analysis.authorization_pair import AuthorizationPair,LiveAuthorizationProbe
from mobileag.assessments.service import AssessmentCancelled
from mobileag.automation.routes import PrivateValidationRoute
from mobileag.llm.broker import catalog

def build_router(service,token):
    router=APIRouter(prefix='/api/assessments',tags=['Guided assessments'],route_class=PrivateValidationRoute)
    @router.get('/providers')
    async def providers():return catalog()
    @router.get('')
    async def list_runs():return service().store().list()
    @router.post('')
    async def start(req:Assessment,request:Request):
        try:return await service().create(req,token(request))
        except PermissionError:raise HTTPException(403,'Assessment scope/provider approval denied')
        except ValueError:raise HTTPException(422,'Invalid assessment plan, targets or capacity; check scope, upload and confirmations')
    @router.get('/{rid}')
    async def get(rid:str):
        try:return service().report(rid)
        except KeyError:raise HTTPException(404,'Assessment not found')
    @router.post('/{rid}/authorization-evidence')
    async def authorization_evidence(rid:str,req:AuthorizationPair,request:Request):
        try:return service().record_authorization_pair(rid,req,token(request))
        except AssessmentCancelled:raise HTTPException(409,'Assessment cancelled; evidence was not imported')
        except PermissionError:raise HTTPException(403,'Evidence outside current assessment scope')
        except ValueError:raise HTTPException(422,'Invalid, duplicate or over-budget paired evidence')
        except KeyError:raise HTTPException(404,'Assessment not found')
    @router.post('/{rid}/authorization-probe')
    async def authorization_probe(rid:str,req:LiveAuthorizationProbe,request:Request):
        try:return await service().run_authorization_probe(rid,req,token(request))
        except AssessmentCancelled:raise HTTPException(409,'Assessment cancelled; probe stopped')
        except PermissionError:raise HTTPException(403,'Probe outside current assessment/server scope')
        except ValueError:raise HTTPException(422,'Invalid or incomplete paired API probe; inspect scope and evidence limits')
        except KeyError:raise HTTPException(404,'Assessment not found')
    @router.post('/{rid}/cancel')
    async def cancel(rid:str):
        try:return service().cancel(rid)
        except (ValueError,KeyError):raise HTTPException(409,'Assessment is not active')
    return router
