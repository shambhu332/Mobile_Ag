from fastapi import APIRouter,HTTPException
from mobileag.assessments.models import Assessment
from mobileag.automation.routes import PrivateValidationRoute
from mobileag.llm.broker import catalog

def build_router(service,token):
    router=APIRouter(prefix='/api/assessments',tags=['Guided assessments'],route_class=PrivateValidationRoute)
    @router.get('/providers')
    async def providers():return catalog()
    @router.get('')
    async def list_runs():return service().store().list()
    @router.post('')
    async def start(req:Assessment):
        try:return await service().create(req,token())
        except PermissionError:raise HTTPException(403,'Assessment scope/provider approval denied')
        except ValueError:raise HTTPException(422,'Invalid assessment plan, targets or capacity; check scope, upload and confirmations')
    @router.get('/{rid}')
    async def get(rid:str):
        try:return service().report(rid)
        except KeyError:raise HTTPException(404,'Assessment not found')
    @router.post('/{rid}/cancel')
    async def cancel(rid:str):
        try:return service().cancel(rid)
        except (ValueError,KeyError):raise HTTPException(409,'Assessment is not active')
    return router
