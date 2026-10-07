"""Synthetic vendor responses only; no keys/accounts/devices are contacted."""
import asyncio
import json
from unittest.mock import AsyncMock
import pytest
from mobileag.llm.broker import LLMBroker,LLMReviewError,aggregate
from mobileag.assessments.service import AssessmentCancelled
from tests.test_guided_assessments import setup,plan,finish

@pytest.fixture
def pair(monkeypatch):
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS','gemini,grok')
    for provider,key in [('gemini','GEMINI_API_KEY'),('grok','XAI_API_KEY')]:
        monkeypatch.setenv('MOBILEAG_LLM_'+provider.upper()+'_MODEL','synthetic-'+provider)
        monkeypatch.setenv(key,'synthetic-secret-'+provider)
    return aggregate({'status':'completed','findings':[{'severity':'high','description':'never-send-raw-source'}]})

def response(provider,status=200):
    advice='synthetic-secret-gemini synthetic-secret-grok advice'
    body={'candidates':[{'content':{'parts':[{'text':advice}]}}]} if provider=='gemini' else {'choices':[{'message':{'content':advice}}]}
    return {'status_code':status,'body':json.dumps(body if status==200 else {'error':'private upstream details never persisted'})}

@pytest.mark.asyncio
@pytest.mark.parametrize('primary,secondary',[('gemini','grok'),('grok','gemini')])
async def test_rate_limit_moves_once_to_approved_secondary(pair,primary,secondary):
    transport=AsyncMock(side_effect=[response(primary,429),response(secondary)])
    broker=LLMBroker(transport)
    result=await broker.review(primary,pair,lambda:None,secondary=secondary,fallback_confirmed=True)
    assert result['provider']==secondary and result['primary_provider']==primary and result['fallback_used']
    assert [a['outcome'] for a in result['attempts']]==['rate_limited','completed']
    assert [a['http_status'] for a in result['attempts']]==[429,200]
    assert transport.await_count==2 and not broker.busy
    sent=[]
    for call in transport.await_args_list:
        body=json.loads(call.kwargs['body'])
        sent.append(json.loads(body['contents'][0]['parts'][0]['text']) if 'contents' in body else json.loads(body['messages'][1]['content']))
        assert len(call.kwargs['allowed_origins'])==1
        assert 'never-send-raw-source' not in call.kwargs['body']
    assert sent==[pair,pair]
    assert 'synthetic-secret' not in json.dumps(result) and 'private upstream' not in json.dumps(result)

@pytest.mark.asyncio
async def test_primary_success_never_calls_secondary_and_next_review_starts_primary(pair):
    transport=AsyncMock(side_effect=[response('gemini',429),response('grok'),response('gemini')])
    broker=LLMBroker(transport)
    assert (await broker.review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True))['fallback_used']
    result=await broker.review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    assert result['provider']=='gemini' and not result['fallback_used'] and len(result['attempts'])==1
    assert transport.await_count==3

@pytest.mark.asyncio
@pytest.mark.parametrize('status',[400,401,402,403,404,408,500,503])
async def test_non_429_errors_do_not_fail_over(pair,status):
    transport=AsyncMock(return_value=response('gemini',status));broker=LLMBroker(transport)
    with pytest.raises(LLMReviewError) as caught:
        await broker.review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    assert transport.await_count==1 and not broker.busy
    assert caught.value.attempts[0]['http_status']==status
    assert 'private upstream' not in str(caught.value)

@pytest.mark.asyncio
@pytest.mark.parametrize('error',[TimeoutError('sensitive timeout details'),OSError('sensitive network details')])
async def test_transport_failure_does_not_fail_over(pair,error):
    transport=AsyncMock(side_effect=error);broker=LLMBroker(transport)
    with pytest.raises(LLMReviewError):await broker.review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    assert transport.await_count==1 and not broker.busy

@pytest.mark.asyncio
async def test_blocked_or_invalid_text_is_not_rate_limit(pair):
    transport=AsyncMock(return_value={'status_code':200,'body':'{"error":{"code":429}}'})
    with pytest.raises(LLMReviewError):await LLMBroker(transport).review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    assert transport.await_count==1

@pytest.mark.asyncio
async def test_secondary_429_is_terminal_no_loop(pair):
    transport=AsyncMock(side_effect=[response('gemini',429),response('grok',429)]);broker=LLMBroker(transport)
    with pytest.raises(LLMReviewError) as caught:await broker.review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    assert transport.await_count==2 and not broker.busy
    assert len(caught.value.attempts)==2 and all(a['outcome']=='rate_limited' for a in caught.value.attempts)

@pytest.mark.asyncio
async def test_no_secondary_means_no_fallback(pair):
    transport=AsyncMock(return_value=response('gemini',429))
    with pytest.raises(LLMReviewError):await LLMBroker(transport).review('gemini',pair,lambda:None)
    assert transport.await_count==1

@pytest.mark.asyncio
@pytest.mark.parametrize('secondary,consent,allowed,error',[
    ('grok',False,'gemini,grok',PermissionError),('gemini',True,'gemini,grok',ValueError),
    ('grok',True,'gemini',PermissionError),('unknown',True,'gemini,grok',ValueError),
    (None,True,'gemini,grok',ValueError)])
async def test_invalid_or_unapproved_pair_has_no_network(pair,monkeypatch,secondary,consent,allowed,error):
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS',allowed);transport=AsyncMock()
    with pytest.raises(error):await LLMBroker(transport).review('gemini',pair,lambda:None,secondary=secondary,fallback_confirmed=consent)
    transport.assert_not_called()

@pytest.mark.asyncio
async def test_missing_secondary_model_blocks_before_primary(pair,monkeypatch):
    monkeypatch.delenv('MOBILEAG_LLM_GROK_MODEL');transport=AsyncMock()
    with pytest.raises(PermissionError):await LLMBroker(transport).review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    transport.assert_not_called()

@pytest.mark.asyncio
@pytest.mark.parametrize('failure',[PermissionError('revoked'),AssessmentCancelled()])
async def test_guard_revocation_after_429_prevents_secondary(pair,failure):
    revoked=False
    async def transport(*args,**kw):
        nonlocal revoked
        revoked=True;return response('gemini',429)
    def guard():
        if revoked:raise failure
    mock=AsyncMock(side_effect=transport);broker=LLMBroker(mock)
    with pytest.raises(type(failure)):await broker.review('gemini',pair,guard,secondary='grok',fallback_confirmed=True)
    assert mock.await_count==1 and not broker.busy

@pytest.mark.asyncio
async def test_provider_approval_revocation_after_429_prevents_secondary(pair,monkeypatch):
    async def transport(*args,**kw):
        monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS','gemini');return response('gemini',429)
    mock=AsyncMock(side_effect=transport)
    with pytest.raises(PermissionError):await LLMBroker(mock).review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True)
    assert mock.await_count==1

@pytest.mark.asyncio
async def test_task_cancellation_and_busy_latch(pair):
    entered=asyncio.Event()
    async def transport(*args,**kw):entered.set();await asyncio.Event().wait()
    broker=LLMBroker(AsyncMock(side_effect=transport));task=asyncio.create_task(broker.review('gemini',pair,lambda:None,secondary='grok',fallback_confirmed=True))
    await entered.wait()
    with pytest.raises(ValueError):await broker.review('gemini',pair,lambda:None)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    assert broker.transport.await_count==1 and not broker.busy

@pytest.mark.asyncio
async def test_assessment_persists_pair_and_actual_fallback_without_credentials(setup,pair):
    svc,apk,_,_,token=setup
    svc.broker.transport=AsyncMock(side_effect=[response('gemini',429),response('grok')])
    request=plan(apk,llm_provider='gemini',llm_metadata_egress_confirmed=True,llm_secondary_provider='grok',llm_fallback_egress_confirmed=True)
    doc=await finish(svc,request,token)
    assert doc['stages']['llm']['status']=='completed' and doc['stages']['llm']['review']['fallback_used']
    assert doc['ai_selection']['secondary_provider']=='grok' and doc['ai_selection']['maximum_provider_attempts']==2
    assert 'synthetic-secret' not in json.dumps(doc)

@pytest.mark.asyncio
@pytest.mark.parametrize('primary,secondary,consent,error',[(None,'grok',True,ValueError),('gemini','grok',False,PermissionError),('gemini','gemini',True,ValueError)])
async def test_assessment_rejects_invalid_pair_before_policy_static_and_network(setup,pair,primary,secondary,consent,error):
    svc,apk,_,_,token=setup
    before=svc.repository().get_policy()
    with pytest.raises(error):await svc.create(plan(apk,llm_provider=primary,llm_metadata_egress_confirmed=True,llm_secondary_provider=secondary,llm_fallback_egress_confirmed=consent),token)
    assert svc.repository().get_policy()==before and not svc.store().list()
    svc.static_runner.assert_not_called();svc.broker.transport.assert_not_called()

@pytest.mark.asyncio
async def test_assessment_secondary_rate_limit_records_error_not_clean_advice(setup,pair):
    svc,apk,_,_,token=setup;svc.broker.transport=AsyncMock(side_effect=[response('gemini',429),response('grok',429)])
    doc=await finish(svc,plan(apk,llm_provider='gemini',llm_metadata_egress_confirmed=True,llm_secondary_provider='grok',llm_fallback_egress_confirmed=True),token)
    assert doc['stages']['llm']['status']=='error' and len(doc['stages']['llm']['attempts'])==2
    assert 'review' not in doc['stages']['llm'] and 'private upstream' not in json.dumps(doc)

@pytest.mark.asyncio
async def test_real_loopback_http_429_switches_only_to_approved_local_origin(monkeypatch):
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import threading
    observed=[]
    def handler(provider,status):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                observed.append((provider,self.path,body))
                data=json.dumps(response('grok',status)['body']).encode() if status!=200 else response('grok')['body'].encode()
                self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
            def log_message(self,*args):pass
        return Handler
    servers=[ThreadingHTTPServer(('127.0.0.1',0),handler('ollama',429)),ThreadingHTTPServer(('127.0.0.1',0),handler('local_openai',200))]
    threads=[threading.Thread(target=server.serve_forever,daemon=True) for server in servers]
    for thread in threads:thread.start()
    origins=[f'http://127.0.0.1:{server.server_port}' for server in servers]
    monkeypatch.setenv('MOBILEAG_LLM_ALLOWED_PROVIDERS','ollama,local_openai')
    monkeypatch.setenv('MOBILEAG_LLM_LOCAL_ORIGINS',','.join(origins))
    for provider,origin in zip(['ollama','local_openai'],origins):
        monkeypatch.setenv('MOBILEAG_LLM_'+provider.upper()+'_ORIGIN',origin)
        monkeypatch.setenv('MOBILEAG_LLM_'+provider.upper()+'_MODEL','synthetic-local-model')
    try:
        result=await LLMBroker().review('ollama',aggregate({'status':'completed','findings':[]}),lambda:None,secondary='local_openai',fallback_confirmed=True)
        assert result['provider']=='local_openai' and result['fallback_used']
        assert [item[:2] for item in observed]==[('ollama','/api/chat'),('local_openai','/v1/chat/completions')]
        assert [a['http_status'] for a in result['attempts']]==[429,200]
    finally:
        for server in servers:server.shutdown();server.server_close()
        for thread in threads:thread.join(timeout=2)
