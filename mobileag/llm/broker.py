"""Separate, opt-in metadata-only LLM broker. No tools, code or APK egress.

Provider origins/models are configured by the server owner; target API scope
cannot authorize model egress. Model advice is untrusted and never executed.
"""
import json
import os
import re
import asyncio
from urllib.parse import urlsplit
from mobileag.security.network import scoped_request
from mobileag.security.privacy import redact

# name: (display name, protocol, origin, API prefix, key env)
PROVIDERS={
    'openai':('GPT / OpenAI','openai','https://api.openai.com','/v1','OPENAI_API_KEY'),
    'gemini':('Google Gemini','gemini','https://generativelanguage.googleapis.com','/v1beta','GEMINI_API_KEY'),
    'grok':('xAI Grok','openai','https://api.x.ai','/v1','XAI_API_KEY'),
    'claude':('Anthropic Claude','claude','https://api.anthropic.com','/v1','ANTHROPIC_API_KEY'),
    'deepseek':('DeepSeek','openai','https://api.deepseek.com','/v1','DEEPSEEK_API_KEY'),
    'groq':('Groq','openai','https://api.groq.com','/openai/v1','GROQ_API_KEY'),
    'mistral':('Mistral','openai','https://api.mistral.ai','/v1','MISTRAL_API_KEY'),
    'openrouter':('OpenRouter (may route to additional processors)','openai','https://openrouter.ai','/api/v1','OPENROUTER_API_KEY'),
    'ollama':('Local Ollama','ollama','http://127.0.0.1:11434','',''),
    'local_openai':('Local OpenAI-compatible / LM Studio / vLLM','openai','http://127.0.0.1:1234','/v1','MOBILEAG_LOCAL_LLM_KEY'),
}
SYSTEM='Summarize the supplied aggregate assessment counts and coverage. Never invent vulnerabilities or claim production readiness. Provide concise next validation steps. You cannot execute tools or actions. Counts are unverified static candidates.'

def setup_fields(name):
    """Public variable names only; never expose credentials or their values."""
    local=name in {'ollama','local_openai'}
    return {'approval_variable':'MOBILEAG_LLM_ALLOWED_PROVIDERS',
        'model_variable':'MOBILEAG_LLM_'+name.upper()+'_MODEL',
        'key_variable':PROVIDERS[name][4] or None,
        'origin_variable':'MOBILEAG_LLM_'+name.upper()+'_ORIGIN' if local else None,
        'allowed_origins_variable':'MOBILEAG_LLM_LOCAL_ORIGINS' if local else None,
        'default_origin':PROVIDERS[name][2] if local else None}

def configured(name):
    if name not in PROVIDERS:raise ValueError('Unknown provider')
    title,protocol,origin,prefix,key_env=PROVIDERS[name]
    model=os.getenv('MOBILEAG_LLM_'+name.upper()+'_MODEL','')
    local=name in {'ollama','local_openai'}
    if local:origin=os.getenv('MOBILEAG_LLM_'+name.upper()+'_ORIGIN',origin).rstrip('/')
    parsed=urlsplit(origin)
    if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:raise ValueError('Invalid server model origin')
    if local and parsed.hostname not in {'127.0.0.1','localhost','::1'}:raise ValueError('Local model must use loopback')
    enabled=name in {s.strip() for s in os.getenv('MOBILEAG_LLM_ALLOWED_PROVIDERS','').split(',') if s.strip()}
    locals_={s.strip().rstrip('/') for s in os.getenv('MOBILEAG_LLM_LOCAL_ORIGINS','').split(',') if s.strip()}
    key=os.getenv(key_env,'') if key_env else ''
    if key and (len(key)>4096 or '\n' in key or '\r' in key):raise ValueError('Invalid server provider key')
    valid_model=bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:+-]{0,127}',model)) and '..' not in model and '?' not in model
    missing=[]
    if not enabled:missing.append('Add '+name+' to MOBILEAG_LLM_ALLOWED_PROVIDERS')
    if not valid_model:missing.append('Set a valid exact model ID in MOBILEAG_LLM_'+name.upper()+'_MODEL')
    if local and origin not in locals_:missing.append('Approve the configured loopback origin in MOBILEAG_LLM_LOCAL_ORIGINS')
    if not local and not key:missing.append('Set '+key_env+' privately on the server')
    available=not missing
    return {'id':name,'title':title,'protocol':protocol,'origin':origin,'prefix':prefix,'key':key,'model':model if valid_model else '',
            'local':local,'enabled':available,'reason':'; '.join(missing) if missing else None}

def catalog():
    rows=[]
    for name in PROVIDERS:
        try:
            config=configured(name)
            rows.append({k:config[k] for k in ('id','title','model','local','enabled','reason')})
        except ValueError:rows.append({'id':name,'title':PROVIDERS[name][0],'model':'','local':name in {'ollama','local_openai'},'enabled':False,'reason':'Invalid server configuration'})
        rows[-1]['setup']=setup_fields(name)
    return {'providers':rows,'data_policy':'aggregate counts/status only; no APK, source, URLs, identifiers, findings text, credentials or raw responses',
            'credentials':'server environment only; no dashboard key storage','health':'not contacted; configuration is not availability'}

def aggregate(scan,api=None,dast=None):
    levels=['critical','high','medium','low','info']
    # Construct a fresh allowlisted structure; never forward worker dictionaries.
    counts={level:min(100000,sum(isinstance(f,dict) and str(f.get('severity','')).lower()==level for f in scan.get('findings',[])[:100000])) for level in levels}
    status=scan.get('status') if scan.get('status') in {'completed','partial','error','cancelled'} else 'unknown'
    return {'static_status':status,'static_candidate_counts':counts,'static_confirmed':False,
        'api_cases_executed':min(10,int(api or 0)),'dast_screens_observed':min(60,int(dast or 0)),'production_readiness':'not_assessed'}

def validate_review_selection(primary,secondary=None,fallback_confirmed=False):
    """Validate both destinations before any egress; keys alone grant nothing."""
    if secondary and (not primary or secondary==primary):
        raise ValueError('Select distinct primary and secondary providers')
    if fallback_confirmed and not secondary:
        raise ValueError('Fallback consent requires a secondary provider')
    if secondary and not fallback_confirmed:
        raise PermissionError('Secondary provider needs explicit rate-limit fallback consent')
    for name in filter(None,[primary,secondary]):
        if not configured(name)['enabled']:
            raise PermissionError('Provider not server-approved/configured')

class ProviderResponseError(ValueError):
    def __init__(self,status):
        self.status=status
        super().__init__('Provider returned a non-successful HTTP status')

class LLMReviewError(ValueError):
    """Sanitized terminal evidence; never store provider bodies/headers/errors."""
    def __init__(self,message,attempts):
        self.attempts=attempts
        super().__init__(message)

class _GuardFailure(Exception):
    def __init__(self,cause):self.cause=cause

class LLMBroker:
    def __init__(self,transport=scoped_request):self.transport=transport;self.busy=False
    async def review(self,name,summary,guard,*,secondary=None,fallback_confirmed=False):
        if self.busy:raise ValueError('LLM broker busy')
        if not name:raise ValueError('Primary provider required')
        validate_review_selection(name,secondary,fallback_confirmed)
        # Reject arbitrary strings/objects before either provider is contacted.
        allowed={'static_status','static_candidate_counts','static_confirmed','api_cases_executed','dast_screens_observed','production_readiness'}
        counts=summary.get('static_candidate_counts',{})
        if (set(summary)!=allowed or set(counts)!={'critical','high','medium','low','info'}
            or any(type(v) is not int or not 0<=v<=100000 for v in counts.values())
            or summary['static_status'] not in {'completed','partial','error','cancelled','unknown'}
            or summary['static_confirmed'] is not False or summary['production_readiness']!='not_assessed'
            or type(summary['api_cases_executed']) is not int or not 0<=summary['api_cases_executed']<=10
            or type(summary['dast_screens_observed']) is not int or not 0<=summary['dast_screens_observed']<=60):
            raise ValueError('Invalid aggregate metadata')
        def checked_guard():
            try:guard()
            except Exception as error:raise _GuardFailure(error) from None
        guard();self.busy=True;attempts=[]
        try:
            # At most one primary request and one explicitly approved secondary.
            # Never retry the throttled provider, loop providers or switch on text.
            for index,provider in enumerate(filter(None,[name,secondary])):
                guard()
                config=configured(provider)  # Recheck approvals/credentials at use.
                if not config['enabled']:raise PermissionError('Provider approval/configuration revoked')
                attempt={'provider':provider,'model':config['model']}
                try:
                    result=await self._review_once(config,summary,checked_guard)
                except ProviderResponseError as error:
                    attempt.update(outcome='rate_limited' if error.status==429 else 'http_error',http_status=error.status)
                    attempts.append(attempt)
                    if error.status==429 and index==0 and secondary:
                        guard();continue
                    raise LLMReviewError('Provider rate limited; no further provider attempt' if error.status==429 else 'Provider HTTP error; fallback only applies to HTTP 429',attempts) from None
                except _GuardFailure as error:raise error.cause
                except PermissionError:raise
                except Exception:
                    guard()
                    attempt.update(outcome='failed');attempts.append(attempt)
                    raise LLMReviewError('Provider timed out, failed or returned invalid text; no rate-limit fallback',attempts) from None
                attempt.update(outcome='completed',http_status=200);attempts.append(attempt)
                return {**result,'primary_provider':name,'secondary_provider':secondary,'fallback_used':index==1,'attempts':attempts}
        finally:self.busy=False

    async def _review_once(self,config,summary,guard):
        user=json.dumps(summary);headers={'Content-Type':'application/json'};protocol=config['protocol'];model=config['model']
        messages=[{'role':'system','content':SYSTEM},{'role':'user','content':user}]
        if protocol=='gemini':
            url=config['origin']+config['prefix']+'/models/'+model+':generateContent'
            headers['x-goog-api-key']=config['key']
            body={'systemInstruction':{'parts':[{'text':SYSTEM}]},'contents':[{'role':'user','parts':[{'text':user}]}],'generationConfig':{'maxOutputTokens':1024}}
        elif protocol=='claude':
            url=config['origin']+config['prefix']+'/messages';headers.update({'x-api-key':config['key'],'anthropic-version':'2023-06-01'})
            body={'model':model,'max_tokens':1024,'system':SYSTEM,'messages':[{'role':'user','content':user}]}
        elif protocol=='ollama':
            url=config['origin']+'/api/chat';body={'model':model,'messages':messages,'stream':False,'options':{'num_predict':1024}}
        else:
            url=config['origin']+config['prefix']+'/chat/completions'
            if config['key']:headers['Authorization']='Bearer '+config['key']
            body={'model':model,'messages':messages,'stream':False}
            body['max_completion_tokens' if config['id']=='openai' else 'max_tokens']=1024
            if config['id']=='openai':body['store']=False
        async with asyncio.timeout(25):
            guard()
            response=await self.transport(url,'POST',headers=headers,body=json.dumps(body),timeout=15,raw=True,
                allowed_origins={config['origin']},allow_private=config['local'],loopback_only=config['local'])
            guard()
        if response['status_code']!=200:raise ProviderResponseError(response['status_code'])
        value=json.loads(response['body'])
        if protocol=='gemini':text=value['candidates'][0]['content']['parts'][0]['text']
        elif protocol=='claude':text='\n'.join(block['text'] for block in value['content'] if block.get('type')=='text')
        elif protocol=='ollama':text=value['message']['content']
        else:text=value['choices'][0]['message']['content']
        if not isinstance(text,str) or not text.strip():raise ValueError('Provider returned no text')
        # Remove exact configured key even if it is not a recognizable key format.
        for row in PROVIDERS.values():
            secret=os.getenv(row[4],'') if row[4] else ''
            if secret:text=text.replace(secret,'[REDACTED]')
        return {'provider':config['id'],'model':model,'advice':redact(text[:8192]),'classification':'untrusted AI advice; not a finding or executed test',
                'egress':'aggregate_metadata_only','tools_executed':False}
