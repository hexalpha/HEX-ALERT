"""Admin-only AI settings. Returned settings never contain credentials."""
import json
from datetime import timedelta
import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from config.ai import AIOptions, KEYS, options, PUBLIC_ASSISTANT_NAME, PUBLIC_DEVELOPER_BRAND
from config.settings import get_settings
from config.runtime_config import get_runtime_config, update_runtime_config, RuntimeConfigError
from services.ai_chat import chat_service
from services.ai_providers import AIUnavailable, make_provider
from services.time_utils import utc_now
from services.ai_benchmark import measure_configuration, configure_engine
from config.internet_search import InternetSearchOptions
from services.internet_search import internet_search, InternetSearchError, SearchNotConfigured

benchmark_state={'status':'idle','progress':'','result':None,'error':''}
benchmark_task=None
log=logging.getLogger('hexalert.ai.benchmark')

class SaveAI(BaseModel):
    settings: AIOptions
    api_keys: dict[str,str] = Field(default_factory=dict, max_length=4)
    clear_keys: list[str] = Field(default_factory=list, max_length=4)

class SaveInternetSearch(BaseModel):
    settings: InternetSearchOptions
    api_keys: dict[str,str] = Field(default_factory=dict, max_length=7)
    clear_keys: list[str] = Field(default_factory=list, max_length=7)

class TestInternetSearch(BaseModel):
    query: str = Field(default='cybersecurity news', min_length=1, max_length=300)
    provider: str | None = Field(default=None, max_length=30)

class TestAI(BaseModel):
    provider: str = Field(default='local_gguf', max_length=30)
    question: str = Field(default='What is the difference between IDS and IPS?', min_length=1,max_length=1500)

class DiscordTestAI(BaseModel):
    question: str = Field(default='What is the difference between IDS and IPS?', min_length=1,max_length=1500)

class TuneCandidate(BaseModel):
    context_size: int | None = Field(default=None,ge=2048,le=16384)
    threads: int | None = Field(default=None,ge=0,le=64)
    threads_batch: int | None = Field(default=None,ge=0,le=64)
    batch_size: int | None = Field(default=None,ge=32,le=1024)
    ubatch_size: int | None = Field(default=None,ge=32,le=1024)
    kv_cache_type: str | None = Field(default=None,pattern='^(f16|q8_0|q4_0)$')

def router(require_admin):
    routes=APIRouter(prefix='/api/ai',dependencies=[Depends(require_admin)])

    @routes.get('/settings')
    async def settings():
        cfg=options(); raw=get_runtime_config(); bootstrap=get_settings()
        return {'settings':cfg.model_dump(), 'public_identity':{'name':PUBLIC_ASSISTANT_NAME,'brand':PUBLIC_DEVELOPER_BRAND,'purpose':'Cybersecurity AI Assistant'}, 'keys_configured':{name:bool(raw.get(key,getattr(bootstrap,key.lower(),''))) for name,key in KEYS.items()},
                'model_path':'/models/CyberSecurity.gguf',
                'intent_notice':'/ask needs no privileged intent. Optional direct @mentions use Discord mention content access; Message Content Intent is not enabled.'}

    @routes.post('/settings')
    async def save(payload:SaveAI):
        if benchmark_state['status']=='running': raise HTTPException(409,'Wait for the local performance benchmark to finish before changing AI settings.')
        cfg=payload.settings
        if any(name not in KEYS for name in (*payload.api_keys,*payload.clear_keys)) or any(len(value)>1000 for value in payload.api_keys.values()):
            raise HTTPException(422,'Invalid provider credential settings')
        if cfg.provider!='disabled' and not cfg.providers[cfg.provider].enabled:
            raise HTTPException(422,'Enable the selected default provider first')
        if cfg.fallback_enabled and not cfg.providers[cfg.fallback_provider].enabled:
            raise HTTPException(422,'Enable the fallback provider before allowing external fallback')
        values={'AI_OPTIONS':cfg.model_dump(),'AI_PROVIDER':cfg.provider,
                'AI_MODEL':cfg.providers[cfg.provider].model if cfg.provider!='disabled' else ''}
        values.update({KEYS[name]:value for name,value in payload.api_keys.items() if value})
        values.update({KEYS[name]:'' for name in payload.clear_keys})
        try: update_runtime_config(values); get_settings.cache_clear()
        except RuntimeConfigError: raise HTTPException(503,'Unable to save AI configuration.') from None
        chat_service.memory.clear()  # Never forward old provider conversations after a switch.
        chat_service.response_cache.clear()
        applied=True
        try: await chat_service.configure_engine(cfg)
        except Exception: applied=False
        return {'saved':True,'engine_applied':applied,'message':'Settings saved.' if applied else 'Settings saved; local engine is offline. Retry Apply after it starts.'}

    @routes.get('/internet-search/settings')
    async def internet_settings():
        from config.internet_search import get_search_options
        from config.runtime_config import get_runtime_config
        from database.db import SessionLocal
        from database.models import SystemLog
        from datetime import datetime, timezone
        opts=get_search_options(); raw=get_runtime_config(); configured=internet_search.configured_providers()
        key_names={'google':'GOOGLE_SEARCH_API_KEY','google_engine_id':'GOOGLE_SEARCH_ENGINE_ID','tavily':'TAVILY_API_KEY',
                   'serper':'SERPER_API_KEY','brave':'BRAVE_SEARCH_API_KEY','bing_compatible':'BING_SEARCH_API_KEY','custom':'CUSTOM_SEARCH_API_KEY'}
        stats={'queries_today':0,'successful':0,'failed':0,'cache_hits':0,'google_requests_today':0}
        midnight=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
        try:
            async with SessionLocal() as session:
                logs=(await session.scalars(select(SystemLog).where(SystemLog.component=='INTERNET_SEARCH',SystemLog.created_at>=midnight).order_by(SystemLog.created_at.desc()).limit(2000))).all()
            for row in logs:
                try: item=json.loads(row.message)
                except (TypeError,ValueError): continue
                stats['queries_today']+=1; stats['successful']+=item.get('status')=='success'; stats['failed']+=item.get('status')!='success'
                stats['cache_hits']+=bool(item.get('cache_hit')); stats['google_requests_today']+=item.get('provider')=='google'
        except Exception: pass
        return {'settings':opts.model_dump(),'providers':{name:{'configured':ok} for name,ok in configured.items()},
                'keys_configured':{name:bool(raw.get(key)) for name,key in key_names.items()},
                'health':internet_search.status(),'metrics':stats,
                'provider_notes':{'google':'Custom Search JSON API access is closed to new customers; existing customers have until January 1, 2027.','bing_compatible':'Microsoft Bing Search APIs were retired; configure only a third-party compatible endpoint.'}}

    @routes.post('/internet-search/settings')
    async def save_internet_settings(payload:SaveInternetSearch):
        allowed={'GOOGLE_SEARCH_API_KEY','GOOGLE_SEARCH_ENGINE_ID','TAVILY_API_KEY','SERPER_API_KEY','BRAVE_SEARCH_API_KEY','BING_SEARCH_API_KEY','CUSTOM_SEARCH_API_KEY'}
        if any(name not in allowed for name in (*payload.api_keys,*payload.clear_keys)) or any(len(value)>1000 for value in payload.api_keys.values()):
            raise HTTPException(422,'Invalid internet search credentials')
        values={'INTERNET_SEARCH_SETTINGS':payload.settings.model_dump()}
        values.update({name:value for name,value in payload.api_keys.items() if value})
        values.update({name:'' for name in payload.clear_keys})
        try: update_runtime_config(values)
        except RuntimeConfigError: raise HTTPException(503,'Unable to save internet search configuration.') from None
        internet_search.cache.clear()
        return {'saved':True,'message':'Internet search settings saved. Credentials are encrypted and are never returned.'}

    @routes.post('/internet-search/test')
    async def test_internet_search(payload:TestInternetSearch):
        try:
            result=await internet_search.search(payload.query,requester_id='admin-dashboard',
                provider_override=payload.provider,allow_fallback=True,bypass_rate_limit=True)
            return {'status':'ready','provider':result['provider'],'latency_ms':result['latency_ms'],
                    'results_found':len(result['results']),'domains':sorted({row['domain'] for row in result['results']})[:5],
                    'cache_hit':result['cache_hit']}
        except (InternetSearchError,SearchNotConfigured) as exc:
            return {'status':'failed','provider':payload.provider or internet_search.status().get('provider'),
                    'latency_ms':None,'results_found':0,'domains':[],'error':str(exc)[:240]}

    @routes.get('/status')
    async def status():
        state=await chat_service.health()
        from database.db import SessionLocal
        from database.models import SystemLog
        metrics=[]
        try:
            async with SessionLocal() as session:
                rows=(await session.scalars(select(SystemLog).where(SystemLog.component=='AI_CHAT',SystemLog.created_at>=utc_now().replace(hour=0,minute=0,second=0,microsecond=0)).order_by(SystemLog.created_at.desc()).limit(500))).all()
            for row in rows:
                try:
                    item=json.loads(row.message)
                    if 'success' in item: metrics.append(item)
                except (ValueError,TypeError): pass
        except Exception: pass
        latest=metrics[0] if metrics else {}
        last={key:latest.get(key) for key in ('provider','model','latency_seconds','first_token_seconds','first_visible_seconds','model_first_visible_seconds',
             'queue_wait_seconds','rag_ms','db_query_ms','prompt_eval_seconds','rag_tokens_estimate','request_max_tokens',
             'input_tokens','output_tokens','prompt_cache_tokens','prompt_eval_tokens_per_second','generation_tokens_per_second','cache_hit') if key in latest}
        return {**state,'internet_search':internet_search.status(),'metrics':{'requests_today_utc':len(metrics),'successful':sum(bool(x.get('success')) for x in metrics),
                'failed':sum(not x.get('success') for x in metrics),'tokens_generated':sum(x.get('output_tokens',0) for x in metrics),
                'average_latency':round(sum(x.get('latency_seconds',0) for x in metrics)/max(1,len(metrics)),3),
                'last_request':last}}

    async def run_autotune(candidate_overrides):
        benchmark_state.update(status='running',progress='Preparing isolated local-only benchmark',result=None,error='')
        chat_service.maintenance=True
        original_options=options()
        original=original_options.engine_config()
        from services.ai_providers import make_provider
        try:
            health=await make_provider('local_gguf',original_options,chat_service.http()).health()
            if health.get('status')!='ready': raise RuntimeError('Local GGUF must be ready before tuning.')
            for key in ('context_size','batch_size','ubatch_size'):
                if health.get(key) is not None: original[key]=health[key]
            original['threads']=health.get('threads',original.get('threads',0))
            original['threads_batch']=health.get('threads_batch',original.get('threads_batch',0))
            original['kv_cache_type']=health.get('kv_cache_type',original.get('kv_cache_type','f16'))
            candidate=dict(original)
            candidate.update({key:value for key,value in candidate_overrides.items() if value is not None})
            # Button default is a bounded one-step comparison, never an unmeasured permanent change.
            if not candidate_overrides.get('threads'):
                choices=[4,5,6,8,10,12]
                candidate['threads']=next((n for n in choices if n>int(original['threads'])),choices[0])
            if not candidate_overrides.get('threads_batch'):
                candidate['threads_batch']=candidate['threads']
            benchmark_state['progress']='Measuring the current stable configuration (warmup + 3 samples per case)'
            baseline=await measure_configuration(original,repetitions=3)
            benchmark_state['progress']='Temporarily testing candidate; requests will resume after automatic rollback'
            await configure_engine(candidate,persist=False)
            candidate_result=await measure_configuration(candidate,repetitions=3)
            baseline_values=[v.get('first_token_seconds') for v in baseline['cases'].values() if v.get('first_token_seconds') is not None]
            candidate_values=[v.get('first_token_seconds') for v in candidate_result['cases'].values() if v.get('first_token_seconds') is not None]
            base_score=sum(baseline_values)/max(1,len(baseline_values)); candidate_score=sum(candidate_values)/max(1,len(candidate_values))
            result={'baseline':baseline,'candidate':candidate_result,'candidate_config':candidate,
                    'baseline_mean_first_token_seconds':round(base_score,4),
                    'candidate_mean_first_token_seconds':round(candidate_score,4),
                    'recommended':bool(candidate_score<base_score*.97),
                    'note':'Temporary single-candidate comparison; settings were not saved. Full thread/batch sweeps are available in the repeatable benchmark harness.'}
            benchmark_state.update(status='restoring',progress='Restoring current known-good settings',result=result,error='')
        except Exception as exc:
            benchmark_state.update(status='failed',progress='',error=f'Benchmark failed ({type(exc).__name__}). Known-good settings were restored.')
            log.warning('Local AI benchmark failed (%s)',type(exc).__name__)
        finally:
            restore_ok=True
            try:
                # Reapply and persist the original effective runtime to guarantee rollback.
                await configure_engine(original,persist=True)
            except Exception as exc:
                restore_ok=False
                benchmark_state.update(status='failed',error='Benchmark rollback failed; local AI may need administrator attention.')
                log.error('Local AI benchmark rollback failed (%s)',type(exc).__name__)
            chat_service.maintenance=False
            if restore_ok and benchmark_state['status']=='restoring':
                benchmark_state.update(status='complete',progress='')

    @routes.post('/auto-tune')
    async def auto_tune(payload:TuneCandidate):
        global benchmark_task
        if options().provider!='local_gguf': raise HTTPException(409,'Select Local GGUF as the default provider before tuning.')
        if benchmark_state['status']=='running' or (benchmark_task and not benchmark_task.done()):
            raise HTTPException(409,'A local model benchmark is already running.')
        if chat_service.active or chat_service.waiting: raise HTTPException(409,'Wait until current AI requests finish before benchmarking.')
        chat_service.maintenance=True
        benchmark_task=asyncio.create_task(run_autotune(payload.model_dump()),name='hex-alert-local-ai-autotune')
        return {'status':'started','message':'A temporary local-only benchmark started. Current settings will be restored automatically.'}

    @routes.get('/auto-tune')
    async def auto_tune_status():
        state=dict(benchmark_state)
        if state.get('result') and 'candidate_config' in state['result']:
            state['result']={k:v for k,v in state['result'].items() if k!='candidate_config'}
        return state

    @routes.post('/auto-tune/apply')
    async def apply_tune():
        if benchmark_state['status']!='complete' or chat_service.maintenance or not benchmark_state.get('result'):
            raise HTTPException(409,'Complete a benchmark before applying a candidate.')
        result=benchmark_state['result']
        if not result.get('recommended'): raise HTTPException(409,'The candidate did not beat the current stable configuration by at least 3%.')
        cfg=options(); selected=cfg.model_copy(update={k:v for k,v in result['candidate_config'].items() if k in cfg.engine_config()})
        try:
            update_runtime_config({'AI_OPTIONS':selected.model_dump(),'AI_PROVIDER':selected.provider,
                'AI_MODEL':selected.providers[selected.provider].model})
            await chat_service.configure_engine(selected)
        except Exception: raise HTTPException(503,'Unable to apply the measured local model configuration.') from None
        chat_service.response_cache.clear()
        benchmark_state.update(status='applied',progress='',error='')
        return {'applied':True,'config':selected.engine_config()}

    @routes.post('/probe')
    async def probe(payload:TestAI):
        try:
            return await chat_service.ask(('admin-probe',payload.provider),payload.question,remember=False,provider_override=payload.provider,priority=1)
        except AIUnavailable as exc: raise HTTPException(503,str(exc)) from None

    @routes.post('/apply')
    async def apply():
        try: await chat_service.configure_engine(options())
        except Exception: raise HTTPException(503,'Local engine is unavailable.') from None
        return {'applied':True}

    @routes.post('/discord-test')
    async def discord_test(payload:DiscordTestAI=DiscordTestAI()):
        import discord
        from api.app import runtime
        from services.discord_routing import resolve_discord_channel, RoutingError
        from services.ai_chat import split_response, audit_metric, record_delivery
        if not get_settings().test_mode: raise HTTPException(409,'Enable TEST_MODE for this test')
        try: route=await resolve_discord_channel('test_alerts',bot=runtime.get('bot'))
        except RoutingError as exc: raise HTTPException(422,str(exc)) from None
        try:
            result=await chat_service.ask(('admin-discord-test',), payload.question.strip(),remember=False,provider_override='local_gguf',priority=1)
            ids=[]
            for part in split_response('🧠 HEX ALPHA — TEST MODE\n\n'+result['answer']):
                sent=await route.channel.send(part,allowed_mentions=discord.AllowedMentions.none())
                await route.channel.fetch_message(sent.id)
                ids.append(str(sent.id))
            await record_delivery(route.guild_id, route.channel_id, route.channel_name, ids,
                                  provider=result['provider'],model=result['model'],latency_seconds=result['latency_seconds'])
            await audit_metric({'event':'discord_delivery','provider':'local_gguf','message_ids':ids,'channel_id':route.channel_id,'guild_id':route.guild_id,'status':'SENT','test':True})
            return {'status':'SENT','message_ids':ids,'channel':route.channel_name,'provider':'local_gguf'}
        except AIUnavailable as exc: raise HTTPException(503,str(exc)) from None
        except discord.HTTPException:
            await record_delivery(getattr(route, 'guild_id', ''), getattr(route, 'channel_id', ''),
                                  getattr(route, 'channel_name', ''), [], 'failed', 'Discord test delivery failed',
                                  provider='local_gguf',model='CyberSecurity.gguf')
            await audit_metric({'event':'discord_delivery','status':'FAILED','test':True})
            raise HTTPException(502,'Discord test delivery failed.') from None

    return routes
