import asyncio
import json
import struct
from types import SimpleNamespace
from unittest.mock import AsyncMock
import httpx
import pytest
from fastapi.testclient import TestClient
from config.ai import AIOptions
from config.runtime_config import RuntimeConfigStore
from config.settings import get_settings
from services import ai_chat
from services.ai_providers import AIUnavailable, make_provider
from services.gguf_metadata import inspect_gguf

@pytest.fixture
def ai_env(monkeypatch,tmp_path):
    monkeypatch.setenv('HEX_ALERT_CONFIG_DIR',str(tmp_path))
    monkeypatch.setenv('SESSION_SECRET','hex-alert-ai-unit-test-master-secret-0123456789')
    get_settings.cache_clear()
    cfg=AIOptions(cooldown_seconds=0,use_data_context=False)
    monkeypatch.setattr(ai_chat,'options',lambda:cfg)
    monkeypatch.setattr(ai_chat,'audit_metric',AsyncMock())
    from services.smart_social import smart_social
    monkeypatch.setattr(smart_social,'mention_reaction',AsyncMock(return_value=False))
    yield cfg
    get_settings.cache_clear()

def test_gguf_metadata_and_missing_path(tmp_path):
    def string(s): return struct.pack('<Q',len(s))+s.encode()
    p=tmp_path/'tiny.gguf'
    p.write_bytes(b'GGUF'+struct.pack('<IQQ',3,0,2)+string('general.architecture')+struct.pack('<I',8)+string('qwen3')+string('general.file_type')+struct.pack('<II',4,15))
    assert inspect_gguf(str(p))['architecture']=='qwen3'
    assert inspect_gguf(str(p))['quantization_type']==15
    p.write_bytes(b'NOT GGUF')
    with pytest.raises(ValueError): inspect_gguf(str(p))
    with pytest.raises(FileNotFoundError): inspect_gguf(str(tmp_path/'missing.gguf'))

@pytest.mark.parametrize('name',['local_gguf','openai','gemini','groq','ollama','custom'])
def test_provider_selection(name,ai_env):
    provider=make_provider(name,ai_env,None)
    assert provider.name==name
    assert provider.model_info()['provider']==name

@pytest.mark.asyncio
async def test_local_health_and_stream(ai_env):
    def respond(request):
        assert request.url.host=='llm'
        if request.url.path=='/health': return httpx.Response(200,json={'status':'ready'})
        assert json.loads(request.content)['stream'] is True
        return httpx.Response(200,text='data: {"choices":[{"delta":{"content":"IDS detects."}}]}\n\ndata: {"choices":[],"usage":{"completion_tokens":3}}\n\ndata: [DONE]\n\n')
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        provider=make_provider('local_gguf',ai_env,client)
        assert (await provider.health())['status']=='ready'
        assert await provider.chat([{'role':'user','content':'IDS?'}],ai_env)=='IDS detects.'
        assert provider.usage['completion_tokens']==3

def test_disabled_external_is_not_contacted(ai_env):
    with pytest.raises(AIUnavailable): make_provider('groq',ai_env,None).connection()

class FakeProvider:
    name='local_gguf'
    config=SimpleNamespace(model='CyberSecurity.gguf')
    usage={'prompt_tokens':4,'completion_tokens':5}
    def model_info(self): return {'provider':self.name,'model':self.config.model}
    async def stream_chat(self,messages,settings): yield 'Safe answer.'

@pytest.mark.asyncio
async def test_memory_reset_and_redacted_metrics(ai_env,monkeypatch,caplog):
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:FakeProvider())
    service=ai_chat.ChatService()
    result=await service.ask((1,2,3),'private input not logged')
    assert result['answer']=='Safe answer.\n'+chr(0x2728)
    assert len(service.memory[(1,2,3)][0])==2
    assert 'private input not logged' not in caplog.text
    assert 'private input not logged' not in str(ai_chat.audit_metric.call_args)
    service.reset((1,2,3)); assert (1,2,3) not in service.memory
    await service.close()

@pytest.mark.asyncio
async def test_no_implicit_fallback(ai_env,monkeypatch):
    calls=[]
    class Broken(FakeProvider):
        async def stream_chat(self,*args):
            raise AIUnavailable('offline')
            yield ''
    def provider(name,*args): calls.append(name); return Broken()
    monkeypatch.setattr(ai_chat,'make_provider',provider)
    service=ai_chat.ChatService()
    with pytest.raises(AIUnavailable): await service.ask('user','question')
    assert calls==['local_gguf']
    assert service.active==0 and not service.inflight
    await service.close()

@pytest.mark.asyncio
async def test_explicit_fallback(ai_env,monkeypatch):
    ai_env.fallback_enabled=True; ai_env.providers['ollama'].enabled=True
    calls=[]
    class Broken(FakeProvider):
        async def stream_chat(self,*args):
            raise AIUnavailable('offline')
            yield ''
    def provider(name,*args): calls.append(name); return Broken() if name=='local_gguf' else FakeProvider()
    monkeypatch.setattr(ai_chat,'make_provider',provider)
    service=ai_chat.ChatService(); await service.ask('user','question')
    assert calls==['local_gguf','ollama']; await service.close()

@pytest.mark.asyncio
async def test_question_echo_retries_once_before_returning_answer(ai_env,monkeypatch):
    prompts=[]
    class EchoThenAnswer(FakeProvider):
        async def stream_chat(self,messages,settings):
            prompts.append(messages[-1]['content'])
            if len(prompts)==1: yield 'What is a very specific question about network security?'
            else: yield 'IDS monitors network activity for suspicious patterns.'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:EchoThenAnswer())
    service=ai_chat.ChatService()
    result=await service.ask('echo-user','What is a very specific question about network security?',remember=False)
    assert len(prompts)==2
    assert 'Do not repeat or paraphrase' in prompts[1]
    assert 'IDS monitors' in result['answer']
    assert 'What is a very specific question' not in result['answer']
    await service.close()

@pytest.mark.asyncio
async def test_queue_and_timeout_release(ai_env,monkeypatch):
    ai_env.timeout_seconds=.5; ai_env.max_queue=1
    class Slow(FakeProvider):
        async def stream_chat(self,*args):
            await asyncio.sleep(1); yield 'answer'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:Slow())
    service=ai_chat.ChatService(); queued=AsyncMock()
    first=asyncio.create_task(service.ask('one','question'))
    await asyncio.sleep(.01)
    second=asyncio.create_task(service.ask('two','question',on_queued=queued))
    await asyncio.sleep(.01)
    with pytest.raises(AIUnavailable,match='busy'): await service.ask('three','question')
    results=await asyncio.gather(first,second,return_exceptions=True)
    assert all(isinstance(x,AIUnavailable) for x in results)
    assert queued.await_count==1
    assert service.active==0 and service.waiting==0 and not service.inflight
    await service.close()

@pytest.mark.asyncio
async def test_rag_injected_read_only(ai_env,monkeypatch):
    ai_env.use_data_context=True
    context='Read-only HEX ALERT records:\n'+json.dumps([{'title':'CVE-2026-12345','published':'2026-10-01','url':'https://vendor.example/advisory','details':'A stored vulnerability.'}])
    async def fake_context(question,diagnostics=None,**kwargs):
        diagnostics.update(intent='cves')
        return context
    monkeypatch.setattr(ai_chat,'data_context',fake_context)
    seen=[]
    class Recording(FakeProvider):
        async def stream_chat(self,messages,settings): seen.extend(messages); yield 'answer'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:Recording())
    service=ai_chat.ChatService(); result=await service.ask('user','latest CVEs')
    assert result['data_context_used']
    assert any('CVE-2026-12345' in x['content'] for x in seen)
    assert all('https://vendor.example/advisory' not in x['content'] for x in seen)
    assert all(set(x)=={'role','content'} for x in seen)
    assert 'HEX ALERT references:' in result['answer'] and '<https://vendor.example/advisory>' in result['answer']
    await service.close()

@pytest.mark.asyncio
async def test_hybrid_rag_delivers_verified_records_before_model_generation(ai_env,monkeypatch):
    ai_env.use_data_context=True
    context='HEX ALERT current data (facts only):\n'+json.dumps([{'title':'CVE-2026-12345','published':'2026-10-01','url':'https://vendor.example/a','details':'HIGH · CVSS 8.1 · Example vulnerability.'}])
    async def fake_context(question,diagnostics=None,**kwargs):
        diagnostics.update(intent='cves')
        return context
    monkeypatch.setattr(ai_chat,'data_context',fake_context)
    events=[]
    class Recording(FakeProvider):
        async def stream_chat(self,messages,settings):
            assert events and 'CVE-2026-12345' in events[0]
            yield 'HEX ALPHA analysis.'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:Recording())
    async def on_data(value): events.append(value)
    service=ai_chat.ChatService(); result=await service.ask('user','What are the latest critical CVEs?',remember=False,on_data=on_data)
    assert 'verified critical CVEs' in events[0]
    assert result['answer'].startswith('HEX ALPHA analysis.') and result['answer'].endswith(chr(0x2728))
    assert result['first_visible_seconds'] is not None
    await service.close()

@pytest.mark.asyncio
async def test_dynamic_rag_top_k_limits_specific_and_comparison_queries(ai_env,monkeypatch):
    import database.db as db
    captured=[]
    class Result:
        def all(self): return []
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return False
        async def execute(self,query): captured.append(query._limit_clause.value); return Result()
    monkeypatch.setattr(db,'SessionLocal',Session)
    await ai_chat.data_context('What is CVE-2026-12345?')
    await ai_chat.data_context('Compare the latest critical CVEs')
    assert captured==[1,2]

def test_long_responses_split():
    chunks=ai_chat.split_response('An explanation. '*600)
    assert len(chunks)>1 and all(len(x)<=1900 for x in chunks)

def test_fast_ai_defaults_and_deterministic_data_intents():
    cfg=AIOptions()
    assert (cfg.context_size,cfg.max_tokens,cfg.temperature,cfg.concurrency)==(4096,256,.25,1)
    assert (cfg.memory_messages,cfg.rag_top_k,cfg.rag_context_max_tokens)==(6,3,1200)
    assert cfg.reasoning_mode=='fast' and cfg.engine_config()['ubatch_size']==512
    assert ai_chat.classify_data_intent('What is IDS versus IPS?') is None
    assert ai_chat.classify_data_intent('What are the latest critical CVEs in HEX ALERT?')=='cves'
    assert ai_chat.classify_data_intent('latest cybersecurity jobs')=='jobs'
    assert ai_chat.classify_data_intent('CVE-2026-12345')=='cves'

@pytest.mark.asyncio
async def test_concise_fast_path_uses_bounded_per_request_output(ai_env,monkeypatch):
    observed=[]
    class Capture(FakeProvider):
        async def stream_chat(self,messages,settings): observed.append(settings.max_tokens); yield 'Short answer.'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:Capture())
    service=ai_chat.ChatService()
    await service.ask('simple','What is IDS versus IPS?',remember=False)
    await service.ask('detail','Explain IDS versus IPS in detail.',remember=False)
    ai_env.use_data_context=True
    monkeypatch.setattr(ai_chat,'data_context',AsyncMock(return_value='Read-only HEX ALERT records:\n[]'))
    await service.ask('rag','What are the latest critical CVEs?',remember=False)
    assert observed==[160,256,128]
    await service.close()

@pytest.mark.asyncio
async def test_stream_progress_is_coalesced_and_cache_is_conversation_scoped(ai_env,monkeypatch):
    ai_env.use_data_context=False
    calls=[]
    class Streaming(FakeProvider):
        async def stream_chat(self,messages,settings):
            calls.append(1)
            await asyncio.sleep(1.05)
            yield 'A concise answer with enough useful text for a streamed Discord update.'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:Streaming())
    service=ai_chat.ChatService(); updates=[]
    async def progress(text): updates.append(text)
    first=await service.ask(('guild','channel','user'),'question',remember=False,on_progress=progress)
    second=await service.ask(('guild','channel','user'),'question',remember=False)
    assert updates and first['first_token_seconds']>=1
    assert first['first_visible_seconds']<=first['latency_seconds']
    assert second['cache_hit'] is True and second['answer']==first['answer']
    assert len(calls)==1
    await service.close()

@pytest.mark.asyncio
async def test_background_summaries_yield_queue_to_interactive_chat(ai_env,monkeypatch):
    ai_env.use_data_context=False
    entered=asyncio.Event(); release=asyncio.Event(); order=[]
    class PriorityProvider(FakeProvider):
        async def stream_chat(self,messages,settings):
            name=messages[-1]['content']; order.append(name)
            if name=='active':
                entered.set(); await release.wait()
            yield 'Done.'
    monkeypatch.setattr(ai_chat,'make_provider',lambda *args:PriorityProvider())
    service=ai_chat.ChatService()
    active=asyncio.create_task(service.ask('active-key','active'))
    await entered.wait()
    background=asyncio.create_task(service.ask('background-key','background',priority=3))
    await asyncio.sleep(.02)
    interactive=asyncio.create_task(service.ask('chat-key','interactive',priority=0))
    await asyncio.sleep(.02); release.set()
    await asyncio.gather(active,interactive,background)
    assert order==['active','interactive','background']
    await service.close()

@pytest.mark.asyncio
async def test_rag_compacts_projection_and_limits_cve_rows(ai_env,monkeypatch):
    from contextlib import asynccontextmanager
    from types import ModuleType,SimpleNamespace
    from datetime import datetime,timezone
    import sys
    captured={}
    class Result:
        def all(self):
            return [SimpleNamespace(_mapping={'cve_id':'CVE-2026-12345','severity':'CRITICAL','cvss':9.8,
                'description':'A confirmed vulnerability. '+'detail '*100,'published_at':datetime.now(timezone.utc),
                'source_url':'https://nvd.nist.gov/vuln/detail/CVE-2026-12345'})]
    class Session:
        async def execute(self,query):
            captured['query']=query
            return Result()
    @asynccontextmanager
    async def session_factory(): yield Session()
    db=ModuleType('database.db'); db.SessionLocal=session_factory
    monkeypatch.setitem(sys.modules,'database.db',db)
    ai_chat._rag_cache.clear()
    diagnostics={}
    context=await ai_chat.data_context('latest critical CVEs',diagnostics)
    assert 'CVE-2026-12345' in context and len(context)<1000
    assert 'cves.references' not in str(captured['query']).lower()
    assert captured['query']._limit_clause.value==3
    assert diagnostics['db_query_ms']>=0

@pytest.mark.asyncio
async def test_delivery_record_contains_safe_metadata_only(monkeypatch):
    import sys
    from contextlib import asynccontextmanager
    from types import ModuleType
    captured=[]
    class FakeSession:
        def add(self,row): captured.append(row)
        async def flush(self):
            for row in captured:
                if hasattr(row,'category'): row.id=42
        async def commit(self): pass
    @asynccontextmanager
    async def session_factory(): yield FakeSession()
    db=ModuleType('database.db');db.SessionLocal=session_factory
    monkeypatch.setitem(sys.modules,'database.db',db)
    await ai_chat.record_delivery('100','200','test',['300'],provider='local_gguf',model='CyberSecurity.gguf',latency_seconds=2.5,interaction_id='400')
    delivery=next(row for row in captured if getattr(row,'component','')=='AI_DELIVERY')
    metadata=json.loads(delivery.message)
    assert metadata=={'guild_id':'100','channel_id':'200','channel_name':'test','message_ids':['300'],
                      'interaction_id':'400','requesting_user_id':'','reply_to_message_id':'','delivery_type':'slash',
                      'provider':'local_gguf','model':'CyberSecurity.gguf','latency_seconds':2.5,
                      'status':'sent','failure_reason':''}
    assert all('prompt' not in row.message.lower() and 'answer' not in row.message.lower()
               for row in captured if hasattr(row,'message'))

def test_ai_admin_endpoints_require_authentication(ai_env):
    from api.app import app
    client=TestClient(app)
    assert client.get('/api/ai/settings').status_code==401
    assert client.post('/api/ai/discord-test').status_code==401

def test_ai_discord_test_requires_test_mode(ai_env,monkeypatch):
    from api.app import app,require_admin
    import api.ai_routes as routes
    monkeypatch.setattr(routes,'get_settings',lambda:SimpleNamespace(test_mode=False))
    app.dependency_overrides[require_admin]=lambda:True
    try:
        assert TestClient(app).post('/api/ai/discord-test').status_code==409
    finally: app.dependency_overrides.pop(require_admin,None)

def test_discord_ai_test_uses_visible_question_and_forces_local_provider(ai_env,monkeypatch):
    from api.app import app,require_admin
    import api.ai_routes as routes
    import services.ai_chat as chat
    import services.discord_routing as routing
    sent=[]; calls=[]
    class Channel:
        async def send(self,content,**kwargs):
            sent.append(content); return SimpleNamespace(id='message-123')
        async def fetch_message(self,message_id): return SimpleNamespace(id=message_id)
    route=SimpleNamespace(channel=Channel(),channel_id='channel-123',guild_id='guild-123',channel_name='hex-alert-test')
    async def ask(key,question,**kwargs):
        calls.append((key,question,kwargs)); return {'answer':'Grounded test response','provider':'local_gguf','model':'CyberSecurity.gguf','latency_seconds':1.25}
    async def record(*args,**kwargs): return None
    async def metric(*args,**kwargs): return None
    monkeypatch.setattr(routes,'get_settings',lambda:SimpleNamespace(test_mode=True))
    monkeypatch.setattr(chat.chat_service,'ask',ask)
    async def resolve(*args,**kwargs): return route
    monkeypatch.setattr(routing,'resolve_discord_channel',resolve)
    monkeypatch.setattr(chat,'record_delivery',record)
    monkeypatch.setattr(chat,'audit_metric',metric)
    app.dependency_overrides[require_admin]=lambda:True
    try:
        response=TestClient(app).post('/api/ai/discord-test',json={'question':'  What are the latest critical CVEs?  ','provider':'openai'})
        assert response.status_code==200
        assert calls==[(('admin-discord-test',),'What are the latest critical CVEs?',{'remember':False,'provider_override':'local_gguf','priority':1})]
        assert response.json()['message_ids']==['message-123']
        assert 'Grounded test response' in sent[0]
    finally: app.dependency_overrides.pop(require_admin,None)

@pytest.mark.asyncio
async def test_local_failure_health_isolated(ai_env):
    def respond(request): raise httpx.ConnectError('offline')
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result=await make_provider('local_gguf',ai_env,client).health()
        assert result['status']=='offline'

@pytest.mark.asyncio
async def test_clear_key_does_not_reuse_bootstrap_secret(ai_env,monkeypatch):
    from config.runtime_config import update_runtime_config
    monkeypatch.setenv('GROQ_API_KEY','bootstrap-test-secret')
    get_settings.cache_clear()
    update_runtime_config({'GROQ_API_KEY':''})
    ai_env.providers['groq'].enabled=True
    with pytest.raises(AIUnavailable,match='no configured API key'):
        make_provider('groq',ai_env,None).connection()

def test_api_settings_encrypted_persistent_and_redacted(ai_env,monkeypatch,tmp_path):
    from api.app import app,require_admin
    monkeypatch.setattr(ai_chat.chat_service,'configure_engine',AsyncMock())
    app.dependency_overrides[require_admin]=lambda:True
    try:
        client=TestClient(app); cfg=AIOptions(); cfg.providers['custom'].enabled=True
        cfg.providers['custom'].base_url='https://example.com/v1';cfg.providers['custom'].model='example'
        key='private-unit-test-custom-api-key'
        response=client.post('/api/ai/settings',json={'settings':cfg.model_dump(),'api_keys':{'custom':key}})
        assert response.status_code==200
        assert key not in response.text
        get_settings.cache_clear()
        read=client.get('/api/ai/settings')
        assert read.json()['settings']['provider']=='local_gguf'
        assert read.json()['keys_configured']['custom'] is True
        assert key not in read.text and key not in (tmp_path/'runtime.json').read_text()
        cfg.provider='custom'
        assert client.post('/api/ai/settings',json={'settings':cfg.model_dump()}).status_code==200
        assert client.get('/api/ai/settings').json()['settings']['provider']=='custom'
    finally: app.dependency_overrides.pop(require_admin,None)

@pytest.mark.asyncio
async def test_discord_ask_and_reset(ai_env,monkeypatch):
    from bot.commands.ai import AIChat
    cog=AIChat(None)
    monkeypatch.setattr(ai_chat.chat_service,'ask',AsyncMock(return_value={'answer':'A CVE identifies a publicly disclosed vulnerability.','provider':'local_gguf','model':'CyberSecurity.gguf'}))
    monkeypatch.setattr('bot.commands.ai.record_delivery',AsyncMock())
    interaction=SimpleNamespace(guild_id=1,channel_id=2,user=SimpleNamespace(id=3),
        response=SimpleNamespace(defer=AsyncMock(),send_message=AsyncMock()),
        edit_original_response=AsyncMock(return_value=SimpleNamespace(id=123)),followup=SimpleNamespace(send=AsyncMock()))
    await cog.ask.callback(cog,interaction,'Explain CVE')
    assert interaction.response.defer.await_count==1
    assert 'CVE' in interaction.edit_original_response.call_args.kwargs['content']
    assert ai_chat.chat_service.ask.call_args.args[0]==(1,2,3)
    monkeypatch.setattr(ai_chat.chat_service,'reset',lambda key:None)
    await cog.reset_chat.callback(cog,interaction)
    assert interaction.response.send_message.await_count==1

@pytest.mark.asyncio
async def test_mention_chat_replies_with_requester_and_reply_metadata(ai_env,monkeypatch):
    from bot.commands.ai import AIChat,_seen_mention_events
    ai_env.mention_chat=True
    _seen_mention_events.clear()
    bot_user=SimpleNamespace(id=99)
    author=SimpleNamespace(id=42,bot=False)
    sent=[]
    class Channel:
        id=7; name='cyber-chat'
        class Typing:
            async def __aenter__(self): return None
            async def __aexit__(self,*args): return False
        def typing(self): return self.Typing()
    async def reply(content,**kwargs):
        sent.append((content,kwargs)); return SimpleNamespace(id=100+len(sent))
    message=SimpleNamespace(id=88,author=author,webhook_id=None,mentions=[bot_user],
        content='<@99> Explain IDS',guild=SimpleNamespace(id=5),channel=Channel(),reply=reply)
    bot=SimpleNamespace(user=bot_user)
    result={'answer':'IDS monitors activity and reports suspicious events.','provider':'local_gguf',
            'model':'CyberSecurity.gguf','latency_seconds':1.2}
    async def respond_with_verified_preview(*args,**kwargs):
        await kwargs['on_data']('🔎 HEX ALERT found 1 verified critical CVEs:\n• CVE-2026-10001 — verified')
        return result
    ask=AsyncMock(side_effect=respond_with_verified_preview)
    delivery=AsyncMock(); metric=AsyncMock()
    monkeypatch.setattr('bot.commands.ai.options',lambda:ai_env)
    monkeypatch.setattr('bot.commands.ai.chat_service.ask',ask)
    monkeypatch.setattr('bot.commands.ai.record_delivery',delivery)
    monkeypatch.setattr('bot.commands.ai.audit_metric',metric)
    await AIChat(bot).on_message(message)
    ask.assert_awaited_once()
    assert ask.await_args.args==( (5,7,42),'Explain IDS')
    assert ask.await_args.kwargs['priority']==0
    assert set(ask.await_args.kwargs)=={'on_data','priority'}
    assert len(sent)==1
    assert '🔎 HEX ALERT found 1 verified critical CVEs:' in sent[0][0]
    assert sent[0][0].startswith('<@42>')
    assert author in sent[0][1]['allowed_mentions'].users
    delivery.assert_awaited_once()
    assert delivery.await_args.kwargs['requesting_user_id']==42
    assert delivery.await_args.kwargs['reply_to_message_id']==88
    assert delivery.await_args.kwargs['delivery_type']=='mention'
    await AIChat(bot).on_message(message)
    await asyncio.sleep(0)
    assert ask.await_count==1


def test_mention_events_are_deduplicated():
    from bot.commands.ai import _claim_mention_event,_seen_mention_events
    _seen_mention_events.clear()
    assert _claim_mention_event('message-duplicate-check') is True
    assert _claim_mention_event('message-duplicate-check') is False
    _seen_mention_events.clear()

def test_mention_detection_uses_raw_user_ids_and_strips_only_bot_tag():
    from bot.commands.ai import _mention_question, _mentions_this_bot
    message=SimpleNamespace(mentions=[],raw_mentions=[99],content='hello <@!99> please')
    assert _mentions_this_bot(message,99) is True
    assert _mention_question(message,99)=='hello please'
    role_only=SimpleNamespace(mentions=[],raw_mentions=[])
    assert _mentions_this_bot(role_only,99) is False


@pytest.mark.parametrize('tag',['<@99>','<@!99>'])
def test_mention_detection_supports_both_discord_user_tag_forms(tag):
    from bot.commands.ai import _mention_question,_mentions_this_bot
    message=SimpleNamespace(content=f'{tag} hii',mentions=[],raw_mentions=[])
    assert _mentions_this_bot(message,99)
    assert _mention_question(message,99)=='hii'


def test_raw_gateway_message_create_metadata_is_safe_and_available_after_reconnect(ai_env,monkeypatch):
    from bot.commands.ai import MENTION_DIAGNOSTICS,_gateway_message_mentions,note_gateway_message_create,gateway_mention_user_ids
    _gateway_message_mentions.clear()
    bot=SimpleNamespace(user=SimpleNamespace(id=99))
    payload={'op':0,'t':'MESSAGE_CREATE','d':{'id':'810','guild_id':'5','channel_id':'7',
        'author':{'id':'42'},'content':'','mentions':[{'id':'99','username':'Hex-Alpha'}]}}
    note_gateway_message_create(payload,bot)
    assert gateway_mention_user_ids(810)==('99',)
    assert MENTION_DIAGNOSTICS['last_message_create']['content_length']==0
    assert MENTION_DIAGNOSTICS['last_direct_mention']['message_id']=='810'
    assert 'content' not in MENTION_DIAGNOSTICS['last_message_create']
    _gateway_message_mentions.clear()


@pytest.mark.asyncio
async def test_empty_content_raw_mention_gets_prompt_and_deduplicates(ai_env,monkeypatch):
    from bot.commands.ai import AIChat,_seen_mention_events,_gateway_message_mentions,MENTION_DIAGNOSTICS
    ai_env.mention_chat=True
    _seen_mention_events.clear();_gateway_message_mentions.clear()
    author=SimpleNamespace(id=42,bot=False); bot_user=SimpleNamespace(id=99); sent=[]
    async def reply(content,**kwargs):
        sent.append((content,kwargs));return SimpleNamespace(id=901)
    class Channel:
        id=7;name='hex-alert-test';parent=None
    message=SimpleNamespace(id=900,author=author,webhook_id=None,mentions=[],raw_mentions=[],content=None,
        guild=SimpleNamespace(id=5,me=None),channel=Channel(),reply=reply,mention_everyone=False)
    note={'message_id':'900','mention_user_ids':['99'],'raw_mentions':[]}
    import time
    _gateway_message_mentions['900']=(time.monotonic(),{'mention_user_ids':['99'],'raw_mentions':[]})
    ask=AsyncMock();delivery=AsyncMock();metric=AsyncMock()
    monkeypatch.setattr('bot.commands.ai.options',lambda:ai_env)
    monkeypatch.setattr('bot.commands.ai.chat_service.ask',ask)
    monkeypatch.setattr('bot.commands.ai.record_delivery',delivery)
    monkeypatch.setattr('bot.commands.ai.audit_metric',metric)
    await AIChat(SimpleNamespace(user=bot_user)).on_message(message)
    await AIChat(SimpleNamespace(user=bot_user)).on_message(message)
    ask.assert_not_awaited()
    assert len(sent)==1 and sent[0][0].startswith('<@42>')
    assert 'Haan bro, bolo' in sent[0][0]
    assert delivery.await_args.kwargs['model']=='empty-mention'
    assert MENTION_DIAGNOSTICS['last_handler_result']=='duplicate_event'
    assert MENTION_DIAGNOSTICS['last_reply_result']=='sent'
    await asyncio.sleep(0)
    _seen_mention_events.clear();_gateway_message_mentions.clear()


def test_mention_diagnostics_refreshes_numeric_bot_id_without_caching_user(ai_env,monkeypatch):
    from bot.commands.ai import MENTION_DIAGNOSTICS,refresh_mention_runtime
    ai_env.mention_chat=True
    class Cog:
        def get_listeners(self): return [('on_message',lambda:None)]
    class Bot:
        user=SimpleNamespace(id=99)
        def get_cog(self,name): return Cog()
        def is_ready(self): return True
    bot=Bot()
    first=refresh_mention_runtime(bot,'ready')
    bot.user=SimpleNamespace(id=100)
    resumed=refresh_mention_runtime(bot,'resumed')
    assert first['bot_user_id']=='99' and resumed['bot_user_id']=='100'
    assert resumed['listener_registered'] and resumed['listener_count']==1
    assert 'bot_user_id' not in MENTION_DIAGNOSTICS


@pytest.mark.asyncio
async def test_direct_mention_in_thread_stays_in_thread(ai_env,monkeypatch):
    from bot.commands.ai import AIChat,_seen_mention_events
    ai_env.mention_chat=True;_seen_mention_events.clear()
    bot_user=SimpleNamespace(id=99);author=SimpleNamespace(id=43,bot=False);sent=[]
    async def reply(content,**kwargs): sent.append(content);return SimpleNamespace(id=1001)
    channel=SimpleNamespace(id=71,name='thread',parent=SimpleNamespace(id=7))
    message=SimpleNamespace(id=1000,author=author,webhook_id=None,mentions=[bot_user],raw_mentions=[],
        content='<@!99> hii',guild=SimpleNamespace(id=5,me=None),channel=channel,reply=reply,mention_everyone=False)
    monkeypatch.setattr('bot.commands.ai.options',lambda:ai_env)
    monkeypatch.setattr('bot.commands.ai.record_delivery',AsyncMock())
    monkeypatch.setattr('bot.commands.ai.audit_metric',AsyncMock())
    await AIChat(SimpleNamespace(user=bot_user)).on_message(message)
    await asyncio.sleep(0)
    assert len(sent)==1 and sent[0].startswith('<@43>')
    _seen_mention_events.clear()


@pytest.mark.asyncio
async def test_smart_social_skips_direct_bot_mentions(ai_env,monkeypatch):
    from bot.bot import CommunityEvents
    from services.community import community_automation
    from services.smart_social import smart_social
    monkeypatch.setattr(community_automation,'note_activity',lambda *args:None)
    monkeypatch.setattr('services.member_directory.record_interaction',AsyncMock())
    process=AsyncMock();monkeypatch.setattr(smart_social,'process_message',process)
    guild=SimpleNamespace(id=5);channel=SimpleNamespace(id=7)
    message=SimpleNamespace(id=1500,guild=guild,channel=channel,author=SimpleNamespace(id=42,bot=False),
        webhook_id=None,mention_everyone=False,_hex_direct_bot_mention=True)
    await CommunityEvents(SimpleNamespace(user=SimpleNamespace(id=99))).on_message(message)
    await asyncio.sleep(0)
    process.assert_not_awaited()


@pytest.mark.asyncio
async def test_mention_ping_has_deterministic_ack_without_calling_ai(ai_env,monkeypatch):
    from bot.commands.ai import AIChat,_seen_mention_events
    ai_env.mention_chat=True
    _seen_mention_events.clear()
    bot_user=SimpleNamespace(id=99)
    author=SimpleNamespace(id=42,bot=False)
    sent=[]
    async def reply(content,**kwargs):
        sent.append((content,kwargs));return SimpleNamespace(id=501)
    message=SimpleNamespace(id=502,author=author,webhook_id=None,mentions=[bot_user],
        content='<@99> ping',guild=SimpleNamespace(id=5),
        channel=SimpleNamespace(id=7,name='hex-alert-test'),reply=reply,mention_everyone=False)
    ask=AsyncMock()
    delivery=AsyncMock();metric=AsyncMock()
    monkeypatch.setattr('bot.commands.ai.options',lambda:ai_env)
    monkeypatch.setattr('bot.commands.ai.chat_service.ask',ask)
    monkeypatch.setattr('bot.commands.ai.record_delivery',delivery)
    monkeypatch.setattr('bot.commands.ai.audit_metric',metric)
    await AIChat(SimpleNamespace(user=bot_user)).on_message(message)
    ask.assert_not_awaited()
    assert sent[0][0].startswith('<@42> Mention chat is working.')
    assert '\U0001F6E1' in sent[0][0]
    delivery.assert_awaited_once()
    assert delivery.await_args.kwargs['delivery_type']=='mention'
    await asyncio.sleep(0)
    _seen_mention_events.clear()


@pytest.mark.asyncio
async def test_mention_greeting_fast_path_does_not_call_ai(ai_env,monkeypatch):
    from bot.commands.ai import AIChat,_seen_mention_events
    from services.smart_social import smart_social
    ai_env.mention_chat=True
    _seen_mention_events.clear()
    bot_user=SimpleNamespace(id=99)
    author=SimpleNamespace(id=42,bot=False)
    sent=[]
    async def reply(content,**kwargs):
        sent.append((content,kwargs));return SimpleNamespace(id=601)
    message=SimpleNamespace(id=602,author=author,webhook_id=None,mentions=[bot_user],
        content='<@99> hii',guild=SimpleNamespace(id=5),
        channel=SimpleNamespace(id=7,name='hex-alert-test'),reply=reply,mention_everyone=False)
    ask=AsyncMock();delivery=AsyncMock();metric=AsyncMock()
    reaction=AsyncMock();monkeypatch.setattr(smart_social,'mention_reaction',reaction)
    monkeypatch.setattr('bot.commands.ai.options',lambda:ai_env)
    monkeypatch.setattr('bot.commands.ai.chat_service.ask',ask)
    monkeypatch.setattr('bot.commands.ai.record_delivery',delivery)
    monkeypatch.setattr('bot.commands.ai.audit_metric',metric)
    await AIChat(SimpleNamespace(user=bot_user)).on_message(message)
    await asyncio.sleep(0)
    ask.assert_not_awaited()
    assert sent[0][0].startswith("<@42> ")
    assert "Hii bro! HEX ALPHA online hai." in sent[0][0]
    assert '\U0001F44B' in sent[0][0]
    assert delivery.await_args.kwargs['provider']=='fast_path'
    assert delivery.await_args.kwargs['model']=='greeting'
    _seen_mention_events.clear()
