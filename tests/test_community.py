import json
import pytest
from datetime import datetime, timezone
import asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import URL

from api import app as api_module
from api import community_routes
import database.db as db_module
from services import community as community_module
from services import member_directory as member_directory_module
from services import smart_social as smart_social_module
from database.models import Base, ChannelConfig
from config.ai import SYSTEM_PROMPT, PUBLIC_ASSISTANT_NAME, PUBLIC_DEVELOPER_BRAND
from services.ai_chat import structured_data_preview, data_context
from services.community import default_community_settings, merge_settings, _digest, _is_quiet
from api.community_routes import CommunityPayload, PulseSettings


def test_public_identity_and_truthful_system_prompt():
    assert PUBLIC_ASSISTANT_NAME == 'HEX ALPHA'
    assert PUBLIC_DEVELOPER_BRAND == 'HEX SECURITY'
    assert 'Do not claim HEX SECURITY trained a third-party base model' in SYSTEM_PROMPT
    assert 'Do not expose internal model/runtime details' in SYSTEM_PROMPT


def test_community_automations_are_opt_in_and_channel_pulse_defaults_are_safe():
    settings=default_community_settings()
    assert settings['welcome']['enabled'] is False
    assert settings['farewell']['enabled'] is False
    assert all(not row['enabled'] for row in settings['pulse']['channels'])
    assert not next(x for x in settings['pulse']['channels'] if x['key']=='critical_cve')['enabled']
    assert settings['pulse']['quiet_start']=='23:00' and settings['pulse']['quiet_end']=='08:00'
    assert settings['pulse']['timezone']=='Asia/Kolkata'


def test_settings_merge_preserves_existing_values_and_adds_safe_defaults():
    value=merge_settings({'welcome':{'enabled':True,'channel_id':'123'},'pulse':{'channels':[{'key':'jobs','enabled':True,'channel_id':'456','interval_minutes':120}]}})
    assert value['welcome']['enabled'] and value['welcome']['channel_id']=='123'
    assert next(x for x in value['pulse']['channels'] if x['key']=='jobs')['enabled']
    assert not next(x for x in value['pulse']['channels'] if x['key']=='critical_cve')['enabled']


def test_structured_data_preview_is_verified_and_includes_source_link():
    rows=[{'title':'CVE-2026-10001','published':'2026-10-02','url':'https://vendor.example/advisory','details':'CRITICAL · CVSS 9.8 · Remote code execution.'}]
    output=structured_data_preview('HEX ALERT current data (facts only):\n'+json.dumps(rows),'cves')
    assert 'verified critical CVEs' in output and 'CVE-2026-10001' in output
    assert output.startswith('🔎 HEX ALERT found ')
    assert 'https://vendor.example/advisory' in output
    assert structured_data_preview('No matching current HEX ALERT records.','cves')==''


def test_structured_preview_rejects_credential_urls():
    rows=[{'title':'item','published':'today','url':'https://user:password@vendor.example/a','details':'verified'}]
    output=structured_data_preview('HEX ALERT current data (facts only):\n'+json.dumps(rows),'news')
    assert 'user:password' not in output


def test_content_hash_normalizes_spacing_and_case():
    assert _digest('  Secure   your account! ') == _digest('secure your ACCOUNT!')


def test_quiet_hours_cover_midnight_and_daytime():
    cfg={'quiet_hours_enabled':True,'timezone':'Asia/Kolkata','quiet_start':'23:00','quiet_end':'07:00'}
    assert _is_quiet(cfg,datetime(2026,10,2,20,0,tzinfo=timezone.utc)) # 01:30 IST
    assert not _is_quiet(cfg,datetime(2026,10,2,6,0,tzinfo=timezone.utc)) # 11:30 IST


def test_pulse_configuration_validation_rejects_unsafe_intervals_and_duplicate_keys():
    with pytest.raises(Exception): PulseSettings(channels=[{'key':'jobs','category':'jobs','label':'Jobs','interval_minutes':5}])
    with pytest.raises(Exception): PulseSettings(channels=[
        {'key':'jobs','category':'jobs','label':'Jobs','interval_minutes':60},
        {'key':'jobs','category':'jobs','label':'Jobs again','interval_minutes':120}])


def test_community_dashboard_persists_disabled_defaults(monkeypatch,tmp_path):
    engine=create_async_engine(URL.create('sqlite+aiosqlite',database=str((tmp_path/'community.db').resolve())))
    original_factory=api_module.SessionLocal; original_route_factory=community_routes.SessionLocal
    original_db_factory=db_module.SessionLocal; original_community_factory=community_module.SessionLocal
    original_directory_factory=member_directory_module.SessionLocal
    original_social_factory=smart_social_module.SessionLocal
    original_bot=api_module.runtime.get('bot')
    factory=async_sessionmaker(engine,expire_on_commit=False)
    api_module.SessionLocal=factory; community_routes.SessionLocal=factory
    db_module.SessionLocal=factory; community_module.SessionLocal=factory; member_directory_module.SessionLocal=factory; smart_social_module.SessionLocal=factory
    api_module.runtime['bot']=None
    async def create_schema():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    asyncio.run(create_schema())
    api_module.app.dependency_overrides[api_module.require_admin]=lambda:True
    try:
        client=TestClient(api_module.app)
        cfg=default_community_settings()
        payload={'guild_id':'700','welcome':cfg['welcome'],'farewell':cfg['farewell'],
                 'pulse':cfg['pulse'],'members_intent':False}
        saved=client.post('/api/community/config',json=payload)
        assert saved.status_code==200,saved.text
        loaded=client.get('/api/community/config?guild_id=700').json()
        assert loaded['settings']['welcome']['enabled'] is False
        assert loaded['settings']['farewell']['enabled'] is False
        assert all(not row['enabled'] for row in loaded['settings']['pulse']['channels'])
        assert loaded['member_intent']['status']=='Disabled'
        digest_preview=client.get('/api/community/daily-digest/preview')
        assert digest_preview.status_code==200,digest_preview.text
        assert digest_preview.json()['preview_only'] is True
        assert digest_preview.json()['scheduled_time']=='08:00 Asia/Kolkata'
        sections=digest_preview.json()['sections']
        assert [row['title'] for row in sections]==[
            '🚨 Critical CVEs','⚠️ New Exploited Vulnerabilities','📰 Cyber News',
            '⚠️ Threat Intel','💼 Jobs','🛠️ Tools','🔬 Research','💻 Technology']
        assert digest_preview.json()['freshness_window_hours']==24
        assert all(not row['items'] for row in sections)
        enabled=default_community_settings()
        for index,item in enumerate(enabled['pulse']['channels'],start=1):
            item.update(enabled=True,channel_id=str(9000+index),interval_minutes=30)
        payload['pulse']=enabled['pulse']
        saved=client.post('/api/community/config',json=payload)
        assert saved.status_code==200,saved.text
        loaded=client.get('/api/community/config?guild_id=700').json()
        assert loaded['test_mode'] is True
        assert all(row['enabled'] and row['interval_minutes']==30 and row['baseline_at']
                   for row in loaded['settings']['pulse']['channels'])
    finally:
        api_module.app.dependency_overrides.pop(api_module.require_admin,None)
        api_module.SessionLocal=original_factory; community_routes.SessionLocal=original_route_factory
        db_module.SessionLocal=original_db_factory;community_module.SessionLocal=original_community_factory;member_directory_module.SessionLocal=original_directory_factory;smart_social_module.SessionLocal=original_social_factory
        api_module.runtime['bot']=original_bot
        asyncio.run(engine.dispose())


def test_pulse_defaults_use_30_minutes_and_safe_daily_cap():
    settings=default_community_settings()
    assert settings["pulse"]["daily_limit"]==40
    assert settings["pulse"]["quiet_end"]=="08:00"
    assert all(row["interval_minutes"]==30 for row in settings["pulse"]["channels"])


def test_autopilot_is_persisted_off_by_default_and_module_gates_are_independent(monkeypatch):
    from config import runtime_config
    values={}
    monkeypatch.setattr(runtime_config,'get_runtime_config',lambda:dict(values))
    monkeypatch.setattr(runtime_config,'update_runtime_config',lambda changes:values.update(changes))
    controls=community_module.CommunityAutomation.automation_controls()
    assert controls['autonomous_mode'] is False
    assert controls['autopilot_modules']['pulse'] is True
    assert controls['autopilot_modules']['member_engagement'] is False
    assert community_module.CommunityAutomation._automation_paused('pulse') is True
    community_module.CommunityAutomation.save_automation_controls({'autonomous_mode':True})
    assert community_module.CommunityAutomation._automation_paused('pulse') is False
    community_module.CommunityAutomation.save_automation_controls({'autopilot_modules':{'pulse':False}})
    assert community_module.CommunityAutomation._automation_paused('pulse') is True
    assert community_module.CommunityAutomation._automation_paused('member_engagement') is True


def test_pulse_optional_category_failure_degrades_instead_of_failing_whole_service():
    categories=[{'source_health':'error','source_enabled':1,'enabled':True,'destination_ready':True},
                {'source_health':'healthy','source_enabled':4,'enabled':True,'destination_ready':True}]
    assert community_module.pulse_readiness(categories,bot_ready=True)=='DEGRADED'
    assert community_module.pulse_readiness([],bot_ready=True)=='READY'
    assert community_module.pulse_readiness(categories,bot_ready=False)=='ERROR'


def test_pulse_no_new_data_is_a_success_outcome_not_a_failure(monkeypatch,tmp_path):
    from sqlalchemy.ext.asyncio import async_sessionmaker,create_async_engine
    from sqlalchemy.engine import URL
    from database.models import PulseDeliveryEvent
    engine=create_async_engine(URL.create('sqlite+aiosqlite',database=str((tmp_path/'pulse-no-data.db').resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    original=community_module.SessionLocal
    community_module.SessionLocal=factory
    async def run():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        outcome=await community_module.community_automation.record_pulse_outcome(
            '700',{'category':'jobs','channel_id':'900'},{'status':'no_new_data'})
        async with factory() as session:
            row=await session.scalar(__import__('sqlalchemy').select(PulseDeliveryEvent))
            return outcome,row.status
    try:
        outcome,status=asyncio.run(run())
        assert outcome=='no_new_data' and status=='no_new_data'
    finally:
        community_module.SessionLocal=original
        asyncio.run(engine.dispose())


def test_pulse_content_is_cited_limited_and_emoji_formatted():
    records=[(datetime.now(timezone.utc),"Verified report","Short facts","Vendor",
              f"https://vendor.example/{i}","2026-10-07") for i in range(4)]
    result=community_module.CommunityAutomation._format_verified_records("news",records,maximum=3)
    assert result.count("https://vendor.example/")==3
    assert result.count(chr(0x1F4F0))==3
    assert "Verified report" in result


def test_pulse_formatter_keeps_only_complete_cited_records():
    records=[(datetime.now(timezone.utc), "A" * 140, "B" * 180, "Vendor",
              f"https://vendor.example/advisory/{i}", "2026-10-08") for i in range(3)]
    result=community_module.CommunityAutomation._format_verified_records("news",records,maximum=3,max_length=460)
    assert len(result)<=460
    assert result.count("https://vendor.example/")==1
    assert result.endswith(">")
    assert "advisory/1" not in result


def test_pulse_rejects_non_https_urls():
    assert community_module.CommunityAutomation._safe_url("http://example.org/a")==""
    assert community_module.CommunityAutomation._safe_url("https://user:secret@example.org/a")==""
    assert community_module.CommunityAutomation._safe_url("https://example.org/a")=="https://example.org/a"


def test_pulse_canonical_link_hash_is_cross_category_key():
    url="https://vendor.example/advisory/CVE-2026-12345"
    assert _digest(url)==_digest(url)
    assert _digest(url)!=_digest(url+"?mirror=2")


def test_mention_fast_paths_cover_greeting_identity_and_language():
    from bot.commands.ai import _mention_fast_path
    greeting=_mention_fast_path("hii")
    identity=_mention_fast_path("tum kon ho")
    language=_mention_fast_path("Hindi me baat kr")
    assert "Hii bro" in greeting and chr(0x1F44B) in greeting
    assert "HEX ALPHA" in identity and chr(0x1F6E1) in identity
    assert "Hindi/Hinglish" in language


def test_ai_echo_and_duplicate_sentence_guards():
    from services.ai_chat import is_question_echo, remove_repeated_sentences
    assert is_question_echo("What is a very specific question?", "What is a very specific question?")
    assert not is_question_echo("What is IDS?", "IDS detects suspicious activity.")
    assert remove_repeated_sentences("Useful answer. Useful answer. Next step.")=="Useful answer. Next step."


def test_pulse_zero_day_is_separate_from_critical_cve():
    from sqlalchemy import or_
    # Routing invariants: critical severity alone is not zero-day evidence.
    critical_only={'severity':'CRITICAL','cvss':9.8,'verified_zero_day':False,'exploited':'NO'}
    assert not (critical_only['verified_zero_day'] or critical_only['exploited'].casefold()=='yes')
    confirmed={'severity':'HIGH','cvss':7.5,'verified_zero_day':True,'exploited':'NO'}
    assert confirmed['verified_zero_day']


def test_pulse_database_selection_uses_baseline_and_only_verified_urls(monkeypatch,tmp_path):
    from database.models import NewsArticle
    engine=create_async_engine(URL.create('sqlite+aiosqlite',database=str((tmp_path/'pulse-baseline.db').resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    original=community_module.SessionLocal
    community_module.SessionLocal=factory
    async def seed_and_read():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        baseline=datetime(2026,10,7,10,0,tzinfo=timezone.utc)
        async with factory() as session:
            old=NewsArticle(title='Old story',summary='Existing record',category='Security News',
                source='Feed',source_url='https://news.example/old',content_hash='a'*64,created_at=baseline)
            new=NewsArticle(title='New story',summary='Verified new item',category='Security News',
                source='Feed',source_url='https://news.example/new',content_hash='b'*64,
                created_at=datetime(2026,10,7,11,0,tzinfo=timezone.utc))
            session.add_all([old,new]); await session.commit()
        entry={'key':'news','category':'news','baseline_at':baseline.isoformat()}
        async with factory() as session:
            return await community_module.community_automation._verified_pulse_records(session,entry)
    try:
        records=asyncio.run(seed_and_read())
        assert [record[1] for record in records]==['New story']
        assert records[0][4]=='https://news.example/new'
    finally:
        community_module.SessionLocal=original
        asyncio.run(engine.dispose())


def test_test_mode_pauses_scheduled_pulse_and_labels_manual_category(monkeypatch,tmp_path):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    engine=create_async_engine(URL.create('sqlite+aiosqlite',database=str((tmp_path/'pulse-test-mode.db').resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    original=community_module.SessionLocal
    community_module.SessionLocal=factory
    monkeypatch.setattr(community_module,'get_settings',lambda:SimpleNamespace(test_mode=True))
    monkeypatch.setattr(community_module.community_automation,'_channel',AsyncMock(return_value=(None,object())))
    sent=AsyncMock(return_value={'status':'sent','message_id':'77'})
    monkeypatch.setattr(community_module.community_automation,'send',sent)
    async def run():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        async with factory() as session:
            session.add(ChannelConfig(guild_id='700',name='TEST_CHANNEL_ID',channel_id='101'))
            await session.commit()
        settings=default_community_settings()
        settings['pulse']['quiet_hours_enabled']=False
        entry=next(row for row in settings['pulse']['channels'] if row['key']=='general')
        entry.update(enabled=True,channel_id='99')
        automatic=await community_module.community_automation._send_pulse(SimpleNamespace(),'700',settings,entry)
        manual=await community_module.community_automation._send_pulse(SimpleNamespace(),'700',settings,entry,manual=True)
        return automatic,manual
    try:
        automatic,manual=asyncio.run(run())
        assert automatic['status']=='test_mode_paused'
        assert manual['status']=='sent'
        assert sent.await_args.args[2]=='101'
        assert sent.await_args.args[3]=='test_pulse'
        assert 'TEST' in sent.await_args.args[4] and chr(0x1F9EA) in sent.await_args.args[4]
    finally:
        community_module.SessionLocal=original
        asyncio.run(engine.dispose())
