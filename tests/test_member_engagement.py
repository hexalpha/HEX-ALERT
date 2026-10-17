import asyncio
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import URL
from sqlalchemy import select
from database.models import Base, ChannelConfig, CommunityEngagementEvent, CommunityEngagementMember
from services import member_engagement as me, member_directory as directory
from services.ai_chat import ensure_response_emoji
from services.community import default_community_settings, merge_settings

class FixedRandom:
    def __init__(self, value): self.value=value
    def randint(self, low, high): return max(low,min(self.value,high))
    def choices(self, seq, weights=None, k=1): return [seq[0]]

def test_engagement_defaults_disabled_and_everyone_disabled():
    cfg=default_community_settings()["member_engagement"]
    assert cfg["enabled"] is False and cfg["everyone_enabled"] is False
    assert (cfg["min_interval_hours"],cfg["max_interval_hours"])==(2,4)
    assert cfg["server_daily_limit"]==6 and cfg["user_repeat_cooldown_hours"]>=24
    assert cfg["quiet_start"]=="23:00" and cfg["quiet_end"]=="08:00"

def test_interval_is_randomly_selected_within_two_to_four_hours():
    cfg=me.normalize_settings({})
    now=datetime(2026,10,7,10,tzinfo=timezone.utc)
    for minutes in (120,180,240):
        run=me.next_run_at(cfg,now,FixedRandom(minutes))
        assert timedelta(hours=2)<=run-now<=timedelta(hours=4)

def test_interval_clamps_unsafe_minimum_and_maximum():
    cfg=me.normalize_settings({"min_interval_hours":1,"max_interval_hours":1})
    assert cfg["min_interval_hours"]==2 and cfg["max_interval_hours"]==2

def test_quiet_hours_shift_due_time_to_random_after_eight_ist():
    cfg=me.normalize_settings({})
    now=datetime(2026,10,7,20,0,tzinfo=timezone.utc)
    run=me.next_run_at(cfg,now,FixedRandom(180))
    local=run.astimezone(__import__("zoneinfo").ZoneInfo("Asia/Kolkata"))
    assert local.hour==8 and 0<=local.minute<=59

def test_startup_recovery_uses_a_delayed_grace_period():
    cfg=me.normalize_settings({})
    now=datetime(2026,10,7,10,tzinfo=timezone.utc)
    assert me.startup_run_at(cfg,now,FixedRandom(17))==now+timedelta(minutes=17)

def test_same_day_and_under_24_hour_repeat_are_blocked():
    now=datetime(2026,10,7,10,tzinfo=timezone.utc)
    zone=__import__("zoneinfo").ZoneInfo("Asia/Kolkata")
    assert not me.member_cooldown_eligible(now-timedelta(hours=2),now,zone,24)
    assert me.member_cooldown_eligible(now-timedelta(hours=26),now,zone,24)
    same_day=datetime(2026,10,7,1,tzinfo=timezone.utc)
    assert not me.member_cooldown_eligible(same_day,now,zone,24)

def test_weighted_styles_respect_admin_style_switches():
    cfg=me.normalize_settings({"styles":{"friendly":False,"funny":True}})
    assert me.choose_style(cfg,FixedRandom(0))=="funny"

def test_templates_have_emoji_and_no_mass_or_role_mentions():
    for style in me.STYLES:
        text=me.render_message(style,"safe name")
        assert any(ord(ch)>0x1F000 for ch in text)
        assert "@everyone" not in text and "@here" not in text and "<@&" not in text

def test_allowed_mentions_are_scoped_to_one_user_and_everyone_is_explicit():
    user=SimpleNamespace(id=12345)
    individual=me.individual_allowed_mentions(user).to_dict()
    everyone=me.everyone_allowed_mentions().to_dict()
    assert individual.get("users")==[12345]
    assert individual.get("parse",[])==[] and "roles" not in individual and "everyone" not in individual
    assert everyone.get("parse")==["everyone"] and "roles" not in everyone

def test_ai_emoji_formatter_preserves_urls():
    result=ensure_response_emoji("Review https://example.org/path for more.")
    assert "https://example.org/path" in result and result.endswith("✨")

def test_emoji_formatter_does_not_add_duplicates():
    assert ensure_response_emoji("Hello 👋").count("✨")==0

def test_settings_merge_keeps_pulse_and_engagement_separate():
    value=merge_settings({"pulse":{"daily_limit":9},"member_engagement":{"enabled":False,"server_daily_limit":4}})
    assert value["pulse"]["daily_limit"]==9
    assert value["member_engagement"]["server_daily_limit"]==4
    assert value["member_engagement"]["enabled"] is False

def test_activity_and_optout_store_only_metadata(tmp_path,monkeypatch):
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"engagement.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(me,"SessionLocal",factory)
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    asyncio.run(setup())
    async def exercise():
        await me.record_activity("700","12345","Member")
        await me.set_opt_out("700","12345",True)
        async with factory() as session:
            row=await session.scalar(__import__("sqlalchemy").select(CommunityEngagementMember))
            assert row.last_activity_at is not None and row.opted_out is True
            assert not hasattr(row,"message_content")
    asyncio.run(exercise())
    asyncio.run(engine.dispose())


def test_automatic_selection_filters_directory_and_prefers_oldest_rotation(tmp_path,monkeypatch):
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"selection.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False);monkeypatch.setattr(me,"SessionLocal",factory)
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    asyncio.run(setup())
    now=datetime(2026,10,7,10,tzinfo=timezone.utc)
    def member(uid,*,bot=False,roles=()):
        return SimpleNamespace(id=uid,name=str(uid),display_name=str(uid),bot=bot,
            roles=[SimpleNamespace(id=r) for r in roles])
    eligible=member(11); opted=member(12); bot=member(13,bot=True); excluded_role=member(14,roles=(77,))
    excluded_user=member(15); tagged=member(16); inactive=member(17)
    members={m.id:m for m in (eligible,opted,bot,excluded_role,excluded_user,tagged,inactive)}
    guild=SimpleNamespace(id=700,me=SimpleNamespace(id=999),get_member=lambda uid:members.get(uid),fetch_member=lambda uid:None)
    async def exercise():
        async with factory() as session:
            for m in members.values():
                row=CommunityEngagementMember(guild_id="700",user_id=str(m.id),display_name=m.display_name,
                    is_bot=m.bot,is_active=(m.id!=17),role_ids=[str(r.id) for r in m.roles])
                if m.id==12: row.opted_out=True
                if m.id==16: row.last_nudged_at=now-timedelta(hours=3);row.last_nudged_date="2026-10-07"
                if m.id==11: row.last_nudged_at=now-timedelta(days=2)
                session.add(row)
            await session.commit()
        settings=me.normalize_settings({"excluded_member_ids":["15"],"excluded_role_ids":["77"]})
        candidates=await me.eligible_members(guild,settings,now=now)
        assert [row.user_id for _,row in candidates]==["11"]
        selected=await me.preview(guild,settings,now=now)
        assert selected["target"]["id"]=="11"
        async def fetch_member(uid): return members.get(uid)
        cache_empty=SimpleNamespace(id=700,me=SimpleNamespace(id=999),get_member=lambda uid:None,fetch_member=fetch_member)
        refreshed=await me.eligible_members(cache_empty,settings,now=now,fetch_members=True)
        assert [row.user_id for _,row in refreshed]==["11"]
    asyncio.run(exercise());asyncio.run(engine.dispose())


def test_everyone_permission_and_cooldown_are_hard_gates():
    cfg=me.normalize_settings({"everyone_enabled":True,"everyone_cooldown_days":7})
    now=datetime(2026,10,7,10,tzinfo=timezone.utc)
    assert not me.everyone_allowed(cfg,False,None,now)
    assert me.everyone_allowed(cfg,True,None,now)
    assert not me.everyone_allowed(cfg,True,now-timedelta(days=6),now)
    assert me.everyone_allowed(cfg,True,now-timedelta(days=7),now)


def test_local_ai_engagement_falls_back_when_unavailable(monkeypatch):
    from unittest.mock import AsyncMock
    from services.ai_providers import AIUnavailable
    monkeypatch.setattr(me.chat_service,"ask",AsyncMock(side_effect=AIUnavailable("offline")))
    settings=me.normalize_settings({"use_ai":True})
    result=__import__("asyncio").run(me.generate_text(settings,"friendly","Member","Server"))
    assert any(ord(ch)>0x1F000 for ch in result)
    me.chat_service.ask.assert_awaited_once()
    assert me.chat_service.ask.await_args.kwargs["provider_override"]=="local_gguf"

def test_ai_generated_mentions_are_removed_and_safe_emoji_is_kept(monkeypatch):
    from unittest.mock import AsyncMock
    monkeypatch.setattr(me.chat_service,"ask",AsyncMock(return_value={"answer":"Hello @everyone @here <@123> <@&456> "+chr(0x1F44B)}))
    monkeypatch.setattr(type(me.chat_service),"active",property(lambda self:False),raising=False)
    monkeypatch.setattr(type(me.chat_service),"waiting",property(lambda self:0),raising=False)
    result=__import__("asyncio").run(me.generate_text(me.normalize_settings({"use_ai":True}),"friendly","Member","Server"))
    assert "@everyone" not in result and "@here" not in result and "<@" not in result
    assert chr(0x1F44B) in result
def test_engagement_admin_settings_are_persisted_and_disabled_by_default(monkeypatch,tmp_path):
    from fastapi.testclient import TestClient
    from api import app as app_module
    from api import community_routes
    import database.db as db_module
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"engagement-api.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    originals=(app_module.SessionLocal,community_routes.SessionLocal,db_module.SessionLocal,me.SessionLocal,directory.SessionLocal,app_module.runtime.get("bot"))
    app_module.SessionLocal=community_routes.SessionLocal=db_module.SessionLocal=me.SessionLocal=directory.SessionLocal=factory
    app_module.runtime["bot"]=None
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    asyncio.run(setup())
    app_module.app.dependency_overrides[app_module.require_admin]=lambda:True
    try:
        client=TestClient(app_module.app)
        cfg=me.engagement_defaults()
        response=client.post("/api/community/engagement/config",json={"guild_id":"700","settings":cfg})
        assert response.status_code==200,response.text
        status=client.get("/api/community/engagement/status?guild_id=700")
        assert status.status_code==200,status.text
        assert status.json()["settings"]["enabled"] is False
        assert status.json()["settings"]["everyone_enabled"] is False
    finally:
        app_module.app.dependency_overrides.pop(app_module.require_admin,None)
        app_module.SessionLocal,community_routes.SessionLocal,db_module.SessionLocal,me.SessionLocal,directory.SessionLocal,old_bot=originals
        app_module.runtime["bot"]=old_bot
        asyncio.run(engine.dispose())


def test_manual_member_test_is_one_style_one_send_and_idempotent(monkeypatch,tmp_path):
    from unittest.mock import AsyncMock
    from uuid import uuid4
    import discord
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"member-test.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(me,"SessionLocal",factory)
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        async with factory() as session:
            session.add(ChannelConfig(guild_id="700",name="TEST_CHANNEL_ID",channel_id="900"))
            session.add(CommunityEngagementMember(guild_id="700",user_id="11",display_name="Safe Member"))
            await session.commit()
    asyncio.run(setup())
    target=SimpleNamespace(id=11,bot=False,display_name="Safe Member")
    guild=SimpleNamespace(id=700,name="HEX TEST",get_member=lambda _uid:target,fetch_member=None)
    bot=SimpleNamespace(user=SimpleNamespace(id=99),get_guild=lambda _gid:guild)
    monkeypatch.setattr(me,"get_test_mode",lambda:True)
    monkeypatch.setattr(me,"read_settings",AsyncMock(return_value={"member_engagement":{"channel_id":"general"}}))
    monkeypatch.setattr(me,"generate_text",AsyncMock(return_value="Hello 👋"))
    message=SimpleNamespace(id="message-123",nonce="",author=bot.user)
    send=AsyncMock(return_value=message)
    channel=SimpleNamespace(id=900,name="hex-alert-test",send=send)
    monkeypatch.setattr(me,"community_channel",AsyncMock(return_value=channel))
    monkeypatch.setattr(me,"individual_allowed_mentions",lambda _target:"only-selected-user")
    run_id=str(uuid4())
    async def exercise():
        first=await me.member_engagement.test_send(bot,"700","11","friendly",run_id)
        second=await me.member_engagement.test_send(bot,"700","11","shayari",run_id)
        async with factory() as session:
            events=(await session.scalars(select(CommunityEngagementEvent).where(
                CommunityEngagementEvent.test_run_id==run_id))).all()
        return first,second,events
    result,duplicate,events=asyncio.run(exercise())
    assert result["message_id"]=="message-123"
    assert result["channel_id"]=="900" and result["status"]=="sent"
    assert duplicate["message_id"]=="message-123" and duplicate["reused"] is True
    assert send.await_count==1
    assert send.await_args.kwargs["nonce"]
    assert discord.http.handle_message_parameters("test",nonce=send.await_args.kwargs["nonce"]).payload["enforce_nonce"] is True
    assert send.await_args.kwargs["allowed_mentions"]=="only-selected-user"
    assert "TEST COMMUNITY ENGAGEMENT" in send.await_args.args[0]
    assert len(events)==1 and events[0].status=="sent" and events[0].message_id=="message-123"
    asyncio.run(engine.dispose())


def test_concurrent_same_test_run_id_sends_once(monkeypatch,tmp_path):
    from unittest.mock import AsyncMock
    from uuid import uuid4
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"member-test-concurrent.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False);monkeypatch.setattr(me,"SessionLocal",factory)
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        async with factory() as session:
            session.add(ChannelConfig(guild_id="700",name="TEST_CHANNEL_ID",channel_id="900"))
            session.add(CommunityEngagementMember(guild_id="700",user_id="11",display_name="Safe Member"))
            await session.commit()
    asyncio.run(setup())
    target=SimpleNamespace(id=11,bot=False,display_name="Safe Member")
    guild=SimpleNamespace(id=700,name="HEX TEST",get_member=lambda _uid:target,fetch_member=None)
    bot=SimpleNamespace(user=SimpleNamespace(id=99),get_guild=lambda _gid:guild)
    monkeypatch.setattr(me,"get_test_mode",lambda:True)
    monkeypatch.setattr(me,"read_settings",AsyncMock(return_value={"member_engagement":{}}))
    generate=AsyncMock(return_value="One test style 👋")
    monkeypatch.setattr(me,"generate_text",generate)
    message=SimpleNamespace(id="message-once",nonce="",author=bot.user)
    send=AsyncMock(return_value=message)
    monkeypatch.setattr(me,"community_channel",AsyncMock(return_value=SimpleNamespace(id=900,name="hex-alert-test",send=send)))
    monkeypatch.setattr(me,"individual_allowed_mentions",lambda _target:"only-selected-user")
    run_id=str(uuid4())
    async def exercise():
        return await asyncio.gather(*(me.member_engagement.test_send(bot,"700","11","friendly",run_id) for _ in range(3)))
    results=asyncio.run(exercise())
    async def count_events():
        async with factory() as session:
            return len((await session.scalars(select(CommunityEngagementEvent).where(
                CommunityEngagementEvent.test_run_id==run_id,CommunityEngagementEvent.status=="sent"))).all())
    assert asyncio.run(count_events())==1
    assert send.await_count==1
    assert generate.await_count==1
    assert len({result.get("message_id") for result in results if result.get("status")=="sent"})==1
    asyncio.run(engine.dispose())


def test_successful_discord_send_recovers_pending_event_without_resending(monkeypatch,tmp_path):
    from unittest.mock import AsyncMock
    from uuid import uuid4
    import hashlib
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"member-test-recovery.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False);monkeypatch.setattr(me,"SessionLocal",factory)
    run_id=str(uuid4());nonce=hashlib.sha256(f"700:member_engagement_test:{run_id}".encode()).hexdigest()[:24]
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        async with factory() as session:
            session.add_all([
                ChannelConfig(guild_id="700",name="TEST_CHANNEL_ID",channel_id="900"),
                CommunityEngagementMember(guild_id="700",user_id="11",display_name="Safe Member"),
                CommunityEngagementEvent(guild_id="700",channel_id="900",target_user_id="11",event_type="TEST",
                    style="friendly",content_hash="pending-hash",status="pending",test_run_id=run_id,
                    action_type="member_engagement_test"),
            ])
            await session.commit()
    asyncio.run(setup())
    target=SimpleNamespace(id=11,bot=False,display_name="Safe Member")
    guild=SimpleNamespace(id=700,name="HEX TEST",get_member=lambda _uid:target,fetch_member=None)
    bot=SimpleNamespace(user=SimpleNamespace(id=99),get_guild=lambda _gid:guild)
    recovered=SimpleNamespace(id="discord-already-sent",nonce=nonce,author=bot.user)
    async def history(*,limit):
        yield recovered
    send=AsyncMock()
    channel=SimpleNamespace(id=900,name="hex-alert-test",history=history,send=send)
    monkeypatch.setattr(me,"get_test_mode",lambda:True)
    monkeypatch.setattr(me,"read_settings",AsyncMock(return_value={"member_engagement":{}}))
    monkeypatch.setattr(me,"community_channel",AsyncMock(return_value=channel))
    monkeypatch.setattr(me,"individual_allowed_mentions",lambda _target:"only-selected-user")
    result=asyncio.run(me.member_engagement.test_send(bot,"700","11","shayari",run_id))
    assert result["status"]=="sent" and result["message_id"]=="discord-already-sent"
    assert result["reused"] is True and send.await_count==0
    async def read_event():
        async with factory() as session:
            return await session.scalar(select(CommunityEngagementEvent).where(CommunityEngagementEvent.test_run_id==run_id))
    event=asyncio.run(read_event())
    assert event.status=="sent" and event.message_id=="discord-already-sent"
    asyncio.run(engine.dispose())


def test_send_success_then_database_error_recovers_same_discord_message(monkeypatch,tmp_path):
    from unittest.mock import AsyncMock
    from uuid import uuid4
    import hashlib
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"member-test-db-recovery.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False)
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        async with factory() as session:
            session.add_all([ChannelConfig(guild_id="700",name="TEST_CHANNEL_ID",channel_id="900"),
                CommunityEngagementMember(guild_id="700",user_id="11",display_name="Safe Member")])
            await session.commit()
    asyncio.run(setup())
    run_id=str(uuid4());nonce=hashlib.sha256(f"700:member_engagement_test:{run_id}".encode()).hexdigest()[:24]
    commit_count={"value":0}
    class SessionProxy:
        def __init__(self):self.session=factory()
        async def __aenter__(self):await self.session.__aenter__();return self
        async def __aexit__(self,*args):return await self.session.__aexit__(*args)
        def __getattr__(self,name):return getattr(self.session,name)
        async def commit(self):
            commit_count["value"]+=1
            if commit_count["value"]==2:raise RuntimeError("transient database failure after Discord accepted send")
            await self.session.commit()
    monkeypatch.setattr(me,"SessionLocal",SessionProxy)
    target=SimpleNamespace(id=11,bot=False,display_name="Safe Member")
    guild=SimpleNamespace(id=700,name="HEX TEST",get_member=lambda _uid:target,fetch_member=None)
    bot=SimpleNamespace(user=SimpleNamespace(id=99),get_guild=lambda _gid:guild)
    sent=[]
    async def capture_send(*args,**kwargs):
        message=SimpleNamespace(id="discord-accepted-once",nonce=kwargs["nonce"],author=bot.user)
        sent.append(message)
        return message
    async def history(*,limit):
        for message in sent:yield message
    channel=SimpleNamespace(id=900,name="hex-alert-test",send=AsyncMock(side_effect=capture_send),history=history)
    monkeypatch.setattr(me,"get_test_mode",lambda:True)
    monkeypatch.setattr(me,"read_settings",AsyncMock(return_value={"member_engagement":{}}))
    monkeypatch.setattr(me,"generate_text",AsyncMock(return_value="One selected style 👋"))
    monkeypatch.setattr(me,"community_channel",AsyncMock(return_value=channel))
    monkeypatch.setattr(me,"individual_allowed_mentions",lambda _target:"only-selected-user")
    async def exercise():
        first=await me.member_engagement.test_send(bot,"700","11","friendly",run_id)
        second=await me.member_engagement.test_send(bot,"700","11","shayari",run_id)
        return first,second
    first,second=asyncio.run(exercise())
    assert first["status"]=="pending" and first["message_id"]=="discord-accepted-once"
    assert second["status"]=="sent" and second["message_id"]=="discord-accepted-once"
    assert channel.send.await_count==1
    assert commit_count["value"]==3
    asyncio.run(engine.dispose())


def test_unknown_send_outcome_same_request_id_never_retries_send(monkeypatch,tmp_path):
    from unittest.mock import AsyncMock
    from uuid import uuid4
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"member-test-unknown.db").resolve())))
    factory=async_sessionmaker(engine,expire_on_commit=False);monkeypatch.setattr(me,"SessionLocal",factory)
    async def setup():
        async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        async with factory() as session:
            session.add_all([ChannelConfig(guild_id="700",name="TEST_CHANNEL_ID",channel_id="900"),
                CommunityEngagementMember(guild_id="700",user_id="11",display_name="Safe Member")])
            await session.commit()
    asyncio.run(setup())
    target=SimpleNamespace(id=11,bot=False,display_name="Safe Member")
    guild=SimpleNamespace(id=700,name="HEX TEST",get_member=lambda _uid:target,fetch_member=None)
    bot=SimpleNamespace(user=SimpleNamespace(id=99),get_guild=lambda _gid:guild)
    async def history(*,limit):
        if False: yield None
    send=AsyncMock(side_effect=RuntimeError("uncertain delivery"))
    channel=SimpleNamespace(id=900,name="hex-alert-test",history=history,send=send)
    monkeypatch.setattr(me,"get_test_mode",lambda:True)
    monkeypatch.setattr(me,"read_settings",AsyncMock(return_value={"member_engagement":{}}))
    monkeypatch.setattr(me,"generate_text",AsyncMock(return_value="One style only 👋"))
    monkeypatch.setattr(me,"community_channel",AsyncMock(return_value=channel))
    monkeypatch.setattr(me,"individual_allowed_mentions",lambda _target:"only-selected-user")
    run_id=str(uuid4())
    async def exercise():
        first=await me.member_engagement.test_send(bot,"700","11","friendly",run_id)
        second=await me.member_engagement.test_send(bot,"700","11","shayari",run_id)
        return first,second
    first,second=asyncio.run(exercise())
    assert first["status"]=="pending" and second["status"]=="pending"
    assert second["reused"] is True and send.await_count==1
    asyncio.run(engine.dispose())

