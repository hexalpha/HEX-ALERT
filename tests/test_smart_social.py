import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import discord
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import URL

from database.models import Base, CommunityConfig, SocialInteractionMember, SocialInteractionEvent
from services import smart_social as social
from services import community


def test_social_defaults_are_off_and_replies_are_low_frequency():
    cfg = social.normalize_social({})
    assert cfg["enabled"] is False
    assert cfg["channels"] == {}
    assert cfg["normal_reaction_probability"] == 25
    assert cfg["auto_reply_probability"] == 5
    assert social.normalize_social({"auto_reply_probability": 100})["auto_reply_probability"] == 15


def test_reaction_selector_chooses_one_content_aware_or_generic_emoji():
    class First:
        def choice(self, values): return values[0]
    assert social.select_reaction("just installed Kali Linux", First()) == social.REACTION_GROUPS["cyber"][0]
    generic = social.select_reaction(None, First())
    assert generic in social.GENERIC_REACTIONS
    assert len(generic) > 0


def test_reply_classifier_is_conservative_and_ignores_sensitive_content():
    assert social.classify_social_reply("bro aaj kali linux install kiya") == "SHORT_REPLY"
    assert social.classify_social_reply("What is the latest CVE?") == "REACT_ONLY"
    for text in ("my password is abc", "here is my API token", "I have an emergency", "private key: x"):
        assert social.classify_social_reply(text) == "IGNORE"


def test_reply_sanitization_blocks_mentions_and_requires_unicode_emoji():
    safe = social._safe_reply_text("Nice @everyone <@123> <@&456>")
    assert "@everyone" not in safe and "<@" not in safe and "@here" not in safe
    assert any(ord(ch) > 127 for ch in safe)
    assert social._safe_reply_text("??") in social.SAFE_REPLIES


def test_allowed_mentions_only_allow_the_author():
    author = SimpleNamespace(id=12345)
    result = social._allowed_mentions(author).to_dict()
    assert result.get("users") == [12345]
    assert result.get("parse", []) == []
    assert not result.get("everyone") and not result.get("roles")


def test_database_optout_permission_and_content_limited_mode(tmp_path, monkeypatch):
    from config import runtime_config
    from config import settings as settings_module
    monkeypatch.setattr(runtime_config,"get_runtime_config",lambda:{"AUTONOMOUS_MODE":True,
        "AUTOPILOT_MODULES":{"smart_social":True}})
    monkeypatch.setattr(settings_module,'get_settings',lambda:SimpleNamespace(test_mode=False))
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str((tmp_path / "smart-social.db").resolve())))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(social, "SessionLocal", factory)
    monkeypatch.setattr(community, "SessionLocal", factory)

    class FixedRandom:
        def randrange(self, _n): return 0
        def choice(self, values): return values[0]
    monkeypatch.setattr(social.smart_social, "random", FixedRandom())

    async def setup():
        async with engine.begin() as connection: await connection.run_sync(Base.metadata.create_all)
    asyncio.run(setup())

    async def exercise():
        settings = community.default_community_settings()
        settings["smart_social"].update({"enabled": True, "normal_reaction_probability": 100,
            "auto_reply_probability": 15, "use_ai_replies": False,
            "channels": {"22": {"reactions_enabled": True, "auto_replies_enabled": True}}})
        async with factory() as session:
            session.add(CommunityConfig(guild_id="700", settings=settings))
            await session.commit()
        author = SimpleNamespace(id=11, bot=False, roles=[])
        bot_user = SimpleNamespace(intents=SimpleNamespace(message_content=False))
        channel = SimpleNamespace(id=22, parent=None, permissions_for=lambda _member: SimpleNamespace(
            view_channel=True, add_reactions=True, send_messages=True, send_messages_in_threads=False,
            read_message_history=True))
        guild = SimpleNamespace(id=700, me=object())
        message = SimpleNamespace(id=33, guild=guild, channel=channel, author=author, webhook_id=None,
            mention_everyone=False, content="bro aaj kali linux install kiya", _state=SimpleNamespace(_get_client=lambda: bot_user),
            add_reaction=AsyncMock(), reply=AsyncMock(return_value=SimpleNamespace(id=44)))
        result = await social.smart_social.process_message(message)
        assert result["content_mode"] == "LIMITED"
        assert result.get("reacted") is True
        assert "replied" not in result
        message.add_reaction.assert_awaited_once()
        await social.smart_social.set_opt_out(700, 11, True)
        ignored = await social.smart_social.process_message(message)
        assert ignored["status"] == "opted_out"
        async with factory() as session:
            preference = await session.scalar(__import__("sqlalchemy").select(SocialInteractionMember))
            events = (await session.scalars(__import__("sqlalchemy").select(SocialInteractionEvent))).all()
            assert preference.opted_out is True
            assert len(events) == 1 and not hasattr(events[0], "content")

    asyncio.run(exercise())
    asyncio.run(engine.dispose())


def test_full_content_replies_in_same_thread_with_scoped_author_tag(tmp_path, monkeypatch):
    from config import runtime_config
    from config import settings as settings_module
    monkeypatch.setattr(runtime_config,"get_runtime_config",lambda:{"AUTONOMOUS_MODE":True,
        "AUTOPILOT_MODULES":{"smart_social":True}})
    monkeypatch.setattr(settings_module,'get_settings',lambda:SimpleNamespace(test_mode=False))
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str((tmp_path / "social-reply.db").resolve())))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(social, "SessionLocal", factory)
    monkeypatch.setattr(community, "SessionLocal", factory)
    class FixedRandom:
        def randrange(self, _n): return 0
        def choice(self, values): return values[0]
    monkeypatch.setattr(social.smart_social, "random", FixedRandom())
    async def setup():
        async with engine.begin() as connection: await connection.run_sync(Base.metadata.create_all)
    asyncio.run(setup())

    async def exercise():
        settings = community.default_community_settings()
        settings["smart_social"].update({"enabled": True, "normal_reaction_probability": 0,
            "auto_reply_probability": 15, "use_ai_replies": False,
            "channels": {"22": {"reactions_enabled": False, "auto_replies_enabled": True}}})
        async with factory() as session:
            session.add(CommunityConfig(guild_id="700", settings=settings)); await session.commit()
        author = SimpleNamespace(id=11, bot=False, roles=[])
        bot_user = SimpleNamespace(intents=SimpleNamespace(message_content=True))
        channel = SimpleNamespace(id=23, parent=SimpleNamespace(id=22), permissions_for=lambda _member: SimpleNamespace(
            view_channel=True, add_reactions=True, send_messages=False, send_messages_in_threads=True,
            read_message_history=True))
        message = SimpleNamespace(id=33, guild=SimpleNamespace(id=700, me=object()), channel=channel,
            author=author, webhook_id=None, mention_everyone=False, content="bro aaj kali linux install kiya",
            _state=SimpleNamespace(_get_client=lambda: bot_user), reply=AsyncMock(return_value=SimpleNamespace(id=44)),
            add_reaction=AsyncMock())
        result = await social.smart_social.process_message(message)
        assert result["replied"] is True
        message.reply.assert_awaited_once()
        content = message.reply.await_args.args[0]
        kwargs = message.reply.await_args.kwargs
        assert content.startswith("<@11> ") and "TEST" not in content
        assert kwargs["allowed_mentions"].users == [author]
        assert kwargs["mention_author"] is False
        assert message.reply.await_args.args[0]
        async with factory() as session:
            event = await session.scalar(__import__("sqlalchemy").select(SocialInteractionEvent))
            assert event.event_kind == "SOCIAL_REPLY" and event.delivery_message_id == "44"
            assert event.channel_id == "23"  # reply stays in the source thread
            assert not hasattr(event, "content")

    asyncio.run(exercise())
    asyncio.run(engine.dispose())


def test_manual_social_test_does_not_repeat_one_action_on_the_same_message(tmp_path, monkeypatch):
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str((tmp_path / "social-test-dedupe.db").resolve())))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(social, "SessionLocal", factory)
    async def exercise():
        async with engine.begin() as connection: await connection.run_sync(Base.metadata.create_all)
        message=SimpleNamespace(id=33,guild=SimpleNamespace(id=700),channel=SimpleNamespace(id=22),author=SimpleNamespace(id=11))
        cfg=social.normalize_social({})
        first=await social.smart_social._reserve(message,"TEST_REPLY",settings=cfg,enforce_limits=False)
        second=await social.smart_social._reserve(message,"TEST_REPLY",settings=cfg,enforce_limits=False)
        distinct=await social.smart_social._reserve(message,"TEST_REACTION",settings=cfg,enforce_limits=False)
        assert first is not None and second is None and distinct is not None
        async with factory() as session:
            rows=(await session.scalars(__import__("sqlalchemy").select(SocialInteractionEvent))).all()
            assert len(rows)==2
    asyncio.run(exercise())
    asyncio.run(engine.dispose())


def test_pending_reactions_enforce_persisted_per_user_rate_limit(tmp_path, monkeypatch):
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str((tmp_path / "social-limits.db").resolve())))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(social, "SessionLocal", factory)
    async def setup():
        async with engine.begin() as connection: await connection.run_sync(Base.metadata.create_all)
    asyncio.run(setup())
    author = SimpleNamespace(id=11)
    guild = SimpleNamespace(id=700)
    channel = SimpleNamespace(id=22)
    def message(message_id):
        return SimpleNamespace(id=message_id, guild=guild, channel=channel, author=author)
    cfg = social.normalize_social({"reaction_user_hour_limit": 1})
    async def exercise():
        first = await social.smart_social._reserve(message(33), "REACTION", settings=cfg, enforce_limits=True)
        second = await social.smart_social._reserve(message(34), "REACTION", settings=cfg, enforce_limits=True)
        assert first is not None and second is None
        async with factory() as session:
            rows = (await session.scalars(__import__("sqlalchemy").select(SocialInteractionEvent).order_by(SocialInteractionEvent.id))).all()
            assert [row.status for row in rows] == ["pending", "limited"]
            assert all(not hasattr(row, "content") for row in rows)
    asyncio.run(exercise())
    asyncio.run(engine.dispose())


def test_pending_social_replies_enforce_cooldown_and_server_limits(tmp_path, monkeypatch):
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str((tmp_path / "social-reply-limits.db").resolve())))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(social, "SessionLocal", factory)
    async def setup():
        async with engine.begin() as connection: await connection.run_sync(Base.metadata.create_all)
    asyncio.run(setup())
    cfg = social.normalize_social({"reply_user_cooldown_minutes": 30, "reply_server_hour_limit": 1})
    def message(user_id, message_id):
        return SimpleNamespace(id=message_id, guild=SimpleNamespace(id=700), channel=SimpleNamespace(id=22),
            author=SimpleNamespace(id=user_id))
    async def exercise():
        first = await social.smart_social._reserve(message(11, 33), "SOCIAL_REPLY", settings=cfg, enforce_limits=True)
        second = await social.smart_social._reserve(message(11, 34), "SOCIAL_REPLY", settings=cfg, enforce_limits=True)
        other_user = await social.smart_social._reserve(message(12, 35), "SOCIAL_REPLY", settings=cfg, enforce_limits=True)
        assert first is not None and second is None and other_user is None
        async with factory() as session:
            statuses = (await session.scalars(__import__("sqlalchemy").select(SocialInteractionEvent.status).order_by(SocialInteractionEvent.id))).all()
            assert statuses == ["pending", "limited", "limited"]
    asyncio.run(exercise())
    asyncio.run(engine.dispose())


def test_bots_webhooks_and_mass_mentions_never_enter_social_classifier():
    async def exercise():
        guild = SimpleNamespace(id=700)
        channel = SimpleNamespace(id=22)
        bot_message = SimpleNamespace(guild=guild, channel=channel, author=SimpleNamespace(id=1, bot=True), webhook_id=None)
        webhook_message = SimpleNamespace(guild=guild, channel=channel, author=SimpleNamespace(id=2, bot=False), webhook_id=9)
        mass_message = SimpleNamespace(guild=guild, channel=channel, author=SimpleNamespace(id=3, bot=False), webhook_id=None, mention_everyone=True)
        assert (await social.smart_social.process_message(bot_message))["status"] == "ignored"
        assert (await social.smart_social.process_message(webhook_message))["status"] == "ignored"
        assert (await social.smart_social.process_message(mass_message))["status"] == "mass_mention_ignored"
    asyncio.run(exercise())
