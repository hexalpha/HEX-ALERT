from types import SimpleNamespace
from unittest.mock import AsyncMock
from pathlib import Path

import discord
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from database.models import Alert, Base, ChannelConfig, NewsArticle, SentMessage
from services import dispatcher as dispatcher_module
from services import discord_routing as routing_module
from services.discord_routing import (RoutingError, category_for_item, normalize_category,
                                      resolve_discord_channel)
from services.dispatcher import DiscordDispatcher


def test_routing_matrix_uses_the_rendered_category_attribute():
    script = (Path(__file__).parents[1] / "api" / "static" / "app.js").read_text(encoding="utf-8")
    assert "data-route-test=\"${esc(r.category)}\"" in script
    assert "button.dataset.routeTest" in script
    assert "button.dataset.route}" not in script


def test_category_aliases_normalize_to_one_route():
    cases = {
        "CVE": "critical_cve", "critical-cve": "critical_cve",
        "critical_cvEs": "critical_cve", "jobs": "jobs", "job": "jobs",
        "threat-intelligence": "threat_intel", "threat": "threat_intel",
        "tech": "technology", "github": "github_tools",
        "security-research": "security_research", "test_alerts": "test_alerts",
    }
    for source, expected in cases.items():
        assert normalize_category(source) == expected


def test_item_route_does_not_assume_kev_is_zero_day():
    cve = SimpleNamespace(exploited="YES", verified_zero_day=False)
    assert category_for_item("cve", cve) == "critical_cve"
    cve.verified_zero_day = True
    assert category_for_item("critical-CVEs", cve) == "zero_day"


@pytest.mark.asyncio
async def test_resolver_uses_postgres_mapping_and_checks_permissions():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(ChannelConfig(guild_id="17", name="NEWS_CHANNEL_ID", channel_id="202"))
        await session.commit()

    member = object()
    permissions = SimpleNamespace(view_channel=True, send_messages=True, embed_links=True,
                                  read_message_history=True)
    channel = SimpleNamespace(id=202, name="cyber-news", guild=None,
                              permissions_for=lambda _: permissions)
    guild = SimpleNamespace(id=17, me=member, get_channel=lambda cid: channel if cid == 202 else None)
    channel.guild = guild
    bot = SimpleNamespace(get_guild=lambda gid: guild if gid == 17 else None)
    try:
        route = await resolve_discord_channel("Cybersecurity News", "17", bot=bot,
                                              session_factory=sessions)
        assert (route.category, route.channel_name, route.channel_id) == ("news", "cyber-news", "202")
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_resolver_never_falls_back_to_test_channel():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(ChannelConfig(guild_id="17", name="TEST_CHANNEL_ID", channel_id="999"))
        await session.commit()

    bot = SimpleNamespace(get_guild=lambda _gid: None)
    try:
        with pytest.raises(RoutingError, match="No PostgreSQL channel mapping exists for news"):
            await resolve_discord_channel("news", bot=bot, session_factory=sessions)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_jobs_deliver_uses_existing_job_embed_factory(monkeypatch):
    from config import runtime_config
    monkeypatch.setattr(runtime_config,"get_runtime_config",lambda:{"AUTONOMOUS_MODE":True,
        "AUTOPILOT_MODULES":{"jobs":True}})
    monkeypatch.setattr(dispatcher_module, "get_settings",
                        lambda: SimpleNamespace(test_mode=True, critical_cve_threshold=8.0))
    dispatcher = DiscordDispatcher(SimpleNamespace())
    dispatcher.post = AsyncMock(return_value=False)
    job = SimpleNamespace(
        id=1, posted_to_discord=False, title="SOC Analyst Intern", company="Example",
        location="Remote", experience="Fresher", employment_type="Internship", salary="Not public",
        skills=[], source="Public Feed", source_url="https://example.org/job/1", published_at=None,
        match_category="Fresher", description="Entry-level SOC role",
    )
    await dispatcher.deliver("jobs", [job])
    dispatcher.post.assert_awaited_once()
    args = dispatcher.post.await_args.args
    assert args[1] == "jobs"
    assert isinstance(args[2], discord.Embed)


@pytest.mark.asyncio
async def test_test_mode_suppresses_collector_alert_and_records_reason(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(dispatcher_module, "SessionLocal", sessions)
    monkeypatch.setattr(routing_module, "SessionLocal", sessions)
    monkeypatch.setattr(dispatcher_module, "get_settings",
                        lambda: SimpleNamespace(test_mode=True, critical_cve_threshold=8.0))
    bot = SimpleNamespace(get_channel=lambda _cid: pytest.fail("TEST_MODE must not resolve/send to test channel"))
    dispatcher = DiscordDispatcher(bot)
    item = SimpleNamespace(id=3, title="Security bulletin", source="Feed",
                           source_url="https://example.org/a", posted_to_discord=False)
    try:
        assert await dispatcher.post(item, "news", discord.Embed(title="Test")) is False
        async with sessions() as session:
            alert = await session.scalar(select(Alert).where(Alert.category == "news"))
            assert alert.status == "suppressed"
            assert alert.channel_id == ""
            assert "TEST_MODE" in alert.error
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_successful_mapped_send_persists_channel_name_and_message(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(dispatcher_module, "SessionLocal", sessions)
    monkeypatch.setattr(dispatcher_module, "get_settings",
                        lambda: SimpleNamespace(test_mode=False, critical_cve_threshold=8.0))

    class Channel:
        async def send(self, **_kwargs):
            return SimpleNamespace(id=98765)

    resolution = SimpleNamespace(category="news", guild_id="17", channel_id="202",
                                 channel_name="cyber-news", channel=Channel())
    monkeypatch.setattr(dispatcher_module, "resolve_discord_channel", AsyncMock(return_value=resolution))
    async with sessions() as session:
        item = NewsArticle(title="Security bulletin", summary="brief", category="Security News",
                           source="Feed", source_url="https://example.org/a", content_hash="a" * 64)
        session.add(item)
        await session.commit()
        item_id = item.id
    try:
        dispatcher = DiscordDispatcher(SimpleNamespace())
        async with sessions() as session:
            item = await session.get(NewsArticle, item_id)
        assert await dispatcher.post(item, "news", discord.Embed(title="News")) is True
        async with sessions() as session:
            alert = await session.scalar(select(Alert).where(Alert.message_id == "98765"))
            sent = await session.scalar(select(SentMessage).where(SentMessage.message_id == "98765"))
            assert alert.category == "news" and alert.channel_name == "cyber-news"
            assert alert.channel_id == "202" and alert.status == "sent"
            assert sent.guild_id == "17" and sent.channel_id == "202"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_missing_mapping_is_failed_not_redirected(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(dispatcher_module, "SessionLocal", sessions)
    monkeypatch.setattr(routing_module, "SessionLocal", sessions)
    monkeypatch.setattr(dispatcher_module, "get_settings",
                        lambda: SimpleNamespace(test_mode=False, critical_cve_threshold=8.0))
    monkeypatch.setattr(dispatcher_module, "resolve_discord_channel", resolve_discord_channel)
    bot = SimpleNamespace(get_guild=lambda _gid: None, get_channel=lambda _cid: pytest.fail("No test fallback"))
    item = SimpleNamespace(id=1, title="No route", source="Feed", source_url="https://example.org/no",
                           posted_to_discord=False)
    try:
        dispatcher = DiscordDispatcher(bot)
        assert await dispatcher.post(item, "news", discord.Embed(title="No route")) is False
        async with sessions() as session:
            alert = await session.scalar(select(Alert).where(Alert.category == "news"))
            assert alert.status == "failed" and alert.channel_id == ""
            assert "No PostgreSQL channel mapping" in alert.error
    finally:
        await engine.dispose()
