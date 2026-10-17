"""Canonical Discord alert categories and PostgreSQL-backed channel resolution."""
from __future__ import annotations

from dataclasses import dataclass
import re

import discord
from sqlalchemy import select

from database.db import SessionLocal
from database.models import ChannelConfig, CustomDiscordRoute


ROUTE_CHANNEL_KEYS = {
    "jobs": "JOB_CHANNEL_ID",
    "news": "NEWS_CHANNEL_ID",
    "critical_cve": "CVE_CHANNEL_ID",
    "zero_day": "ZERO_DAY_CHANNEL_ID",
    "threat_intel": "THREAT_CHANNEL_ID",
    "technology": "TECH_CHANNEL_ID",
    "github_tools": "GITHUB_TOOLS_CHANNEL_ID",
    "security_research": "RESEARCH_CHANNEL_ID",
    "daily_digest": "DIGEST_CHANNEL_ID",
    "bot_status": "STATUS_CHANNEL_ID",
    "test_alerts": "TEST_CHANNEL_ID",
}

_ALIASES = {
    "job": "jobs", "jobs": "jobs",
    "news": "news", "cybersecurity_news": "news", "article": "news", "articles": "news",
    "cve": "critical_cve", "cves": "critical_cve", "critical_cve": "critical_cve",
    "zero_day": "zero_day", "zeroday": "zero_day", "zerodays": "zero_day",
    "threat": "threat_intel", "threats": "threat_intel", "threat_intel": "threat_intel",
    "threat_intelligence": "threat_intel",
    "technology": "technology", "tech": "technology", "tool": "technology", "tools": "technology",
    "github": "github_tools", "github_tool": "github_tools", "github_tools": "github_tools",
    "research": "security_research", "security_research": "security_research",
    "daily_digest": "daily_digest", "digest": "daily_digest",
    "bot_status": "bot_status", "status": "bot_status",
    "test": "test_alerts", "test_alert": "test_alerts", "test_alerts": "test_alerts",
}


class RoutingError(RuntimeError):
    """A safe, user-displayable channel mapping or permission failure."""


@dataclass(frozen=True)
class ChannelResolution:
    category: str
    guild_id: str
    channel_id: str
    channel_name: str
    channel: discord.abc.Messageable


def normalize_category(category: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", str(category or "").strip().lower()).strip("_")
    # Mapping keys are accepted so old UI/database values remain compatible.
    key = re.sub(r"_?channel_id$", "", key)
    if key in {"cve_critical", "critical_cves", "critical_cve"}:
        key = "critical_cve"
    elif key in {"zero_day_alert", "zero_days"}:
        key = "zero_day"
    return _ALIASES.get(key, key)


def category_for_item(kind: str, item=None) -> str:
    category = normalize_category(kind)
    if category == "critical_cve":
        # A zero-day route requires an explicit, verified flag. CISA KEV alone
        # means known exploitation; it does not establish zero-day status.
        if getattr(item, "verified_zero_day", False) is True:
            return "zero_day"
        return "critical_cve"
    if category == "technology":
        candidate = " ".join(str(getattr(item, name, "") or "") for name in ("github_url", "source_url", "source"))
        if re.search(r"(?:github\.com|github security|github repo)", candidate, re.I):
            return "github_tools"
        if re.search(r"(?:arxiv\.org|security research|research paper)", candidate, re.I):
            return "security_research"
    return category


def route_storage_names(category: str) -> tuple[str, ...]:
    canonical = normalize_category(category)
    key = ROUTE_CHANNEL_KEYS.get(canonical)
    if not key:
        raise RoutingError(f"Unknown Discord alert category: {canonical or 'empty'}")
    aliases = {
        "critical_cve": (key, "critical_cve", "critical-cve", "cve", "CVE"),
        "zero_day": (key, "zero_day", "zero-day", "zero-day-alert"),
        "threat_intel": (key, "threat_intel", "threat-intelligence", "threat"),
        "technology": (key, "technology", "tech", "tool"),
        "github_tools": (key, "github_tools", "github-tools", "github"),
        "security_research": (key, "security_research", "security-research", "research"),
        "daily_digest": (key, "daily_digest", "daily-digest", "digest"),
        "bot_status": (key, "bot_status", "bot-status", "status"),
        "test_alerts": (key, "test_alerts", "test-alerts", "test"),
    }
    return aliases.get(canonical, (key, canonical))


def _missing_permissions(channel, guild) -> list[str]:
    member = getattr(guild, "me", None)
    if not member:
        return ["Bot member unavailable in mapped server"]
    try:
        permissions = channel.permissions_for(member)
    except (AttributeError, TypeError):
        return ["Unable to verify channel permissions"]
    return [name for attr, name in (
        ("view_channel", "View Channel"),
        ("send_messages", "Send Messages"),
        ("embed_links", "Embed Links"),
        ("read_message_history", "Read Message History"),
    ) if not getattr(permissions, attr, False)]


async def resolve_discord_channel(category: str, guild_id: str | None = None, *, bot=None,
                                  session_factory=None) -> ChannelResolution:
    """Resolve only a configured PostgreSQL category mapping; never test-fallback."""
    canonical = normalize_category(category)
    names = route_storage_names(canonical)
    if bot is None:
        raise RoutingError("Discord bot is unavailable")
    session_factory = session_factory or SessionLocal
    query = select(ChannelConfig).where(ChannelConfig.name.in_(names)).order_by(ChannelConfig.id.desc())
    if guild_id:
        query = query.where(ChannelConfig.guild_id == str(guild_id))
    async with session_factory() as session:
        rows = (await session.scalars(query)).all()
    if not rows:
        raise RoutingError(f"No PostgreSQL channel mapping exists for {canonical}")
    reasons = []
    for row in rows:
        if not row.channel_id.isdigit() or not row.guild_id.isdigit():
            reasons.append("Mapped guild/channel ID is invalid")
            continue
        guild = bot.get_guild(int(row.guild_id))
        if not guild:
            reasons.append(f"Mapped server {row.guild_id} is not connected")
            continue
        channel = guild.get_channel(int(row.channel_id))
        if channel is None:
            try:
                fetched = await bot.fetch_channel(int(row.channel_id))
                if getattr(getattr(fetched, "guild", None), "id", None) == int(row.guild_id):
                    channel = fetched
            except (discord.HTTPException, discord.Forbidden, discord.NotFound):
                channel = None
        if channel is None or getattr(getattr(channel, "guild", None), "id", None) != int(row.guild_id):
            reasons.append(f"Mapped channel {row.channel_id} is unavailable in server {row.guild_id}")
            continue
        missing = _missing_permissions(channel, guild)
        if missing:
            reasons.append("Missing permissions: " + ", ".join(missing))
            continue
        return ChannelResolution(canonical, row.guild_id, row.channel_id,
                                 str(getattr(channel, "name", row.channel_id)), channel)
    raise RoutingError("; ".join(dict.fromkeys(reasons)) or f"No usable mapped channel for {canonical}")


async def resolve_explicit_channel(channel_id: int | str, *, bot=None) -> ChannelResolution:
    """Validate a rule's explicitly configured channel without changing routes."""
    if bot is None:
        raise RoutingError("Discord bot is unavailable")
    try:
        cid = int(channel_id)
    except (TypeError, ValueError):
        raise RoutingError("Configured rule channel ID is invalid") from None
    channel = bot.get_channel(cid)
    if channel is None:
        try:
            channel = await bot.fetch_channel(cid)
        except (discord.HTTPException, discord.Forbidden, discord.NotFound):
            raise RoutingError(f"Configured rule channel {cid} is unavailable") from None
    guild = getattr(channel, "guild", None)
    if guild is None:
        raise RoutingError(f"Configured rule channel {cid} is not a guild channel")
    missing = _missing_permissions(channel, guild)
    if missing:
        raise RoutingError("Missing permissions: " + ", ".join(missing))
    return ChannelResolution("", str(guild.id), str(channel.id), str(channel.name), channel)


async def resolve_custom_route(route_key: str, *, bot=None, session_factory=None) -> tuple[CustomDiscordRoute, ChannelResolution]:
    """Resolve an enabled custom route and verify its configured guild and permissions."""
    key = str(route_key or "").strip().lower()
    if not key:
        raise RoutingError("Custom route key is empty")
    session_factory = session_factory or SessionLocal
    async with session_factory() as session:
        route = await session.scalar(select(CustomDiscordRoute).where(CustomDiscordRoute.route_key == key))
        if not route:
            raise RoutingError(f"Custom route '{key}' has no PostgreSQL mapping")
        if not route.enabled:
            raise RoutingError(f"Custom route '{key}' is disabled")
        row = CustomDiscordRoute(id=route.id, route_name=route.route_name, route_key=route.route_key,
                                 description=route.description, guild_id=route.guild_id,
                                 channel_id=route.channel_id, category=route.category,
                                 keywords=route.keywords, priority=route.priority,
                                 enabled=route.enabled, status=route.status)
    resolution = await resolve_explicit_channel(row.channel_id, bot=bot)
    if resolution.guild_id != row.guild_id:
        raise RoutingError(f"Custom route '{key}' channel does not belong to its configured server")
    return row, ChannelResolution(row.category, resolution.guild_id, resolution.channel_id,
                                  resolution.channel_name, resolution.channel)
