"""Safe, persistent Discord member directory with intent-aware reconciliation."""
import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from database.db import SessionLocal
from database.models import CommunityConfig, CommunityEngagementMember, DiscordMemberSyncState
from services.time_utils import utc_now

log = logging.getLogger("hexalert.member_directory")
_locks: dict[str, asyncio.Lock] = {}


def _lock(guild_id: str) -> asyncio.Lock:
    return _locks.setdefault(str(guild_id), asyncio.Lock())


def _safe_name(value, limit=80):
    value = " ".join(str(value or "").split())
    return value[:limit]


async def upsert_member(guild_id, member, *, active=True, interaction=False):
    """Upsert identity, roles and timestamps; message content is never accepted."""
    now = utc_now()
    user_id = str(member.id)
    async with SessionLocal() as session:
        row = await session.scalar(select(CommunityEngagementMember).where(
            CommunityEngagementMember.guild_id == str(guild_id),
            CommunityEngagementMember.user_id == user_id))
        if row is None:
            row = CommunityEngagementMember(guild_id=str(guild_id), user_id=user_id)
            session.add(row)
        row.username = _safe_name(getattr(member, "name", ""))
        row.display_name = _safe_name(getattr(member, "display_name", None) or getattr(member, "name", ""))
        row.is_bot = bool(getattr(member, "bot", False))
        row.is_active = bool(active)
        joined_at = getattr(member, "joined_at", None)
        if joined_at is not None:
            row.joined_at = joined_at
        row.role_ids = sorted({str(role.id) for role in getattr(member, "roles", ()) if getattr(role, "id", None) is not None})
        row.last_seen_at = now
        if interaction:
            row.last_interaction_at = now
            row.last_activity_at = now
            if row.last_nudged_at:
                row.last_response_at = now
        row.updated_at = now
        await session.commit()
    return row


async def record_interaction(guild_id, member):
    if not guild_id or not member or getattr(member, "bot", False):
        return
    await upsert_member(guild_id, member, active=True, interaction=True)


async def mark_left(guild_id, member):
    if not guild_id or not member:
        return
    await upsert_member(guild_id, member, active=False)


async def sync_guild(guild, *, bot_user_id=None, members_intent=None, force_fetch=True):
    """Full REST enumeration when privileged intent is enabled, cache-only otherwise."""
    guild_id = str(guild.id)
    async with _lock(guild_id):
        now = utc_now()
        full = bool(members_intent)
        # Discord.py exposes the active client intent on the guild state in supported versions.
        bot = getattr(guild, "_state", None)
        if members_intent is None and bot is not None and getattr(bot, "_client", None) is not None:
            full = bool(getattr(bot._client.intents, "members", full))
        state_status = "syncing"
        from services.member_engagement import normalize_settings
        async with SessionLocal() as session:
            config_row = await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id == guild_id))
        engagement = normalize_settings((config_row.settings if config_row and isinstance(config_row.settings, dict) else {}).get("member_engagement"))
        excluded_members = set(engagement["excluded_member_ids"])
        excluded_roles = set(engagement["excluded_role_ids"])
        async with SessionLocal() as session:
            state = await session.get(DiscordMemberSyncState, guild_id)
            if state is None:
                state = DiscordMemberSyncState(guild_id=guild_id)
                session.add(state)
            state.status = state_status
            state.last_attempt_at = now
            await session.commit()

        members = []
        full_success = False
        error_kind = ""
        if full and force_fetch:
            try:
                async for member in guild.fetch_members(limit=None):
                    members.append(member)
                full_success = True
            except Exception as exc:
                error_kind = type(exc).__name__
                log.warning("Member directory sync limited for guild %s (%s)", guild_id, error_kind)
        if not full_success:
            members = list(getattr(guild, "members", ()) or ())

        seen = set()
        for member in members:
            user_id = str(getattr(member, "id", ""))
            if not user_id or user_id in seen:
                continue
            seen.add(user_id)
            await upsert_member(guild_id, member, active=True)

        if full_success:
            async with SessionLocal() as session:
                rows = (await session.scalars(select(CommunityEngagementMember).where(
                    CommunityEngagementMember.guild_id == guild_id,
                    CommunityEngagementMember.is_active.is_(True)))).all()
                for row in rows:
                    if row.user_id not in seen:
                        row.is_active = False
                        row.updated_at = now
                await session.commit()

        async with SessionLocal() as session:
            rows = (await session.scalars(select(CommunityEngagementMember).where(
                CommunityEngagementMember.guild_id == guild_id))).all()
            humans = sum(1 for row in rows if row.is_active and not row.is_bot)
            bots = sum(1 for row in rows if row.is_active and row.is_bot)
            opted_out = sum(1 for row in rows if row.is_active and row.opted_out)
            eligible = sum(1 for row in rows if row.is_active and not row.is_bot and not row.opted_out
                           and str(row.user_id) != str(bot_user_id or "")
                           and row.user_id not in excluded_members
                           and not (set(str(x) for x in (row.role_ids or [])) & excluded_roles))
            state = await session.get(DiscordMemberSyncState, guild_id)
            state.status = "ready" if full_success else ("limited" if members or not error_kind else "unavailable")
            state.total_members = humans + bots
            state.human_members = humans
            state.bots_excluded = bots
            state.opted_out = opted_out
            state.eligible_members = eligible
            if full_success or not error_kind:
                state.last_sync_at = now
            state.updated_at = now
            await session.commit()
            result = {"guild_id": guild_id, "guild_name": _safe_name(getattr(guild, "name", ""), 100),
                      "status": state.status, "members_discovered": len(members), "humans": humans,
                      "bots_excluded": bots, "opted_out": opted_out, "eligible": eligible,
                      "last_sync_at": state.last_sync_at.isoformat() if state.last_sync_at else None,
                      "full_sync": full_success, "error": error_kind}
        log.info("Member directory sync guild=%s discovered=%d humans=%d bots_excluded=%d opted_out=%d eligible=%d status=%s",
                 guild_id, result["members_discovered"], result["humans"], result["bots_excluded"],
                 result["opted_out"], result["eligible"], result["status"])
        return result


async def reconcile_all(bot, *, force_fetch=True):
    results = []
    if not bot or not bot.is_ready():
        return results
    for guild in list(bot.guilds):
        try:
            results.append(await sync_guild(guild, bot_user_id=getattr(getattr(bot, "user", None), "id", None),
                                            members_intent=bool(getattr(getattr(bot, "intents", None), "members", False)),
                                            force_fetch=force_fetch))
        except Exception as exc:
            log.warning("Member directory reconciliation failed for guild %s (%s)", guild.id, type(exc).__name__)
    return results


async def directory_status(guild_id):
    async with SessionLocal() as session:
        state = await session.get(DiscordMemberSyncState, str(guild_id))
        rows = (await session.scalars(select(CommunityEngagementMember).where(
            CommunityEngagementMember.guild_id == str(guild_id)))).all()
    return {"status": state.status if state else "unavailable",
            "total": state.total_members if state else 0,
            "humans": state.human_members if state else sum(1 for r in rows if r.is_active and not r.is_bot),
            "bots_excluded": state.bots_excluded if state else sum(1 for r in rows if r.is_active and r.is_bot),
            "eligible": state.eligible_members if state else sum(1 for r in rows if r.is_active and not r.is_bot and not r.opted_out),
            "opted_out": state.opted_out if state else sum(1 for r in rows if r.is_active and r.opted_out),
            "last_sync_at": state.last_sync_at.isoformat() if state and state.last_sync_at else None,
            "last_attempt_at": state.last_attempt_at.isoformat() if state and state.last_attempt_at else None}


async def list_members(guild_id):
    async with SessionLocal() as session:
        rows = (await session.scalars(select(CommunityEngagementMember).where(
            CommunityEngagementMember.guild_id == str(guild_id)).order_by(
                CommunityEngagementMember.display_name, CommunityEngagementMember.username))).all()
    return [{"id": row.user_id, "username": row.username, "display_name": row.display_name,
             "is_bot": row.is_bot, "is_active": row.is_active, "joined_at": row.joined_at.isoformat() if row.joined_at else None,
             "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
             "last_interaction_at": row.last_interaction_at.isoformat() if row.last_interaction_at else None,
             "last_engagement_at": row.last_engagement_at.isoformat() if row.last_engagement_at else None,
             "opted_out": row.opted_out, "role_ids": list(row.role_ids or []),
             "eligible": row.is_active and not row.is_bot and not row.opted_out}
            for row in rows]
