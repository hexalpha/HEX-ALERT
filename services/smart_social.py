"""Low-frequency, opt-in Discord reactions and social replies.

Only aggregate counters and delivery metadata are persisted. Message text is used
transiently for classification or a selected reply and is never written to disk.
"""
from __future__ import annotations

import asyncio
import logging
import random
import re
from datetime import datetime, timedelta, timezone

import discord
from sqlalchemy import select, func

from database.db import SessionLocal
from database.models import CommunityConfig, SocialInteractionMember, SocialInteractionEvent

log = logging.getLogger("hexalert.smart_social")

GENERIC_REACTIONS = ("👍", "😄", "🔥", "👀")
REACTION_GROUPS = {
    "funny": ("😂", "🤣", "😄"),
    "cool": ("😎", "🔥", "💯"),
    "cyber": ("🛡️", "💻", "🔐", "👾"),
    "thinking": ("👀", "🤔", "🧠"),
    "success": ("✅", "🚀", "👏"),
    "friendly": ("😄", "👋", "❤️"),
}
SAFE_REPLIES = (
    "😎 Solid one! 🔥", "😂 HEX ALPHA approves this message.",
    "🛡️ Cyber squad energy detected. 🔥", "👀 Interesting...",
)
SENSITIVE_RE = re.compile(
    r"\b(passwords?|passwds?|passcode|api[ _-]?key|access[ _-]?tokens?|tokens?|secrets?|private key|bearer|"
    r"confidential|confidentiality|ssn|credit card|bank account|otp|one.time password|"
    r"suicid|self.harm|abuse|doxx|doxing|moderator|moderation|ban appeal|reporting a user|"
    r"grief|bereavement|death in the family|hospital|seriously ill|depressed|anxiety attack|"
    r"panic attack|break.up|divorce|harassment|emergency)\b",
    re.I,
)
MENTION_RE = re.compile(r"<@!?\d+>|<@&\d+>|@everyone|@here", re.I)
_guild_locks: dict[str, asyncio.Lock] = {}


def social_defaults():
    return {
        "enabled": False,
        "normal_reaction_probability": 25,
        "auto_reply_probability": 5,
        "mention_reactions_enabled": True,
        "reaction_user_hour_limit": 3,
        "reaction_channel_hour_limit": 15,
        "reply_user_cooldown_minutes": 30,
        "reply_channel_hour_limit": 3,
        "reply_server_hour_limit": 6,
        "use_ai_replies": True,
        "channels": {},
        "excluded_channel_ids": [],
        "excluded_role_ids": [],
        "excluded_member_ids": [],
    }


def normalize_social(raw):
    value = social_defaults()
    if isinstance(raw, dict):
        value.update({k: v for k, v in raw.items() if k in value})
    for key in ("normal_reaction_probability", "auto_reply_probability"):
        try: value[key] = max(0, min(100, int(value[key])))
        except (TypeError, ValueError): value[key] = social_defaults()[key]
    value["auto_reply_probability"] = min(15, value["auto_reply_probability"])
    bounds = {
        "reaction_user_hour_limit": (1, 20), "reaction_channel_hour_limit": (1, 100),
        "reply_user_cooldown_minutes": (5, 1440), "reply_channel_hour_limit": (1, 20),
        "reply_server_hour_limit": (1, 100),
    }
    for key, (low, high) in bounds.items():
        try: value[key] = max(low, min(high, int(value[key])))
        except (TypeError, ValueError): value[key] = social_defaults()[key]
    value["enabled"] = bool(value["enabled"])
    value["mention_reactions_enabled"] = bool(value["mention_reactions_enabled"])
    value["use_ai_replies"] = bool(value["use_ai_replies"])
    if not isinstance(value.get("channels"), dict): value["channels"] = {}
    value["channels"] = {
        str(channel_id): {"reactions_enabled": bool((cfg or {}).get("reactions_enabled", False)),
                          "auto_replies_enabled": bool((cfg or {}).get("auto_replies_enabled", False))}
        for channel_id, cfg in value["channels"].items() if str(channel_id).isdigit() and isinstance(cfg, dict)
    }
    for key in ("excluded_channel_ids", "excluded_role_ids", "excluded_member_ids"):
        raw_ids = value.get(key)
        if not isinstance(raw_ids, (list, tuple, set)): raw_ids = []
        value[key] = list(dict.fromkeys(str(x) for x in raw_ids if str(x).isdigit()))[:500]
    return value


def channel_policy(settings, channel):
    channel_id = str(getattr(channel, "id", ""))
    parent = getattr(channel, "parent", None)
    parent_id = str(getattr(parent, "id", "")) if parent else ""
    return settings["channels"].get(channel_id) or settings["channels"].get(parent_id) or {}


def select_reaction(message_context, rng=None):
    """Return exactly one valid emoji; safe generic pool when content is unavailable."""
    content = message_context if isinstance(message_context, str) else getattr(message_context, "content", None)
    if not isinstance(content, str): return random.choice(GENERIC_REACTIONS) if rng is None else rng.choice(GENERIC_REACTIONS)
    text = content.casefold()
    if re.search(r"\b(lol|lmao|haha|rofl|😂|🤣|joke|funny)\b", text): group = "funny"
    elif re.search(r"\b(kali|linux|cyber|security|hacker|ctf|vulnerability|exploit|soc|vapt)\b", text): group = "cyber"
    elif re.search(r"\b(congrats|passed|finished|built|shipped|success|won|achievement)\b", text): group = "success"
    elif "?" in text or re.search(r"\b(what|why|how|which|anyone know)\b", text): group = "thinking"
    elif re.search(r"\b(hi|hello|hey|thanks|thank you|good morning)\b", text): group = "friendly"
    elif re.search(r"\b(cool|nice|awesome|fire|great|bro is cooking)\b", text): group = "cool"
    else: group = "generic"
    pool = REACTION_GROUPS.get(group, GENERIC_REACTIONS)
    return random.choice(pool) if rng is None else rng.choice(pool)


def classify_social_reply(content):
    """Conservative deterministic gate. Most normal messages are ignored."""
    if not isinstance(content, str) or not content.strip(): return "IGNORE"
    if SENSITIVE_RE.search(content): return "IGNORE"
    if re.search(r"\b(what|why|how|which|anyone know|does anyone|can someone)\b", content, re.I):
        return "REACT_ONLY"
    if len(content) > 1200: return "IGNORE"
    return "SHORT_REPLY"


def _allowed_mentions(author):
    return discord.AllowedMentions(users=[author], roles=False, everyone=False, replied_user=False)


def _safe_reply_text(value):
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(value or ""))
    text = MENTION_RE.sub("", text).replace("@", "")
    text = re.sub(r"\s+", " ", text).strip()[:150]
    if not text or "\ufffd" in text or re.fullmatch(r"\?{2,}", text): return random.choice(SAFE_REPLIES)
    if not any(ord(char) > 127 for char in text): text += " 😄"
    return text


class SmartSocial:
    def __init__(self):
        self.random = random.SystemRandom()

    async def config(self, guild_id):
        async with SessionLocal() as session:
            row = await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id == str(guild_id)))
        from services.community import merge_settings
        return normalize_social(merge_settings(row.settings if row else None).get("smart_social"))

    async def set_opt_out(self, guild_id, user_id, opted_out):
        async with SessionLocal() as session:
            row = await session.scalar(select(SocialInteractionMember).where(
                SocialInteractionMember.guild_id == str(guild_id), SocialInteractionMember.user_id == str(user_id)))
            if row is None:
                row = SocialInteractionMember(guild_id=str(guild_id), user_id=str(user_id))
                session.add(row)
            row.opted_out = bool(opted_out)
            await session.commit()

    async def _is_opted_out(self, guild_id, user_id):
        async with SessionLocal() as session:
            row = await session.scalar(select(SocialInteractionMember).where(
                SocialInteractionMember.guild_id == str(guild_id), SocialInteractionMember.user_id == str(user_id)))
            return bool(row and row.opted_out)

    @staticmethod
    def _permissions(message):
        guild = getattr(message, "guild", None)
        channel = getattr(message, "channel", None)
        bot_member = getattr(guild, "me", None)
        if not (channel and bot_member and hasattr(channel, "permissions_for")): return None
        try: return channel.permissions_for(bot_member)
        except Exception: return None

    async def mention_reaction(self, message, *, thinking=False):
        """Non-blocking acknowledgement for explicit mention chat when configured."""
        if not getattr(message, "guild", None) or getattr(message, "webhook_id", None): return False
        from config.settings import get_settings
        from services.community import CommunityAutomation
        if get_settings().test_mode or CommunityAutomation._automation_paused('smart_social'): return False
        author = getattr(message, "author", None)
        if not author or getattr(author, "bot", False): return False
        cfg = await self.config(message.guild.id)
        if not cfg["enabled"] or not cfg["mention_reactions_enabled"]: return False
        policy = channel_policy(cfg, message.channel)
        if not policy.get("reactions_enabled") or str(message.channel.id) in cfg["excluded_channel_ids"]: return False
        return await self._react(message, "👀" if thinking else "👋", kind="MENTION_REACTION",
                                 enforce_limits=False, respect_optout=False)

    async def _reserve(self, message, event_kind, *, settings, enforce_limits, respect_optout=True):
        guild_id, channel_id, user_id = (str(message.guild.id), str(message.channel.id), str(message.author.id))
        now = datetime.now(timezone.utc)
        lock = _guild_locks.setdefault(guild_id, asyncio.Lock())
        async with lock:
            async with SessionLocal() as session:
                member = await session.scalar(select(SocialInteractionMember).where(
                    SocialInteractionMember.guild_id == guild_id, SocialInteractionMember.user_id == user_id))
                if member is None:
                    member = SocialInteractionMember(guild_id=guild_id, user_id=user_id)
                    session.add(member)
                    await session.flush()
                if respect_optout and member.opted_out: return None
                # A manual test bypasses rate limits, but it must not replay the
                # same action on one human message after a retry or double click.
                source_id=str(getattr(message, "id", ""))
                if source_id:
                    duplicate=await session.scalar(select(SocialInteractionEvent.id).where(
                        SocialInteractionEvent.guild_id==guild_id,
                        SocialInteractionEvent.channel_id==channel_id,
                        SocialInteractionEvent.source_message_id==source_id,
                        SocialInteractionEvent.event_kind==event_kind,
                        SocialInteractionEvent.status.in_(["pending", "sent"])).limit(1))
                    if duplicate: return None
                if enforce_limits:
                    since = now - timedelta(hours=1)
                    recent = select(SocialInteractionEvent).where(
                        SocialInteractionEvent.status.in_(["pending", "sent"]),
                        SocialInteractionEvent.created_at >= since)
                    sub = recent.subquery()
                    if event_kind == "REACTION":
                        per_user = await session.scalar(select(func.count()).select_from(sub).where(
                            sub.c.guild_id == guild_id, sub.c.user_id == user_id, sub.c.event_kind == "REACTION"))
                        per_channel = await session.scalar(select(func.count()).select_from(sub).where(
                            sub.c.guild_id == guild_id, sub.c.channel_id == channel_id, sub.c.event_kind == "REACTION"))
                        if (per_user or 0) >= settings["reaction_user_hour_limit"] or (per_channel or 0) >= settings["reaction_channel_hour_limit"]:
                            session.add(SocialInteractionEvent(guild_id=guild_id, channel_id=channel_id, user_id=user_id,
                                source_message_id=str(getattr(message, "id", "")), event_kind=event_kind,
                                status="limited", created_at=now))
                            await session.commit()
                            return None
                    else:
                        cooldown = now - timedelta(minutes=settings["reply_user_cooldown_minutes"])
                        last = await session.scalar(select(func.max(SocialInteractionEvent.created_at)).where(
                            SocialInteractionEvent.guild_id == guild_id, SocialInteractionEvent.user_id == user_id,
                            SocialInteractionEvent.event_kind == "SOCIAL_REPLY", SocialInteractionEvent.status.in_(["pending", "sent"])))
                        if last is not None and last.tzinfo is None: last = last.replace(tzinfo=timezone.utc)
                        channel_count = await session.scalar(select(func.count()).select_from(sub).where(
                            sub.c.guild_id == guild_id, sub.c.channel_id == channel_id, sub.c.event_kind == "SOCIAL_REPLY"))
                        server_count = await session.scalar(select(func.count()).select_from(sub).where(
                            sub.c.guild_id == guild_id, sub.c.event_kind == "SOCIAL_REPLY"))
                        if (last and last >= cooldown) or (channel_count or 0) >= settings["reply_channel_hour_limit"] or (server_count or 0) >= settings["reply_server_hour_limit"]:
                            session.add(SocialInteractionEvent(guild_id=guild_id, channel_id=channel_id, user_id=user_id,
                                source_message_id=str(getattr(message, "id", "")), event_kind=event_kind,
                                status="limited", created_at=now))
                            await session.commit()
                            return None
                event = SocialInteractionEvent(guild_id=guild_id, channel_id=channel_id, user_id=user_id,
                    source_message_id=str(getattr(message, "id", "")), event_kind=event_kind,
                    status="pending", created_at=now)
                session.add(event)
                await session.commit()
                return event.id

    async def _finish(self, event_id, *, status, reaction="", delivery_message_id=""):
        async with SessionLocal() as session:
            event = await session.get(SocialInteractionEvent, event_id)
            if event:
                event.status = status
                event.reaction = reaction
                event.delivery_message_id = str(delivery_message_id or "")
                member = await session.scalar(select(SocialInteractionMember).where(
                    SocialInteractionMember.guild_id == event.guild_id, SocialInteractionMember.user_id == event.user_id))
                if member and status == "sent":
                    if event.event_kind in {"REACTION", "MENTION_REACTION", "TEST_REACTION"}:
                        member.last_reaction_at = datetime.now(timezone.utc); member.reaction_count += 1
                    if event.event_kind in {"SOCIAL_REPLY", "TEST_REPLY"}:
                        member.last_social_reply_at = datetime.now(timezone.utc); member.reply_count += 1
                await session.commit()

    async def _react(self, message, reaction, *, kind="REACTION", enforce_limits=True, settings=None, respect_optout=True):
        if not message.guild or not message.author or message.author.bot or getattr(message, "webhook_id", None): return False
        perms = self._permissions(message)
        if not perms or not getattr(perms, "view_channel", False) or not getattr(perms, "add_reactions", False): return False
        cfg = settings or await self.config(message.guild.id)
        event_id = await self._reserve(message, kind, settings=cfg, enforce_limits=enforce_limits,
                                      respect_optout=respect_optout)
        if event_id is None: return False
        try:
            await message.add_reaction(reaction)
        except (discord.Forbidden, discord.HTTPException) as exc:
            await self._finish(event_id, status="failed", reaction=reaction)
            log.info("Social reaction failed (%s)", type(exc).__name__)
            return False
        await self._finish(event_id, status="sent", reaction=reaction)
        return True

    async def process_message(self, message):
        """Run low-frequency social behavior; explicit mentions are owned by AIChat."""
        author = getattr(message, "author", None)
        guild = getattr(message, "guild", None)
        if not guild or not author or author.bot or getattr(message, "webhook_id", None): return {"status": "ignored"}
        if getattr(message, "mention_everyone", False): return {"status": "mass_mention_ignored"}
        bot = getattr(getattr(message, "_state", None), "_get_client", lambda: None)()
        bot_user = getattr(bot, 'user', None)
        if bot_user and any(str(getattr(user,'id',''))==str(bot_user.id) for user in (getattr(message,'mentions',()) or ())):
            return {"status":"explicit_mention_owned"}
        from services.community import CommunityAutomation
        if CommunityAutomation._automation_paused('smart_social'): return {"status":"paused"}
        from config.settings import get_settings
        if get_settings().test_mode: return {"status":"test_mode_paused"}
        cfg = await self.config(guild.id)
        if not cfg["enabled"]: return {"status": "disabled"}
        channel_id = str(getattr(message.channel, "id", ""))
        policy = channel_policy(cfg, message.channel)
        if channel_id in cfg["excluded_channel_ids"]: return {"status": "channel_excluded"}
        if not policy.get("reactions_enabled") and not policy.get("auto_replies_enabled"): return {"status": "channel_disabled"}
        member = getattr(message, "author", None)
        role_ids = {str(role.id) for role in (getattr(member, "roles", ()) or ())}
        if str(member.id) in cfg["excluded_member_ids"] or role_ids.intersection(cfg["excluded_role_ids"]): return {"status": "member_excluded"}
        if await self._is_opted_out(guild.id, member.id): return {"status": "opted_out"}
        content_intent = bool(getattr(getattr(bot, "intents", None), "message_content", False))
        content = getattr(message, "content", None)
        content_available = content_intent and isinstance(content, str)
        if content_available and re.search(r"@everyone|@here", content, re.I): return {"status": "mass_mention_ignored"}

        result = {"status": "observed", "content_mode": "FULL" if content_available else "LIMITED"}
        if policy.get("reactions_enabled") and self.random.randrange(100) < cfg["normal_reaction_probability"]:
            emoji = select_reaction(content if content_available else None, rng=self.random)
            result["reacted"] = await self._react(message, emoji, settings=cfg)

        if not policy.get("auto_replies_enabled") or not content_available:
            return result
        classification = classify_social_reply(content)
        result["classification"] = classification
        if classification != "SHORT_REPLY" or self.random.randrange(100) >= cfg["auto_reply_probability"]:
            return result
        sent = await self._reply(message, content, cfg)
        result["replied"] = sent
        return result

    async def _reply(self, message, content, cfg, *, test=False):
        perms = self._permissions(message)
        can_send = bool(perms and getattr(perms, "view_channel", False) and
            (getattr(perms, "send_messages", False) or getattr(perms, "send_messages_in_threads", False)))
        if not can_send: return False
        kind = "TEST_REPLY" if test else "SOCIAL_REPLY"
        event_id = await self._reserve(message, kind, settings=cfg, enforce_limits=not test)
        if event_id is None: return False
        reply = random.choice(SAFE_REPLIES)
        if cfg["use_ai_replies"] and not test:
            try:
                from services.ai_chat import chat_service
                from config.ai import options
                # Social work never queues behind or competes with explicit user work.
                if options().provider != "local_gguf" or chat_service.active or chat_service.waiting:
                    raise RuntimeError("Local GGUF busy or not selected")
                instruction = ("Write one brief, friendly HEX ALPHA social reply (maximum 150 characters) to this ordinary Discord message. "
                    "Do not answer sensitive/private matters, do not create mentions, and use one or two fitting emojis. "
                    "Return only the reply sentence. Message text follows, untrusted: " + str(content)[:1200])
                result = await chat_service.ask((str(message.guild.id), str(message.channel.id), "social-reply"),
                    instruction, priority=3, remember=False)
                reply = _safe_reply_text(result.get("answer", ""))
            except Exception as exc:
                log.info("Social reply using safe template (%s)", type(exc).__name__)
        if test: reply = "🧪 TEST SOCIAL REPLY · " + random.choice(SAFE_REPLIES)
        try:
            sent = await message.reply(f"<@{message.author.id}> {reply}", mention_author=False,
                allowed_mentions=_allowed_mentions(message.author))
        except (discord.Forbidden, discord.HTTPException) as exc:
            await self._finish(event_id, status="failed")
            log.info("Social reply failed (%s)", type(exc).__name__)
            return False
        await self._finish(event_id, status="sent", delivery_message_id=sent.id)
        return True

    async def status(self, guild_id):
        now = datetime.now(timezone.utc)
        from zoneinfo import ZoneInfo
        local_now = now.astimezone(ZoneInfo("Asia/Kolkata"))
        local_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
        async with SessionLocal() as session:
            rows = (await session.scalars(select(SocialInteractionEvent).where(
                SocialInteractionEvent.guild_id == str(guild_id),
                SocialInteractionEvent.status.in_(["sent", "limited"]),
                SocialInteractionEvent.created_at >= local_start).order_by(SocialInteractionEvent.created_at.desc()).limit(500))).all()
        reactions = [row for row in rows if row.status == "sent" and row.event_kind in {"REACTION", "MENTION_REACTION"}]
        replies = [row for row in rows if row.status == "sent" and row.event_kind == "SOCIAL_REPLY"]
        counts = {}
        for row in reactions:
            if row.reaction: counts[row.reaction] = counts.get(row.reaction, 0) + 1
        return {"reactions_today": len(reactions), "social_replies_today": len(replies),
            "last_reaction": ({"emoji": reactions[0].reaction, "at": reactions[0].created_at.isoformat()} if reactions else None),
            "last_social_reply": ({"at": replies[0].created_at.isoformat(), "message_id": replies[0].delivery_message_id} if replies else None),
            "most_used_emoji": max(counts, key=counts.get) if counts else None,
            "rate_limited_today": sum(1 for row in rows if row.status == "limited")}


smart_social = SmartSocial()
