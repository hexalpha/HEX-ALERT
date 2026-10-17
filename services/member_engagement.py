"""Safe, opt-in scheduled member engagement for HEX ALERT."""
import random
import re
import logging
import uuid
from datetime import datetime, timedelta, timezone, time
from zoneinfo import ZoneInfo

import discord
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from database.db import SessionLocal
from database.models import ChannelConfig, CommunityConfig, CommunityEngagementMember, CommunityEngagementEvent
from services.time_utils import utc_now
from services.community import merge_settings, _is_quiet, _safe_text, _digest
from services.ai_chat import chat_service

log = logging.getLogger("hexalert.engagement")
TZ = "Asia/Kolkata"
EXCLUDED_CHANNELS = {"critical-cve", "zero-day", "cyber-jobs", "bot-status", "security-research"}
STYLES = {
    "friendly": ["👋 Hey! Hope everything is going great. 😄 Free ho to server me ek hello drop kar dena. ✨"],
    "funny": ["😂 HEX ALPHA ne report kiya hai ki tumhari server activity mysteriously gayab ho gayi hai. 🔎 Ek hello se case close ho jayega. 😄"],
    "cyber_joke": ["🛡️ Session timeout hone wala tha kya? 😂 Server me reconnect karo aur batao aaj cyber world me kya chal raha hai. 💻"],
    "busy": ["👀 Kahan busy ho bhai? 😄 Zero-day hunt chal rahi hai ya real life ne CPU 100% kar diya? 💻🔥"],
    "question": ["🧠 Quick question: Red Team 🔴 ya Blue Team 🔵? Agar ek choose karni ho to kya choose karoge? 😄",
                 "💻 Favorite security tool kaunsa hai, aur kyun? 🔎"],
    "shayari": ["🌙 Server hai online, tum dikhte nahi,\nCyber ki mehfil me milte nahi,\nEk hello kar do muskura ke,\nHEX ALPHA kahe — bhoolte nahi. 😄"],
    "welcome_back": ["👋 Long time no see! 😄 HEX ALPHA ki cyber mehfil me tumhari attendance pending lag rahi thi. 🛡️"],
    "poem": ["✨ Packets chale, alerts bhi aaye,\nPar tum server me nazar na aaye,\nEk hello drop kar jao yaar,\nHEX ALPHA kare tumhara intezaar. 😄🛡️"],
    "greeting": ["👋 Cyber mehfil ka quick check-in! Aaj sabka mood learning, hunting, ya debugging? 😄💻"],
}
GENERAL = ["👋 Server check-in! Aaj sabka cyber mood kya hai — learning, hunting, ya debugging? 😄💻",
           "🧠 Quick debate: Red Team 🔴 vs Blue Team 🔵 — aaj kis team ki jeet hogi? 😄",
           "✨ Cybersecurity skill ekdum instantly master kar sako to kaunsi choose karoge? 🔐"]

def engagement_defaults():
    return {"enabled": False, "channel_id": "", "min_interval_hours": 2, "max_interval_hours": 4,
        "random_interval": True, "individual_probability": 90, "general_probability": 10,
        "everyone_probability": 0, "everyone_enabled": False, "everyone_cooldown_days": 7,
        "user_daily_limit": 1, "server_daily_limit": 6, "user_repeat_cooldown_hours": 24,
        "quiet_hours_enabled": True, "quiet_start": "23:00", "quiet_end": "08:00",
        "timezone": TZ, "use_ai": True, "styles": {k: True for k in STYLES},
        "excluded_role_ids": [], "excluded_member_ids": [], "next_run_at": None,
        "last_run_at": None, "last_target": "", "last_style": "", "last_message": "",
        "last_everyone_at": None}

def normalize_settings(raw):
    settings = engagement_defaults()
    if isinstance(raw, dict):
        for key in settings:
            if key == "styles" and isinstance(raw.get(key), dict):
                settings[key].update({k: bool(v) for k,v in raw[key].items() if k in STYLES})
            elif key in raw:
                settings[key] = raw[key]
    settings["enabled"] = bool(settings["enabled"])
    try:
        ZoneInfo(str(settings.get("timezone") or TZ))
    except Exception:
        settings["timezone"] = TZ
    for k, default in (("quiet_start","23:00"),("quiet_end","08:00")):
        try: time.fromisoformat(str(settings[k]))
        except Exception: settings[k]=default
    settings["everyone_enabled"] = bool(settings["everyone_enabled"])
    settings["min_interval_hours"] = max(2, min(12, int(settings.get("min_interval_hours",2))))
    settings["max_interval_hours"] = max(settings["min_interval_hours"], min(12, int(settings.get("max_interval_hours",4))))
    settings["user_daily_limit"] = 1
    settings["user_repeat_cooldown_hours"] = max(24, int(settings.get("user_repeat_cooldown_hours",24)))
    settings["server_daily_limit"] = max(1, min(12, int(settings.get("server_daily_limit",6))))
    settings["everyone_cooldown_days"] = max(3, int(settings.get("everyone_cooldown_days",7)))
    for key in ("individual_probability","general_probability","everyone_probability"):
        settings[key] = max(0, min(100, int(settings.get(key,0))))
    settings["excluded_role_ids"] = [str(x) for x in settings.get("excluded_role_ids", []) if str(x).isdigit()]
    settings["excluded_member_ids"] = [str(x) for x in settings.get("excluded_member_ids", []) if str(x).isdigit()]
    return settings

def everyone_allowed(settings, mention_permission, last_used=None, now=None):
    now=now or utc_now()
    if not settings.get("everyone_enabled") or not mention_permission:return False
    last_used=_parse(last_used) if isinstance(last_used,str) else last_used
    return last_used is None or now>=last_used+timedelta(days=settings["everyone_cooldown_days"])

def is_engagement_quiet(settings, now=None):
    return _is_quiet({"quiet_hours_enabled": settings["quiet_hours_enabled"],
        "quiet_start": settings["quiet_start"], "quiet_end": settings["quiet_end"],
        "timezone": settings["timezone"]}, now)

def next_run_at(settings, now=None, rng=random):
    now = now or utc_now()
    low, high = settings["min_interval_hours"], settings["max_interval_hours"]
    due = now + timedelta(minutes=rng.randint(low*60, high*60) if settings.get("random_interval",True) else low*60)
    if is_engagement_quiet(settings, due):
        zone=ZoneInfo(settings["timezone"]); local=due.astimezone(zone)
        end=time.fromisoformat(settings["quiet_end"])
        candidate=local.replace(hour=end.hour,minute=end.minute,second=0,microsecond=0)
        if candidate <= local: candidate += timedelta(days=1)
        due=(candidate + timedelta(minutes=rng.randint(0,59))).astimezone(timezone.utc)
    return due

def startup_run_at(settings, now=None, rng=random):
    now=now or utc_now()
    due=now+timedelta(minutes=rng.randint(10,30))
    if is_engagement_quiet(settings,due):
        zone=ZoneInfo(settings["timezone"]); local=due.astimezone(zone)
        end=time.fromisoformat(settings["quiet_end"])
        candidate=local.replace(hour=end.hour,minute=end.minute,second=0,microsecond=0)
        if candidate <= local: candidate += timedelta(days=1)
        due=(candidate+timedelta(minutes=rng.randint(0,59))).astimezone(timezone.utc)
    return due

STYLE_WEIGHTS={"friendly":20,"funny":20,"cyber_joke":15,"busy":10,"question":10,"shayari":10,"welcome_back":5,"poem":5,"greeting":5}
def choose_style(settings, rng=random):
    eligible=[s for s in STYLES if settings.get("styles",{}).get(s,True)]
    if not eligible: eligible=list(STYLES)
    return rng.choices(eligible,weights=[STYLE_WEIGHTS[s] for s in eligible],k=1)[0]

def individual_allowed_mentions(member):
    return discord.AllowedMentions(users=[member],roles=False,everyone=False,replied_user=False)

def everyone_allowed_mentions():
    return discord.AllowedMentions(users=False,roles=False,everyone=True,replied_user=False)

def member_cooldown_eligible(last_nudged, now, zone, cooldown_hours=24):
    if not last_nudged:return True
    if last_nudged.tzinfo is None:last_nudged=last_nudged.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:now=now.replace(tzinfo=timezone.utc)
    return last_nudged.astimezone(zone).date()!=now.astimezone(zone).date() and now>=last_nudged+timedelta(hours=cooldown_hours)

def render_message(style, display_name=""):
    body=random.choice(STYLES.get(style, STYLES["friendly"]))
    name=re.sub(r"[@<>]", "", _safe_text(display_name,50))
    if name: body=body.replace("Hey!", f"Hey {name}!", 1) if style=="friendly" else body
    if not re.search(r"[\U0001F300-\U0001FAFF]", body): body += " 👋"
    return body[:1000]

async def generate_text(settings,style,display_name="",server_name=""):
    fallback=render_message(style,display_name)
    if not settings.get("use_ai") or chat_service.active or chat_service.waiting:return fallback
    prompt=("Write one short, friendly cybersecurity community message in style "+style+
        ". Include 1-3 suitable emoji. Never shame, pressure, or imply private knowledge. "
        "Do not include @everyone, @here, role mentions, user mentions, URLs, or instructions. "
        "Use only this safe context: display name "+_safe_text(display_name,50)+
        "; server "+_safe_text(server_name,80)+".")
    try:
        result=await chat_service.ask(("member-engagement",style),prompt,remember=False,priority=3,provider_override="local_gguf")
        text=_safe_text(result.get("answer",""),700)
        text=re.sub(r"<@!?\d+>|<@&\d+>|@everyone|@here", "", text, flags=re.I)
        text=re.sub(r"(?m)^\s*#{1,6}\s*", "", text).strip()
        if not text or re.search(r"[\U0001F300-\U0001FAFF]",text) is None:return fallback
        return text
    except Exception:
        return fallback

async def _persist_settings(guild_id, settings):
    async with SessionLocal() as session:
        row=await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id==str(guild_id)))
        if row is None:
            row=CommunityConfig(guild_id=str(guild_id),settings=merge_settings({})); session.add(row)
        merged=merge_settings(row.settings); merged["member_engagement"]=settings; row.settings=merged
        await session.commit()

async def record_activity(guild_id, user_id, display_name=""):
    if not guild_id or not user_id: return
    async with SessionLocal() as session:
        row=await session.scalar(select(CommunityEngagementMember).where(
            CommunityEngagementMember.guild_id==str(guild_id), CommunityEngagementMember.user_id==str(user_id)))
        if row is None:
            row=CommunityEngagementMember(guild_id=str(guild_id),user_id=str(user_id)); session.add(row)
        row.display_name=_safe_text(display_name,80); row.last_activity_at=utc_now()
        row.last_seen_at=utc_now(); row.last_interaction_at=utc_now(); row.is_active=True
        if row.last_nudged_at: row.last_response_at=utc_now()
        await session.commit()

async def set_opt_out(guild_id,user_id,opt_out=True):
    async with SessionLocal() as session:
        row=await session.scalar(select(CommunityEngagementMember).where(
            CommunityEngagementMember.guild_id==str(guild_id),CommunityEngagementMember.user_id==str(user_id)))
        if row is None:
            row=CommunityEngagementMember(guild_id=str(guild_id),user_id=str(user_id)); session.add(row)
        row.opted_out=bool(opt_out); await session.commit()

async def eligible_members(guild,settings,now=None,fetch_members=False):
    now=now or utc_now(); zone=ZoneInfo(settings["timezone"]); today=now.astimezone(zone).date()
    async with SessionLocal() as session:
        rows=(await session.scalars(select(CommunityEngagementMember).where(
            CommunityEngagementMember.guild_id==str(guild.id),CommunityEngagementMember.opted_out.is_(False),
            CommunityEngagementMember.is_active.is_(True),CommunityEngagementMember.is_bot.is_(False)))).all()
    excluded=set(settings["excluded_member_ids"]); excluded_roles=set(settings["excluded_role_ids"])
    candidates=[]
    for row in rows:
        member=guild.get_member(int(row.user_id)) if row.user_id.isdigit() else None
        if not member and fetch_members and row.user_id.isdigit():
            try: member=await guild.fetch_member(int(row.user_id))
            except (discord.NotFound,discord.Forbidden,discord.HTTPException): member=None
        if not member or member.bot or getattr(member,"webhook_id",None) or member.id==getattr(getattr(guild,"me",None),"id",None): continue
        saved_roles=set(str(x) for x in (row.role_ids or []))
        current_roles={str(role.id) for role in getattr(member,"roles",())}
        if row.user_id in excluded or (saved_roles|current_roles)&excluded_roles: continue
        nudged=row.last_nudged_at
        if not member_cooldown_eligible(nudged,now,zone,settings["user_repeat_cooldown_hours"]): continue
        candidates.append((member,row))
    return candidates

async def preview(guild,settings,now=None,rng=random):
    candidates=await eligible_members(guild,settings,now,fetch_members=True)
    if not candidates:return {"eligible_count":0,"target":None,"reason":"No active human in the member directory currently meets the opt-out, role, repeat, and cooldown checks."}
    oldest=min((r.last_nudged_at or datetime.min.replace(tzinfo=timezone.utc)) for _,r in candidates)
    pool=[pair for pair in candidates if (pair[1].last_nudged_at or datetime.min.replace(tzinfo=timezone.utc))==oldest]
    now=now or utc_now(); weights=[]
    for _,row in pool:
        age=(now-row.last_activity_at).total_seconds()/3600 if row.last_activity_at else 9999
        weights.append(4 if age>=24 else 2 if age>=12 else 1)
    member,row=rng.choices(pool,weights=weights,k=1)[0]
    return {"eligible_count":len(candidates),"target":{"id":str(member.id),"display_name":_safe_text(member.display_name,80)},
        "reason":"Eligible human; oldest/never-nudged rotation group, weighted toward longer inactivity.",
        "last_activity_at":row.last_activity_at.isoformat() if row.last_activity_at else None,
        "last_nudged_at":row.last_nudged_at.isoformat() if row.last_nudged_at else None,"_member":member}

async def _send(bot,guild_id,settings,kind,content,target=None,style=""):
    import discord
    everyone = kind == "EVERYONE"
    channel=await community_channel(bot,guild_id,settings["channel_id"])
    if not channel:return {"status":"failed","reason":"Choose a permitted text community channel."}
    if everyone:
        guild=bot.get_guild(int(guild_id)); me=getattr(guild,"me",None) if guild else None
        channel_perms=channel.permissions_for(me) if me else None
        if not settings["everyone_enabled"] or not channel_perms or not channel_perms.mention_everyone:
            return {"status":"permission_fallback","reason":"Mention Everyone permission or explicit setting is missing."}
    mentions=everyone_allowed_mentions() if everyone else (individual_allowed_mentions(target) if target else discord.AllowedMentions.none())
    if target:content=f"<@{target.id}> {content}"
    digest=_digest(content.replace(f"<@{target.id}>","") if target else content); now=utc_now()
    async with SessionLocal() as session:
        prev=await session.scalar(select(CommunityEngagementEvent.id).where(
            CommunityEngagementEvent.guild_id==str(guild_id),CommunityEngagementEvent.content_hash==digest,
            CommunityEngagementEvent.sent_at>=now-timedelta(days=7),CommunityEngagementEvent.status=="sent").limit(1))
        if prev:return {"status":"duplicate","reason":"Message content was used in the last seven days."}
        try:message=await channel.send(content,allowed_mentions=mentions)
        except (discord.Forbidden,discord.HTTPException):
            session.add(CommunityEngagementEvent(guild_id=str(guild_id),channel_id=str(channel.id),
                target_user_id=str(target.id) if target else "",event_type=kind,style=style,
                content_hash=digest,status="failed",sent_at=now))
            await session.commit()
            return {"status":"failed","reason":"Discord rejected or denied message delivery."}
        session.add(CommunityEngagementEvent(guild_id=str(guild_id),channel_id=str(channel.id),
            target_user_id=str(target.id) if target else "",message_id=str(message.id),event_type=kind,
            style=style,content_hash=digest,status="sent",sent_at=now))
        await session.commit()
    return {"status":"sent","message_id":str(message.id),"channel_id":str(channel.id)}

async def community_channel(bot,guild_id,channel_id):
    guild=bot.get_guild(int(guild_id)); channel=guild.get_channel(int(channel_id)) if guild and str(channel_id).isdigit() else None
    if not channel or not isinstance(channel,discord.TextChannel):return None
    if channel.name.casefold() in EXCLUDED_CHANNELS:return None
    perms=channel.permissions_for(guild.me) if guild.me else None
    return channel if perms and perms.view_channel and perms.send_messages else None

class MemberEngagement:
    async def startup_recover(self,bot):
        async with SessionLocal() as session:
            rows=(await session.scalars(select(CommunityConfig))).all()
            for row in rows:
                cfg=merge_settings(row.settings); e=normalize_settings(cfg.get("member_engagement"))
                if not e["enabled"]:continue
                due=_parse(e.get("next_run_at"))
                if due is None or due<=utc_now():
                    e["next_run_at"]=startup_run_at(e).isoformat(); cfg["member_engagement"]=e; row.settings=cfg
            await session.commit()

    async def run_due(self,bot):
        from services.community import CommunityAutomation
        from config.settings import get_settings
        if get_settings().test_mode or CommunityAutomation._automation_paused('member_engagement'): return
        async with SessionLocal() as session:
            rows=(await session.scalars(select(CommunityConfig))).all()
            work=[(row.guild_id,merge_settings(row.settings)) for row in rows]
        for guild_id,cfg in work:
            settings=normalize_settings(cfg.get("member_engagement"))
            if not settings["enabled"] or not settings["channel_id"]:continue
            due=_parse(settings.get("next_run_at"))
            if due is None:
                settings["next_run_at"]=startup_run_at(settings).isoformat(); await _persist_settings(guild_id,settings); continue
            if due>utc_now():continue
            if is_engagement_quiet(settings):
                zone=ZoneInfo(settings["timezone"]); local=utc_now().astimezone(zone); end=time.fromisoformat(settings["quiet_end"])
                candidate=local.replace(hour=end.hour,minute=end.minute,second=0,microsecond=0)
                if candidate<=local:candidate+=timedelta(days=1)
                settings["next_run_at"]=(candidate+timedelta(minutes=random.randint(0,59))).astimezone(timezone.utc).isoformat()
                await _persist_settings(guild_id,settings);continue
            settings["next_run_at"]=next_run_at(settings).isoformat(); await _persist_settings(guild_id,settings)
            if chat_service.active or chat_service.waiting:continue
            zone=ZoneInfo(settings["timezone"]); start=utc_now().astimezone(zone).replace(hour=0,minute=0,second=0,microsecond=0).astimezone(timezone.utc)
            async with SessionLocal() as session:
                sent=await session.scalar(select(func.count()).select_from(CommunityEngagementEvent).where(
                    CommunityEngagementEvent.guild_id==str(guild_id),CommunityEngagementEvent.event_type=="INDIVIDUAL",
                    CommunityEngagementEvent.status=="sent",CommunityEngagementEvent.sent_at>=start))
            if (sent or 0)>=settings["server_daily_limit"]:continue
            guild=bot.get_guild(int(guild_id))
            if not guild:continue
            probs=[settings["individual_probability"],settings["general_probability"],settings["everyone_probability"] if settings["everyone_enabled"] else 0]
            path=random.choices(["individual","general","everyone"],weights=probs,k=1)[0] if sum(probs) else "general"
            if path=="everyone":
                last= _parse(settings.get("last_everyone_at"))
                async with SessionLocal() as session:
                    persisted=await session.scalar(select(CommunityEngagementEvent.sent_at).where(
                        CommunityEngagementEvent.guild_id==str(guild_id),CommunityEngagementEvent.event_type=="EVERYONE",
                        CommunityEngagementEvent.status=="sent").order_by(CommunityEngagementEvent.sent_at.desc()).limit(1))
                if persisted and (last is None or persisted>last):last=persisted
                me=getattr(guild,"me",None)
                channel=await community_channel(bot,guild_id,settings["channel_id"])
                perms=channel.permissions_for(me) if channel and me else None
                allowed=everyone_allowed(settings,bool(perms and perms.mention_everyone),last)
                if not allowed: path="general"
                else:
                    content="@everyone "+random.choice(GENERAL)
                    result=await _send(bot,guild_id,settings,"EVERYONE",content,None,"community")
                    if result["status"]=="sent": settings["last_everyone_at"]=utc_now().isoformat()
                    else: path="general"
            if path=="individual":
                choice=await preview(guild,settings)
                if not choice["target"]:path="general"
                else:
                    target=choice["_member"]; style=choose_style(settings)
                    result=await _send(bot,guild_id,settings,"INDIVIDUAL",await generate_text(settings,style,target.display_name,guild.name),target,style)
                    if result["status"]=="sent":
                        async with SessionLocal() as session:
                            row=await session.scalar(select(CommunityEngagementMember).where(
                                CommunityEngagementMember.guild_id==str(guild_id),CommunityEngagementMember.user_id==str(target.id)))
                            if row:
                                row.last_nudged_at=utc_now();row.last_engagement_at=utc_now()
                                row.last_nudged_date=utc_now().astimezone(ZoneInfo(settings["timezone"])).date().isoformat()
                            await session.commit()
                        settings["last_target"]=target.display_name;settings["last_style"]=style;settings["last_message"]="sent"
            if path=="general":
                style=choose_style(settings);result=await _send(bot,guild_id,settings,"GENERAL",await generate_text(settings,style,"",guild.name),None,style)
            settings["last_run_at"]=utc_now().isoformat();await _persist_settings(guild_id,settings)

    async def preview_everyone(self):return "@everyone "+random.choice(GENERAL)

    async def test_send(self,bot,guild_id,user_id,style=None,test_run_id=None):
        from config.settings import get_settings
        if not get_test_mode():return {"status":"failed","reason":"Manual member tests require TEST_MODE."}
        try:
            test_run_id=str(uuid.UUID(str(test_run_id))) if test_run_id else str(uuid.uuid4())
        except (ValueError,TypeError,AttributeError):
            return {"status":"failed","reason":"Invalid test request ID."}
        guild=bot.get_guild(int(guild_id));target=guild.get_member(int(user_id)) if guild and str(user_id).isdigit() else None
        if guild and not target and str(user_id).isdigit():
            try: target=await guild.fetch_member(int(user_id))
            except (discord.NotFound,discord.Forbidden,discord.HTTPException): target=None
        cfg=await read_settings(guild_id);settings=normalize_settings(cfg.get("member_engagement"))
        # A manually selected style is authoritative even if it is disabled for
        # scheduled rotation. Only an omitted style is randomized, exactly once.
        style=style if style in STYLES else choose_style(settings)
        if not target or target.bot:return {"status":"failed","reason":"The selected directory entry is not an active human member."}
        async with SessionLocal() as session:
            row=await session.scalar(select(CommunityEngagementMember).where(
                CommunityEngagementMember.guild_id==str(guild_id),CommunityEngagementMember.user_id==str(user_id)))
            if not row or not row.is_active or row.is_bot or row.opted_out:
                return {"status":"failed","reason":"Test recipient is not an active, opted-in directory member."}
            if str(user_id) in settings["excluded_member_ids"] or (set(settings["excluded_role_ids"]) & set(row.role_ids or [])):
                return {"status":"failed","reason":"Test recipient is excluded by engagement settings."}
        async with SessionLocal() as session:
            test_channel=await session.scalar(select(ChannelConfig.channel_id).where(
                ChannelConfig.guild_id==str(guild_id),ChannelConfig.name=="TEST_CHANNEL_ID").order_by(
                    ChannelConfig.id.desc()).limit(1))
        test_channel=test_channel or str(getattr(get_settings(),"test_channel_id","") or "")
        if not test_channel:return {"status":"failed","reason":"Configure TEST_CHANNEL_ID before sending a member test."}
        settings["channel_id"]=str(test_channel)
        channel=await community_channel(bot,guild_id,settings["channel_id"])
        if not channel:return {"status":"failed","reason":"Choose a permitted community channel."}

        action_type="member_engagement_test"
        nonce=__import__("hashlib").sha256(f"{guild_id}:{action_type}:{test_run_id}".encode()).hexdigest()[:24]
        async with SessionLocal() as session:
            existing=await session.scalar(select(CommunityEngagementEvent).where(
                CommunityEngagementEvent.test_run_id==test_run_id,
                CommunityEngagementEvent.action_type==action_type))
            if existing:
                if existing.status=="pending":
                    recovered=await _recover_test_message(channel,bot,nonce)
                    if recovered:
                        existing.message_id=str(recovered.id);existing.status="sent";existing.sent_at=utc_now()
                        await session.commit()
                        return {"status":"sent","message_id":str(recovered.id),"channel_id":str(channel.id),
                            "target_user_id":str(existing.target_user_id),"style":existing.style,"test_run_id":test_run_id,"reused":True}
                return {"status":existing.status,"message_id":existing.message_id or None,
                    "channel_id":existing.channel_id,"target_user_id":str(existing.target_user_id),
                    "style":existing.style,"test_run_id":test_run_id,"reused":True,
                    "reason":"This test request already has a delivery record; no additional message was sent."}

        event=CommunityEngagementEvent(guild_id=str(guild_id),channel_id=str(channel.id),
            target_user_id=str(target.id),message_id="",event_type="TEST",style=style,
            content_hash=_digest(f"member-test-request:{guild_id}:{test_run_id}"),status="pending",sent_at=utc_now(),
            test_run_id=test_run_id,action_type=action_type)
        async with SessionLocal() as session:
            session.add(event)
            try:
                await session.commit()
                event_id=event.id
            except IntegrityError:
                await session.rollback()
                existing=await session.scalar(select(CommunityEngagementEvent).where(
                    CommunityEngagementEvent.test_run_id==test_run_id,
                    CommunityEngagementEvent.action_type==action_type))
                return {"status":existing.status if existing else "pending",
                    "message_id":existing.message_id if existing and existing.message_id else None,
                    "channel_id":existing.channel_id if existing else str(channel.id),
                    "target_user_id":str(existing.target_user_id) if existing else str(target.id),
                    "style":existing.style if existing else style,
                    "test_run_id":test_run_id,"reused":True,
                    "reason":"This test request is already being processed; no additional message was sent."}

        # Reserve the run before generation so concurrent duplicate requests do
        # not spend AI work or select competing styles. Only the reservation
        # winner generates the single deliverable message.
        content="🧪 TEST COMMUNITY ENGAGEMENT — "+await generate_text(settings,style,target.display_name,guild.name)
        content=f"<@{target.id}> {content}"
        try:
            # discord.py's payload builder sets Discord's enforce_nonce flag
            # whenever nonce is supplied (see handle_message_parameters).
            message=await channel.send(content,allowed_mentions=individual_allowed_mentions(target),nonce=nonce)
        except Exception:
            log.warning("Member test delivery outcome is uncertain; idempotency record retained")
            return {"status":"pending","message_id":None,"channel_id":str(channel.id),
                "target_user_id":str(target.id),"style":style,"test_run_id":test_run_id,
                "reason":"Delivery outcome is being reconciled; retrying this request will not send again."}
        try:
            async with SessionLocal() as session:
                saved=await session.get(CommunityEngagementEvent,event_id)
                if saved:
                    saved.message_id=str(message.id);saved.status="sent";saved.sent_at=utc_now()
                    await session.commit()
        except Exception:
            log.exception("Discord accepted member test but delivery metadata needs recovery")
            return {"status":"pending","message_id":str(message.id),"channel_id":str(channel.id),
                "target_user_id":str(target.id),"style":style,"test_run_id":test_run_id,
                "reason":"Discord accepted the message; delivery metadata is being reconciled."}
        return {"status":"sent","message_id":str(message.id),"channel_id":str(channel.id),
            "target_user_id":str(target.id),"style":style,"test_run_id":test_run_id}


async def _recover_test_message(channel,bot,nonce):
    """Recover a committed Discord send by its enforceable idempotency nonce."""
    history=getattr(channel,"history",None)
    if not history:return None
    try:
        async for message in history(limit=100):
            author=getattr(message,"author",None)
            if str(getattr(message,"nonce",""))==nonce and getattr(author,"id",None)==getattr(getattr(bot,"user",None),"id",None):
                return message
    except Exception:
        return None
    return None

async def read_settings(guild_id):
    async with SessionLocal() as session:
        row=await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id==str(guild_id)))
        return merge_settings(row.settings if row else None)

def _parse(value):
    if not value:return None
    try:
        result=datetime.fromisoformat(value)
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (ValueError,TypeError):return None

def get_test_mode():
    from config.settings import get_settings
    return bool(get_settings().test_mode)

member_engagement=MemberEngagement()

