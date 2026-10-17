"""Opt-in Discord welcome, farewell and channel pulse automation."""
import hashlib
import json
import logging
import re
from datetime import datetime, time, timedelta, timezone

import discord
from sqlalchemy import select, func

from config.settings import get_settings
from database.db import SessionLocal
from database.models import CommunityConfig, CommunityPost, PulseDeliveryEvent, SystemLog, NewsArticle, Job, CVE, Threat, SecurityTool, Source, ChannelConfig
from services.time_utils import get_timezone, utc_now
from services.ai_chat import chat_service
from services.ai_providers import AIUnavailable

log = logging.getLogger('hexalert.community')

PULSE_DEFAULTS = (
    ('general', 'General', 30), ('news', 'Cybersecurity news', 30),
    ('jobs', 'Cybersecurity careers', 30), ('threat_intel', 'Threat intelligence', 30),
    ('technology', 'Cybersecurity technology', 30), ('github_tools', 'GitHub tools', 30),
    ('security_research', 'Security research', 30), ('critical_cve', 'Critical CVEs', 30),
    ('zero_day', 'Zero-day', 30),
)


def default_community_settings():
    from services.member_engagement import engagement_defaults
    from services.smart_social import social_defaults
    return {
        'members_intent': False,
        'welcome': {'enabled': False, 'channel_id': '', 'use_ai': False, 'mention_member': True,
                    'include_server_name': True, 'prompt': '',
                    'fallback': 'Welcome {user} to {server}! HEX ALPHA is glad to have you here. Check out our cybersecurity channels and stay curious. 🛡️'},
        'farewell': {'enabled': False, 'channel_id': '', 'use_ai': False, 'mention_member': False,
                     'prompt': '', 'fallback': '{user} has left {server}. Thanks for being part of our community. Stay secure. 🛡️'},
        'member_engagement': engagement_defaults(),
        'smart_social': social_defaults(),
        'pulse': {'quiet_hours_enabled': True, 'quiet_start': '23:00', 'quiet_end': '08:00',
                  'timezone': 'Asia/Kolkata', 'skip_if_active': True, 'activity_minutes': 10,
                  'daily_limit': 40, 'delivery_paused': False,
                  'channels': [{'key': key, 'category': key, 'label': label, 'channel_id': '',
                                'enabled': False, 'interval_minutes': minutes, 'prompt': '', 'baseline_at': ''}
                               for key, label, minutes in PULSE_DEFAULTS]},
    }


def merge_settings(raw):
    defaults = default_community_settings()
    if not isinstance(raw, dict): return defaults
    for section in ('welcome', 'farewell', 'pulse'):
        if isinstance(raw.get(section), dict): defaults[section].update(raw[section])
    if isinstance(defaults['pulse'].get('channels'), list):
        given = {str(row.get('key')): row for row in defaults['pulse']['channels'] if isinstance(row, dict)}
        channels = []
        for key, label, interval in PULSE_DEFAULTS:
            row = {'key': key, 'category': key, 'label': label, 'channel_id': '', 'enabled': False,
                   'interval_minutes': interval, 'prompt': '', 'baseline_at': ''}
            row.update(given.get(key, {})); channels.append(row)
        defaults['pulse']['channels'] = channels
    from services.member_engagement import normalize_settings
    defaults['member_engagement'] = normalize_settings(raw.get('member_engagement'))
    from services.smart_social import normalize_social
    defaults['smart_social'] = normalize_social(raw.get('smart_social'))
    defaults['members_intent'] = bool(raw.get('members_intent', False))
    return defaults


def _safe_text(value, limit=500):
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value or ''))
    return value.strip()[:limit]


def _digest(content):
    normalized = re.sub(r'\s+', ' ', _safe_text(content, 2000)).casefold().strip()
    return hashlib.sha256(normalized.encode()).hexdigest()


def _is_quiet(pulse, now=None):
    if not pulse.get('quiet_hours_enabled', True): return False
    try:
        tz = get_timezone(pulse.get('timezone') or 'Asia/Kolkata')
        local = (now or utc_now()).astimezone(tz).timetz().replace(tzinfo=None)
        start = time.fromisoformat(pulse.get('quiet_start', '23:00'))
        end = time.fromisoformat(pulse.get('quiet_end', '07:00'))
    except Exception:
        return True
    return start <= local < end if start <= end else (local >= start or local < end)


def pulse_readiness(categories, bot_ready=True):
    """Report capability independently from operator enablement or pause state."""
    if not bot_ready:return 'ERROR'
    source_degraded=any(row.get('source_enabled',0)>0 and
        row.get('source_health') in {'error','unavailable','degraded'} for row in categories)
    route_degraded=any(row.get('enabled') and not row.get('destination_ready') for row in categories)
    return 'DEGRADED' if source_degraded or route_degraded else 'READY'


class CommunityAutomation:
    def __init__(self): self.last_human_activity = {}

    def note_activity(self, guild_id, channel_id):
        self.last_human_activity[(str(guild_id), str(channel_id))] = utc_now()

    async def _settings(self, guild_id):
        async with SessionLocal() as session:
            row = await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id == str(guild_id)))
            return merge_settings(row.settings if row else None)

    @staticmethod
    def automation_controls():
        from config.runtime_config import get_runtime_config
        try:
            values=get_runtime_config()
        except Exception:
            values={}
        module_defaults={'pulse':True,'urgent_alerts':True,'jobs':True,'daily_digest':True,
                         'smart_social':False,'member_engagement':False,'welcome_farewell':False}
        configured=values.get('AUTOPILOT_MODULES',{})
        modules={key:bool(configured.get(key,default)) for key,default in module_defaults.items()} if isinstance(configured,dict) else module_defaults
        return {
            'autonomous_mode':bool(values.get('AUTONOMOUS_MODE',False)),
            'autopilot_modules':modules,
            'all_community_paused':bool(values.get('COMMUNITY_AUTOMATION_PAUSED',False)),
            'pulse_paused':bool(values.get('PULSE_DELIVERY_PAUSED',False)),
            'smart_social_paused':bool(values.get('SMART_SOCIAL_PAUSED',False)),
            'member_engagement_paused':bool(values.get('MEMBER_ENGAGEMENT_PAUSED',False)),
        }

    @staticmethod
    def save_automation_controls(changes):
        from config.runtime_config import update_runtime_config
        allowed={'all_community_paused':'COMMUNITY_AUTOMATION_PAUSED',
                 'pulse_paused':'PULSE_DELIVERY_PAUSED',
                 'smart_social_paused':'SMART_SOCIAL_PAUSED',
                 'member_engagement_paused':'MEMBER_ENGAGEMENT_PAUSED'}
        update={allowed[key]:bool(value) for key,value in changes.items() if key in allowed}
        if 'autonomous_mode' in changes:update['AUTONOMOUS_MODE']=bool(changes['autonomous_mode'])
        if 'autopilot_modules' in changes and isinstance(changes['autopilot_modules'],dict):
            current=CommunityAutomation.automation_controls()['autopilot_modules']
            current.update({str(key):bool(value) for key,value in changes['autopilot_modules'].items() if key in current})
            update['AUTOPILOT_MODULES']=current
        update_runtime_config(update)
        return CommunityAutomation.automation_controls()

    @classmethod
    def _automation_paused(cls, name):
        controls=cls.automation_controls()
        module={'pulse':'pulse','smart_social':'smart_social','member_engagement':'member_engagement',
                'welcome_farewell':'welcome_farewell','urgent_alerts':'urgent_alerts','jobs':'jobs',
                'daily_digest':'daily_digest'}.get(name,name)
        return (not controls['autonomous_mode'] or controls['all_community_paused']
                or controls.get(name+'_paused',False) or not controls['autopilot_modules'].get(module,False))

    @staticmethod
    async def _audit(level, message):
        try:
            async with SessionLocal() as session:
                session.add(SystemLog(level=level,component='COMMUNITY',message=_safe_text(message,300),status='CURRENT'))
                await session.commit()
        except Exception: log.warning('Community automation status could not be persisted')

    async def save_settings(self, guild_id, settings):
        value = merge_settings(settings)
        async with SessionLocal() as session:
            row = await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id == str(guild_id)))
            if row is None: row = CommunityConfig(guild_id=str(guild_id), settings=value); session.add(row)
            else: row.settings = value
            await session.commit()
        return value

    async def _channel(self, bot, guild_id, channel_id):
        guild = bot.get_guild(int(guild_id)) if str(guild_id).isdigit() else None
        channel = guild.get_channel(int(channel_id)) if guild and str(channel_id).isdigit() else None
        if channel is None and str(channel_id).isdigit():
            try: channel = await bot.fetch_channel(int(channel_id))
            except (discord.HTTPException, discord.NotFound, discord.Forbidden): return None, None
        if channel is None or not isinstance(channel, (discord.TextChannel, discord.Thread)): return guild, None
        if guild is None: guild = getattr(channel, 'guild', None)
        if guild and getattr(getattr(channel,'guild',None),'id',None)!=guild.id: return None, None
        me = getattr(guild, 'me', None) if guild else None
        if me and isinstance(channel, discord.TextChannel):
            perms = channel.permissions_for(me)
            if not perms.view_channel or not perms.send_messages: return guild, None
        return guild, channel

    async def _ai_text(self, key, instruction, priority=2, search_query_override=None):
        result = await chat_service.ask(key, instruction, remember=False, priority=priority,
                                        search_query_override=search_query_override)
        return self._trim_pulse(result.get('answer', ''))

    @staticmethod
    def _trim_pulse(text):
        text = _safe_text(text, 1500)
        # Channel automation is deliberately short even if a model ignores the token cap.
        sentences = re.split(r'(?<=[.!?])\s+', text)
        return _safe_text(' '.join(sentences[:4]), 500)

    async def send(self, bot, guild_id, channel_id, kind, content, *, is_test=False, allowed_mentions=None, dedupe_key=''):
        guild, channel = await self._channel(bot, guild_id, channel_id)
        if not channel: return {'status': 'failed', 'reason': 'Channel is missing or the bot cannot view/send messages.'}
        content = _safe_text(content, 500 if kind in ('pulse', 'test_pulse') else 1200)
        if not content: return {'status': 'failed', 'reason': 'Message content is empty.'}
        digest = _digest(dedupe_key or content)
        now = utc_now()
        async with SessionLocal() as session:
            duplicate_query=select(CommunityPost.id).where(
                CommunityPost.guild_id == str(guild_id), CommunityPost.content_hash == digest,
                CommunityPost.status == 'sent')
            if dedupe_key:
                duplicate_query=duplicate_query.where(CommunityPost.kind=='pulse')
            else:
                duplicate_query=duplicate_query.where(CommunityPost.channel_id==str(channel_id),
                    CommunityPost.created_at>=now-timedelta(hours=24))
            previous=await session.scalar(duplicate_query.limit(1))
            if previous: return {'status': 'duplicate', 'reason': 'Same automated message was sent in this channel within 24 hours.'}
        try:
            message = await channel.send(content, allowed_mentions=allowed_mentions or discord.AllowedMentions.none())
        except discord.HTTPException:
            log.warning('Community message send failed kind=%s channel_id=%s', kind, str(channel_id))
            await self._audit('ERROR',f'{kind} Discord send failed in channel {channel_id}')
            async with SessionLocal() as session:
                session.add(CommunityPost(guild_id=str(guild_id), channel_id=str(channel_id), kind=kind,
                                          content_hash=digest, status='failed'))
                await session.commit()
            return {'status': 'failed', 'reason': 'Discord rejected the message.'}
        async with SessionLocal() as session:
            session.add(CommunityPost(guild_id=str(guild_id), channel_id=str(channel_id), kind=kind,
                                      content_hash=digest, message_id=str(message.id), status='sent'))
            await session.commit()
        return {'status': 'sent', 'message_id': str(message.id), 'channel_id': str(channel.id),
                'guild_id': str(guild.id if guild else guild_id)}

    async def member_event(self, bot, member, kind):
        if self._automation_paused('welcome_farewell'): return
        if get_settings().test_mode:return
        settings = await self._settings(member.guild.id)
        cfg = settings.get(kind, {})
        if not cfg.get('enabled') or not cfg.get('channel_id'): return
        mention = member.mention if cfg.get('mention_member') else _safe_text(member.display_name, 80)
        server = _safe_text(member.guild.name, 100) if cfg.get('include_server_name', True) else 'our community'
        fallback = _safe_text(cfg.get('fallback'), 400).replace('{user}', mention).replace('{server}', server)
        content = fallback
        if cfg.get('use_ai'):
            instruction = ('Write one short, respectful Discord '+('welcome' if kind == 'welcome' else 'farewell')+
                ' message for a cybersecurity community. Never invent details or include mentions. 1–2 sentences, under 60 words. '
                + _safe_text(cfg.get('prompt'), 400))
            try:
                generated = await self._ai_text(('community', member.guild.id, kind), instruction, priority=2)
                if generated: content = (mention + ' ' + generated) if cfg.get('mention_member') else generated
                if cfg.get('include_server_name') and server.casefold() not in content.casefold(): content += f' Welcome to {server}.' if kind == 'welcome' else ''
            except AIUnavailable:
                log.info('Community %s used deterministic fallback (AI unavailable)', kind)
                await self._audit('WARNING',f'{kind} used deterministic fallback because local AI was unavailable')
        mentions=(discord.AllowedMentions(users=[member],everyone=False,roles=False,replied_user=False)
                  if cfg.get('mention_member') else discord.AllowedMentions.none())
        await self.send(bot, member.guild.id, cfg['channel_id'], kind, content,allowed_mentions=mentions)

    async def test(self, bot, guild_id, kind, channel_id=None):
        settings = await self._settings(guild_id)
        cfg = settings.get(kind, {}) if kind in ('welcome', 'farewell') else None
        if kind in ('welcome', 'farewell'):
            channel_id = channel_id or cfg.get('channel_id')
            if not channel_id: return {'status': 'failed', 'reason': f'Choose a {kind} channel first.'}
            content = '[TEST AUTOMATION] ' + _safe_text(cfg.get('fallback'), 400).replace('{user}', '@member').replace('{server}', 'Hex-Alpha')
            if cfg.get('use_ai'):
                instruction = f'Write one short {kind} test message for HEX ALPHA, a cybersecurity community. No personal names or mentions. 1–2 sentences. ' + _safe_text(cfg.get('prompt'), 400)
                try: content = '[TEST AUTOMATION] ' + await self._ai_text(('community-test', guild_id, kind), instruction, priority=1)
                except AIUnavailable: pass
        else:
            channel_id = str(channel_id or '')
            if not channel_id: return {'status': 'failed', 'reason': 'Choose a Channel Pulse channel first.'}
            entry=next((x for x in settings.get('pulse',{}).get('channels',[]) if str(x.get('channel_id'))==channel_id),{})
            label=_safe_text(entry.get('label') or entry.get('category') or 'Channel Pulse',80)
            content = f"{chr(0x1F9EA)} TEST AUTOMATION | HEX ALPHA {label} mapped-channel delivery check. No intelligence finding is asserted by this test. {chr(0x1F6E1)}"
        result = await self.send(bot, guild_id, channel_id, 'test_' + kind, content, is_test=True)
        if result['status'] == 'sent': result['status'] = 'SUCCESS'
        return result

    async def run_now(self, bot, guild_id, channel_key):
        settings = await self._settings(guild_id)
        entry = next((x for x in settings['pulse']['channels'] if x['key'] == channel_key), None)
        if not entry or not entry.get('enabled') or not entry.get('channel_id'):
            return {'status': 'failed', 'reason': 'Enable this channel and choose a destination before Run Now.'}
        return await self._send_pulse(bot, guild_id, settings, entry, manual=True)

    @staticmethod
    def _safe_url(value):
        from urllib.parse import urlsplit
        value = str(value or "").strip()
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return ""
        if re.search(r"(?i)(?:api[_-]?key|access[_-]?token|secret|password)=",parsed.query): return ""
        return value

    async def _verified_pulse_records(self, session, entry):
        """Return only verifiable category records observed after the saved baseline."""
        from sqlalchemy import or_
        try:
            baseline = datetime.fromisoformat(str(entry.get("baseline_at") or "").replace("Z", "+00:00"))
            if baseline.tzinfo is None: baseline = baseline.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return []
        key = entry.get("category")
        records = []
        if key in {"news", "technology", "security_research"}:
            query = select(NewsArticle).where(NewsArticle.created_at > baseline)
            if key == "technology": query = query.where(NewsArticle.category.ilike("%technology%"))
            if key == "security_research":
                query = query.where(or_(NewsArticle.category.ilike("%research%"), NewsArticle.category.ilike("%paper%")))
            rows = (await session.scalars(query.order_by(NewsArticle.created_at.desc()).limit(20))).all()
            for row in rows:
                url = self._safe_url(row.source_url)
                if url: records.append((row.created_at, row.title, row.summary, row.source or "Source", url,
                    row.published_at.isoformat()[:10] if row.published_at else "date unavailable"))
        elif key == "jobs":
            rows = (await session.scalars(select(Job).where(Job.first_seen_at > baseline,
                Job.is_cybersecurity.is_(True), Job.alert_eligible.is_(True), Job.suppressed.is_(False))
                .order_by(Job.first_seen_at.desc()).limit(20))).all()
            for row in rows:
                url = self._safe_url(row.apply_url or row.source_url)
                if url: records.append((row.first_seen_at, row.title, row.company, row.source or "Career source", url,
                    row.published_at.isoformat()[:10] if row.published_at else "date unavailable"))
        elif key in {"critical_cve", "zero_day"}:
            query = select(CVE).where(CVE.created_at > baseline)
            if key == "critical_cve": query = query.where(or_(CVE.severity.ilike("critical"), CVE.cvss >= 9.0))
            else: query = query.where(or_(CVE.verified_zero_day.is_(True), CVE.exploited.ilike("yes")))
            rows = (await session.scalars(query.order_by(CVE.created_at.desc()).limit(20))).all()
            for row in rows:
                url = self._safe_url(row.source_url)
                if url:
                    details = f"{row.severity} | CVSS {row.cvss if row.cvss is not None else 'not scored'} | {row.description}"
                    records.append((row.created_at, row.cve_id, details, "NVD/vendor advisory", url,
                        row.published_at.isoformat()[:10] if row.published_at else "date unavailable"))
        elif key == "threat_intel":
            rows = (await session.scalars(select(Threat).where(Threat.created_at > baseline)
                .order_by(Threat.created_at.desc()).limit(20))).all()
            for row in rows:
                url = self._safe_url(row.source_url)
                if url: records.append((row.created_at, row.title, row.summary, row.source or "Threat research", url,
                    row.published_at.isoformat()[:10] if row.published_at else "date unavailable"))
        elif key == "github_tools":
            rows = (await session.scalars(select(SecurityTool).where(SecurityTool.created_at > baseline)
                .order_by(SecurityTool.created_at.desc()).limit(20))).all()
            for row in rows:
                url = self._safe_url(row.github_url or row.source_url)
                if url and "github.com" in url.casefold():
                    records.append((row.created_at, row.name, f"{row.category}: {row.description}",
                        row.developer or row.source or "GitHub", url,
                        row.published_at.isoformat()[:10] if row.published_at else "date unavailable"))
        return records

    @staticmethod
    def _format_verified_records(category, records, maximum=3, max_length=500):
        codes={"news":0x1F4F0,"jobs":0x1F4BC,"threat_intel":0x26A0,"technology":0x1F4BB,
               "github_tools":0x1F6E0,"security_research":0x1F52C,"critical_cve":0x1F6A8,"zero_day":0x1F6E1}
        emoji=chr(codes.get(category,0x1F50E))
        blocks=[]
        for _, title, details, source, url, published in records[:maximum]:
            title=_safe_text(title,140); details=_safe_text(details,180)
            if title and url:
                block=f"{emoji} **{title}**\n{details}\nSource: {source} | Published: {published}\n<{url}>"
                if len("\n\n".join([*blocks,block])) > max_length:
                    break  # Never publish a partial record without its source link.
                blocks.append(block)
        return "\n\n".join(blocks)

    async def _send_pulse(self, bot, guild_id, settings, entry, manual=False):
        if not manual and (chat_service.active or chat_service.waiting):
            return {"status":"deferred","reason":"Interactive AI request has priority."}
        if not manual and _is_quiet(settings["pulse"]): return {"status":"quiet_hours"}
        key=(str(guild_id),str(entry.get("channel_id")))
        pulse=settings["pulse"]
        if not manual and pulse.get("skip_if_active",True):
            last=self.last_human_activity.get(key)
            if last and (utc_now()-last).total_seconds()<int(pulse.get("activity_minutes",10))*60:
                return {"status":"skipped_active"}
        now=utc_now()
        async with SessionLocal() as session:
            zone=get_timezone(pulse.get("timezone") or "Asia/Kolkata")
            start=now.astimezone(zone).replace(hour=0,minute=0,second=0,microsecond=0).astimezone(timezone.utc)
            sent_today=await session.scalar(select(func.count()).select_from(CommunityPost).where(
                CommunityPost.guild_id==str(guild_id),CommunityPost.channel_id==key[1],
                CommunityPost.kind=="pulse",CommunityPost.status=="sent",CommunityPost.created_at>=start))
            if (sent_today or 0)>=int(pulse.get("daily_limit",40)): return {"status":"daily_limit"}
            last_sent=await session.scalar(select(CommunityPost.created_at).where(
                CommunityPost.guild_id==str(guild_id),CommunityPost.channel_id==key[1],
                CommunityPost.kind=="pulse",CommunityPost.status=="sent")
                .order_by(CommunityPost.created_at.desc()).limit(1))
            records=await self._verified_pulse_records(session,entry)
        interval=max(30,min(int(entry.get("interval_minutes") or 30),10080))
        if not manual and last_sent and (now-last_sent).total_seconds()<interval*60: return {"status":"not_due"}
        if entry.get("category")=="general":
            if last_sent and (now-last_sent).total_seconds()<(30*60 if manual else 6*3600):
                return {"status":"not_due"}
            wave=chr(0x1F44B); brain=chr(0x1F9E0); shield=chr(0x1F6E1); sparkles=chr(0x2728)
            prompts=(
                f"{wave} Quick cyber check-in: which security skill are you learning this week? {brain}",
                f"{shield} Tiny debate: Red Team or Blue Team today? {sparkles}",
                f"{chr(0x1F4BB)} What is one security tool you would recommend to a beginner? {sparkles}",
                f"{chr(0x1F510)} What makes a password manager trustworthy in your view? {chr(0x1F440)}")
            content=prompts[(now.date().toordinal()+now.hour)%len(prompts)]
        else:
            if not records: return {"status":"no_new_data"}
        test_mode=get_settings().test_mode
        if test_mode and not manual:
            return {"status":"test_mode_paused","reason":"Scheduled Pulse delivery is paused in TEST_MODE; use the labelled Run Now action."}
        if not manual and self._automation_paused('pulse'):
            return {'status':'paused','reason':'Pulse delivery is paused by the automation kill switch.'}
        delivery_channel=key[1]
        if test_mode and manual:
            async with SessionLocal() as session:
                safe_channel=await session.scalar(select(ChannelConfig.channel_id).where(
                    ChannelConfig.guild_id==str(guild_id),ChannelConfig.name=='TEST_CHANNEL_ID').order_by(ChannelConfig.id.desc()).limit(1))
            safe_channel=safe_channel or getattr(get_settings(),'test_channel_id','')
            if not safe_channel:
                return {'status':'failed','reason':'TEST_MODE test destination is not configured.'}
            delivery_channel=str(safe_channel)
            test_guild,test_target=await self._channel(bot,guild_id,delivery_channel)
            if not test_target:
                return {'status':'failed','reason':'TEST_MODE test destination is missing or lacks View Channel / Send Messages.'}
        if entry.get("category")=="general":
            if test_mode: content=f"{chr(0x1F9EA)} TEST PULSE · General · {content}"
            result=await self.send(bot,guild_id,delivery_channel,"test_pulse" if test_mode else "pulse",content,is_test=test_mode)
            if result.get('status')=='sent': result['dedupe_keys']=[content]
            return result
        sent_ids=[]
        if test_mode and manual:
            prefix=f"{chr(0x1F9EA)} TEST PULSE · {_safe_text(entry.get('label') or entry.get('category'),80)}\n"
            content=self._format_verified_records(entry.get('category'),records,maximum=3,max_length=500-len(prefix))
            if not content:return {'status':'no_new_data','reason':'No complete verified record fits the labelled test message.'}
            content=prefix+content
            result=await self.send(bot,guild_id,delivery_channel,'test_pulse',content,is_test=True)
            if result.get('status')=='sent':
                result['dedupe_keys']=[record[4] for record in records[:3] if f"<{record[4]}>" in content]
            return result
        for record in records:
            if len(sent_ids)>=3: break
            content=self._format_verified_records(entry.get("category"),[record],maximum=1)
            if not content: continue
            if test_mode: content=f"{chr(0x1F9EA)} TEST | {content}"
            result=await self.send(bot,guild_id,key[1],"test_pulse" if test_mode else "pulse",content,
                                   is_test=test_mode,dedupe_key="" if test_mode else record[4])
            if result.get("status")=="sent": sent_ids.append(result.get("message_id",""))
            elif result.get("status")=="failed": return result
        if sent_ids: return {"status":"sent","message_ids":sent_ids,"dedupe_keys":[r[4] for r in records[:len(sent_ids)]],"channel_id":key[1],"guild_id":str(guild_id)}
        return {"status":"no_new_data"}

    async def preview_all_pulse(self, bot, guild_id):
        """Inspect saved, post-baseline records and routing without sending or collecting."""
        settings=await self._settings(guild_id); pulse=settings['pulse']; now=utc_now()
        guild=bot.get_guild(int(guild_id)) if bot and str(guild_id).isdigit() else None
        channels={str(c.id):c for c in getattr(guild,'text_channels',())}
        controls=self.automation_controls()
        paused=(not controls['autonomous_mode'] or not controls['autopilot_modules'].get('pulse',False)
                or controls['all_community_paused'] or controls['pulse_paused'])
        rows=[]
        source_categories={
            'news':{'news','custom'},'jobs':{'jobs'},'threat_intel':{'threat','threat_intel'},
            'technology':{'technology','tech'},'github_tools':{'github_tools','tools'},
            'security_research':{'research','security_research'},'critical_cve':{'cve','cves'},
            'zero_day':{'cve','cves'},
        }
        for entry in pulse.get('channels',[]):
            category=str(entry.get('category') or entry.get('key') or '')
            channel_id=str(entry.get('channel_id') or '')
            channel=channels.get(channel_id)
            perms=channel.permissions_for(guild.me) if channel and guild and guild.me else None
            channel_ready=bool(perms and perms.view_channel and perms.send_messages)
            baseline=str(entry.get('baseline_at') or '')
            candidate_records=[]; duplicates=[]; source_rows=[]; last_collection=None
            async with SessionLocal() as session:
                source_keys=source_categories.get(category,set())
                if source_keys:
                    source_rows=(await session.scalars(select(Source).where(Source.category.in_(source_keys)))).all()
                    source_times=[getattr(s,'last_fetch',None) or getattr(s,'last_success',None) for s in source_rows]
                    source_times=[v for v in source_times if v]
                    if source_times:last_collection=max(source_times).isoformat()
                if entry.get('enabled') and category!='general' and baseline:
                    candidate_records=await self._verified_pulse_records(session,entry)
                    for record in candidate_records:
                        digest=_digest(record[4])
                        prior=await session.scalar(select(PulseDeliveryEvent.id).where(
                            PulseDeliveryEvent.guild_id==str(guild_id),PulseDeliveryEvent.category==category,
                            PulseDeliveryEvent.content_hash==digest,PulseDeliveryEvent.status=='sent').limit(1))
                        duplicates.append(bool(prior))
                last_event=(await session.scalars(select(PulseDeliveryEvent).where(
                    PulseDeliveryEvent.guild_id==str(guild_id),PulseDeliveryEvent.category==category,
                    PulseDeliveryEvent.status=='sent').order_by(PulseDeliveryEvent.created_at.desc()).limit(1))).first()
                if last_event is None:
                    last_post=(await session.scalars(select(CommunityPost).where(
                        CommunityPost.guild_id==str(guild_id),CommunityPost.channel_id==channel_id,
                        CommunityPost.kind.in_(['pulse','test_pulse']),CommunityPost.status=='sent')
                        .order_by(CommunityPost.created_at.desc()).limit(1))).first()
                else:last_post=None
                zone=get_timezone(pulse.get('timezone') or 'Asia/Kolkata')
                day_start=now.astimezone(zone).replace(hour=0,minute=0,second=0,microsecond=0).astimezone(timezone.utc)
                sent_today=await session.scalar(select(func.count()).select_from(CommunityPost).where(
                    CommunityPost.guild_id==str(guild_id),CommunityPost.channel_id==channel_id,
                    CommunityPost.kind=='pulse',CommunityPost.status=='sent',CommunityPost.created_at>=day_start))
                event_rows=(await session.scalars(select(PulseDeliveryEvent).where(
                    PulseDeliveryEvent.guild_id==str(guild_id),PulseDeliveryEvent.category==category,
                    PulseDeliveryEvent.created_at>=day_start))).all()
            source_enabled=[s for s in source_rows if s.enabled]
            source_health=('not_required' if category=='general' else
                ('healthy' if source_enabled and all(s.healthy for s in source_enabled) else
                 'degraded' if source_enabled and any(s.healthy for s in source_enabled) else
                 'error' if source_enabled else 'unavailable'))
            fresh=[record for index,record in enumerate(candidate_records) if index>=len(duplicates) or not duplicates[index]]
            selected=fresh[:3] if category!='general' else []
            last_sent=(last_event.created_at if last_event else getattr(last_post,'created_at',None))
            interval=max(30,min(int(entry.get('interval_minutes') or 30),10080))
            next_run=(last_sent+timedelta(minutes=interval) if last_sent else now) if entry.get('enabled') else None
            skip=''
            if not entry.get('enabled'):skip='Disabled'
            elif not channel_id:skip='Destination channel is not configured'
            elif not channel_ready:skip='Destination channel is unavailable or missing View/Send permission'
            elif category!='general' and not baseline:skip='Baseline is missing'
            elif category!='general' and not candidate_records:skip='No verified post-baseline records'
            elif category!='general' and not selected:skip='All candidates were already delivered'
            elif (sent_today or 0)>=int(pulse.get('daily_limit',40)):skip='Daily channel limit reached'
            elif last_sent and (now-last_sent).total_seconds()<interval*60:skip='Category interval has not elapsed'
            elif category=='general' and last_sent and (now-last_sent).total_seconds()<6*3600:skip='General message cooldown has not elapsed'
            elif _is_quiet(pulse,now):skip='Quiet hours'
            elif paused:skip='Automation kill switch is paused'
            elif get_settings().test_mode:skip='Scheduled delivery paused in TEST_MODE'
            if category=='general':
                content=f"{chr(0x1F6E1)} Tiny debate: Red Team or Blue Team today? {chr(0x2728)}"
                candidate_count=1 if entry.get('enabled') else 0; duplicate_count=0
            else:
                content=self._format_verified_records(category,selected,maximum=3)
                candidate_count=len(candidate_records);duplicate_count=sum(1 for d in duplicates if d)
            counts={key:sum(1 for ev in event_rows if ev.status==value) for key,value in {
                'sent':'sent','no_new_data':'no_new_data','skipped':'skipped','duplicate':'duplicate',
                'rate_limited':'rate_limited','failed':'failed'}.items()}
            counts['attempted']=len(event_rows)
            source_diagnostics=[]
            for source in source_rows:
                retry_at=None
                retry_time=None
                if source.category=='jobs' and source.last_failure and source.failure_count:
                    from collectors.jobs.collector import source_retry_delay
                    retry_time=source.last_failure
                    if retry_time.tzinfo is None:retry_time=retry_time.replace(tzinfo=timezone.utc)
                    retry_time=retry_time+source_retry_delay(source.failure_count);retry_at=retry_time.isoformat()
                raw_error=str(source.last_error or '').casefold()
                http_status=getattr(source,'http_status',None)
                parser_status=str(getattr(source,'parser_status','') or '').upper()
                rate_status=str(getattr(source,'rate_limit_status','') or '').upper()
                error_code=('rate_limited' if http_status==429 or 'LIMIT' in rate_status or '429' in raw_error else
                            'http_error' if (http_status and http_status>=400) or 'http' in raw_error or 'status' in raw_error else
                            'parser_error' if parser_status=='FAILED' or 'parse' in raw_error or 'xml' in raw_error or 'json' in raw_error else
                            'network_error' if any(x in raw_error for x in ('timeout','connect','dns','network')) else
                            'source_error' if raw_error else None)
                source_diagnostics.append({'name':_safe_text(source.name,100),'category':source.category,
                    'enabled':bool(source.enabled),'state':'HEALTHY' if source.healthy else ('BACKING_OFF' if retry_time and utc_now()<retry_time else 'DEGRADED'),
                    'last_collection':source.last_fetch.isoformat() if source.last_fetch else None,
                    'last_success':source.last_success.isoformat() if source.last_success else None,
                    'last_error_code':error_code,'failure_count':int(source.failure_count or 0),
                    'http_status':http_status,'rate_limit_status':rate_status or None,
                    'parser_status':parser_status or None,'response_time_ms':source.response_time_ms,
                    'retry_at':retry_at,'items_found':int(source.items_found or 0),
                    'relevant_items':int(source.relevant_items or 0)})
            rows.append({'key':entry.get('key'), 'category':category,'label':entry.get('label'),
                'enabled':bool(entry.get('enabled')),'destination':getattr(channel,'name',None) or channel_id or None,
                'destination_ready':channel_ready,'source_health':source_health,
                'source_count':len(source_rows),'source_enabled':len(source_enabled),
                'source_unhealthy':sum(1 for s in source_enabled if not s.healthy),
                'sources':source_diagnostics,
                'last_collection':last_collection,'baseline_at':baseline or None,'candidate_count':candidate_count,
                'duplicates':duplicate_count,'selected':len(selected) if category!='general' else candidate_count,
                'last_delivery':last_sent.isoformat() if last_sent else None,
                'next_scheduled_run':next_run.isoformat() if next_run else None,
                'reason_skipped':skip or None,'would_send':not bool(skip),'preview':content,
                'delivery_counts':counts,'dedupe_state':{'candidate_count':candidate_count,
                    'duplicate_count':duplicate_count,'new_count':max(0,candidate_count-duplicate_count)},
                'delivery_state':'PAUSED' if paused else ('READY' if not skip else 'WAITING'),
                'last_failure':next((ev.created_at.isoformat() for ev in event_rows if ev.status=='failed'),None)})
        return {'guild_id':str(guild_id),'test_mode':get_settings().test_mode,'paused':paused,
            'dry_run_only':True,'source_refresh_performed':False,'categories':rows}

    async def record_pulse_outcome(self,guild_id,entry,result,*,manual=False):
        status=str(result.get('status','failed'))
        mapped={'sent':'sent','duplicate':'duplicate','daily_limit':'rate_limited',
                'quiet_hours':'skipped','not_due':'skipped','skipped_active':'skipped',
                'no_new_data':'no_new_data','test_mode_paused':'skipped','deferred':'skipped',
                'paused':'skipped','permission_fallback':'skipped'}
        outcome=mapped.get(status,'failed')
        message_ids=[str(x) for x in (result.get('message_ids') or [])]
        if result.get('message_id'): message_ids=[str(result['message_id'])]
        dedupe_keys=result.get('dedupe_keys') or ([result['dedupe_key']] if result.get('dedupe_key') else [])
        if not dedupe_keys: dedupe_keys=['']
        async with SessionLocal() as session:
            for index,dedupe_key in enumerate(dedupe_keys):
                session.add(PulseDeliveryEvent(guild_id=str(guild_id),category=str(entry.get('category') or entry.get('key') or ''),
                    channel_id=str(result.get('channel_id') or entry.get('channel_id') or ''),content_hash=_digest(dedupe_key) if dedupe_key and not manual else '',
                    status=outcome,reason=_safe_text(result.get('reason') or status,180),
                    message_id=message_ids[min(index,len(message_ids)-1)] if message_ids else ''))
            await session.commit()
        return outcome

    async def run_due(self, bot):
        async with SessionLocal() as session:
            rows = (await session.scalars(select(CommunityConfig))).all()
            work = [(row.guild_id, merge_settings(row.settings)) for row in rows]
        sent = 0
        for guild_id, settings in work:
            for entry in settings['pulse']['channels']:
                if not entry.get('enabled') or not entry.get('channel_id'): continue
                try:
                    result = await self._send_pulse(bot, guild_id, settings, entry)
                    if result.get('status') in {'not_due','paused','deferred','quiet_hours','skipped_active','test_mode_paused'}:
                        continue
                    await self.record_pulse_outcome(guild_id,entry,result)
                    if result.get('status') == 'sent': sent += 1
                except Exception as exc:
                    try: await self.record_pulse_outcome(guild_id,entry,{'status':'failed','reason':type(exc).__name__})
                    except Exception: pass
                    log.warning('Channel Pulse failed channel_id=%s error=%s', entry.get('channel_id'), type(exc).__name__)
        return sent


community_automation = CommunityAutomation()
