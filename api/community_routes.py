"""Admin-only controls for safe, opt-in Discord community automation."""
import asyncio
import re
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select, func
from config.settings import get_settings

from config.runtime_config import get_runtime_config, update_runtime_config, RuntimeConfigError
from database.db import SessionLocal
from database.models import CommunityConfig, CommunityPost, PulseDeliveryEvent, CommunityEngagementMember, CommunityEngagementEvent, SocialInteractionEvent
from services.community import community_automation, default_community_settings, merge_settings, pulse_readiness

KEYS = {'general','news','jobs','critical_cve','zero_day','threat_intel','technology','github_tools','security_research'}


class WelcomeSettings(BaseModel):
    enabled: bool = False
    channel_id: str = Field(default='', max_length=32)
    use_ai: bool = False
    mention_member: bool = True
    include_server_name: bool = True
    prompt: str = Field(default='', max_length=400)
    fallback: str = Field(default='', max_length=400)

    @field_validator('channel_id')
    @classmethod
    def channel(cls, value):
        if value and not value.isdigit(): raise ValueError('Choose a valid Discord channel')
        return value


class FarewellSettings(WelcomeSettings):
    mention_member: bool = False
    include_server_name: bool = True


class PulseChannel(BaseModel):
    key: str
    category: str = Field(max_length=40)
    label: str = Field(max_length=80)
    channel_id: str = Field(default='', max_length=32)
    enabled: bool = False
    interval_minutes: int = Field(ge=30, le=10080)
    prompt: str = Field(default='', max_length=400)

    @field_validator('key','category')
    @classmethod
    def key_valid(cls, value):
        if value not in KEYS: raise ValueError('Unknown pulse channel category')
        return value

    @field_validator('channel_id')
    @classmethod
    def channel(cls, value):
        if value and not value.isdigit(): raise ValueError('Choose a valid Discord channel')
        return value


class PulseSettings(BaseModel):
    quiet_hours_enabled: bool = True
    quiet_start: str = Field(default='23:00', pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
    quiet_end: str = Field(default='08:00', pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
    timezone: str = Field(default='Asia/Kolkata', max_length=64)
    skip_if_active: bool = True
    activity_minutes: int = Field(default=10, ge=1, le=180)
    daily_limit: int = Field(default=40, ge=1, le=100)
    channels: list[PulseChannel] = Field(default_factory=list, max_length=20)

    @field_validator('timezone')
    @classmethod
    def timezone_valid(cls, value):
        try: ZoneInfo(value)
        except (ZoneInfoNotFoundError,ValueError): raise ValueError('Use a valid IANA timezone') from None
        return value

    @model_validator(mode='after')
    def unique_channels(self):
        keys=[row.key for row in self.channels]
        if len(keys)!=len(set(keys)): raise ValueError('Pulse channel categories must be unique')
        return self


class CommunityPayload(BaseModel):
    guild_id: str = Field(min_length=1, max_length=32, pattern=r'^\d+$')
    welcome: WelcomeSettings
    farewell: FarewellSettings
    pulse: PulseSettings
    members_intent: bool = False


def router(require_admin):
    routes=APIRouter(prefix='/api/community',dependencies=[Depends(require_admin)])

    @routes.get('/config')
    async def get_config(guild_id: str = ''):
        from api.app import runtime, bot_state
        bot=runtime.get('bot')
        guilds=[{'id':str(g.id),'name':str(g.name)} for g in (bot.guilds if bot and bot.is_ready() else [])]
        if not guild_id and guilds: guild_id=guilds[0]['id']
        settings=default_community_settings()
        posts=[]
        if guild_id and guild_id.isdigit():
            async with SessionLocal() as session:
                row=await session.scalar(select(CommunityConfig).where(CommunityConfig.guild_id==guild_id))
                if row: settings=merge_settings(row.settings)
                since=datetime.now(timezone.utc)-timedelta(days=1)
                recent=(await session.scalars(select(CommunityPost).where(CommunityPost.guild_id==guild_id)
                    .order_by(CommunityPost.created_at.desc()).limit(50))).all()
                posts=recent
        channels=[]
        guild=bot.get_guild(int(guild_id)) if bot and guild_id.isdigit() else None
        if guild:
            for channel in guild.text_channels:
                me=guild.me; perms=channel.permissions_for(me) if me else None
                channels.append({'id':str(channel.id),'name':channel.name,
                                 'ready':bool(perms and perms.view_channel and perms.send_messages),
                                 'can_add_reactions':bool(perms and perms.view_channel and perms.add_reactions),
                                 'can_read_history':bool(perms and perms.view_channel and perms.read_message_history)})
        intent_requested=bool(get_runtime_config().get('COMMUNITY_MEMBERS_INTENT',False))
        intent_ready=bool(bot and bot.is_ready() and bot.intents.members)
        content_requested=bool(get_runtime_config().get('COMMUNITY_MESSAGE_CONTENT_INTENT',False))
        content_ready=bool(bot and bot.is_ready() and getattr(bot.intents,'message_content',False))
        from services.member_directory import directory_status
        member_directory=await directory_status(guild_id) if guild_id.isdigit() else {'status':'unavailable','total':0,'humans':0,'bots_excluded':0,'eligible':0,'opted_out':0,'last_sync_at':None}
        from services.smart_social import smart_social
        social_status=await smart_social.status(guild_id) if guild_id.isdigit() else {}
        return {'guild_id':guild_id,'guilds':guilds,'channels':channels,'settings':settings,
                'test_mode':get_settings().test_mode,
                'member_intent':{'enabled':intent_ready,'requested':intent_requested,
                    'status':'Enabled' if intent_ready else ('Pending Discord Developer Portal permission' if intent_requested else 'Disabled'),
                    'instruction':'Enable Server Members Intent in Discord Developer Portal for full discovery.'},
                'member_directory':member_directory,
                'message_content_intent':{'enabled':content_ready,'requested':content_requested,
                    'guild_messages_enabled':bool(bot and bot.is_ready() and bot.intents.messages),
                    'direct_mention_content':'AVAILABLE' if bot and bot.is_ready() else 'UNAVAILABLE',
                    'normal_content':'AVAILABLE' if content_ready else 'LIMITED',
                    'social_mode':'FULL' if content_ready else 'LIMITED',
                    'instruction':'Enable Message Content Intent in Discord Developer Portal before enabling here.'},
                'smart_social_status':social_status,
                'bot_ready':bool(bot and bot.is_ready()), 'last_posts':[{'kind':p.kind,'channel_id':p.channel_id,
                    'message_id':p.message_id,'status':p.status,'created_at':p.created_at.isoformat()} for p in posts]}

    @routes.post('/config')
    async def save_config(payload: CommunityPayload):
        from api.app import runtime
        import discord
        bot=runtime.get('bot')
        guild=bot.get_guild(int(payload.guild_id)) if bot and bot.is_ready() else None
        if bot and bot.is_ready() and not guild:
            raise HTTPException(422,'The bot is not a member of the selected server.')
        value=payload.model_dump()
        value.pop('guild_id',None)
        intent_value=bool(value.pop('members_intent',False))
        if guild:
            destinations=[]
            for section in ('welcome','farewell'):
                item=value[section]
                if item['enabled'] and not item['channel_id']:
                    raise HTTPException(422,f'Choose a destination channel for {section}.')
                if item['channel_id']: destinations.append((section,item['channel_id']))
            for item in value['pulse']['channels']:
                if item['enabled'] and not item['channel_id']:
                    raise HTTPException(422,f"Choose a destination channel for {item['label']}.")
                if item['channel_id']: destinations.append((item['label'],item['channel_id']))
            for label,channel_id in destinations:
                channel=guild.get_channel(int(channel_id))
                if not isinstance(channel,discord.TextChannel): raise HTTPException(422,f'{label}: select a text channel in this server.')
                perms=channel.permissions_for(guild.me) if guild.me else None
                if not perms or not perms.view_channel or not perms.send_messages:
                    raise HTTPException(422,f'{label}: bot needs View Channel and Send Messages in that channel.')
        if (value['welcome']['enabled'] or value['farewell']['enabled']) and not intent_value:
            raise HTTPException(409,'Enable Server Members Intent in the Discord Developer Portal and turn it on here before enabling welcome or farewell events.')
        old_intent=bool(get_runtime_config().get('COMMUNITY_MEMBERS_INTENT',False))
        previous_settings=await community_automation._settings(payload.guild_id)
        prior_pulse={row['key']:row for row in previous_settings.get('pulse',{}).get('channels',[])}
        observed_at=datetime.now(timezone.utc).isoformat()
        for item in value['pulse']['channels']:
            prior=prior_pulse.get(item['key'],{})
            if item['enabled'] and (not prior.get('enabled') or prior.get('channel_id')!=item['channel_id']):
                # Existing DB rows become the baseline; only records discovered later are alertable.
                item['baseline_at']=observed_at
            else:
                item['baseline_at']=prior.get('baseline_at') or item.get('baseline_at','')
        value['member_engagement'] = previous_settings.get('member_engagement', {})
        value['smart_social'] = previous_settings.get('smart_social', {})
        await community_automation.save_settings(payload.guild_id,value)
        if intent_value != old_intent:
            try: update_runtime_config({'COMMUNITY_MEMBERS_INTENT':intent_value})
            except RuntimeConfigError: raise HTTPException(503,'Unable to save community settings.') from None
            controller=runtime.get('controller')
            from config.settings import get_settings
            token=get_settings().discord_token
            if controller and token and controller.bot:
                try:
                    await controller.start_bot(token)
                    await asyncio.wait_for(controller.bot.wait_until_ready(),timeout=20)
                except Exception:
                    try:
                        update_runtime_config({'COMMUNITY_MEMBERS_INTENT':old_intent})
                        get_settings.cache_clear()
                        await community_automation.save_settings(payload.guild_id,previous_settings)
                        if token: await controller.start_bot(token)
                    except Exception: pass
                    raise HTTPException(409,'Discord did not accept the Server Members Intent. Enable it in the Developer Portal, then retry.') from None
            get_settings.cache_clear()
        return {'saved':True,'settings':value,'member_intent_restart_required':intent_value!=old_intent and not (runtime.get('bot') and runtime['bot'].is_ready())}

    @routes.post('/members-intent')
    async def members_intent(payload: dict):
        enabled=payload.get('enabled')
        if not isinstance(enabled,bool): raise HTTPException(422,'enabled must be true or false')
        config=await get_config()
        if not config['guild_id']: raise HTTPException(409,'Connect HEX ALERT to a Discord server first.')
        settings=merge_settings(config['settings']); settings['members_intent']=enabled
        shaped=CommunityPayload(guild_id=config['guild_id'],welcome=settings['welcome'],farewell=settings['farewell'],
            pulse=settings['pulse'],members_intent=enabled)
        return await save_config(shaped)

    @routes.post('/test/{kind}')
    async def test_automation(kind: str, payload: dict):
        from api.app import runtime
        bot=runtime.get('bot')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        if kind not in {'welcome','farewell','pulse'}: raise HTTPException(404,'Unknown automation test.')
        guild_id=str(payload.get('guild_id','')); channel_id=str(payload.get('channel_id',''))
        if not guild_id.isdigit(): raise HTTPException(422,'Select a Discord server.')
        result=await community_automation.test(bot,guild_id,kind,channel_id)
        if result.get('status') not in {'SUCCESS'}: raise HTTPException(422,result.get('reason','Automation test failed.'))
        return result

    @routes.post('/run/{channel_key}')
    async def run_pulse(channel_key: str, payload: dict):
        from api.app import runtime
        bot=runtime.get('bot')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        result=await community_automation.run_now(bot,str(payload.get('guild_id','')),channel_key)
        entry=next((x for x in (await community_automation._settings(str(payload.get('guild_id',''))))['pulse']['channels'] if x.get('key')==channel_key),{'key':channel_key})
        await community_automation.record_pulse_outcome(str(payload.get('guild_id','')),entry,result,manual=True)
        if result.get('status')!='sent': raise HTTPException(409,result.get('reason',result.get('status','Pulse was not sent.')))
        return result

    @routes.post('/social/config')
    async def save_social_config(payload: dict):
        from api.app import runtime
        from services.smart_social import normalize_social
        guild_id=str(payload.get('guild_id','')); raw=payload.get('settings')
        if not guild_id.isdigit() or not isinstance(raw,dict): raise HTTPException(422,'Select a server and provide valid Smart Reactions settings.')
        bot=runtime.get('bot'); guild=bot.get_guild(int(guild_id)) if bot and bot.is_ready() else None
        if bot and bot.is_ready() and not guild: raise HTTPException(404,'Selected Discord server is not connected.')
        settings=normalize_social(raw)
        if guild:
            available={str(c.id):c for c in guild.text_channels}
            for channel_id, policy in settings['channels'].items():
                if channel_id not in available: raise HTTPException(422,'Choose channels from the selected Discord server.')
                perms=available[channel_id].permissions_for(guild.me) if guild.me else None
                if (policy['reactions_enabled'] or policy['auto_replies_enabled']) and (not perms or not perms.view_channel):
                    raise HTTPException(422,f"Bot needs View Channel in #{available[channel_id].name}.")
                if policy['reactions_enabled'] and (not perms or not perms.add_reactions):
                    raise HTTPException(422,f"Bot needs Add Reactions in #{available[channel_id].name}.")
                if policy['auto_replies_enabled'] and (not perms or not perms.send_messages or not perms.read_message_history):
                    raise HTTPException(422,f"Bot needs View Channel, Send Messages, and Read Message History in #{available[channel_id].name}.")
        current=await community_automation._settings(guild_id)
        current['smart_social']=settings
        await community_automation.save_settings(guild_id,current)
        return {'saved':True,'settings':settings}

    @routes.post('/social/message-content-intent')
    async def social_message_content_intent(payload: dict):
        from api.app import runtime
        from config.settings import get_settings
        enabled=payload.get('enabled')
        if not isinstance(enabled,bool): raise HTTPException(422,'enabled must be true or false')
        old=bool(get_runtime_config().get('COMMUNITY_MESSAGE_CONTENT_INTENT',False))
        if old==enabled: return {'enabled':old,'restarted':False}
        try: update_runtime_config({'COMMUNITY_MESSAGE_CONTENT_INTENT':enabled})
        except RuntimeConfigError: raise HTTPException(503,'Unable to save runtime intent configuration.') from None
        controller=runtime.get('controller'); token=get_settings().discord_token
        try:
            get_settings.cache_clear()
            if controller and token:
                await controller.start_bot(token)
                await asyncio.wait_for(controller.bot.wait_until_ready(),timeout=20)
                if bool(controller.bot.intents.message_content)!=enabled: raise RuntimeError('intent not active')
        except Exception:
            try:
                update_runtime_config({'COMMUNITY_MESSAGE_CONTENT_INTENT':old})
                get_settings.cache_clear()
                if controller and token: await controller.start_bot(token)
            except Exception: pass
            raise HTTPException(409,'Discord did not accept Message Content Intent. Enable it in the Developer Portal, then retry.') from None
        return {'enabled':enabled,'restarted':bool(controller and token)}

    async def _test_safe_message(bot, payload):
        from config.settings import get_settings
        if not get_settings().test_mode: raise HTTPException(409,'Smart social tests require TEST_MODE.')
        guild_id=str(payload.get('guild_id','')); channel_id=str(payload.get('channel_id','')); user_id=str(payload.get('user_id',''))
        guild=bot.get_guild(int(guild_id)) if guild_id.isdigit() else None
        channel=guild.get_channel(int(channel_id)) if guild and channel_id.isdigit() else None
        if not guild or not channel: raise HTTPException(404,'Select a channel in a connected Discord server.')
        perms=channel.permissions_for(guild.me) if guild.me else None
        if not perms or not perms.view_channel or not perms.read_message_history: raise HTTPException(422,'Bot needs View Channel and Read Message History to find a test-safe message.')
        if not hasattr(channel,'history'): raise HTTPException(422,'Select a text channel or thread with history access.')
        async for message in channel.history(limit=50):
            if message.author.bot or getattr(message,'webhook_id',None) or getattr(message,'mention_everyone',False): continue
            if user_id and str(message.author.id)!=user_id: continue
            return message
        raise HTTPException(404,'No recent human message found for the selected test member.')

    @routes.post('/social/test-reaction')
    async def test_social_reaction(payload: dict):
        from api.app import runtime
        from services.smart_social import smart_social, select_reaction
        bot=runtime.get('bot')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        message=await _test_safe_message(bot,payload)
        reaction=select_reaction(getattr(message,'content',None) if getattr(bot.intents,'message_content',False) else None)
        if not await smart_social._react(message,reaction,kind='TEST_REACTION',enforce_limits=False):
            raise HTTPException(422,'Test reaction failed; check Add Reactions permission and member opt-out.')
        return {'status':'sent','reaction':reaction,'source_message_id':str(message.id),'channel_id':str(message.channel.id),'user_id':str(message.author.id)}

    @routes.post('/social/test-reply')
    async def test_social_reply(payload: dict):
        from api.app import runtime
        from services.smart_social import smart_social
        bot=runtime.get('bot')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        message=await _test_safe_message(bot,payload)
        settings=await smart_social.config(message.guild.id)
        if not await smart_social._reply(message,'',settings,test=True):
            raise HTTPException(422,'Test social reply failed; check Send Messages permission and member opt-out.')
        return {'status':'sent','source_message_id':str(message.id),'channel_id':str(message.channel.id),'user_id':str(message.author.id)}


    @routes.get('/engagement/status')
    async def engagement_status(guild_id: str):
        from api.app import runtime
        from services.member_engagement import normalize_settings, eligible_members, preview as preview_member, read_settings
        if not guild_id.isdigit(): raise HTTPException(422,'Select a Discord server.')
        cfg=await read_settings(guild_id); settings=normalize_settings(cfg.get('member_engagement'))
        bot=runtime.get('bot'); guild=bot.get_guild(int(guild_id)) if bot else None
        if guild and not settings.get('channel_id'):
            default_channel=next((c for c in guild.text_channels if c.name.casefold()=='general'),None)
            if default_channel: settings['channel_id']=str(default_channel.id)
        people=[]; rows=[]
        async with SessionLocal() as session:
            rows=(await session.scalars(select(CommunityEngagementMember).where(
                CommunityEngagementMember.guild_id==guild_id))).all()
        for row in rows:
            if row.is_active and not row.is_bot:
                people.append({'id':row.user_id,'name':str(row.display_name or row.username)[:80],
                    'username':row.username,'opted_out':row.opted_out,'eligible':not row.opted_out})
        eligible=await eligible_members(guild,settings,fetch_members=True) if guild else []
        now=datetime.now(timezone.utc); zone=ZoneInfo(settings['timezone'])
        start=now.astimezone(zone).replace(hour=0,minute=0,second=0,microsecond=0).astimezone(timezone.utc)
        async with SessionLocal() as session:
            today=await session.scalar(select(func.count()).select_from(CommunityEngagementEvent).where(
                CommunityEngagementEvent.guild_id==guild_id,CommunityEngagementEvent.status=='sent',
                CommunityEngagementEvent.event_type.in_(['INDIVIDUAL','GENERAL','EVERYONE']),
                CommunityEngagementEvent.sent_at>=start))
            last=(await session.scalars(select(CommunityEngagementEvent).where(
                CommunityEngagementEvent.guild_id==guild_id).order_by(CommunityEngagementEvent.sent_at.desc()).limit(1))).first()
        def _parse(value):
            try:return datetime.fromisoformat(value) if value else None
            except (ValueError,TypeError):return None
        next_at=settings.get('next_run_at')
        next_minutes=max(0,int((_parse(next_at)-now).total_seconds()/60)) if next_at and _parse(next_at) else None
        today_local=now.astimezone(ZoneInfo(settings['timezone'])).date().isoformat()
        tagged_today=sum(1 for r in rows if r.last_nudged_date==today_local)
        last_target_name=next((x['name'] for x in people if last and x['id']==last.target_user_id),'')
        everyone_next=None
        last_everyone=_parse(settings.get('last_everyone_at'))
        if last_everyone:everyone_next=(last_everyone+timedelta(days=settings['everyone_cooldown_days'])).isoformat()
        from services.member_directory import directory_status
        directory=await directory_status(guild_id)
        return {'settings':settings,'eligible_count':len(eligible),'observed_members':people,'directory':directory,'tagged_today':tagged_today,
            'last_target_name':last_target_name,'everyone_next_eligible':everyone_next,
            'messages_today':int(today or 0),'next_interval_minutes':next_minutes,'last_event':({'type':last.event_type,'target_user_id':last.target_user_id,
            'style':last.style,'sent_at':last.sent_at.isoformat(),'message_id':last.message_id} if last else None),
            'everyone_last_used':settings.get('last_everyone_at'),'bot_ready':bool(bot and bot.is_ready())}

    @routes.get('/members')
    async def member_directory(guild_id: str):
        from services.member_directory import directory_status, list_members
        if not guild_id.isdigit(): raise HTTPException(422,'Select a Discord server.')
        return {'status':await directory_status(guild_id),'members':await list_members(guild_id)}

    @routes.get('/members/{user_id}/history')
    async def member_history(user_id: str, guild_id: str):
        if not guild_id.isdigit() or not user_id.isdigit(): raise HTTPException(422,'Select a valid server member.')
        async with SessionLocal() as session:
            events=(await session.scalars(select(CommunityEngagementEvent).where(
                CommunityEngagementEvent.guild_id==guild_id,
                CommunityEngagementEvent.target_user_id==user_id).order_by(
                    CommunityEngagementEvent.sent_at.desc()).limit(30))).all()
        return {'events':[{'type':event.event_type,'style':event.style,'status':event.status,
                'message_id':event.message_id,'sent_at':event.sent_at.isoformat()} for event in events]}

    @routes.post('/members/sync')
    async def sync_members(payload: dict):
        from api.app import runtime
        from services.member_directory import sync_guild
        guild_id=str(payload.get('guild_id','')); bot=runtime.get('bot')
        if not guild_id.isdigit(): raise HTTPException(422,'Select a Discord server.')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        guild=bot.get_guild(int(guild_id))
        if not guild: raise HTTPException(404,'Selected Discord server is not connected.')
        result=await sync_guild(guild,bot_user_id=getattr(getattr(bot,'user',None),'id',None),
                                members_intent=bool(getattr(bot.intents,'members',False)),force_fetch=True)
        return result

    @routes.post('/engagement/auto-test-member')
    async def auto_test_member(payload: dict):
        from api.app import runtime
        from services.member_engagement import member_engagement, normalize_settings, read_settings, preview as choose_member, STYLES
        from config.settings import get_settings
        if not get_settings().test_mode: raise HTTPException(409,'Member tests require TEST_MODE.')
        guild_id=str(payload.get('guild_id','')); style=str(payload.get('style','')); test_run_id=engagement_test_request_id(payload); bot=runtime.get('bot')
        if style and style not in STYLES: raise HTTPException(422,'Select a supported style.')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        guild=bot.get_guild(int(guild_id)) if guild_id.isdigit() else None
        if not guild: raise HTTPException(404,'Selected Discord server is not connected.')
        settings=normalize_settings((await read_settings(guild_id)).get('member_engagement'))
        choice=await choose_member(guild,settings)
        if not choice.get('target'): raise HTTPException(409,choice.get('reason','No eligible directory member is available.'))
        result=await member_engagement.test_send(bot,guild_id,choice['target']['id'],style or None,test_run_id)
        if result.get('status') in {'pending','unknown'}:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=202,content={**result,'target':choice['target'],'reason':choice['reason'],'normal_limits_affected':False})
        if result.get('status')!='sent': raise HTTPException(409,result.get('reason','Member test failed.'))
        return {**result,'target':choice['target'],'reason':choice['reason'],'normal_limits_affected':False}

    def engagement_test_request_id(payload):
        value=payload.get('test_run_id')
        try:return str(uuid.UUID(str(value))) if value else str(uuid.uuid4())
        except (ValueError,TypeError,AttributeError):raise HTTPException(422,'Invalid test request ID.')

    @routes.post('/engagement/config')
    async def save_engagement(payload: dict):
        from api.app import runtime
        from services.member_engagement import normalize_settings, read_settings, _persist_settings, next_run_at
        guild_id=str(payload.get('guild_id',''))
        if not guild_id.isdigit(): raise HTTPException(422,'Select a Discord server.')
        bot=runtime.get('bot'); guild=bot.get_guild(int(guild_id)) if bot else None
        raw=payload.get('settings',{})
        if not isinstance(raw,dict): raise HTTPException(422,'Invalid engagement settings.')
        old=(await read_settings(guild_id)).get('member_engagement',{})
        settings=normalize_settings(raw)
        if settings['enabled'] and not settings['channel_id']: raise HTTPException(422,'Choose a community destination channel.')
        if settings['channel_id'] and not str(settings['channel_id']).isdigit(): raise HTTPException(422,'Choose a valid Discord channel ID.')
        if settings['channel_id'] and guild:
            import discord
            channel=guild.get_channel(int(settings['channel_id'])) if settings['channel_id'].isdigit() else None
            if not isinstance(channel,discord.TextChannel) or channel.name.casefold() in {'critical-cve','zero-day','cyber-jobs','bot-status','security-research'}:
                raise HTTPException(422,'Select a regular community text channel.')
            perms=channel.permissions_for(guild.me) if guild.me else None
            if not perms or not perms.view_channel or not perms.send_messages: raise HTTPException(422,'Bot needs View Channel and Send Messages in that channel.')
        if settings['enabled'] and not old.get('enabled'): settings['next_run_at']=next_run_at(settings).isoformat()
        elif not settings['enabled']: settings['next_run_at']=None
        elif not settings.get('next_run_at'): settings['next_run_at']=next_run_at(settings).isoformat()
        await _persist_settings(guild_id,settings)
        return {'saved':True,'settings':settings}

    @routes.post('/engagement/preview-member')
    async def engagement_preview(payload: dict):
        from api.app import runtime
        from services.member_engagement import normalize_settings, read_settings, preview as preview_member
        guild_id=str(payload.get('guild_id','')); bot=runtime.get('bot')
        guild=bot.get_guild(int(guild_id)) if bot and guild_id.isdigit() else None
        if not guild: raise HTTPException(503,'Discord server is not connected.')
        settings=normalize_settings((await read_settings(guild_id)).get('member_engagement'))
        result=await preview_member(guild,settings)
        result.pop('_member',None)
        result['last_engagement_at']=result.get('last_nudged_at')
        result['cooldown_state']='Eligible now; daily and minimum-repeat cooldown checks passed.' if result.get('target') else 'No member currently eligible.'
        return result

    @routes.post('/engagement/preview-everyone')
    async def engagement_preview_everyone():
        from services.member_engagement import member_engagement
        return {'preview':await member_engagement.preview_everyone(),'sent':False,'allowed_mentions':'none'}

    @routes.post('/engagement/test')
    async def engagement_test(payload: dict):
        from api.app import runtime
        from services.member_engagement import member_engagement, STYLES
        from config.settings import get_settings
        if not get_settings().test_mode: raise HTTPException(409,'Member tests require TEST_MODE.')
        guild_id=str(payload.get('guild_id','')); user_id=str(payload.get('user_id','')); style=str(payload.get('style','')); test_run_id=engagement_test_request_id(payload)
        if style and style not in STYLES: raise HTTPException(422,'Select a supported style.')
        bot=runtime.get('bot')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        result=await member_engagement.test_send(bot,guild_id,user_id,style or None,test_run_id)
        if result.get('status') in {'pending','unknown'}:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=202,content=result)
        if result.get('status')!='sent': raise HTTPException(409,result.get('reason','Test message failed.'))
        return result

    @routes.post('/pulse/dry-run')
    async def pulse_dry_run(payload: dict):
        from api.app import runtime
        from config.settings import get_settings
        guild_id=str(payload.get('guild_id','')); bot=runtime.get('bot')
        if not guild_id.isdigit(): raise HTTPException(422,'Select a Discord server.')
        if not bot or not bot.is_ready(): raise HTTPException(503,'Discord bot is not connected.')
        if not get_settings().test_mode:
            raise HTTPException(409,'The full Pulse dry run requires TEST_MODE so collector results cannot be delivered.')
        scheduler=runtime.get('scheduler')
        if not scheduler: raise HTTPException(503,'Collection scheduler is not ready.')
        # Run only the existing public collector pipelines. Their Discord
        # dispatcher is hard-blocked by TEST_MODE; source backoff/due checks
        # remain in each collector and are never bypassed here.
        source_runs={}
        for category in ('news','jobs','threat','technology','cve'):
            try:
                await scheduler.run(category)
                source_runs[category]='completed'
            except Exception as exc:
                source_runs[category]=type(exc).__name__
        report=await community_automation.preview_all_pulse(bot,guild_id)
        for row in report.get('categories',[]):
            category=row.get('category')
            row['result']=('ERROR' if row.get('source_health')=='error' else
                'DEGRADED' if row.get('source_health')=='degraded' else
                'SUCCESS_NO_NEW_DATA' if not row.get('candidate_count') else 'PASS')
            row['pipeline_stages']=(['SOURCE','FETCH','NORMALIZE','DB','DEDUPE','CLASSIFY','SCORE','SELECT','FORMAT']
                if category in {'news','jobs','threat_intel','technology','critical_cve','zero_day'} else
                ['DB','DEDUPE','SELECT','FORMAT'])
            row['source_run']=source_runs.get({'threat_intel':'threat','critical_cve':'cve','zero_day':'cve'}.get(category,category))
        report['dry_run_only']=True
        report['source_refresh_performed']=True
        report['delivery_blocked_by_test_mode']=True
        report['source_runs']=source_runs
        return report

    @routes.get('/daily-digest/preview')
    async def daily_digest_preview():
        from services.daily_digest import recent_digest_sections
        cfg=get_settings()
        async with SessionLocal() as session:
            data=await recent_digest_sections(session)
        def rows(items, *, jobs=False):
            return [{'title':str(getattr(item,'title',getattr(item,'cve_id','Alert')) or 'Alert')[:180],
                'url':str((getattr(item,'apply_url','') or getattr(item,'source_url','')) if jobs else getattr(item,'source_url','') or '')[:500],
                **({'company':str(getattr(item,'company','') or '')[:100],
                    'location':str(getattr(item,'location','') or '')[:100]} if jobs else {})} for item in items]
        return {'preview_only':True,'scheduled_time':f"{cfg.daily_digest_hour:02d}:00 {cfg.daily_digest_timezone}",
            'freshness_window_hours':data['window_hours'],
            'sections':[{'title':'🚨 Critical CVEs','items':rows(data['cves'])},
                {'title':'⚠️ New Exploited Vulnerabilities','items':rows(data['exploited_cves'])},
                {'title':'📰 Cyber News','items':rows(data['news'])},
                {'title':'⚠️ Threat Intel','items':rows(data['threats'])},
                {'title':'💼 Jobs','items':rows(data['jobs'],jobs=True)},
                {'title':'🛠️ Tools','items':rows(data['tools'])},
                {'title':'🔬 Research','items':rows(data['research'])},
                {'title':'💻 Technology','items':rows(data['technology'])}]}

    @routes.post('/rollout/controls')
    async def rollout_controls(payload: dict):
        allowed={'all_community_paused','pulse_paused','smart_social_paused','member_engagement_paused','autonomous_mode'}
        changes={key:value for key,value in payload.items() if key in allowed}
        modules=payload.get('autopilot_modules')
        if isinstance(modules,dict):changes['autopilot_modules']=modules
        if not changes or any(not isinstance(value,bool) for key,value in changes.items() if key!='autopilot_modules') or (modules is not None and (not isinstance(modules,dict) or any(not isinstance(v,bool) for v in modules.values()))):
            raise HTTPException(422,'Provide one or more boolean automation pause controls.')
        try: controls=community_automation.save_automation_controls(changes)
        except Exception: raise HTTPException(503,'Automation controls could not be persisted.') from None
        return {'saved':True,'controls':controls}

    @routes.post('/rollout/canary-presets')
    async def save_canary_presets(payload: dict):
        from api.app import runtime
        from services.member_engagement import normalize_settings as normalize_engagement
        from services.smart_social import normalize_social
        guild_id=str(payload.get('guild_id','')); bot=runtime.get('bot')
        guild=bot.get_guild(int(guild_id)) if bot and bot.is_ready() and guild_id.isdigit() else None
        if not guild: raise HTTPException(503,'Discord server is not connected.')
        channel=next((c for c in guild.text_channels if c.name.casefold()=='general'),None)
        if not channel: raise HTTPException(409,'A #general channel is required for the staged canary presets.')
        perms=channel.permissions_for(guild.me) if guild.me else None
        if not perms or not perms.view_channel or not perms.send_messages: raise HTTPException(409,'HEX ALERT needs View Channel and Send Messages in #general.')
        current=await community_automation._settings(guild_id)
        social=normalize_social(current.get('smart_social'))
        social.update({'enabled':False,'normal_reaction_probability':20,'auto_reply_probability':3,
            'reply_user_cooldown_minutes':30,'reply_channel_hour_limit':2,'reply_server_hour_limit':4,
            'channels':{str(channel.id):{'reactions_enabled':True,'auto_replies_enabled':True}}})
        current['smart_social']=social
        engagement=normalize_engagement(current.get('member_engagement'))
        engagement.update({'enabled':False,'channel_id':str(channel.id),'min_interval_hours':2,
            'max_interval_hours':4,'random_interval':True,'individual_probability':90,
            'general_probability':10,'everyone_probability':0,'everyone_enabled':False,
            'everyone_cooldown_days':7,'user_daily_limit':1,'user_repeat_cooldown_hours':24,
            'server_daily_limit':6,'quiet_hours_enabled':True,'quiet_start':'23:00','quiet_end':'08:00',
            'timezone':'Asia/Kolkata','next_run_at':None})
        current['member_engagement']=engagement
        await community_automation.save_settings(guild_id,current)
        return {'saved':True,'channel_id':str(channel.id),'channel_name':channel.name,
            'smart_social':social,'member_engagement':engagement,'enabled':False}

    @routes.get('/rollout-status')
    async def rollout_status(guild_id: str=''):
        from api.app import runtime, bot_state, _ai_health
        from services.member_directory import directory_status
        from services.smart_social import smart_social
        from services.member_engagement import normalize_settings as normalize_engagement
        from config.runtime_config import get_runtime_config
        bot=runtime.get('bot')
        if not guild_id and bot and bot.guilds: guild_id=str(bot.guilds[0].id)
        if guild_id and not guild_id.isdigit(): raise HTTPException(422,'Select a valid Discord server.')
        controls=community_automation.automation_controls()
        pulse_preview=await community_automation.preview_all_pulse(bot,guild_id) if bot and bot.is_ready() and guild_id else {'categories':[],'paused':controls['pulse_paused'] or controls['all_community_paused']}
        directory=await directory_status(guild_id) if guild_id else {'status':'unavailable','eligible':0,'humans':0}
        settings=await community_automation._settings(guild_id) if guild_id else default_community_settings()
        social=await smart_social.status(guild_id) if guild_id else {}
        now=datetime.now(timezone.utc)-timedelta(days=1)
        async with SessionLocal() as session:
            pulse_events=(await session.scalars(select(PulseDeliveryEvent).where(PulseDeliveryEvent.guild_id==guild_id,
                PulseDeliveryEvent.created_at>=now).order_by(PulseDeliveryEvent.created_at.desc()).limit(500))).all() if guild_id else []
            social_events=(await session.scalars(select(SocialInteractionEvent).where(SocialInteractionEvent.guild_id==guild_id,
                SocialInteractionEvent.created_at>=now).order_by(SocialInteractionEvent.created_at.desc()).limit(500))).all() if guild_id else []
            engagement_events=(await session.scalars(select(CommunityEngagementEvent).where(CommunityEngagementEvent.guild_id==guild_id,
                CommunityEngagementEvent.sent_at>=now).order_by(CommunityEngagementEvent.sent_at.desc()).limit(500))).all() if guild_id else []
        def counts(events,status_attr,kind_attr=None):
            result={'attempted':len(events),'sent':0,'no_new_data':0,'skipped':0,'duplicate':0,'rate_limited':0,'failed':0}
            for event in events:
                status=str(getattr(event,status_attr,'' )).casefold()
                if status in result: result[status]+=1
                elif status in {'limited','cooldown','duplicate_blocked'}: result['rate_limited']+=1
            return result
        pulse_counts=counts(pulse_events,'status'); social_counts=counts(social_events,'status'); engagement_counts=counts(engagement_events,'status')
        social_mode='FULL' if bot and bot.is_ready() and getattr(bot.intents,'message_content',False) else 'LIMITED'
        mention_ready=bool(bot_state.get('mention_chat_verified',False))
        engagement=normalize_engagement(settings.get('member_engagement'))
        all_paused=controls['all_community_paused']
        pulse_categories=pulse_preview.get('categories',[])
        enabled_pulse=[item for item in pulse_categories if item.get('enabled')]
        # Readiness describes capability. Pausing or leaving a module disabled
        # affects delivery state only and must not turn READY into an error.
        pulse_state=pulse_readiness(pulse_categories,bot_ready=bool(bot and bot.is_ready()))
        ai_health=await _ai_health()
        return {'guild_id':guild_id,'test_mode':bool(get_settings().test_mode),'production_mode':False,
            'mention_chat':'READY' if mention_ready else ('READY' if bot and bot.is_ready() else 'NOT READY'),
            'pulse':{'state':pulse_state,'enabled':bool(enabled_pulse),'delivery_paused':bool(all_paused or controls['pulse_paused'] or not controls['autonomous_mode'] or not controls['autopilot_modules'].get('pulse',False)),'enabled_categories':len(enabled_pulse),
                'source_failures':sum(1 for row in pulse_categories for src in row.get('sources',[]) if src.get('enabled') and src.get('state')!='HEALTHY'),
                'categories':pulse_categories,'delivery_counts':pulse_counts,
                'last_success':next((x.created_at.isoformat() for x in pulse_events if x.status=='sent'),None),
                'last_failure':next((x.created_at.isoformat() for x in pulse_events if x.status=='failed'),None),
                'next_run':min((x['next_scheduled_run'] for x in pulse_preview.get('categories',[]) if x.get('next_scheduled_run')),default=None)},
            'smart_social':{'state':'ERROR' if not bot or not bot.is_ready() else ('DEGRADED' if social_mode=='LIMITED' else 'READY'),
                'enabled':bool(settings.get('smart_social',{}).get('enabled')),'mode':social_mode,'delivery_counts':social_counts,'status':social,
                'last_success':next((x.created_at.isoformat() for x in social_events if x.status=='sent'),None),
                'last_failure':next((x.created_at.isoformat() for x in social_events if x.status=='failed'),None)},
            'member_directory':directory,
            'member_engagement':{'state':'ERROR' if not bot or not bot.is_ready() else 'READY','enabled':engagement.get('enabled',False),
                'delivery_paused':bool(not controls['autonomous_mode'] or not controls['autopilot_modules'].get('member_engagement',False) or controls['all_community_paused'] or controls['member_engagement_paused']),
                'next_run':engagement.get('next_run_at'),'delivery_counts':engagement_counts,
                'last_success':next((x.sent_at.isoformat() for x in engagement_events if x.status=='sent'),None),
                'last_failure':next((x.sent_at.isoformat() for x in engagement_events if x.status=='failed'),None)},
            'controls':controls,'autonomous_mode':controls['autonomous_mode'],'bot_ready':bool(bot and bot.is_ready()),
            'intents':{'message_content':bool(bot and getattr(bot.intents,'message_content',False)),
                'members':bool(bot and getattr(bot.intents,'members',False)),
                'message_content_action':'Enable Message Content Intent in Discord Developer Portal, save, then reconnect.' if not bot or not getattr(bot.intents,'message_content',False) else 'Enabled',
                'members_action':'Enable Server Members Intent in Discord Developer Portal, save, then reconnect.' if not bot or not getattr(bot.intents,'members',False) else 'Enabled'},
            'local_gguf_ready':bool(ai_health.get('provider')=='local_gguf' and ai_health.get('status') in {'ready','online','healthy'}),
            'ai_health':ai_health}

    return routes
