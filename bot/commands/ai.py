"""Read-only conversational AI. No shell, crawler controls, or model tool execution."""
import asyncio
import logging
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
import discord
from discord import app_commands
from discord.ext import commands
from config.ai import options, PUBLIC_ASSISTANT_NAME
from config.settings import get_settings
from services.ai_chat import chat_service, split_response, audit_metric, record_delivery, ensure_response_emoji
from services.ai_providers import AIUnavailable

log = logging.getLogger("hexalert.ai")
log.setLevel(logging.INFO)
_seen_mention_events=OrderedDict()
_MENTION_EVENT_TTL=600
_MENTION_EVENT_LIMIT=5000
_gateway_message_mentions=OrderedDict()
_GATEWAY_MESSAGE_TTL=120
_GATEWAY_MESSAGE_LIMIT=512
MENTION_DIAGNOSTICS={
    "last_message_create": None,
    "last_direct_mention": None,
    "last_handler_result": "not_seen",
    "last_ai_dispatch": "not_seen",
    "last_reply_result": "not_seen",
}

def _claim_mention_event(message_id):
    now=time.monotonic()
    while _seen_mention_events:
        _,(seen_at,_)=next(iter(_seen_mention_events.items()))
        if now-seen_at<=_MENTION_EVENT_TTL: break
        _seen_mention_events.popitem(last=False)
    key=str(message_id)
    if key in _seen_mention_events: return False
    _seen_mention_events[key]=(now,True)
    while len(_seen_mention_events)>_MENTION_EVENT_LIMIT: _seen_mention_events.popitem(last=False)
    return True

def _mention_allowed(author):
    return discord.AllowedMentions(users=[author],roles=False,everyone=False,replied_user=False)


def _numeric_id(value):
    try:
        candidate=value.get("id") if isinstance(value,dict) else getattr(value,"id",value)
        return str(int(candidate))
    except (TypeError,ValueError):
        return ""


def _mention_ids_from_message(message,include_content=True):
    ids=set()
    for user in (getattr(message,"mentions",()) or ()):
        value=_numeric_id(user)
        if value: ids.add(value)
    for value in (getattr(message,"raw_mentions",()) or ()):
        value=_numeric_id(value)
        if value: ids.add(value)
    content=getattr(message,"content",None) if include_content else None
    if isinstance(content,str): ids.update(re.findall(r"<@!?(\d+)>",content))
    ids.update(str(value) for value in (getattr(message,"_hex_gateway_mention_user_ids",()) or ()) if str(value).isdigit())
    return ids


def _mentions_this_bot(message, bot_id, gateway_mention_user_ids=(),include_content=True):
    """Match only Discord user mention IDs; display names are never trusted."""
    target=_numeric_id(bot_id)
    if not target: return False
    ids=_mention_ids_from_message(message,include_content=include_content)
    ids.update(str(value) for value in gateway_mention_user_ids if str(value).isdigit())
    return target in ids


def _prune_gateway_message_mentions(now=None):
    now=now or time.monotonic()
    while _gateway_message_mentions:
        _,(seen_at,_)=next(iter(_gateway_message_mentions.items()))
        if now-seen_at<=_GATEWAY_MESSAGE_TTL: break
        _gateway_message_mentions.popitem(last=False)


def note_gateway_message_create(payload,bot=None):
    """Capture safe MESSAGE_CREATE metadata from discord.py's raw socket hook."""
    if not isinstance(payload,dict) or payload.get("t")!="MESSAGE_CREATE": return
    data=payload.get("d")
    if not isinstance(data,dict): return
    message_id=_numeric_id(data.get("id"))
    if not message_id: return
    mention_user_ids=sorted({value for item in (data.get("mentions") or []) if (value:=_numeric_id(item))})
    content=data.get("content")
    raw_mentions=sorted(set(re.findall(r"<@!?(\d+)>",content))) if isinstance(content,str) else []
    bot_user_id=_numeric_id(getattr(getattr(bot,"user",None),"id",None))
    metadata={
        "message_id":message_id,"guild_id":_numeric_id(data.get("guild_id")) or "dm",
        "channel_id":_numeric_id(data.get("channel_id")),
        "author_id":_numeric_id((data.get("author") or {}).get("id")),
        "raw_mentions":raw_mentions,"mention_user_ids":mention_user_ids,"bot_user_id":bot_user_id,
        "content_available":isinstance(content,str),"content_length":len(content) if isinstance(content,str) else 0,
        "seen_at":datetime.now(timezone.utc).isoformat(),
    }
    direct=bool(bot_user_id and bot_user_id in set(mention_user_ids)|set(raw_mentions))
    MENTION_DIAGNOSTICS["last_message_create"]=metadata
    log.info("MESSAGE_CREATE_METADATA message_id=%s guild_id=%s channel_id=%s author_id=%s raw_mentions=%s mention_user_ids=%s bot_user_id=%s content_available=%s content_length=%d bot_mentioned=%s",
             metadata["message_id"],metadata["guild_id"],metadata["channel_id"],metadata["author_id"],
             raw_mentions,mention_user_ids,bot_user_id,metadata["content_available"],metadata["content_length"],direct)
    _prune_gateway_message_mentions()
    if mention_user_ids or raw_mentions:
        _gateway_message_mentions[message_id]=(time.monotonic(),metadata)
        _gateway_message_mentions.move_to_end(message_id)
        while len(_gateway_message_mentions)>_GATEWAY_MESSAGE_LIMIT: _gateway_message_mentions.popitem(last=False)
    if direct:
        MENTION_DIAGNOSTICS["last_direct_mention"]={key:metadata[key] for key in ("message_id","guild_id","channel_id","author_id","seen_at")}


def gateway_mention_user_ids(message_id):
    _prune_gateway_message_mentions()
    row=_gateway_message_mentions.get(_numeric_id(message_id))
    return tuple(row[1]["mention_user_ids"]+row[1]["raw_mentions"]) if row else ()


def mention_diagnostics(bot):
    cog=bot.get_cog("AIChat") if bot and hasattr(bot,"get_cog") else None
    listeners=sum(1 for name,_ in (cog.get_listeners() if cog else ()) if name=="on_message")
    state={key:(dict(value) if isinstance(value,dict) else value) for key,value in MENTION_DIAGNOSTICS.items()}
    state.update({"bot_user_id":_numeric_id(getattr(getattr(bot,"user",None),"id",None)),
        "listener_registered":listeners==1,"listener_count":listeners,
        "mention_chat_enabled":bool(options().mention_chat),"gateway_connected":bool(bot and bot.is_ready())})
    return state


def refresh_mention_runtime(bot,reason="ready"):
    """Refresh safe runtime state after startup/resume without retaining discord.User."""
    from api.app import bot_state
    state=mention_diagnostics(bot)
    bot_state.update(mention_listener_registered=state["listener_registered"],
        mention_chat_enabled=state["mention_chat_enabled"],mention_bot_user_id=state["bot_user_id"],
        mention_gateway_connected=state["gateway_connected"])
    log.info("MENTION_RUNTIME_REFRESH reason=%s bot_user_id=%s ready=%s mention_chat_enabled=%s listener_registered=%s listener_count=%d",
        reason,state["bot_user_id"],str(state["gateway_connected"]).lower(),
        str(state["mention_chat_enabled"]).lower(),str(state["listener_registered"]).lower(),state["listener_count"])
    return state


def _mention_question(message, bot_id):
    content = getattr(message, "content", "") or ""
    return " ".join(re.sub(r"<@!?" + re.escape(str(bot_id)) + r">", " ", content).split())


def _mention_fast_path(question):
    """Small deterministic replies keep greetings and identity questions natural."""
    normalized = re.sub(r"[^\w\s]", " ", str(question or "").casefold(), flags=re.UNICODE)
    normalized = " ".join(normalized.split())
    if normalized in {"hi", "hii", "hiii", "hello", "hey", "hey there", "good morning", "good afternoon", "good evening"}:
        return "\U0001F44B\U0001F60E Hii bro! HEX ALPHA online hai. Batao kya scene hai? \U0001F525"
    if any(phrase in normalized for phrase in ("tum kon ho", "tum kaun ho", "aap kaun ho", "who are you", "what are you")):
        return "\U0001F60E Main HEX ALPHA hoon — HEX SECURITY ka cybersecurity AI assistant. \U0001F6E1\U0000FE0F"
    if any(phrase in normalized for phrase in ("hindi me baat", "hindi mein baat", "hinglish me baat", "hindi me bolo", "hindi mein bolo")):
        return "\U0001F604 Bilkul bro, ab Hindi/Hinglish me baat karte hain. Batao kya puchna hai? \U0001F6E1\U0000FE0F"
    return None

class AIChat(commands.Cog):
    def __init__(self,bot): self.bot=bot

    @app_commands.command(name='ask',description='Ask HEX ALPHA, HEX SECURITY’s cybersecurity assistant')
    async def ask(self,interaction:discord.Interaction,question:str):
        await interaction.response.defer(thinking=True)
        key=(interaction.guild_id,interaction.channel_id,interaction.user.id)
        data_message_ids=[]
        async def instant_data(preview):
            sent=await interaction.followup.send(preview,allowed_mentions=discord.AllowedMentions.none(),wait=True)
            data_message_ids.append(str(sent.id))
            await interaction.edit_original_response(content='🧠 HEX ALPHA analysis is generating…')
        async def queued(position=1):
            await interaction.edit_original_response(content=f'HEX ALPHA is busy. Your request is queued (position {position}).')
        async def searching(message_text):
            await interaction.edit_original_response(content=message_text,allowed_mentions=discord.AllowedMentions.none())
        async def progress(partial):
            # Coalesced stream edits: Discord receives useful chunks, never one message per token.
            display='🧠 HEX ALPHA\n\n'+partial.strip()
            if len(display)>1850: display=display[:1847].rsplit(' ',1)[0]+'…'
            await interaction.edit_original_response(content=display,allowed_mentions=discord.AllowedMentions.none())
        try:
            result=await chat_service.ask(key,question,on_queued=queued,on_progress=progress,on_data=instant_data,on_searching=searching,priority=1)
            text='🧠 HEX ALPHA\n\n'+result['answer']
            parts=split_response(text)
            message=await interaction.edit_original_response(content=parts[0],allowed_mentions=discord.AllowedMentions.none())
            ids=[*data_message_ids,str(message.id)]
            for part in parts[1:]:
                sent=await interaction.followup.send(part,allowed_mentions=discord.AllowedMentions.none(),wait=True)
                ids.append(str(sent.id))
            channel = getattr(interaction, 'channel', None)
            await record_delivery(interaction.guild_id, interaction.channel_id,
                                  getattr(channel, 'name', ''), ids, provider=result['provider'],
                                  model=result['model'],latency_seconds=result.get('latency_seconds'),
                                  interaction_id=getattr(interaction, 'id', None))
            await audit_metric({'event':'discord_delivery','provider':result['provider'],'message_ids':ids,
                                'channel_id':str(interaction.channel_id),'guild_id':str(interaction.guild_id),'status':'SENT'})
        except AIUnavailable as exc:
            cfg=options(); entry=cfg.providers.get(cfg.provider)
            channel = getattr(interaction, 'channel', None)
            await record_delivery(interaction.guild_id, interaction.channel_id,
                                  getattr(channel, 'name', ''), [], 'failed', str(exc),cfg.provider,
                                  entry.model if entry else '',interaction_id=getattr(interaction, 'id', None))
            await interaction.edit_original_response(content=str(exc))
        except discord.HTTPException:
            channel = getattr(interaction, 'channel', None)
            await record_delivery(interaction.guild_id, interaction.channel_id,
                                  getattr(channel, 'name', ''), [], 'failed', 'Discord rejected response',
                                  provider=result.get('provider',''),model=result.get('model',''),
                                  latency_seconds=result.get('latency_seconds'),interaction_id=getattr(interaction, 'id', None))
            await audit_metric({'event':'discord_delivery','status':'FAILED','reason':'Discord rejected response'})

    @app_commands.command(name='ai-status',description='Show AI provider, model, health and queue')
    async def ai_status(self,interaction:discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        state=await chat_service.health()
        ready=state.get('status') in ('ready','healthy')
        from services.internet_search import internet_search
        web=internet_search.status()
        web_label='Ready' if web.get('status')=='ready' else 'Not Configured'
        await interaction.followup.send(f"HEX ALPHA\nBrand: HEX SECURITY\nPurpose: Cybersecurity AI Assistant\nStatus: {'Ready' if ready else 'Unavailable'}\nAI: {'Ready' if ready else 'Unavailable'}\nLive Internet Search: {web_label}\nSearch Provider: {web.get('provider','google')}\nLocal Intelligence DB: Ready\nMode: {'Local AI' if options().provider=='local_gguf' else 'Configured AI'}\nQueue: {state.get('queue',0)}",ephemeral=True)

    @app_commands.command(name='model',description='Show the selected AI model; admins change it in AI Settings')
    async def model(self,interaction:discord.Interaction):
        await interaction.response.send_message('Public assistant: HEX ALPHA\nBrand: HEX SECURITY\nPurpose: Cybersecurity AI Assistant\nTechnical model details are available to authorized administrators in Dashboard → AI Settings.',ephemeral=True)

    @app_commands.command(name='reset-chat',description='Forget your conversation in this channel')
    async def reset_chat(self,interaction:discord.Interaction):
        chat_service.reset((interaction.guild_id,interaction.channel_id,interaction.user.id))
        await interaction.response.send_message('Your conversation in this channel has been cleared.',ephemeral=True)

    @app_commands.command(name='engagement-optout',description="Opt out of HEX ALPHA's automated community mentions")
    async def engagement_optout(self,interaction:discord.Interaction):
        if not interaction.guild_id:
            await interaction.response.send_message("This preference is available inside a server.",ephemeral=True); return
        from services.member_engagement import set_opt_out
        await set_opt_out(interaction.guild_id,interaction.user.id,True)
        await interaction.response.send_message("\U0001F515 You will no longer be tagged by HEX ALPHA's automated community messages.",ephemeral=True)

    @app_commands.command(name='engagement-optin',description="Rejoin HEX ALPHA's automated community rotation")
    async def engagement_optin(self,interaction:discord.Interaction):
        if not interaction.guild_id:
            await interaction.response.send_message("This preference is available inside a server.",ephemeral=True); return
        from services.member_engagement import set_opt_out
        await set_opt_out(interaction.guild_id,interaction.user.id,False)
        await interaction.response.send_message("\U0001F514 You're back in HEX ALPHA's community rotation. \U0001F604",ephemeral=True)

    @app_commands.command(name='social-optout',description="Stop HEX ALPHA's automatic reactions and social replies")
    async def social_optout(self, interaction: discord.Interaction):
        if not interaction.guild_id:
            await interaction.response.send_message("This preference is available inside a server.", ephemeral=True); return
        from services.smart_social import smart_social
        await smart_social.set_opt_out(interaction.guild_id, interaction.user.id, True)
        await interaction.response.send_message("\U0001F512 HEX ALPHA won't automatically react or reply to your normal messages anymore.", ephemeral=True)

    @app_commands.command(name='social-optin',description="Re-enable HEX ALPHA's automatic reactions and social replies")
    async def social_optin(self, interaction: discord.Interaction):
        if not interaction.guild_id:
            await interaction.response.send_message("This preference is available inside a server.", ephemeral=True); return
        from services.smart_social import smart_social
        await smart_social.set_opt_out(interaction.guild_id, interaction.user.id, False)
        await interaction.response.send_message("\U0001F514 HEX ALPHA social interactions are enabled for you again. \U0001F60E", ephemeral=True)

    @app_commands.command(name="mention-diagnostics",description="Admin: show direct mention routing health without message text")
    @app_commands.check(lambda interaction: bool(interaction.user.id in get_settings().admin_ids or
        (interaction.guild and interaction.user.guild_permissions.manage_guild)))
    async def mention_diagnostics_command(self,interaction:discord.Interaction):
        state=mention_diagnostics(self.bot)
        last=state.get("last_direct_mention") or {}
        lines=["**HEX ALPHA Mention Chat Diagnostics**",
            f"Bot user ID: {state['bot_user_id'] or 'Unavailable'}",
            f"Listener registered: {'YES' if state['listener_registered'] else 'NO'} ({state['listener_count']})",
            f"Mention chat enabled: {'YES' if state['mention_chat_enabled'] else 'NO'}",
            f"Gateway connected: {'YES' if state['gateway_connected'] else 'NO'}",
            f"Last MESSAGE_CREATE: {(state.get('last_message_create') or {}).get('seen_at','Never')}",
            f"Last direct mention: {last.get('seen_at','Never')} · message {last.get('message_id','—')}",
            f"Last handler: {state['last_handler_result']}",
            f"Last AI dispatch: {state['last_ai_dispatch']}",
            f"Last reply: {state['last_reply_result']}"]
        await interaction.response.send_message("\n".join(lines),ephemeral=True,
            allowed_mentions=discord.AllowedMentions.none())

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        author = getattr(message, "author", None)
        if not author or getattr(author, "bot", False) or getattr(message, "webhook_id", None):
            return

        bot_user = getattr(self.bot, "user", None)
        bot_id = _numeric_id(getattr(bot_user, "id", None))
        guild = getattr(message, "guild", None)
        channel = getattr(message, "channel", None)
        channel_id = getattr(channel, "id", None)
        guild_id = getattr(guild, "id", None)
        message_id = getattr(message, "id", None)
        author_id = getattr(author, "id", None)
        message_key=_numeric_id(message_id)
        gateway_ids=gateway_mention_user_ids(message_key)
        # First trust Discord's parsed/raw user-ID metadata. Content parsing is
        # only a fallback after both metadata sources have been checked.
        mentioned=_mentions_this_bot(message,bot_id,gateway_ids,include_content=False)
        if not mentioned and message_key:
            # discord.py schedules socket callbacks immediately before message listeners.
            await asyncio.sleep(0)
            gateway_ids=gateway_mention_user_ids(message_key)
            mentioned=_mentions_this_bot(message,bot_id,gateway_ids,include_content=False)
        content = getattr(message, "content", None)
        content_available = isinstance(content, str)
        content_length = len(content) if content_available else 0
        if not mentioned:
            mentioned=_mentions_this_bot(message,bot_id,gateway_ids,include_content=True)
        mention_user_ids=sorted(_mention_ids_from_message(message)|set(gateway_ids))
        raw_mentions=sorted({_numeric_id(value) for value in (getattr(message,"raw_mentions",()) or ()) if _numeric_id(value)})
        MENTION_DIAGNOSTICS["last_message_create"]={"message_id":message_key,"guild_id":_numeric_id(guild_id) or "dm",
            "channel_id":_numeric_id(channel_id),"author_id":_numeric_id(author_id),"raw_mentions":raw_mentions,
            "mention_user_ids":mention_user_ids,"bot_user_id":bot_id,"content_available":content_available,
            "content_length":content_length,"seen_at":datetime.now(timezone.utc).isoformat()}
        log.info("MENTION_EVENT_RECEIVED message_id=%s guild_id=%s channel_id=%s author_id=%s raw_mentions=%s mention_user_ids=%s bot_user_id=%s bot_mentioned=%s content_available=%s content_length=%d",
                 message_key,_numeric_id(guild_id) or "dm",_numeric_id(channel_id),_numeric_id(author_id),raw_mentions,
                 mention_user_ids,bot_id,mentioned,content_available,content_length)

        if not bot_user:
            log.warning("MENTION_HANDLER_SKIPPED reason=bot_identity_unavailable message_id=%s", message_id)
            return
        if not options().mention_chat:
            log.info("MENTION_HANDLER_SKIPPED reason=feature_disabled message_id=%s", message_id)
            return
        if not mentioned:
            MENTION_DIAGNOSTICS["last_handler_result"]="ignored_not_a_bot_mention"
            return
        try: setattr(message,"_hex_direct_bot_mention",True)
        except Exception: pass
        MENTION_DIAGNOSTICS["last_direct_mention"]={"message_id":message_key,"guild_id":_numeric_id(guild_id) or "dm",
            "channel_id":_numeric_id(channel_id),"author_id":_numeric_id(author_id),"seen_at":datetime.now(timezone.utc).isoformat()}
        MENTION_DIAGNOSTICS["last_handler_result"]="detected"
        if not content_available:
            log.info("MENTION_CONTENT_UNAVAILABLE message_id=%s; metadata-first mention routing continues",message_id)
        if not _claim_mention_event(message_id):
            MENTION_DIAGNOSTICS["last_handler_result"]="duplicate_event"
            log.info("MENTION_HANDLER_SKIPPED reason=duplicate_event message_id=%s", message_id)
            return

        question = _mention_question(message, bot_id)
        if getattr(message, "mention_everyone", False):
            log.info("MENTION_HANDLER_SKIPPED reason=mass_mention message_id=%s", message_id)
            return
        if not question: question=""

        # Acknowledge an explicit mention immediately without waiting on the social
        # settings read or reaction REST call before starting the user's real answer.
        try:
            from services.smart_social import smart_social
            thinking = bool(re.search(r"\?|\b(cve|news|jobs|search|latest|look up|find|explain)\b", question, re.I))
            asyncio.create_task(smart_social.mention_reaction(message, thinking=thinking),
                                name=f"hex-mention-reaction-{message_id}")
        except Exception as exc:
            log.debug("Mention acknowledgement reaction skipped (%s)", type(exc).__name__)

        permissions = None
        member = getattr(guild, "me", None) if guild else None
        if member and channel and hasattr(channel, "permissions_for"):
            permissions = channel.permissions_for(member)
            can_send = bool(getattr(permissions, "send_messages", False))
            if getattr(channel, "parent", None) is not None:
                can_send = can_send or bool(getattr(permissions, "send_messages_in_threads", False))
            log.info("MENTION_CHANNEL_PERMISSIONS guild_id=%s channel_id=%s view_channel=%s send_messages=%s send_messages_in_threads=%s read_message_history=%s",
                     guild_id, channel_id, bool(getattr(permissions, "view_channel", False)),
                     bool(getattr(permissions, "send_messages", False)),
                     bool(getattr(permissions, "send_messages_in_threads", False)),
                     bool(getattr(permissions, "read_message_history", False)))
            if not can_send:
                log.warning("MENTION_HANDLER_SKIPPED reason=send_permission_missing guild_id=%s channel_id=%s message_id=%s",
                            guild_id, channel_id, message_id)
                return

        key = (guild_id, channel_id, author_id)
        sent_ids = []
        log.info("MENTION_HANDLER_SELECTED guild_id=%s channel_id=%s message_id=%s requester_id=%s",
                 guild_id, channel_id, message_id, author_id)

        async def send_reply(text, index=0):
            prefix = f"<@{author_id}> " if index == 0 else ""
            sent = await message.reply(prefix + text, mention_author=False,
                                       allowed_mentions=_mention_allowed(author))
            sent_ids.append(str(sent.id))
            MENTION_DIAGNOSTICS["last_reply_result"]="sent"
            return sent

        async def queued(position=1):
            log.info("MENTION_QUEUE_STATE guild_id=%s channel_id=%s message_id=%s state=queued position=%s",
                     guild_id, channel_id, message_id, position)
            await send_reply(f"HEX ALPHA is busy. Your request is queued (position {position}).")

        async def searching(message_text):
            await send_reply(message_text)

        try:
            if not question:
                await send_reply("\U0001F44B Haan bro, bolo \U0001F60E")
                await record_delivery(guild_id or "",channel_id,getattr(channel,"name",""),sent_ids,
                    provider="fast_path",model="empty-mention",requesting_user_id=author_id,
                    reply_to_message_id=message_id,delivery_type="mention")
                MENTION_DIAGNOSTICS["last_handler_result"]="sent_empty_mention_prompt"
                MENTION_DIAGNOSTICS["last_ai_dispatch"]="not_needed_empty_mention"
                log.info("MENTION_AI_STATE guild_id=%s channel_id=%s message_id=%s state=completed provider=fast_path model=empty-mention",
                         guild_id,channel_id,message_id)
                log.info("DISCORD_REPLY_SENT guild_id=%s channel_id=%s message_id=%s reply_count=1 diagnostic=false",
                         guild_id,channel_id,message_id)
                return
            # Temporary deterministic live diagnostic. Remove after the real Discord ping test.
            if question.casefold().strip() == "ping":
                await send_reply("Mention chat is working. \U0001F6E1\U0000FE0F")
                await record_delivery(guild_id or "", channel_id, getattr(channel, "name", ""), sent_ids,
                                      provider="diagnostic", model="mention-ping-ack",
                                      requesting_user_id=author_id, reply_to_message_id=message_id,
                                      delivery_type="mention")
                await audit_metric({"event": "discord_delivery", "guild_id": str(guild_id or ""),
                                    "channel_id": str(channel_id), "requesting_user_id": str(author_id),
                                    "reply_to_message_id": str(message_id), "delivery_type": "mention",
                                    "provider": "diagnostic", "model": "mention-ping-ack", "status": "SENT"})
                log.info("DISCORD_REPLY_SENT guild_id=%s channel_id=%s message_id=%s reply_count=%d diagnostic=true",
                         guild_id, channel_id, message_id, len(sent_ids))
                MENTION_DIAGNOSTICS["last_handler_result"]="sent_ping_ack"
                MENTION_DIAGNOSTICS["last_ai_dispatch"]="not_needed_ping"
                return

            fast_reply = _mention_fast_path(question)
            if fast_reply:
                await send_reply(ensure_response_emoji(fast_reply))
                await record_delivery(guild_id or "", channel_id, getattr(channel, "name", ""), sent_ids,
                                      provider="fast_path", model="greeting",
                                      requesting_user_id=author_id, reply_to_message_id=message_id,
                                      delivery_type="mention")
                await audit_metric({"event": "discord_delivery", "guild_id": str(guild_id or ""),
                                    "channel_id": str(channel_id), "requesting_user_id": str(author_id),
                                    "reply_to_message_id": str(message_id), "delivery_type": "mention",
                                    "provider": "fast_path", "model": "greeting", "status": "SENT"})
                from api.app import bot_state
                bot_state["mention_chat_verified"] = True
                MENTION_DIAGNOSTICS["last_handler_result"]="sent_fast_path_reply"
                MENTION_DIAGNOSTICS["last_ai_dispatch"]="not_needed_fast_path"
                log.info("MENTION_AI_STATE guild_id=%s channel_id=%s message_id=%s state=completed provider=fast_path model=greeting",
                         guild_id, channel_id, message_id)
                log.info("DISCORD_REPLY_SENT guild_id=%s channel_id=%s message_id=%s reply_count=%d diagnostic=false",
                         guild_id, channel_id, message_id, len(sent_ids))
                return

            log.info("MENTION_QUEUE_STATE guild_id=%s channel_id=%s message_id=%s state=submitting priority=0",
                     guild_id, channel_id, message_id)
            MENTION_DIAGNOSTICS["last_handler_result"]="ai_dispatch_started"
            MENTION_DIAGNOSTICS["last_ai_dispatch"]="started"
            verified_previews=[]
            async def capture_verified_preview(value):
                if str(value).startswith(f"{chr(0x1F50E)} HEX ALERT found "):
                    verified_previews.append(str(value))
            async with channel.typing():
                log.info("MENTION_AI_STATE guild_id=%s channel_id=%s message_id=%s state=started",
                         guild_id, channel_id, message_id)
                # Keep direct mentions to one final answer; source previews and queue
                # notices must not appear as separate, duplicate replies.
                result = await chat_service.ask(key, question, on_data=capture_verified_preview, priority=0)
            answer=verified_previews[-1] if verified_previews else result["answer"]
            parts = split_response("\U0001F9E0 HEX ALPHA\n\n" + answer)
            for index, part in enumerate(parts):
                await send_reply(part, index)
            await record_delivery(guild_id or "", channel_id, getattr(channel, "name", ""), sent_ids,
                                  provider=result["provider"], model=result["model"],
                                  latency_seconds=result.get("latency_seconds"),
                                  requesting_user_id=author_id, reply_to_message_id=message_id,
                                  delivery_type="mention")
            await audit_metric({"event": "discord_delivery", "message_ids": sent_ids,
                                "channel_id": str(channel_id), "guild_id": str(guild_id or ""),
                                "requesting_user_id": str(author_id), "reply_to_message_id": str(message_id),
                                "delivery_type": "mention", "provider": result["provider"],
                                "model": result["model"], "latency_seconds": result.get("latency_seconds"),
                                "status": "SENT"})
            from api.app import bot_state
            bot_state["mention_chat_verified"] = True
            MENTION_DIAGNOSTICS["last_handler_result"]="sent_ai_reply"
            MENTION_DIAGNOSTICS["last_ai_dispatch"]="completed"
            log.info("MENTION_AI_STATE guild_id=%s channel_id=%s message_id=%s state=completed provider=%s model=%s",
                     guild_id, channel_id, message_id, result["provider"], result["model"])
            log.info("DISCORD_REPLY_SENT guild_id=%s channel_id=%s message_id=%s reply_count=%d diagnostic=false",
                     guild_id, channel_id, message_id, len(sent_ids))
        except AIUnavailable as exc:
            MENTION_DIAGNOSTICS["last_handler_result"]="ai_unavailable"
            MENTION_DIAGNOSTICS["last_ai_dispatch"]="unavailable"
            log.warning("MENTION_AI_STATE guild_id=%s channel_id=%s message_id=%s state=unavailable reason=%s",
                        guild_id, channel_id, message_id, type(exc).__name__)
            await record_delivery(guild_id or "", channel_id, getattr(channel, "name", ""), [],
                                  status="failed", reason=str(exc), requesting_user_id=author_id,
                                  reply_to_message_id=message_id, delivery_type="mention")
            try:
                await send_reply(str(exc))
                log.info("DISCORD_REPLY_SENT guild_id=%s channel_id=%s message_id=%s reply_count=%d error_reply=true",
                         guild_id, channel_id, message_id, len(sent_ids))
            except discord.HTTPException as send_exc:
                log.warning("DISCORD_REPLY_FAILED guild_id=%s channel_id=%s message_id=%s reason=%s",
                            guild_id, channel_id, message_id, type(send_exc).__name__)
        except discord.HTTPException as exc:
            MENTION_DIAGNOSTICS["last_handler_result"]="discord_reply_failed"
            MENTION_DIAGNOSTICS["last_reply_result"]="failed"
            log.warning("DISCORD_REPLY_FAILED guild_id=%s channel_id=%s message_id=%s reason=%s",
                        guild_id, channel_id, message_id, type(exc).__name__)
            await record_delivery(guild_id or "", channel_id, getattr(channel, "name", ""), sent_ids,
                                  status="failed", reason="Discord rejected response", requesting_user_id=author_id,
                                  reply_to_message_id=message_id, delivery_type="mention")
            await audit_metric({"event": "discord_delivery", "status": "FAILED", "delivery_type": "mention",
                                "guild_id": str(guild_id or ""), "channel_id": str(channel_id),
                                "reply_to_message_id": str(message_id), "reason": "Discord rejected response"})
