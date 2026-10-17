import asyncio
import logging
import discord
from discord.ext import commands
from discord import app_commands
from database.db import init_db, SessionLocal
from database.models import CustomCommand
from sqlalchemy import select
from services.scheduler import CollectionScheduler
from bot.commands.general import General, Admin
from bot.commands.ai import AIChat
from services.community import community_automation

log = logging.getLogger("hexalert.bot")
log.setLevel(logging.INFO)


class HexAlertBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        # Privileged member events stay off until an administrator opts in and
        # enables the matching Server Members Intent in the Discord portal.
        from config.runtime_config import get_runtime_config
        # Message and guild events are required for on_message listeners; they are not privileged intents.
        intents.guilds = True
        intents.messages = True
        intents.members = bool(get_runtime_config().get('COMMUNITY_MEMBERS_INTENT', False))
        # Normal-message semantic processing is separately privileged and stays off by default.
        intents.message_content = bool(get_runtime_config().get('COMMUNITY_MESSAGE_CONTENT_INTENT', False))
        # discord.py's debug event exposes decoded gateway envelopes. The handler
        # below records only MESSAGE_CREATE IDs/mention metadata and never content.
        super().__init__(command_prefix="!", intents=intents, help_command=None, enable_debug_events=True)
        self.scheduler = None
        self.member_directory_task = None

    async def setup_hook(self):
        await init_db()
        from api.app import bot_state, runtime
        await self.add_cog(General(self)); await self.add_cog(Admin(self))
        ai_cog = AIChat(self)
        await self.add_cog(ai_cog)
        mention_listener_count = sum(1 for name, _ in ai_cog.get_listeners() if name == "on_message")
        mention_registered = mention_listener_count == 1
        from config.ai import options
        bot_state.update(mention_listener_registered=mention_registered, mention_chat_verified=False,
                         mention_chat_enabled=bool(options().mention_chat))
        log.info("Mention listener registered: %s (count=%d)", "YES" if mention_registered else "NO",mention_listener_count)
        await self.add_cog(CommunityEvents(self))
        async with SessionLocal() as session: custom=(await session.scalars(select(CustomCommand).where(CustomCommand.enabled.is_(True)))).all()
        for row in custom:
            def make_callback(response_text):
                async def callback(interaction:discord.Interaction): await interaction.response.send_message(response_text,ephemeral=True,allowed_mentions=discord.AllowedMentions.none())
                return callback
            try: self.tree.add_command(app_commands.Command(name=row.name,description=f"Hex Alert custom command: {row.name}",callback=make_callback(row.response)))
            except app_commands.CommandAlreadyRegistered: pass
        synced = await self.tree.sync()
        self.scheduler = CollectionScheduler(self); await self.scheduler.start()
        runtime["scheduler"] = self.scheduler
        bot_state.update(online=True, scheduler=True)
        log.info("Hex Alert ready; synced %d application commands", len(synced))

    async def on_ready(self):
        from api.app import bot_state
        bot_state["online"] = True
        log.info("Connected as %s", self.user)
        from bot.commands.ai import refresh_mention_runtime
        refresh_mention_runtime(self,"ready")
        # Directory reconciliation runs in the background and never delays bot readiness.
        if self.member_directory_task is None or self.member_directory_task.done():
            async def reconcile():
                from services.member_directory import reconcile_all
                await reconcile_all(self, force_fetch=True)
            self.member_directory_task = asyncio.create_task(reconcile(), name="hex-member-directory-startup-sync")

    async def on_resumed(self):
        from api.app import bot_state
        bot_state["online"] = True
        from bot.commands.ai import refresh_mention_runtime
        refresh_mention_runtime(self,"resumed")

    async def on_disconnect(self):
        from api.app import bot_state
        bot_state["online"] = False
        bot_state["mention_gateway_connected"] = False

    async def on_socket_raw_receive(self, payload):
        from bot.commands.ai import note_gateway_message_create
        note_gateway_message_create(payload,self)

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        from bot.commands.general import admin_check
        if isinstance(error, app_commands.CheckFailure):
            message = "This command requires Manage Server or an authorized administrator ID."
        else:
            log.error("Slash command failed (%s)", type(error).__name__)
            message = "The command could not be completed. Check the bot logs and try again."
        try:
            if interaction.response.is_done(): await interaction.followup.send(message, ephemeral=True)
            else: await interaction.response.send_message(message, ephemeral=True)
        except discord.HTTPException: pass

    async def close(self):
        from api.app import bot_state
        bot_state.update(online=False, scheduler=False)
        if self.scheduler: await self.scheduler.close()
        if self.member_directory_task and not self.member_directory_task.done():
            self.member_directory_task.cancel()
        await super().close()


class CommunityEvents(commands.Cog):
    def __init__(self, bot): self.bot=bot

    @commands.Cog.listener()
    async def on_member_join(self, member):
        try:
            from services.member_directory import upsert_member
            await upsert_member(member.guild.id, member, active=True)
        except Exception as exc: log.warning('Member directory join update failed (%s)', type(exc).__name__)
        try: await community_automation.member_event(self.bot, member, 'welcome')
        except Exception as exc: log.warning('Welcome automation failed (%s)', type(exc).__name__)

    @commands.Cog.listener()
    async def on_member_remove(self, member):
        try:
            from services.member_directory import mark_left
            await mark_left(member.guild.id, member)
        except Exception as exc: log.warning('Member directory leave update failed (%s)', type(exc).__name__)
        try: await community_automation.member_event(self.bot, member, 'farewell')
        except Exception as exc: log.warning('Farewell automation failed (%s)', type(exc).__name__)

    @commands.Cog.listener()
    async def on_member_update(self, before, after):
        try:
            from services.member_directory import upsert_member
            await upsert_member(after.guild.id, after, active=True)
        except Exception as exc: log.warning('Member directory profile update failed (%s)', type(exc).__name__)

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.guild and not message.author.bot and not getattr(message,"webhook_id",None):
            # Activity detection uses only channel/user metadata, never message content.
            community_automation.note_activity(message.guild.id, message.channel.id)
            from services.member_directory import record_interaction
            try: await record_interaction(message.guild.id,message.author)
            except Exception as exc: log.debug("Community activity metadata not recorded (%s)",type(exc).__name__)
            from bot.commands.ai import _mentions_this_bot, gateway_mention_user_ids
            bot_id = getattr(getattr(self.bot, "user", None), "id", None)
            mentioned = bool(getattr(message,"_hex_direct_bot_mention",False) or
                             _mentions_this_bot(message,bot_id,gateway_mention_user_ids(message.id)))
            if not mentioned and not getattr(message, "mention_everyone", False):
                async def process_social():
                    try:
                        from services.smart_social import smart_social
                        await smart_social.process_message(message)
                    except Exception as exc:
                        log.warning("Smart social processing failed (%s)", type(exc).__name__)
                asyncio.create_task(process_social(), name=f"hex-social-{message.id}")

    @commands.Cog.listener()
    async def on_interaction(self, interaction):
        user=getattr(interaction,"user",None); guild=getattr(interaction,"guild",None)
        if guild and user and not getattr(user,"bot",False):
            try:
                from services.member_directory import record_interaction
                await record_interaction(guild.id,user)
            except Exception as exc: log.debug("Command activity metadata not recorded (%s)",type(exc).__name__)
