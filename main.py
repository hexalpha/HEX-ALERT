import asyncio
import logging
from pathlib import Path
import uvicorn
from alembic import command
from alembic.config import Config
from bot.bot import HexAlertBot
from config.settings import get_settings
from database.db import close_db, init_db
from api import app as api_module

log=logging.getLogger("hexalert.runtime")


class RuntimeController:
    def __init__(self): self.bot=None; self.bot_task=None

    async def start_bot(self, token=None):
        cfg=get_settings()
        token=token or cfg.discord_token
        if not token: return False
        # Saving/replacing credentials must rotate the gateway session immediately.
        if self.bot_task and not self.bot_task.done():
            await self.stop_bot()
        self.bot=HexAlertBot(); api_module.runtime["bot"]=self.bot
        self.bot_task=asyncio.create_task(self._run_bot(self.bot,token),name="hex-alert-discord")
        return True

    async def _run_bot(self,bot,token):
        try: await bot.start(token)
        except asyncio.CancelledError: raise
        except Exception as exc:
            api_module.bot_state.update(online=False,scheduler=False)
            log.error("Discord service stopped (%s)",type(exc).__name__)

    async def stop_bot(self):
        if self.bot:
            await self.bot.close()
        if self.bot_task and not self.bot_task.done():
            self.bot_task.cancel(); await asyncio.gather(self.bot_task,return_exceptions=True)
        self.bot=None; self.bot_task=None; api_module.runtime.update(bot=None,scheduler=None)


async def serve_api():
    cfg=get_settings()
    server=uvicorn.Server(uvicorn.Config(api_module.app,host=cfg.api_host,port=cfg.api_port,log_level=cfg.log_level.lower(),access_log=False))
    await server.serve()


async def migrate_database():
    config=Config(str(Path(__file__).with_name("alembic.ini")))
    await asyncio.to_thread(command.upgrade,config,"head")


async def main():
    cfg=get_settings()
    logging.basicConfig(level=getattr(logging,cfg.log_level.upper(),logging.INFO),format="%(asctime)s %(levelname)s %(name)s %(message)s")
    runtime=RuntimeController(); api_module.runtime["controller"]=runtime
    try:
        await migrate_database()
        await init_db()
    except Exception as exc:
        log.error("Database startup failed (%s); admin UI will show the database as unavailable",type(exc).__name__)
    api_task=asyncio.create_task(serve_api(),name="hex-alert-admin-api")
    from services.ai_chat import chat_service
    from config.ai import options
    async def apply_ai():
        for attempt in range(6):
            try:
                await chat_service.configure_engine(options())
                return
            except Exception:
                await asyncio.sleep(10)
        log.warning("Local AI engine unavailable; dashboard and alert services continue")
    ai_task=asyncio.create_task(apply_ai(),name="hex-alert-ai-configuration")
    if cfg.discord_token: await runtime.start_bot()
    else: log.warning("Discord token is not configured. Complete setup in the local dashboard.")
    try: await api_task
    finally:
        ai_task.cancel(); await asyncio.gather(ai_task,return_exceptions=True)
        await chat_service.close()
        await runtime.stop_bot(); api_task.cancel(); await asyncio.gather(api_task,return_exceptions=True); await close_db()


if __name__=="__main__": asyncio.run(main())
