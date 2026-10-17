"""Custom Discord route persistence and explicit TEST_MODE delivery."""
import asyncio
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api import app as api_module
from database.models import Alert, Base, CustomDiscordRoute, SentMessage


def test_custom_route_saved_and_test_message_persisted(monkeypatch, tmp_path):
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"routes.db").resolve())))
    original_factory=api_module.SessionLocal
    original_bot=api_module.runtime.get("bot")
    original_settings=api_module.get_settings
    try:
        factory=async_sessionmaker(engine,expire_on_commit=False);api_module.SessionLocal=factory
        async def schema():
            async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        asyncio.run(schema())
        permissions=SimpleNamespace(view_channel=True,send_messages=True,embed_links=True,read_message_history=True)
        guild=SimpleNamespace(id=700,me=SimpleNamespace(),get_channel=lambda cid: channel if cid==800 else None)
        messages=[]
        async def send(**kwargs):
            messages.append(kwargs)
            return SimpleNamespace(id=9001)
        channel=SimpleNamespace(id=800,name="ai-security",guild=guild,
                                permissions_for=lambda member:permissions,send=send)
        bot=SimpleNamespace(get_channel=lambda cid:channel if cid==800 else None,
                            fetch_channel=lambda cid:None)
        api_module.runtime["bot"]=bot
        monkeypatch.setattr(api_module,"get_settings",lambda:SimpleNamespace(test_mode=True))
        api_module.app.dependency_overrides[api_module.require_admin]=lambda:True
        client=TestClient(api_module.app)
        payload={"route_name":"AI Security News","route_key":"ai_security","description":"AI security alerts",
                 "guild_id":"700","channel_id":"800","category":"news",
                 "keywords":["prompt injection"],"priority":1}
        created=client.post("/api/discord/custom-routes",json=payload)
        assert created.status_code==200,created.text
        assert created.json()["enabled"] is False
        listed=client.get("/api/discord/custom-routes")
        assert listed.status_code==200 and listed.json()[0]["status"]=="READY"

        test=client.post("/api/discord/custom-routes/ai_security/test",headers={"Origin":"http://testserver"})
        assert test.status_code==200,test.text
        data=test.json()
        assert data["channel_id"]=="800" and data["message_id"]=="9001"
        assert len(messages)==1 and "CUSTOM ROUTE TEST" in messages[0]["embed"].title

        async def records():
            async with factory() as session:
                alert=await session.scalar(select(Alert).where(Alert.message_id=="9001"))
                delivery=await session.scalar(select(SentMessage).where(SentMessage.message_id=="9001"))
                route=await session.scalar(select(CustomDiscordRoute).where(CustomDiscordRoute.route_key=="ai_security"))
                return alert,delivery,route
        alert,delivery,route=asyncio.run(records())
        assert alert and alert.status=="sent" and alert.channel_name=="ai-security"
        assert delivery and delivery.guild_id=="700" and delivery.channel_id=="800"
        assert route and route.last_used and route.status=="SENT"
    finally:
        api_module.app.dependency_overrides.pop(api_module.require_admin,None)
        api_module.SessionLocal=original_factory
        api_module.runtime["bot"]=original_bot
        api_module.get_settings=original_settings
        asyncio.run(engine.dispose())
