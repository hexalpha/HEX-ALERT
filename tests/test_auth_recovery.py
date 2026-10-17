"""HTTP coverage for username normalization and local one-time password recovery."""
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api import app as api_module
from database.models import AdminUser, Base, SystemLog, utcnow
from services.admin_passwords import reset_token_digest, utc_aware


def test_case_insensitive_login_and_local_password_reset_revoke_sessions(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("SESSION_SECRET", "isolated-auth-recovery-session-secret-0123456789")
    monkeypatch.setenv("DASHBOARD_API_KEY", "isolated-auth-recovery-api-key")
    api_module.get_settings.cache_clear()
    api_module._login_failures.clear()
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"auth.db").resolve())))
    original=api_module.SessionLocal
    token="local-one-time-reset-token-never-log-this-0123456789"
    credentials={"username":"Hex","password":"a-very-long-admin-password-123"}
    try:
        factory=async_sessionmaker(engine,expire_on_commit=False);api_module.SessionLocal=factory
        async def schema():
            async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        asyncio.run(schema())
        client=TestClient(api_module.app); origin={"Origin":"http://testserver"}
        assert client.post("/api/auth/setup",json=credentials,headers=origin).status_code==200
        client.post("/api/auth/logout")

        # Account was stored as Hex; matching is now case-insensitive and whitespace-trimmed.
        login=client.post("/api/auth/login",json={**credentials,"username":"  hex  "})
        assert login.status_code==200
        assert client.get("/api/auth/me").status_code==200

        async def set_token():
            async with factory() as session:
                user=await session.scalar(select(AdminUser).where(AdminUser.username=="Hex"))
                user.reset_token_hash=hashlib.sha256(token.encode()).hexdigest()
                user.reset_token_expires_at=utcnow()+timedelta(minutes=10)
                await session.commit()
        asyncio.run(set_token())
        wrong=client.post("/api/auth/password-reset",json={"token":token+"x","new_password":"replacement-admin-password-456"},headers=origin)
        assert wrong.status_code==401
        async def set_expired_token():
            async with factory() as session:
                user=await session.scalar(select(AdminUser).where(AdminUser.username=="Hex"))
                user.reset_token_hash=reset_token_digest(token)
                user.reset_token_expires_at=utcnow()-timedelta(seconds=1)
                user.reset_token_used_at=None
                await session.commit()
        asyncio.run(set_expired_token())
        expired=client.post("/api/auth/password-reset",json={"token":token,"new_password":"replacement-admin-password-456"},headers=origin)
        assert expired.status_code==401
        asyncio.run(set_token())
        result=client.post("/api/auth/password-reset",json={"token":token,"new_password":"replacement-admin-password-456"},headers=origin)
        assert result.status_code==200
        assert token not in result.text
        assert client.get("/api/auth/me").status_code==401
        replay=client.post("/api/auth/password-reset",json={"token":token,"new_password":"another-valid-password-789"},headers=origin)
        assert replay.status_code==401
        wrong=client.post("/api/auth/login",json={"username":"Hex","password":credentials["password"]})
        assert wrong.status_code==401 and wrong.json()["detail"]=="Invalid username or password"
        new=client.post("/api/auth/login",json={"username":"hex","password":"replacement-admin-password-456"})
        assert new.status_code==200
        assert client.get("/api/security/admin-status").json()["session_count"]==1
        bad_change=client.post("/api/auth/change-password",json={"current_password":"wrong-current-password-123","new_password":"final-admin-password-567"},headers=origin)
        assert bad_change.status_code==401
        change=client.post("/api/auth/change-password",json={"current_password":"replacement-admin-password-456","new_password":"final-admin-password-567"},headers=origin)
        assert change.status_code==200
        assert client.get("/api/auth/me").status_code==401
        assert client.post("/api/auth/login",json={"username":"hex","password":"replacement-admin-password-456"}).status_code==401
        assert client.post("/api/auth/login",json={"username":"hex","password":"final-admin-password-567"}).status_code==200

        async def read_audit():
            async with factory() as session:
                messages=list((await session.scalars(select(SystemLog.message))).all())
                user=await session.scalar(select(AdminUser).where(AdminUser.username=="Hex"))
                return messages,user.reset_token_hash,user.session_version,user.reset_token_used_at
        messages,digest,version,used_at=asyncio.run(read_audit())
        assert "PASSWORD_RESET" in messages and "LOGIN_FAILED" in messages and "PASSWORD_CHANGED" in messages
        assert token not in repr(messages) and digest=="" and used_at is not None and version==2
        assert token not in caplog.text
    finally:
        api_module.SessionLocal=original
        api_module._login_failures.clear()
        api_module.get_settings.cache_clear()
        asyncio.run(engine.dispose())


def test_reset_token_helpers_are_exact_secure_and_utc_aware():
    from services.admin_passwords import create_reset_token
    instant=datetime(2026,10,4,6,30,tzinfo=timezone.utc)
    raw,digest,expires=create_reset_token(now=instant)
    assert digest==hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert reset_token_digest(raw+" ")!=digest
    assert reset_token_digest(raw.upper())!=digest
    assert expires==instant+timedelta(minutes=15)
    assert expires.tzinfo is timezone.utc
    assert utc_aware(datetime(2026,10,4,6,30))==instant
    assert utc_aware(instant)==instant


def test_recovery_form_posts_raw_token_once_without_transforming_it():
    script=Path(__file__).parents[1].joinpath("api","static","app.js").read_text(encoding="utf-8")
    handler=script.split("const form=e.target,f=new FormData(form),rawToken=",1)[1].split(";",1)[0]
    assert handler=="String(f.get('token')??'')"
    assert "token:rawToken" in script
    assert "token:rawToken.trim()" not in script
    assert "token:hash" not in script


def test_used_reset_token_is_rejected(monkeypatch,tmp_path):
    monkeypatch.setenv("SESSION_SECRET","isolated-used-token-session-secret-0123456789")
    monkeypatch.setenv("DASHBOARD_API_KEY","isolated-used-token-api-key")
    api_module.get_settings.cache_clear();api_module._login_failures.clear()
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"used.db").resolve())))
    original=api_module.SessionLocal;factory=async_sessionmaker(engine,expire_on_commit=False);api_module.SessionLocal=factory
    token="local-used-token-test-value-1234567890"
    try:
        async def setup():
            async with engine.begin() as c: await c.run_sync(Base.metadata.create_all)
        asyncio.run(setup())
        client=TestClient(api_module.app);origin={"Origin":"http://testserver"}
        assert client.post("/api/auth/setup",json={"username":"used","password":"long-admin-password-1234"},headers=origin).status_code==200
        async def install_used():
            async with factory() as s:
                u=await s.scalar(select(AdminUser));u.reset_token_hash=reset_token_digest(token)
                u.reset_token_expires_at=utcnow()+timedelta(minutes=10);u.reset_token_used_at=utcnow();await s.commit()
        asyncio.run(install_used())
        response=client.post("/api/auth/password-reset",json={"token":token,"new_password":"another-long-password-5678"},headers=origin)
        assert response.status_code==401
    finally:
        api_module.SessionLocal=original;api_module._login_failures.clear();api_module.get_settings.cache_clear();asyncio.run(engine.dispose())
