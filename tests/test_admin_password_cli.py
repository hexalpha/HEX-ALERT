import asyncio
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import URL

import manage
from database.models import AdminSession, AdminUser, Base, SystemLog, utcnow
from services.admin_passwords import hash_password, verify_password


def test_local_admin_set_password_prompts_hidden_and_invalidates_sessions(monkeypatch,tmp_path,capsys):
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"admin-cli.db").resolve())))
    original=manage.SessionLocal
    factory=async_sessionmaker(engine,expire_on_commit=False)
    manage.SessionLocal=factory
    password_values=iter(["private-new-password-123","private-new-password-123"])
    monkeypatch.setattr(manage.getpass,"getpass",lambda prompt:next(password_values))
    try:
        async def prepare():
            async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
            async with factory() as session:
                user=AdminUser(username="LocalAdmin",password_hash=hash_password("old-private-password"),session_version=3,
                    reset_token_hash="a"*64,reset_token_expires_at=utcnow()+timedelta(minutes=10))
                session.add(user);await session.flush()
                session.add(AdminSession(admin_user_id=user.id,session_id="existing-session",session_version=3,
                    expires_at=utcnow()+timedelta(hours=1)))
                await session.commit()
        asyncio.run(prepare())
        assert manage.main(["admin-set-password"])==0
        result=capsys.readouterr()
        assert "updated" in result.out.lower()
        assert "private-new-password-123" not in result.out+result.err
        async def verify():
            async with factory() as session:
                user=await session.scalar(select(AdminUser))
                sessions=await session.scalar(select(func.count()).select_from(AdminSession))
                audit=list((await session.scalars(select(SystemLog.message))).all())
                return user,sessions,audit
        user,sessions,audit=asyncio.run(verify())
        assert verify_password("private-new-password-123",user.password_hash)
        assert user.session_version==4 and sessions==0
        assert user.reset_token_hash=="" and user.reset_token_expires_at is None and user.reset_token_used_at is not None
        assert audit==["ADMIN_PASSWORD_SET_LOCAL"]
    finally:
        manage.SessionLocal=original
        asyncio.run(engine.dispose())


def test_local_admin_set_password_rejects_short_and_mismatch_without_mutation(monkeypatch,tmp_path):
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"admin-cli-invalid.db").resolve())))
    original=manage.SessionLocal;manage.SessionLocal=async_sessionmaker(engine,expire_on_commit=False)
    try:
        async def prepare():
            async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
            async with manage.SessionLocal() as session:
                session.add(AdminUser(username="LocalAdmin",password_hash=hash_password("old-private-password")))
                await session.commit()
        asyncio.run(prepare())
        assert asyncio.run(manage.set_admin_password("LocalAdmin","short","short"))==2
        assert asyncio.run(manage.set_admin_password("LocalAdmin","new-private-password-123","different-private-password-456"))==2
        async def read():
            async with manage.SessionLocal() as session: return await session.scalar(select(AdminUser))
        user=asyncio.run(read())
        assert verify_password("old-private-password",user.password_hash)
    finally:
        manage.SessionLocal=original;asyncio.run(engine.dispose())


def test_admin_reset_rotates_token_and_keeps_only_digest(monkeypatch,tmp_path,capsys):
    from datetime import datetime, timezone
    from database import db
    from services.admin_passwords import reset_token_digest
    engine=create_async_engine(URL.create("sqlite+aiosqlite",database=str((tmp_path/"admin-reset-cli.db").resolve())))
    original=manage.SessionLocal;manage.SessionLocal=async_sessionmaker(engine,expire_on_commit=False)
    try:
        async def prepare():
            async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
            async with manage.SessionLocal() as session:
                session.add(AdminUser(username="LocalAdmin",password_hash=hash_password("old-private-password"),
                    reset_token_hash=reset_token_digest("previous-private-reset-token"),
                    reset_token_expires_at=utcnow()+timedelta(minutes=15)))
                await session.commit()
        asyncio.run(prepare())
        token_values=iter([("new-private-reset-token-1234567890",reset_token_digest("new-private-reset-token-1234567890"),
            datetime(2026,10,4,7,0,tzinfo=timezone.utc))])
        monkeypatch.setattr(manage,"create_reset_token",lambda:next(token_values))
        assert asyncio.run(manage.admin_reset())==0
        output=capsys.readouterr().out
        assert "new-private-reset-token-1234567890" in output
        async def read():
            async with manage.SessionLocal() as session: return await session.scalar(select(AdminUser))
        user=asyncio.run(read())
        assert user.reset_token_hash==reset_token_digest("new-private-reset-token-1234567890")
        assert user.reset_token_hash!="new-private-reset-token-1234567890"
        from services.admin_passwords import utc_aware
        assert utc_aware(user.reset_token_expires_at)==datetime(2026,10,4,7,0,tzinfo=timezone.utc)
        assert user.reset_token_used_at is None
        assert db.SessionLocal is not None
    finally:
        manage.SessionLocal=original;asyncio.run(engine.dispose())
