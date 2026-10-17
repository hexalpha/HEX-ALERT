import shutil
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

import api.app as api_module
from database.models import Base, Source


@pytest.mark.asyncio
async def test_backup_restore_replaces_data_and_keeps_recovery_point(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    backup_dir = Path(__file__).parent / ".backup-test-data"
    monkeypatch.setattr(api_module, "SessionLocal", sessions)
    monkeypatch.setattr(api_module, "BACKUP_DIR", backup_dir)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Source(name="fixture", url="https://example.org/feed", category="news"))
            await session.commit()
        archive_path = await api_module._make_backup()
        async with sessions() as session:
            row = await session.scalar(select(Source).where(Source.name == "fixture"))
            await session.delete(row)
            await session.commit()

        body = archive_path.read_bytes()
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "scheme": "http", "path": "/api/backups/restore", "raw_path": b"/api/backups/restore",
                 "query_string": b"", "headers": [], "server": ("test", 80), "client": ("test", 1), "root_path": ""}
        sent = False
        async def receive():
            nonlocal sent
            if sent: return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        result = await api_module.restore_backup(Request(scope, receive))
        assert result["restored"] is True
        assert result["pre_restore_backup"]
        async with sessions() as session:
            restored = await session.scalar(select(Source).where(Source.name == "fixture"))
            assert restored is not None
    finally:
        await engine.dispose()
        shutil.rmtree(backup_dir, ignore_errors=True)
