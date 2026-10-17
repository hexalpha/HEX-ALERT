import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import collectors.base as base_module
import collectors.crawler as crawler_module
from database.models import Base, CrawlerJob, CrawlerPage, CrawlerRun, SystemLog


@pytest.mark.asyncio
async def test_crawler_fetch_parse_deduplicate_and_store_against_local_fixture(monkeypatch):
    seen_paths = []
    async def handler(reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            path = request.split(b" ", 2)[1]
            seen_paths.append(path.decode())
            if path == b"/robots.txt":
                status, body = b"200 OK", b"User-agent: *\nAllow: /\n"
            else:
                status = b"200 OK"
                body = b"<html><head><title>discard</title></head><body><nav>Noise</nav><main><h1>Security Release</h1><p>Patch guidance</p><a href='/next'>Next</a></main></body></html>"
            writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(crawler_module, "SessionLocal", sessions)

    async def public_for_fixture(host): return {"93.184.216.34"}
    async def pin_local_test_fixture(self, hostname):
        host = hostname.rstrip(".").lower()
        self._pinned_backend._pins[host] = "127.0.0.1"
        return "127.0.0.1"
    async def pin_backend_local_fixture(self, hostname):
        host = hostname.rstrip(".").lower()
        self._pins[host] = "127.0.0.1"
        return "127.0.0.1"
    monkeypatch.setattr(crawler_module, "public_addresses", public_for_fixture)
    monkeypatch.setattr(base_module.PinnedAsyncHTTPTransport, "pin", pin_local_test_fixture)
    monkeypatch.setattr(base_module._PinnedBackend, "pin", pin_backend_local_fixture)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            job = CrawlerJob(name="fixture", start_url=f"http://fixture.test:{port}/", allowed_domain="fixture.test",
                             max_depth=1, max_pages=2, request_delay_ms=1000, follow_links=False,
                             mode="single_page", selectors={})
            session.add(job)
            await session.commit()
            await session.refresh(job)
            crawler_id = job.id

        manager = crawler_module.CrawlerManager()
        await manager.run(crawler_id)
        async with sessions() as session:
            page = await session.scalar(select(CrawlerPage).where(CrawlerPage.crawler_id == crawler_id))
            run = await session.scalar(select(CrawlerRun).where(CrawlerRun.crawler_id == crawler_id))
            messages = list((await session.scalars(select(SystemLog.message))).all())
            assert page and page.title == "Security Release", (seen_paths, messages, run.status if run else None, run.errors if run else None, run.pages_processed if run else None, run.pages_remaining if run else None)
            assert "Noise" not in page.summary
            assert run and run.status == "completed" and run.pages_processed == 1 and run.new_items == 1
    finally:
        server.close()
        await server.wait_closed()
        await engine.dispose()
