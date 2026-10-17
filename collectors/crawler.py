"""Bounded, polite crawler for explicitly configured public pages."""
import asyncio
import hashlib
import ipaddress
import logging
import socket
import time
from collections import deque
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from collectors.base import PinnedAsyncHTTPTransport, validate_public_url
from database.db import SessionLocal
from database.models import CrawlerJob, CrawlerPage, CrawlerRun, SystemLog, Alert, SentMessage, utcnow
from database.repository import normalize_url

log = logging.getLogger("hexalert.crawler")


async def public_addresses(host: str) -> set[str]:
    records = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses = {record[4][0].split("%", 1)[0] for record in records}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Host resolves to a non-public address")
    return addresses


class CrawlerManager:
    def __init__(self,bot=None):
        self.bot=bot
        self.tasks: dict[int, asyncio.Task] = {}
        self.stops: set[int] = set()
        self.pauses: set[int] = set()
        self.wakes: dict[int, asyncio.Event] = {}

    async def start(self, crawler_id: int) -> bool:
        current = self.tasks.get(crawler_id)
        if current and not current.done(): return False
        self.stops.discard(crawler_id); self.pauses.discard(crawler_id)
        self.wakes[crawler_id] = asyncio.Event(); self.wakes[crawler_id].set()
        task = asyncio.create_task(self.run(crawler_id), name=f"crawler-{crawler_id}")
        self.tasks[crawler_id] = task
        return True

    async def stop(self, crawler_id: int):
        self.stops.add(crawler_id)
        wake = self.wakes.get(crawler_id)
        if wake: wake.set()
        task = self.tasks.get(crawler_id)
        if task and not task.done():
            task.cancel(); await asyncio.gather(task,return_exceptions=True)

    def pause(self, crawler_id: int):
        self.pauses.add(crawler_id)
        wake = self.wakes.get(crawler_id)
        if wake: wake.clear()

    def resume(self, crawler_id: int):
        self.pauses.discard(crawler_id)
        wake = self.wakes.get(crawler_id)
        if wake: wake.set()

    async def _allowed(self, url: str, crawler: CrawlerJob) -> bool:
        validate_public_url(url)
        parts = urlsplit(url)
        if parts.hostname != crawler.allowed_domain and not parts.hostname.endswith("." + crawler.allowed_domain): return False
        path = parts.path or "/"
        if crawler.allowed_paths and not any(path.startswith(prefix) for prefix in crawler.allowed_paths): return False
        if any(path.startswith(prefix) for prefix in crawler.blocked_paths): return False
        await public_addresses(parts.hostname)
        return True

    async def _robots_allowed(self, client: httpx.AsyncClient, url: str, crawler: CrawlerJob, cache: dict[str, RobotFileParser]) -> bool:
        parts = urlsplit(url); origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in cache:
            parser = RobotFileParser()
            robots_url = origin + "/robots.txt"
            try:
                if await self._allowed(robots_url, crawler):
                    response = await self._get_limited(client, robots_url)
                    if response.is_success and len(response.content) <= 128_000:
                        parser.set_url(robots_url); parser.parse(response.text.splitlines())
                    else: parser.parse([])
                else: parser.parse([])
            except Exception:
                # Fail closed for this crawl when robots policy cannot be checked.
                parser.parse(["User-agent: *", "Disallow: /"])
            cache[origin] = parser
        return cache[origin].can_fetch(crawler.user_agent, url)

    async def run(self, crawler_id: int):
        async with SessionLocal() as session:
            crawler = await session.get(CrawlerJob, crawler_id)
            if not crawler: return
            run = CrawlerRun(crawler_id=crawler_id, status="running", current_url=crawler.start_url)
            crawler.status = "running"; session.add(run); await session.commit(); await session.refresh(run)
            snapshot = {k: getattr(crawler, k) for k in ("start_url", "allowed_domain", "allowed_paths", "blocked_paths", "max_depth", "max_pages", "request_delay_ms", "user_agent", "follow_links", "mode", "selectors","channel_id")}
            run_id = run.id
        start_time = time.monotonic(); new_count = dup_count = errors = processed = 0
        queue = deque([(snapshot["start_url"], 0)]); seen = set(); robots = {}
        headers = {"User-Agent": snapshot["user_agent"], "Accept": "text/html,application/xhtml+xml"}
        timeout = httpx.Timeout(15.0, connect=8.0)
        transport = PinnedAsyncHTTPTransport()
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers, transport=transport) as client:
                while queue and processed < min(100, max(1, snapshot["max_pages"])):
                    if crawler_id in self.stops: break
                    wake = self.wakes.get(crawler_id)
                    if wake: await wake.wait()
                    url, depth = queue.popleft(); url = normalize_url(url)
                    if url in seen: continue
                    seen.add(url)
                    async with SessionLocal() as session:
                        run = await session.get(CrawlerRun, run_id)
                        if run: run.current_url=url; run.pages_remaining=len(queue); await session.commit()
                    try:
                        if not await self._allowed(url, crawler): raise ValueError("URL left the configured public domain or path scope")
                        if not await self._robots_allowed(client, url, crawler, robots):
                            await self._activity(crawler_id, run_id, "INFO", f"Skipped disallowed path: {url}"); continue
                        current = url
                        response = None
                        for hop in range(4):
                            if not await self._allowed(current, crawler): raise ValueError("Redirect target is outside the allowed public scope")
                            await transport.pin(urlsplit(current).hostname)
                            response = await self._get_limited(client, current)
                            if response.status_code == 429:
                                delay = min(30, int(response.headers.get("Retry-After", "5")) if response.headers.get("Retry-After", "").isdigit() else 5)
                                await asyncio.sleep(delay); response = await self._get_limited(client, current)
                            if response.status_code in {301, 302, 303, 307, 308}:
                                target = response.headers.get("location")
                                if not target: break
                                current = urljoin(current, target); continue
                            break
                        if response is None or response.status_code in {301,302,303,307,308}: raise ValueError("Too many or invalid redirects")
                        response.raise_for_status()
                        if len(response.content) > 2_000_000: raise ValueError("Response exceeded the 2 MB size limit")
                        if "html" not in response.headers.get("content-type", "").lower():
                            await self._activity(crawler_id, run_id, "INFO", "Skipped non-HTML response"); continue
                        data = self._extract(response.text, current, snapshot["selectors"])
                        digest = hashlib.sha256((data["title"]+"\n"+data["summary"]).encode()).hexdigest()
                        async with SessionLocal() as session:
                            page = await session.scalar(select(CrawlerPage).where(CrawlerPage.crawler_id==crawler_id, CrawlerPage.url==current))
                            changed=bool(page and page.content_hash!=digest)
                            if page and not changed: dup_count += 1
                            elif page: page.content_hash=digest; page.title=data["title"]; page.summary=data["summary"]; page.fetched_at=utcnow(); new_count += 1
                            else:
                                session.add(CrawlerPage(crawler_id=crawler_id, url=current, content_hash=digest, title=data["title"], summary=data["summary"])); new_count += 1
                            run = await session.get(CrawlerRun, run_id); run.new_items=new_count; run.duplicate_items=dup_count; run.pages_processed=processed+1
                            await session.commit()
                        if changed and snapshot["mode"]=="change_monitor":await self._send_change(crawler_id,snapshot,current,data)
                        await self._activity(crawler_id, run_id, "INFO", f"Fetched page: {data['title'][:120]}")
                        if snapshot["follow_links"] and depth < min(5, snapshot["max_depth"]):
                            for link in data["links"]:
                                absolute = normalize_url(urljoin(current, link))
                                try:
                                    if await self._allowed(absolute, crawler): queue.append((absolute, depth+1))
                                except (ValueError, OSError): continue
                    except Exception as exc:
                        errors += 1
                        await self._activity(crawler_id, run_id, "WARNING", f"Page failed ({type(exc).__name__})")
                    finally:
                        processed += 1
                        async with SessionLocal() as session:
                            run=await session.get(CrawlerRun,run_id)
                            if run: run.pages_processed=processed; run.pages_remaining=len(queue); run.new_items=new_count; run.duplicate_items=dup_count; run.errors=errors; await session.commit()
                        await asyncio.sleep(min(60, max(250, snapshot["request_delay_ms"])/1000))
            final = "stopped" if crawler_id in self.stops else ("failed" if errors and not processed else "completed")
        except asyncio.CancelledError:
            final="stopped"
        except Exception as exc:
            final = "failed"; errors += 1
            await self._activity(crawler_id, run_id, "ERROR", f"Crawler failed ({type(exc).__name__})")
        async with SessionLocal() as session:
            run=await session.get(CrawlerRun,run_id); crawler=await session.get(CrawlerJob,crawler_id)
            if run: run.status=final; run.finished_at=utcnow(); run.pages_processed=processed; run.new_items=new_count; run.duplicate_items=dup_count; run.errors=errors
            if crawler: crawler.status=final
            await session.commit()
        log.info("Crawler %s completed: %s pages=%d new=%d duplicate=%d errors=%d duration=%.1fs",crawler_id,final,processed,new_count,dup_count,errors,time.monotonic()-start_time)

    @staticmethod
    def _extract(html: str, url: str, selectors: dict):
        soup=BeautifulSoup(html,"html.parser")
        for element in soup.select("script,style,nav,footer,header,aside,noscript,form,svg"): element.decompose()
        title_sel=selectors.get("title")
        content_sel=selectors.get("content")
        title_el=soup.select_one(title_sel) if title_sel else soup.find("h1") or soup.title
        content_el=soup.select_one(content_sel) if content_sel else soup.find("article") or soup.find("main") or soup.body or soup
        title=" ".join(title_el.get_text(" ",strip=True).split())[:500] if title_el else "Untitled page"
        summary=" ".join(content_el.get_text(" ",strip=True).split())[:8000] if content_el else ""
        link_sel=selectors.get("link")
        links=[x.get("href") for x in soup.select(link_sel or "a[href]") if x.get("href") and not x.get("href").startswith(("javascript:","mailto:","tel:"))][:200]
        return {"title":title,"url":url,"summary":summary,"links":links}

    @staticmethod
    async def _get_limited(client, url):
        async with client.stream("GET", url, follow_redirects=False) as response:
            body=bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body)>2_000_000: raise ValueError("Response exceeded the 2 MB size limit")
            headers={key:value for key,value in response.headers.items() if key.lower() not in {"content-encoding","content-length","transfer-encoding"}}
            return httpx.Response(response.status_code, headers=headers, content=bytes(body), request=response.request)

    @staticmethod
    async def _activity(crawler_id, run_id, level, message):
        async with SessionLocal() as session:
            session.add(SystemLog(level=level,component=f"crawler:{crawler_id}",message=message[:500]))
            run=await session.get(CrawlerRun,run_id)
            if run: run.updated_at=utcnow()
            await session.commit()

    async def _send_change(self,crawler_id,snapshot,url,data):
        if not self.bot:return
        from config.settings import get_settings
        from services.discord_routing import resolve_discord_channel, resolve_explicit_channel, RoutingError
        settings=get_settings()
        if settings.test_mode:
            async with SessionLocal() as session:
                session.add(Alert(category="crawler",title=data["title"][:500],source=snapshot["allowed_domain"],
                                  source_url=url,status="suppressed",
                                  error="TEST_MODE: scheduled crawler alert suppressed"))
                await session.commit()
            return
        try:
            resolution=(await resolve_explicit_channel(snapshot["channel_id"],bot=self.bot)
                        if snapshot["channel_id"].isdigit()
                        else await resolve_discord_channel("bot_status",bot=self.bot))
        except RoutingError as exc:
            async with SessionLocal() as session:
                session.add(Alert(category="crawler",title=data["title"][:500],source=snapshot["allowed_domain"],
                                  source_url=url,status="failed",error=str(exc)[:1000]))
                await session.commit()
            return
        channel=resolution.channel
        import discord
        embed=discord.Embed(title=f"Page changed: {data['title'][:240]}",description=f"A monitored public page changed.\n\n[Open source]({url})",color=0xEAB308)
        try:
            message=await channel.send(embed=embed,allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as exc:
            async with SessionLocal() as session:
                session.add(Alert(category="crawler",title=data["title"][:500],source=snapshot["allowed_domain"],
                                  source_url=url,channel_id=resolution.channel_id,channel_name=resolution.channel_name,
                                  status="failed",error=f"Discord HTTP {exc.status}: {type(exc).__name__}"))
                await session.commit()
            return
        async with SessionLocal() as session:
            session.add(Alert(category="crawler",title=data["title"][:500],source=snapshot["allowed_domain"],source_url=url,channel_id=resolution.channel_id,channel_name=resolution.channel_name,message_id=str(message.id),status="sent"))
            session.add(SentMessage(item_type="crawler",item_id=str(crawler_id),guild_id=resolution.guild_id,channel_id=resolution.channel_id,message_id=str(message.id)))
            await session.commit()
