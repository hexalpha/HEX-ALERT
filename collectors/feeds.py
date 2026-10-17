import email.utils
import feedparser
import re
from sqlalchemy import select
from datetime import date, datetime, time, timezone
from urllib.parse import urlparse, urljoin
from collectors.base import Collector
from database.models import Source
from services.time_utils import parse_datetime


def parse_time(entry):
    value = entry.get("published") or entry.get("updated")
    if value:
        parsed = parse_datetime(value)
        if isinstance(parsed, datetime): return parsed.astimezone(timezone.utc)
        try:
            return datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        except (AttributeError, TypeError, ValueError):
            try:
                parsed = email.utils.parsedate_to_datetime(value)
                if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except (TypeError, ValueError): pass
    return None


def is_date_only(value) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()):
        return False
    try: date.fromisoformat(value.strip()); return True
    except ValueError: return False


async def read_feed(collector: Collector, url: str):
    source_cfg=await _source_config(url)
    timeout=collector.settings.request_timeout_seconds;limit=2_000_000
    if source_cfg: timeout=source_cfg.timeout_seconds;limit=source_cfg.max_response_bytes
    collector.client.timeout=__import__("httpx").Timeout(timeout)
    response = await collector.get(url,max_bytes=limit, headers={**await source_headers(collector,url),"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json, text/html"})
    content_type=response.headers.get("content-type","").lower()
    if source_cfg and (source_cfg.parser_type=="json" or "json" in content_type):
        payload=response.json(); raw=payload if isinstance(payload,list) else payload.get("items",payload.get("data",payload.get("results",[]))) if isinstance(payload,dict) else []
        if isinstance(raw,dict): raw=list(raw.values())
        source=urlparse(url).hostname or "Public API"; entries=[]
        for item in raw[:100] if isinstance(raw,list) else []:
            if not isinstance(item,dict): continue
            title=str(item.get("title") or item.get("name") or "").strip(); link=item.get("url") or item.get("link") or item.get("html_url")
            published_value=item.get("published_at") or item.get("published") or item.get("created_at")
            if title and link: entries.append({"title":title[:500],"url":urljoin(url,str(link)),"summary":str(item.get("summary") or item.get("description") or "")[:12000],"published_at":_coerce_date(published_value),"published_at_date_only":is_date_only(published_value),"source":source})
        return entries
    if source_cfg and source_cfg.parser_type=="html":
        from bs4 import BeautifulSoup
        soup=BeautifulSoup(response.text,"html.parser"); source=soup.title.get_text(" ",strip=True) if soup.title else urlparse(url).hostname or "Public website"; entries=[]
        for node in soup.select("article a[href], main a[href], a[href]")[:100]:
            title=" ".join(node.get_text(" ",strip=True).split()); link=node.get("href")
            if title and link and not link.startswith(("javascript:","mailto:","tel:")): entries.append({"title":title[:500],"url":urljoin(url,link),"summary":"","published_at":None,"published_at_date_only":False,"source":source})
        return entries
    feed = feedparser.parse(response.content)
    source = feed.feed.get("title") or urlparse(url).hostname or "Public feed"
    entries = []
    for entry in feed.entries[:100]:
        link = entry.get("link", "")
        title = (entry.get("title") or "").strip()
        if title and link:
            published_value=entry.get("published") or entry.get("updated")
            entries.append({"title": title[:500], "url": link, "summary": (entry.get("summary") or entry.get("description") or "")[:12000], "published_at": parse_time(entry), "published_at_date_only":is_date_only(published_value), "source": source})
    return entries


async def source_headers(collector,url):
    from config.secrets import secret_value
    source=await _source_config(url)
    if not source or source.auth_mode=="none": return {}
    value=secret_value(source.auth_env_var) if source.auth_env_var else None
    if not value: raise ValueError("Source credential is not configured in the environment")
    return {"Authorization":f"Bearer {value}"} if source.auth_mode=="bearer" else {"X-API-Key":value}


async def _source_config(url):
    from database.db import SessionLocal
    async with SessionLocal() as session: return await session.scalar(select(Source).where(Source.url==url))


def _coerce_date(value):
    if not value:return None
    parsed=parse_datetime(str(value))
    if isinstance(parsed, datetime):return parsed.astimezone(timezone.utc)
    if isinstance(parsed, date):return datetime.combine(parsed,time.min,tzinfo=timezone.utc)
    return None


def source_due(source):
    if not source.last_fetch:return True
    previous=source.last_fetch
    if previous.tzinfo is None: previous=previous.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc)-previous).total_seconds() >= max(5,source.interval_minutes)*60
