import re
from sqlalchemy import select
from database.models import Source
from database.repository import save_news, upsert_source
from collectors.feeds import read_feed, source_due
from collectors.base import Collector

SECURITY_TERMS = re.compile(r"\b(?:cve-\d{4}-\d+|vulnerab\w*|ransomware|malware|phishing|cyber|security|breach|exploit|threat|zero.day|patch|apt\d+|botnet|infosec|incident response|advisory)\b", re.I)


class NewsCollector(Collector):
    async def collect(self, session, urls: list[str]):
        added = []
        for url in urls:
            name = url.split("/")[2]
            source = await upsert_source(session, name=f"news:{name}", url=url, category="news", interval=self.settings.poll_news_minutes)
            if not source.enabled or not source_due(source): continue
            try:
                started = __import__("time").monotonic()
                entries = await read_feed(self, url)
                source.healthy = True; source.failure_count = 0; source.last_error = ""
                source.last_success = __import__("database.models", fromlist=["utcnow"]).utcnow()
                source.items_found = len(entries); source.response_time_ms = int((__import__("time").monotonic()-started)*1000)
                for item in entries:
                    if not SECURITY_TERMS.search(item["title"] + " " + item["summary"]): continue
                    row, fresh = await save_news(session, {"title": item["title"], "summary": re.sub("<[^>]+>", " ", item["summary"])[:1800], "category": "Cybersecurity News", "source": item["source"], "source_url": item["url"], "published_at": item["published_at"], "published_at_date_only": item.get("published_at_date_only", False)})
                    if fresh: added.append(row)
            except Exception as exc:
                source.failure_count += 1; source.healthy = source.failure_count < 5; source.last_error = type(exc).__name__
                source.last_failure = __import__("database.models", fromlist=["utcnow"]).utcnow()
            finally:
                from database.models import utcnow
                source.last_fetch = utcnow()
        await session.commit()
        return added
