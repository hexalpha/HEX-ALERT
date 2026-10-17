import re
from collectors.base import Collector
from collectors.feeds import read_feed, source_due
from database.repository import save_threat, upsert_source

THREAT = re.compile(r"\b(ransomware|malware|botnet|phishing|apt\d*|threat actor|campaign|intrusion|supply.chain|data breach|indicators of compromise|ioc)\b", re.I)


class ThreatCollector(Collector):
    async def collect(self, session, urls: list[str]):
        added = []
        for url in urls:
            name = url.split("/")[2]
            source = await upsert_source(session, name=f"threat:{name}", url=url, category="threat", interval=self.settings.poll_threats_minutes)
            if not source.enabled or not source_due(source): continue
            try:
                started = __import__("time").monotonic()
                entries=await read_feed(self,url)
                for item in entries:
                    if not THREAT.search(item["title"] + " " + item["summary"]): continue
                    # Only public reports and their own links are stored; no IOC extraction from arbitrary text.
                    threat, fresh = await save_threat(session, {"title": item["title"], "summary": re.sub("<[^>]+>", " ", item["summary"])[:2500], "actor": "Not publicly available", "malware": "Not publicly available", "techniques": [], "indicators": [], "source": item["source"], "source_url": item["url"], "published_at": item["published_at"], "published_at_date_only": item.get("published_at_date_only", False)})
                    if fresh: added.append(threat)
                source.healthy = True; source.failure_count = 0; source.last_error = ""
                source.last_success = __import__("database.models", fromlist=["utcnow"]).utcnow()
                source.items_found = len(entries); source.response_time_ms = int((__import__("time").monotonic()-started)*1000)
            except Exception as exc:
                source.failure_count += 1; source.healthy = source.failure_count < 5; source.last_error = type(exc).__name__
                source.last_failure = __import__("database.models", fromlist=["utcnow"]).utcnow()
            from database.models import utcnow
            source.last_fetch = utcnow()
        await session.commit()
        return added
