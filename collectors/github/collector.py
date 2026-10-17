import re
from collectors.base import Collector
from collectors.feeds import read_feed, source_due
from database.repository import save_tool, upsert_source

SECURITY = re.compile(r"\b(security|cyber|vulnerability|malware|siem|edr|xdr|pentest|penetration|osint|threat|forensic|soc|devsecops|scanner)\b", re.I)


class TechnologyCollector(Collector):
    async def collect(self, session, urls: list[str]):
        added = []
        for url in urls:
            name = url.split("/")[2]
            source = await upsert_source(session, name=f"technology:{name}", url=url, category="technology", interval=self.settings.poll_tech_minutes)
            if not source.enabled or not source_due(source): continue
            try:
                started = __import__("time").monotonic()
                entries=await read_feed(self,url)
                for item in entries:
                    if not SECURITY.search(item["title"] + " " + item["summary"]): continue
                    match = re.search(r"https?://github\.com/[\w.-]+/[\w.-]+", item["url"])
                    tool, fresh = await save_tool(session, {"name": item["title"][:300], "description": re.sub("<[^>]+>", " ", item["summary"])[:3000], "category": "Cybersecurity Technology", "developer": "Not publicly available", "source": item["source"], "source_url": item["url"], "github_url": match.group(0) if match else "", "documentation_url": "", "open_source": "YES" if match else "UNKNOWN", "published_at": item["published_at"], "published_at_date_only": item.get("published_at_date_only", False)})
                    if fresh: added.append(tool)
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
