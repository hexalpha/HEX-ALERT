import hashlib
import re
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from database.models import Job, NewsArticle, CVE, Threat, SecurityTool, Source, SystemLog


def digest(*parts: str) -> str:
    normalized = "|".join(re.sub(r"\s+", " ", (p or "").strip().lower()) for p in parts)
    return hashlib.sha256(normalized.encode()).hexdigest()


def normalize_url(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts = urlsplit(url.strip())
    tracking = {"ref", "source", "fbclid", "gclid", "mc_cid", "mc_eid", "trk", "trackingid", "campaign", "campaignid", "gh_src", "lever-source"}
    query = [(k, v) for k, v in parse_qsl(parts.query) if not k.lower().startswith(("utm_", "trk_")) and k.lower() not in tracking]
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), urlencode(query), ""))


def canonical_job_key(company: str, title: str, location: str) -> str:
    """Stable cross-source identity; URLs remain evidence, not the only identity."""
    return digest(company, title, location)


def _specific_job_url(url: str) -> str:
    normalized = normalize_url(url)
    from urllib.parse import urlsplit
    parts = urlsplit(normalized)
    segments = [part for part in parts.path.split("/") if part]
    host = parts.netloc.casefold().removeprefix("www.")
    if host == "jobs.lever.co" and len(segments) <= 1:
        return ""
    if host in {"boards.greenhouse.io", "job-boards.greenhouse.io"} and len(segments) <= 1:
        return ""
    if host == "jobs.ashbyhq.com" and len(segments) <= 1:
        return ""
    return normalized


def source_preference(source_type: str) -> int:
    kind = str(source_type or "").casefold()
    if kind in {"company_careers", "public_career_page"}:
        return 4
    if kind in {"greenhouse", "lever", "ashby"}:
        return 3
    if kind in {"remote_ok", "public_job_api", "rss_job_feed", "job_feed"}:
        return 2
    return 1


async def count_rows(session: AsyncSession, model) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


async def latest(session: AsyncSession, model, limit: int = 10):
    return list((await session.scalars(select(model).order_by(model.published_at.desc().nullslast(), model.id.desc()).limit(limit))).all())


async def upsert_source(session: AsyncSession, *, name: str, url: str, category: str, interval: int) -> Source:
    source = await session.scalar(select(Source).where(Source.url == url))
    if source is None: source = await session.scalar(select(Source).where(Source.name == name))
    if source is None:
        source = Source(name=name, url=url, category=category, interval_minutes=interval)
        session.add(source)
    return source


async def log_system_event(session: AsyncSession, level: str, component: str, message: str) -> None:
    # Exception messages may contain URLs/tokens; persist only controlled, sanitized summaries.
    session.add(SystemLog(level=level[:20].upper(), component=component[:100], message=message[:500]))


async def save_job(session: AsyncSession, values: dict) -> tuple[Job, bool]:
    from datetime import datetime, timezone
    source_url = normalize_url(values.get("source_url") or values.get("apply_url") or "")
    apply_url = normalize_url(values.get("apply_url") or values.get("source_url") or "")
    key = values.get("canonical_job_key") or canonical_job_key(values.get("company", ""), values.get("title", ""), values.get("location", ""))
    legacy_fp = digest(values.get("company", ""), values.get("title", ""), values.get("location", ""), apply_url)
    exact_role = and_(func.lower(Job.company) == str(values.get("company", "")).casefold(),
                      func.lower(Job.title) == str(values.get("title", "")).casefold(),
                      func.lower(Job.location) == str(values.get("location", "")).casefold())
    direct_url = _specific_job_url(apply_url)
    external_id = str(values.get("external_id") or values.get("posting_id") or "").strip()
    identity_conditions = [Job.canonical_job_key == key, Job.fingerprint == legacy_fp, exact_role]
    if direct_url:
        identity_conditions.extend((Job.apply_url == direct_url, Job.source_url == direct_url))
    if external_id:
        identity_conditions.append(and_(func.lower(Job.company) == str(values.get("company", "")).casefold(),
                                        Job.external_id == external_id))
    obj = await session.scalar(select(Job).where(or_(*identity_conditions)).order_by(Job.id.asc()).limit(1))
    rank = source_preference(values.get("source_type", ""))
    provenance = {"source": values.get("source", ""), "source_type": values.get("source_type", ""),
                  "source_id": values.get("source_id"), "source_url": source_url,
                  "apply_url": apply_url, "external_id": values.get("external_id") or values.get("posting_id", ""),
                  "rank": rank}
    if obj:
        obj.last_seen_at = datetime.now(timezone.utc)
        obj.canonical_job_key = key
        entries = list(obj.source_provenance or [])
        identity = (provenance["source_type"], provenance["source_url"], provenance["external_id"])
        if identity not in {(item.get("source_type"), item.get("source_url"), item.get("external_id")) for item in entries if isinstance(item, dict)}:
            entries.append(provenance)
            obj.source_provenance = entries
        current_rank = max((int(item.get("rank", 1)) for item in entries if isinstance(item, dict)), default=1)
        current_direct = _specific_job_url(obj.apply_url or obj.source_url)
        if rank >= current_rank or not current_direct or (direct_url and not current_direct):
            obj.apply_url = apply_url
            obj.source_url = source_url
            obj.source = values.get("source", obj.source)
            obj.source_id = values.get("source_id", obj.source_id)
        if values.get("listing_status") in {"OPEN", "CLOSED"}:
            obj.listing_status = values["listing_status"]
        # The same listing can acquire a date, salary, or experience detail later.
        # Refresh only safe normalized fields so stored freshness and matching stay current.
        refreshable = {"experience", "employment_type", "work_mode", "remote_status", "salary", "salary_min", "salary_max", "currency",
                       "skills", "description", "published_at", "published_at_date_only", "freshness_status", "listing_status",
                       "match_score", "score_breakdown", "experience_min", "experience_max", "is_cybersecurity", "is_entry_level",
                       "match_category", "external_id", "posting_id"}
        for key in refreshable:
            value = values.get(key)
            if value not in (None, "", "Not publicly available", []):
                setattr(obj, key, value)
        return obj, False
    allowed = {"title", "company", "location", "experience", "employment_type", "work_mode", "remote_status", "salary", "salary_min", "salary_max", "currency", "skills",
               "description", "source", "source_url", "apply_url", "published_at", "published_at_date_only", "match_category", "freshness_status",
               "listing_status", "match_score", "score_breakdown", "source_id", "posting_id", "external_id", "discovered_at",
               "canonical_job_key", "source_provenance", "is_cybersecurity", "is_entry_level", "experience_min", "experience_max",
               "alert_eligible", "suppressed"}
    safe_values = {key: value for key, value in values.items() if key in allowed}
    safe_values.update({"source_url": source_url, "apply_url": apply_url, "canonical_job_key": key,
                        "source_provenance": [provenance], "external_id": values.get("external_id") or values.get("posting_id", ""),
                        "remote_status": values.get("remote_status") or values.get("work_mode") or "Not publicly available"})
    obj = Job(**safe_values, fingerprint=key)
    session.add(obj)
    await session.flush()
    return obj, True


async def save_news(session: AsyncSession, values: dict) -> tuple[NewsArticle, bool]:
    url = normalize_url(values["source_url"])
    h = digest(values.get("title", ""))
    obj = await session.scalar(select(NewsArticle).where((NewsArticle.source_url == url) | (NewsArticle.content_hash == h)))
    if obj: return obj, False
    values["source_url"] = url
    obj = NewsArticle(**values, content_hash=h)
    session.add(obj); await session.flush()
    return obj, True


async def save_cve(session: AsyncSession, values: dict) -> tuple[CVE, bool]:
    obj = await session.scalar(select(CVE).where(CVE.cve_id == values["cve_id"]))
    if obj: return obj, False
    obj = CVE(**values); session.add(obj); await session.flush()
    return obj, True


async def save_threat(session: AsyncSession, values: dict) -> tuple[Threat, bool]:
    h = digest(values.get("title", ""))
    obj = await session.scalar(select(Threat).where((Threat.source_url == values["source_url"]) | (Threat.content_hash == h)))
    if obj: return obj, False
    obj = Threat(**values, content_hash=h); session.add(obj); await session.flush()
    return obj, True


async def save_tool(session: AsyncSession, values: dict) -> tuple[SecurityTool, bool]:
    h = digest(values.get("name", ""), values.get("source_url", ""))
    obj = await session.scalar(select(SecurityTool).where((SecurityTool.source_url == values["source_url"]) | (SecurityTool.content_hash == h)))
    if obj: return obj, False
    obj = SecurityTool(**values, content_hash=h); session.add(obj); await session.flush()
    return obj, True
