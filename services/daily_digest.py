"""Verified, deduplicated records shared by the daily digest and its preview."""
from __future__ import annotations

import re
import unicodedata
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import select

from database.models import CVE, Job, NewsArticle, SecurityTool, Threat, utcnow

MAX_ITEMS_PER_SECTION = 3
QUERY_LIMIT = 1000
TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source", "trk", "trackingid", "campaign", "campaignid", "gh_src", "lever-source"}


def _normal_text(value):
    value = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return " ".join(re.findall(r"[\w]+", value, flags=re.UNICODE))


def canonical_url(value):
    """Normalize a public URL while dropping fragments and common tracking params."""
    try:
        parts = urlsplit(str(value or "").strip())
        if not parts.scheme or not parts.netloc:
            return ""
        host = parts.netloc.casefold()
        path = re.sub(r"/{2,}", "/", parts.path).rstrip("/")
        query = sorted((key, val) for key, val in parse_qsl(parts.query, keep_blank_values=True)
                       if not key.casefold().startswith(("utm_", "trk_")) and key.casefold() not in TRACKING_KEYS)
        return urlunsplit((parts.scheme.casefold(), host, path, urlencode(query), ""))
    except (TypeError, ValueError):
        return ""


def _job_specific_url(item):
    """Ignore employer board roots as job identities; retain exact posting URLs."""
    value = canonical_url(getattr(item, "apply_url", "") or getattr(item, "source_url", ""))
    if not value:
        return ""
    parts = urlsplit(value)
    segments = [segment for segment in parts.path.split("/") if segment]
    host = parts.netloc.casefold().removeprefix("www.")
    if host == "jobs.lever.co" and len(segments) <= 1:
        return ""
    if host in {"boards.greenhouse.io", "job-boards.greenhouse.io"} and len(segments) <= 1:
        return ""
    if host == "jobs.ashbyhq.com" and len(segments) <= 1:
        return ""
    return value


def job_key(item):
    company = _normal_text(getattr(item, "company", ""))
    direct_url = _job_specific_url(item)
    if direct_url:
        return ("url", direct_url)
    external_id = _normal_text(getattr(item, "external_id", "") or getattr(item, "posting_id", ""))
    if external_id:
        return ("external", company, external_id)
    return ("role", company, _normal_text(getattr(item, "title", "")), _normal_text(getattr(item, "location", "")))


def _job_aliases(item):
    company = _normal_text(getattr(item, "company", ""))
    direct_url = _job_specific_url(item)
    external_id = _normal_text(getattr(item, "external_id", "") or getattr(item, "posting_id", ""))
    title = _normal_text(getattr(item, "title", ""))
    location = _normal_text(getattr(item, "location", ""))
    keys = []
    if direct_url:
        keys.append(("url", direct_url))
    if external_id:
        keys.append(("external", company, external_id))
    if company and title:
        keys.append(("role", company, title, location))
    return keys


def _job_quality(item):
    url = _job_specific_url(item)
    provenance = getattr(item, "source_provenance", None) or []
    rank = max((int(row.get("rank", 0)) for row in provenance if isinstance(row, dict)), default=0)
    host = urlsplit(url).netloc.casefold() if url else ""
    official = int(host in {"jobs.lever.co", "boards.greenhouse.io", "job-boards.greenhouse.io", "jobs.ashbyhq.com"})
    return (int(bool(url)), rank, official, int(bool(getattr(item, "apply_url", ""))))


def _dedupe(items, kind, limit=MAX_ITEMS_PER_SECTION):
    groups = {}
    aliases = {}
    next_id = 0
    for item in items:
        if kind == "cve":
            keys = [("cve", _normal_text(getattr(item, "cve_id", "")))]
        elif kind == "job":
            keys = _job_aliases(item)
        else:
            url_field = "github_url" if kind == "tool" else "source_url"
            url = canonical_url(getattr(item, url_field, "") or getattr(item, "source_url", ""))
            title = getattr(item, "title", "") or getattr(item, "name", "")
            title_key = _normal_text(title)
            keys = ([ ("url", url) ] if url else []) + ([ ("title", title_key) ] if title_key else [])
        keys = [key for key in keys if key and key[-1]]
        if not keys:
            continue
        matches = {aliases[key] for key in keys if key in aliases}
        if not matches:
            group_id = next_id
            next_id += 1
            groups[group_id] = item
        else:
            group_id = min(matches)
            candidates = [groups[index] for index in matches] + [item]
            chosen = max(candidates, key=_job_quality) if kind == "job" else groups[group_id]
            for duplicate_id in matches - {group_id}:
                groups.pop(duplicate_id, None)
                for alias, alias_id in list(aliases.items()):
                    if alias_id == duplicate_id:
                        aliases[alias] = group_id
            groups[group_id] = chosen
        for key in keys:
            aliases[key] = group_id
    return list(groups.values())[:limit]


async def recent_digest_sections(session, *, now=None, window_hours: int = 24):
    """Return only recent verified records, deduped before each section is capped."""
    now = now or utcnow()
    cutoff = now - timedelta(hours=max(1, int(window_hours)))

    async def rows(model, *conditions):
        query = select(model).where(model.created_at >= cutoff, *conditions)
        return list((await session.scalars(
            query.order_by(model.created_at.desc(), model.id.desc()).limit(QUERY_LIMIT)
        )).all())

    cves = _dedupe(await rows(CVE), "cve")
    research = _dedupe(await rows(NewsArticle, NewsArticle.category.ilike("%research%")), "research")
    news = _dedupe(await rows(NewsArticle, NewsArticle.category.not_ilike("%research%")), "news")
    technology = _dedupe(await rows(SecurityTool, SecurityTool.category.ilike("%technology%")), "technology")
    tools = _dedupe(await rows(SecurityTool, SecurityTool.category.not_ilike("%technology%")), "tool")
    # Imported board listings are a baseline, not fresh digest updates.
    jobs = _dedupe(await rows(Job, Job.alert_eligible.is_(True),
                              Job.is_cybersecurity.is_(True),
                              Job.listing_status == 'OPEN',
                              Job.freshness_status != 'OLD',
                              Job.suppressed.is_(False)), 'job')
    threats = _dedupe(await rows(Threat), "threat")
    return {
        "cves": cves,
        "exploited_cves": _dedupe([item for item in cves if item.exploited == "YES"], "cve"),
        "news": news,
        "threats": threats,
        "jobs": jobs,
        "tools": tools,
        "research": research,
        "technology": technology,
        "window_hours": max(1, int(window_hours)),
    }


def digest_fields(data):
    """Format compact Discord digest fields; empty sections are omitted."""
    definitions = [
        ("🚨 Critical CVEs", "cves"),
        ("⚠️ New Exploited Vulnerabilities", "exploited_cves"),
        ("📰 Cyber News", "news"),
        ("⚠️ Threat Intel", "threats"),
        ("💼 Jobs", "jobs"),
        ("🛠️ Tools", "tools"),
        ("🔬 Research", "research"),
        ("💻 Technology", "technology"),
    ]
    fields = []
    for heading, key in definitions:
        items = data.get(key) or []
        if not items:
            continue
        lines = []
        for item in items[:MAX_ITEMS_PER_SECTION]:
            title = str(getattr(item, "cve_id", "") or getattr(item, "title", "") or getattr(item, "name", "Alert")).strip()
            title = title.replace("@everyone", "everyone").replace("@here", "here")[:220]
            url = (getattr(item, "apply_url", "") or getattr(item, "source_url", "") or "").strip()
            if key == "jobs":
                company = str(getattr(item, "company", "") or "Not publicly available").strip()[:100]
                location = str(getattr(item, "location", "") or "Not publicly available").strip()[:100]
                line = f"• **{title}**\n  {company} · {location}"
                if url:
                    line += f"\n  Apply: <{url}>"
            else:
                line = f"• **{title}**"
                if url:
                    line += f"\n  <{url}>"
            lines.append(line)
        fields.append({"name": heading, "value": "\n\n".join(lines)[:1000]})
    return fields
