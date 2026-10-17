"""Permitted public job board adapters. No authenticated or LinkedIn scraping."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import unescape
from time import monotonic
from typing import Any
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import feedparser
from bs4 import BeautifulSoup

from collectors.jobs.normalize import MISSING, normalize_job, present


@dataclass
class JobFetchResult:
    jobs: list[dict[str, Any]]
    parser: str
    http_status: int
    response_time_ms: int
    parse_errors: int = 0
    error: str = ""
    rate_limit: str = "UNKNOWN"


def _board_slug(source, host_suffix: str, api_prefix: str = "") -> str:
    parts = urlsplit(str(source.url))
    path = parts.path.strip("/")
    if api_prefix and path.startswith(api_prefix):
        path = path[len(api_prefix):]
    slug = path.split("/")[0]
    if not slug or slug.lower() in {"jobs", "careers", "postings", "job"}:
        raise ValueError("Public job board URL must include its board identifier")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", slug):
        raise ValueError("Job board identifier contains unsupported characters")
    return slug


def _company(source, fallback=""):
    return str(getattr(source, "company_name", "") or fallback or MISSING).strip()


def _http_error(response):
    status = int(getattr(response, "status_code", 0) or 0)
    return status if not 200 <= status < 300 else 0


def _rate_limit(response) -> str:
    if response is None:
        return "UNKNOWN"
    if getattr(response, "status_code", 0) == 429:
        retry = response.headers.get("retry-after", "")
        return f"LIMITED; retry after {retry}s" if retry else "LIMITED"
    remaining = response.headers.get("x-ratelimit-remaining")
    limit = response.headers.get("x-ratelimit-limit")
    if remaining is not None:
        return f"{remaining}/{limit}" if limit else f"{remaining} remaining"
    return "OK"


def _raw_lever(row, source):
    categories = row.get("categories") if isinstance(row.get("categories"), dict) else {}
    location = categories.get("location") or row.get("workplaceType") or MISSING
    work_mode = row.get("workplaceType") or MISSING
    return {"title": row.get("text"), "company": _company(source), "location": location,
            "experience": row.get("experienceLevel"), "employment_type": categories.get("commitment"),
            "work_mode": work_mode, "salary": row.get("salaryDescription"),
            "published_at": row.get("createdAt"), "description": row.get("descriptionPlain") or BeautifulSoup(str(row.get("description") or ""), "html.parser").get_text(" ", strip=True),
            "apply_url": row.get("applyUrl") or row.get("hostedUrl"), "posting_id": row.get("id"), "listing_status": "OPEN"}


def _raw_greenhouse(row, source):
    location = row.get("location") if isinstance(row.get("location"), dict) else {}
    content = BeautifulSoup(str(row.get("content") or ""), "html.parser").get_text(" ", strip=True)
    return {"title": row.get("title"), "company": _company(source), "location": location.get("name"),
            "published_at": row.get("updated_at") or row.get("created_at"), "description": content,
            "apply_url": row.get("absolute_url"), "posting_id": row.get("id"), "employment_type": row.get("employment_type"), "listing_status": "OPEN"}


def _raw_ashby(row, source):
    location = row.get("location") or row.get("locationName")
    return {"title": row.get("title"), "company": _company(source, row.get("companyName")),
            "location": location, "employment_type": row.get("employmentType"),
            "work_mode": row.get("workplaceType") or row.get("workplace_type"),
            "published_at": row.get("publishedAt") or row.get("updatedAt"),
            "description": BeautifulSoup(str(row.get("descriptionPlain") or row.get("descriptionHtml") or ""), "html.parser").get_text(" ", strip=True),
            "apply_url": row.get("applyUrl") or row.get("jobUrl"), "posting_id": row.get("id"), "listing_status": "OPEN"}


def _raw_remote_ok(row, source):
    """Map the public Remote OK JSON shape into the common job schema."""
    tags = row.get("tags") if isinstance(row.get("tags"), list) else []
    location = row.get("location") or "Remote"
    salary_min = row.get("salary_min")
    salary_max = row.get("salary_max")
    salary = row.get("salary")
    if not salary and (salary_min or salary_max):
        salary = " - ".join(str(x) for x in (salary_min, salary_max) if x not in (None, ""))
    # Remote OK's API includes both `url` and `apply_url`; preserve the direct
    # application link when supplied and retain the listing URL as provenance.
    apply_url = row.get("apply_url") or row.get("url") or row.get("original")
    return {
        "title": row.get("position") or row.get("title"),
        "company": row.get("company"),
        "location": location,
        "employment_type": row.get("type") or row.get("employment_type"),
        "work_mode": "Remote",
        "salary": salary,
        "skills": tags,
        "published_at": row.get("date") or row.get("epoch") or row.get("published_at"),
        "description": BeautifulSoup(str(row.get("description") or ""), "html.parser").get_text(" ", strip=True),
        "apply_url": apply_url,
        "source_url": row.get("url") or row.get("original") or apply_url,
        "posting_id": row.get("id") or row.get("slug"),
        "listing_status": str(row.get("status") or "OPEN").upper(),
    }


def _remote_ok_rows(payload):
    # The first object in the public API is legal/metadata, not a listing.
    rows = payload if isinstance(payload, list) else _generic_api_rows(payload)
    return [row for row in rows if isinstance(row, dict) and (row.get("position") or row.get("title"))]


def _generic_api_rows(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("jobs", "postings", "results", "items", "data"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return rows
        if isinstance(rows, dict):
            return list(rows.values())
    return []


def _raw_generic(row, source):
    location = row.get("location")
    if isinstance(location, dict):
        location = location.get("name") or location.get("location")
    return {"title": row.get("title") or row.get("name"), "company": _company(source, row.get("company")),
            "location": location, "experience": row.get("experience") or row.get("experienceLevel"),
            "employment_type": row.get("employment_type") or row.get("employmentType") or row.get("commitment"),
            "work_mode": row.get("work_mode") or row.get("workplaceType") or row.get("remoteType"),
            "salary": row.get("salary") or row.get("salaryDescription") or row.get("compensation"),
            "published_at": row.get("published_at") or row.get("updated_at") or row.get("created_at") or row.get("publishedAt"),
            "description": row.get("description") or row.get("content"),
            "apply_url": row.get("apply_url") or row.get("applyUrl") or row.get("absolute_url") or row.get("url") or row.get("link"),
            "posting_id": row.get("id") or row.get("posting_id"), "listing_status": str(row.get("listing_status") or row.get("status") or "UNKNOWN").upper()}


def _jsonld_jobs(soup):
    rows = []
    for script in soup.select('script[type="application/ld+json"]'):
        try:
            value = json.loads(script.string or script.get_text())
        except (TypeError, ValueError):
            continue
        objects = value if isinstance(value, list) else value.get("@graph", [value]) if isinstance(value, dict) else []
        for item in objects:
            if not isinstance(item, dict):
                continue
            kind = item.get("@type", "")
            if isinstance(kind, list):
                kind = " ".join(kind)
            if "JobPosting" not in str(kind):
                continue
            org = item.get("hiringOrganization") or {}
            location = item.get("jobLocation") or {}
            if isinstance(location, list):
                location = location[0] if location else {}
            address = location.get("address", {}) if isinstance(location, dict) else {}
            location_text = ", ".join(filter(None, [address.get("addressLocality"), address.get("addressRegion"), address.get("addressCountry")])) if isinstance(address, dict) else ""
            rows.append({"title": item.get("title"), "company": org.get("name") if isinstance(org, dict) else "",
                         "location": location_text, "employment_type": item.get("employmentType"),
                         "published_at": item.get("datePosted"), "valid_through": item.get("validThrough"), "description": BeautifulSoup(str(item.get("description") or ""), "html.parser").get_text(" ", strip=True),
                         "apply_url": item.get("url"), "posting_id": item.get("identifier", {}).get("value") if isinstance(item.get("identifier"), dict) else ""})
    return rows


async def _robots_allowed(collector, url: str) -> tuple[bool, str]:
    parts = urlsplit(url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    try:
        response = await collector.get(robots_url, max_bytes=128_000, allow_error_status=True,
                                       headers={"Accept": "text/plain"})
    except Exception:
        return False, "Robots policy could not be checked"
    if response.status_code == 404:
        return True, ""
    if not 200 <= response.status_code < 300:
        return False, f"Robots policy returned HTTP {response.status_code}"
    parser = RobotFileParser(robots_url)
    parser.parse(response.text.splitlines())
    allowed = parser.can_fetch("HexAlert/1.0 (+public security information aggregator)", url)
    return allowed, "" if allowed else "Robots policy disallows this public career page"


class JobSourceAdapter:
    async def fetch(self, collector, source) -> JobFetchResult:
        kind = str(getattr(source, "source_type", "rss_job_feed") or "rss_job_feed").lower()
        if kind == "job_feed":
            kind = "rss_job_feed"
        url = str(source.url)
        started = monotonic()
        headers = {"Accept": "application/json"} if kind in {"lever", "greenhouse", "ashby", "public_job_api", "remote_ok"} else {"Accept": "text/html,application/rss+xml,application/atom+xml,application/json"}
        response = None
        parser = kind.upper()
        try:
            if kind in {"reference", "linkedin_reference", "wellfound_reference", "naukri_reference"}:
                return JobFetchResult([], "REFERENCE_ONLY", 0, int((monotonic() - started) * 1000), 0,
                                      "Reference-only source; automated collection is disabled")
            if kind == "remote_ok":
                host = (urlsplit(url).hostname or "").lower()
                if host != "remoteok.com":
                    raise ValueError("Remote OK sources must use remoteok.com public feeds")
                # JSON is preferred.  If it is unavailable, the explicitly
                # supported RSS feed is used as a bounded fallback.
                response = await collector.get(url, max_bytes=getattr(source, "max_response_bytes", 5_000_000), headers=headers, allow_error_status=True)
                status = _http_error(response)
                if not status and "/api" in (urlsplit(url).path or ""):
                    try:
                        raw_rows = [_raw_remote_ok(row, source) for row in _remote_ok_rows(response.json())]
                        parser = "REMOTE_OK_JSON"
                    except (TypeError, ValueError, json.JSONDecodeError):
                        status = response.status_code or 502
                elif not status:
                    feed = feedparser.parse(response.content)
                    raw_rows = [{"title": entry.get("title"), "company": _company(source),
                                 "location": "Remote", "work_mode": "Remote", "description": entry.get("summary") or entry.get("description"),
                                 "published_at": entry.get("published") or entry.get("updated"), "apply_url": entry.get("link"),
                                 "posting_id": entry.get("id")} for entry in feed.entries]
                    parser = "REMOTE_OK_RSS"
                if status:
                    fallback = "https://remoteok.com/remote-jobs.rss"
                    response = await collector.get(fallback, max_bytes=getattr(source, "max_response_bytes", 2_000_000), headers={"Accept": "application/rss+xml"}, allow_error_status=True)
                    if (fallback_status := _http_error(response)):
                        return JobFetchResult([], "REMOTE_OK_JSON/RSS", fallback_status, int((monotonic() - started) * 1000), 1, f"HTTP {fallback_status}")
                    feed = feedparser.parse(response.content)
                    raw_rows = [{"title": entry.get("title"), "company": _company(source),
                                 "location": "Remote", "work_mode": "Remote", "description": entry.get("summary") or entry.get("description"),
                                 "published_at": entry.get("published") or entry.get("updated"), "apply_url": entry.get("link"),
                                 "posting_id": entry.get("id")} for entry in feed.entries]
                    parser = "REMOTE_OK_RSS"
            elif kind == "lever":
                host = (urlsplit(url).hostname or "").lower()
                if host not in {"jobs.lever.co", "api.lever.co"}:
                    raise ValueError("Lever sources must use the public jobs.lever.co board")
                slug = _board_slug(source, "lever.co", "/v0/postings/")
                endpoint = f"https://api.lever.co/v0/postings/{slug}?mode=json" if host == "jobs.lever.co" else url
                response = await collector.get(endpoint, max_bytes=5_000_000, headers=headers, allow_error_status=True)
                if status := _http_error(response):
                    return JobFetchResult([], parser, status, int((monotonic() - started) * 1000), 1, f"HTTP {status}")
                payload = response.json()
                rows = payload if isinstance(payload, list) else payload.get("data", []) if isinstance(payload, dict) else []
                raw_rows = [_raw_lever(row, source) for row in rows if isinstance(row, dict)]
            elif kind == "greenhouse":
                host = (urlsplit(url).hostname or "").lower()
                if host not in {"boards.greenhouse.io", "job-boards.greenhouse.io", "boards-api.greenhouse.io"}:
                    raise ValueError("Greenhouse sources must use the public Greenhouse job board")
                slug = _board_slug(source, "greenhouse.io", "/v1/boards/")
                endpoint = url if host == "boards-api.greenhouse.io" else f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true"
                response = await collector.get(endpoint, max_bytes=5_000_000, headers=headers, allow_error_status=True)
                if status := _http_error(response):
                    return JobFetchResult([], parser, status, int((monotonic() - started) * 1000), 1, f"HTTP {status}")
                payload = response.json()
                rows = payload.get("jobs", []) if isinstance(payload, dict) else []
                raw_rows = [_raw_greenhouse(row, source) for row in rows if isinstance(row, dict)]
            elif kind == "ashby":
                host = (urlsplit(url).hostname or "").lower()
                if host not in {"jobs.ashbyhq.com", "api.ashbyhq.com"}:
                    raise ValueError("Ashby sources must use the public Ashby job board")
                slug = _board_slug(source, "ashbyhq.com", "/posting-api/job-board/")
                endpoint = url if host == "api.ashbyhq.com" else f"https://api.ashbyhq.com/posting-api/job-board/{slug}"
                response = await collector.get(endpoint, max_bytes=5_000_000, headers=headers, allow_error_status=True)
                if status := _http_error(response):
                    return JobFetchResult([], parser, status, int((monotonic() - started) * 1000), 1, f"HTTP {status}")
                payload = response.json()
                rows = payload.get("jobs", []) if isinstance(payload, dict) else []
                raw_rows = [_raw_ashby(row, source) for row in rows if isinstance(row, dict)]
            elif kind == "public_job_api":
                response = await collector.get(url, max_bytes=getattr(source, "max_response_bytes", 2_000_000), headers=headers, allow_error_status=True)
                if status := _http_error(response):
                    return JobFetchResult([], parser, status, int((monotonic() - started) * 1000), 1, f"HTTP {status}")
                raw_rows = [_raw_generic(row, source) for row in _generic_api_rows(response.json()) if isinstance(row, dict)]
            elif kind == "rss_job_feed":
                response = await collector.get(url, max_bytes=getattr(source, "max_response_bytes", 2_000_000), headers=headers, allow_error_status=True)
                if status := _http_error(response):
                    return JobFetchResult([], parser, status, int((monotonic() - started) * 1000), 1, f"HTTP {status}")
                feed = feedparser.parse(response.content)
                raw_rows = [{"title": entry.get("title"), "company": _company(source), "description": entry.get("summary") or entry.get("description"),
                             "published_at": entry.get("published") or entry.get("updated"), "apply_url": entry.get("link"), "posting_id": entry.get("id")} for entry in feed.entries]
                parser = "RSS_JOB_FEED"
            elif kind in {"public_career_page", "company_careers"}:
                allowed, reason = await _robots_allowed(collector, url)
                if not allowed:
                    return JobFetchResult([], "PUBLIC_CAREER_PAGE / JSON-LD", 0,
                                          int((monotonic() - started) * 1000), 0, reason)
                response = await collector.get(url, max_bytes=getattr(source, "max_response_bytes", 2_000_000), headers=headers, allow_error_status=True)
                if status := _http_error(response):
                    return JobFetchResult([], parser, status, int((monotonic() - started) * 1000), 1, f"HTTP {status}")
                soup = BeautifulSoup(response.text, "html.parser")
                raw_rows = _jsonld_jobs(soup)
                if not raw_rows:
                    # Respect configured selectors; otherwise only use obvious job links.
                    config = getattr(source, "parser_config", {}) or {}
                    selector = config.get("job_link_selector", "a[href*='job'], a[href*='career'], a[href*='position']")
                    for link in soup.select(selector)[:100]:
                        href = link.get("href")
                        title = " ".join(link.get_text(" ", strip=True).split())
                        if href and title:
                            raw_rows.append({"title": title, "apply_url": __import__("urllib.parse", fromlist=["urljoin"]).urljoin(url, href), "description": ""})
                parser = "PUBLIC_CAREER_PAGE / JSON-LD"
            else:
                raise ValueError(f"Unsupported job source type: {kind}")
            normalized = []
            errors = 0
            for raw in raw_rows[:500]:
                try:
                    item = normalize_job(raw, source)
                    if item["title"] == MISSING or not item["apply_url"]:
                        errors += 1
                        continue
                    normalized.append(item)
                except (TypeError, ValueError, AttributeError):
                    errors += 1
            return JobFetchResult(normalized, parser, response.status_code, int((monotonic() - started) * 1000), errors, "", _rate_limit(response))
        except Exception as exc:
            return JobFetchResult([], parser, getattr(response, "status_code", 0) if response else getattr(exc, "status_code", 0),
                                  int((monotonic() - started) * 1000), 1, type(exc).__name__)
