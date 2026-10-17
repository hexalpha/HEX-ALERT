"""Deterministic normalization, freshness, and match scoring for public job data."""
from __future__ import annotations

import re
import email.utils
from datetime import datetime, timezone
from typing import Any

MISSING = "Not publicly available"
CYBER_TERMS = (
    "soc analyst", "soc l1", "security analyst", "cybersecurity analyst", "cyber security analyst", "cybersecurity", "cyber security",
    "information security", "vapt", "pentest", "penetration test", "penetration tester", "ethical hacker", "security consultant", "grc", "threat intelligence",
    "security intern", "cybersecurity intern", "application security", "cloud security",
    "incident response", "dfir", "vulnerability analyst", "security operations", "security engineer", "red team", "blue team", "network security", "siem",
)
ENTRY_TERMS = ("intern", "internship", "fresher", "graduate", "entry level", "entry-level", "junior", "0 years", "0-1 years", "0–1 years", "0-2 years", "0–2 years", "1 year", "1-2 years", "1–2 years")
SENIOR_TERMS = ("senior", "sr.", "lead", "principal", "manager", "director", "head of", "architect")


def present(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text if text else MISSING


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            # Lever exposes epoch milliseconds.
            return datetime.fromtimestamp(value / (1000 if value > 10_000_000_000 else 1), timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        try:
            parsed=email.utils.parsedate_to_datetime(str(value))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None


def is_date_only(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()))


def freshness(published_at: datetime | None, now: datetime | None = None, *, fresh_hours: int | None = None,
              acceptable_days: int | None = None) -> str:
    if published_at is None:
        return "UNKNOWN"
    now = now or datetime.now(timezone.utc)
    published_at = published_at.replace(tzinfo=timezone.utc) if published_at.tzinfo is None else published_at.astimezone(timezone.utc)
    if fresh_hours is None or acceptable_days is None:
        from config.settings import get_settings
        settings = get_settings()
        fresh_hours = fresh_hours if fresh_hours is not None else settings.job_fresh_hours
        acceptable_days = acceptable_days if acceptable_days is not None else settings.job_acceptable_days
    age_hours = max(0, (now - published_at).total_seconds() / 3600)
    return "FRESH" if age_hours <= fresh_hours else "ACCEPTABLE" if age_hours <= acceptable_days * 24 else "OLD"


def minimum_experience_years(value: Any) -> int | None:
    text = str(value or "").casefold()
    ranged = re.search(r"\b(\d+)\s*(?:-|–|to)\s*(\d+)\s*(?:years?|yrs?)\b", text)
    if ranged:
        return int(ranged.group(1))
    required = re.search(r"\b(?:(?:minimum|min\.?)\s*)?(\d+)\s*\+?\s*(?:years?|yrs?)\b", text)
    return int(required.group(1)) if required else None


def experience_range(value: Any) -> tuple[int | None, int | None]:
    text = str(value or "").casefold().replace("–", "-")
    ranged = re.search(r"\b(\d+)\s*(?:-|to)\s*(\d+)\s*(?:years?|yrs?)\b", text)
    if ranged:
        return int(ranged.group(1)), int(ranged.group(2))
    minimum = minimum_experience_years(text)
    return minimum, minimum


def classify_experience(title: str, experience: str, description: str = "") -> str:
    text = f"{title} {experience} {description}".casefold().replace("–", "-")
    if re.search(r"\bintern(?:ship)?\b", text):
        return "INTERNSHIP"
    if any(term in text for term in ("fresher", "graduate", "0 years", "0-1 year", "0-2 year")):
        return "FRESHER"
    if "entry level" in text or "entry-level" in text:
        return "ENTRY_LEVEL"
    if re.search(r"\bjunior\b", text):
        return "JUNIOR"
    minimum = minimum_experience_years(experience or description)
    if any(term in title.casefold() for term in SENIOR_TERMS) or (minimum is not None and minimum >= 5):
        return "SENIOR"
    if minimum is not None and minimum >= 2:
        return "MID"
    return "UNKNOWN"


def normalize_job(raw: dict[str, Any], source: Any, *, now: datetime | None = None) -> dict[str, Any]:
    title = present(raw.get("title"))
    description = present(raw.get("description"))
    location = present(raw.get("location"))
    company = present(getattr(source, "company_name", "") or raw.get("company"))
    published = parse_datetime(raw.get("published_at"))
    apply_url = str(raw.get("apply_url") or raw.get("url") or "").strip()
    company_text = " ".join(str(getattr(source, "name", "") or "").split())
    source_url = str(raw.get("source_url") or getattr(source, "url", "") or "").strip()
    experience_value = raw.get("experience")
    employment_value = raw.get("employment_type")
    searchable = f"{title} {description}"
    if not experience_value:
        experience_match = re.search(
            r"\b(?:minimum\s+|min\.?\s*)?\d+\s*(?:[-–]\s*\d+|to\s*\d+|\+)?\s*(?:years?|yrs?)\s+(?:(?:of|in)\s+(?:[A-Za-z0-9+/&.-]+\s+){0,4})?experience\b",
            searchable, re.IGNORECASE,
        )
        experience_value = experience_match.group(0).strip() if experience_match else None
    if not employment_value:
        if re.search(r"\bintern(?:ship)?\b", title, re.IGNORECASE):
            employment_value = "Internship"
    experience = present(experience_value)
    employment_type = present(employment_value)
    work_mode = present(raw.get("work_mode"))
    skills = raw.get("skills") if isinstance(raw.get("skills"), list) else []
    skills = [present(x) for x in skills if present(x) != MISSING][:30]
    status = str(raw.get("listing_status") or "UNKNOWN").strip().upper()
    if status in {"ACTIVE", "PUBLISHED", "OPEN", "LIVE"}:
        status = "OPEN"
    elif status in {"CLOSED", "EXPIRED", "INACTIVE", "ARCHIVED", "FILLED"}:
        status = "CLOSED"
    else:
        status = "UNKNOWN"
    valid_through = parse_datetime(raw.get("valid_through"))
    if valid_through and valid_through < (now or datetime.now(timezone.utc)):
        status = "CLOSED"
    result = {
        "title": title, "company": company, "location": location, "experience": experience,
        "employment_type": employment_type, "work_mode": work_mode,
        "salary": present(raw.get("salary")), "published_at": published,
        "published_at_date_only": is_date_only(raw.get("published_at")),
        "apply_url": apply_url, "source": company_text or source_url,
        "source_url": source_url, "description": description if description != MISSING else "",
        "skills": skills, "posting_id": str(raw.get("posting_id") or "")[:150],
        "freshness_status": freshness(published, now),
        "listing_status": status,
    }
    minimum_years, maximum_years = experience_range(experience)
    cyber_title = title.casefold()
    result.update({
        # Stable aliases make the normalized adapter contract useful to API
        # consumers without changing the existing PostgreSQL job columns.
        "external_id": result["posting_id"],
        "remote_status": work_mode,
        "experience_min": minimum_years,
        "experience_max": maximum_years,
        "salary_min": raw.get("salary_min"),
        "salary_max": raw.get("salary_max"),
        "currency": present(raw.get("currency")) if raw.get("currency") else "",
        "discovered_at": now or datetime.now(timezone.utc),
        "is_cybersecurity": any(term in cyber_title for term in CYBER_TERMS),
    })
    result["match_category"] = classify_experience(title, experience, description)
    result["is_entry_level"] = result["match_category"] in {"INTERNSHIP", "FRESHER", "ENTRY_LEVEL", "JUNIOR"}
    result["match_score"], result["score_breakdown"] = score_job(result)
    return result


def score_job(job: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Score only dimensions supported by present source fields; expose every weight."""
    title = str(job.get("title") or "").lower()
    description = str(job.get("description") or "").lower()
    location = str(job.get("location") or "").lower()
    experience = str(job.get("experience") or "").lower()
    work_mode = str(job.get("work_mode") or "").lower()
    skills = " ".join(str(x) for x in (job.get("skills") or [])).lower()
    fields: list[tuple[str, int, int, str]] = []
    role_hit = next((term for term in CYBER_TERMS if term in title), None)
    if title and title != MISSING:
        fields.append(("role", 30, 30 if role_hit else 0, role_hit or "No accepted cyber role title found"))
    experience_evidence = experience if experience != MISSING else title
    if experience_evidence and experience_evidence != MISSING:
        hit = next((term for term in ENTRY_TERMS if term in experience_evidence), None)
        fields.append(("experience", 25, 25 if hit else 5, hit or "Experience stated; entry-level fit not explicit"))
    if location and location != MISSING:
        from config.settings import get_settings
        priorities = get_settings().job_location_priority_list
        hit_index = next((index for index, term in enumerate(priorities) if term.casefold() in location), None)
        if hit_index is None:
            fields.append(("location", 15, 5, "Location stated outside preferred list"))
        else:
            points = max(8, 15 - min(hit_index, 7))
            fields.append(("location", 15, points, priorities[hit_index]))
    if work_mode and work_mode != MISSING:
        remote = any(x in work_mode for x in ("remote", "hybrid")) or "remote" in location
        fields.append(("work_mode", 10, 10 if remote else 6, "remote/hybrid" if remote else "onsite/other"))
    source_skills = skills or description
    if source_skills:
        hit_terms = [term for term in ("siem", "splunk", "sentinel", "edr", "incident response", "vapt", "penetration testing", "cloud security", "grc", "python", "mitre", "threat intelligence") if term in source_skills]
        fields.append(("skills", 10, min(10, 3 * len(hit_terms)), ", ".join(hit_terms) if hit_terms else "No listed security skills matched"))
    date = job.get("published_at")
    if date:
        freshness_value = job.get("freshness_status") or freshness(parse_datetime(date))
        points = {"FRESH": 10, "ACCEPTABLE": 7, "OLD": 0, "UNKNOWN": 0}.get(freshness_value, 0)
        fields.append(("freshness", 10, points, freshness_value))
    employment = str(job.get("employment_type") or "").casefold()
    if employment and employment != MISSING.casefold():
        fit = any(term in employment for term in ("intern", "full-time", "full time", "contract"))
        fields.append(("employment_type", 5, 5 if fit else 3, employment))
    maximum = sum(weight for _, weight, _, _ in fields)
    points = sum(value for _, _, value, _ in fields)
    score = round(points * 100 / maximum) if maximum else 0
    breakdown = {name: {"earned": earned, "available": weight, "evidence": evidence} for name, weight, earned, evidence in fields}
    senior = next((term for term in SENIOR_TERMS if term in title), None)
    if senior:
        score = max(0, score - 35)
        breakdown["seniority_penalty"] = {"points": -35, "evidence": senior}
    minimum_years = minimum_experience_years(experience)
    if minimum_years is not None and minimum_years >= 3:
        score = max(0, score - 30)
        breakdown["experience_penalty"] = {"points": -30, "evidence": experience}
    elif minimum_years == 2:
        score = max(0, score - 10)
        breakdown["experience_penalty"] = {"points": -10, "evidence": experience}
    if job.get("listing_status") == "CLOSED":
        score = 0
        breakdown["closed_listing_penalty"] = {"points": "score set to 0", "evidence": "CLOSED"}
    return max(0, min(100, score)), breakdown


def is_cyber_job(job: dict[str, Any]) -> bool:
    # Company boilerplate in job descriptions commonly mentions cybersecurity even
    # for sales, finance, and general operations roles. Require role-title evidence.
    title = str(job.get("title") or "").casefold()
    return any(term in title for term in CYBER_TERMS)
