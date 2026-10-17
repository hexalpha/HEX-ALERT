"""Collect configured, enabled public job sources without turning failures into cycle failures."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from collectors.base import Collector
from collectors.jobs.adapters import JobSourceAdapter
from collectors.jobs.normalize import CYBER_TERMS, ENTRY_TERMS, is_cyber_job
from database.models import AutomationRule, Job, Source, utcnow
from database.repository import save_job
from services.job_rules import DEFAULT_FRESHER_CYBER_RULE, matches_fresher_cyber_rule

log = logging.getLogger("hexalert.jobs")

SOURCE_CIRCUIT_BREAKER_THRESHOLD = 5
SOURCE_RETRY_BASE_MINUTES = 5
SOURCE_RETRY_MAX_MINUTES = 24 * 60


def source_retry_delay(failure_count: int) -> timedelta:
    """Return bounded exponential backoff for a repeatedly failing source."""
    failures = max(0, int(failure_count or 0))
    if failures < SOURCE_CIRCUIT_BREAKER_THRESHOLD:
        return timedelta(0)
    exponent = min(failures - SOURCE_CIRCUIT_BREAKER_THRESHOLD, 16)
    minutes = min(SOURCE_RETRY_MAX_MINUTES, SOURCE_RETRY_BASE_MINUTES * (2 ** exponent))
    return timedelta(minutes=minutes)


def source_retry_due(failure_count: int, last_failure: datetime | None, now: datetime) -> bool:
    """Use persisted failure metadata to pause a source until its retry window."""
    delay = source_retry_delay(failure_count)
    if delay == timedelta(0) or last_failure is None:
        return True
    if last_failure.tzinfo is None:
        last_failure = last_failure.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now >= last_failure + delay

# Public compatibility patterns used by existing collector health checks.
ROLE = re.compile("|".join(re.escape(term) for term in CYBER_TERMS), re.IGNORECASE)
FRESHER = re.compile("|".join(re.escape(term) for term in ENTRY_TERMS), re.IGNORECASE)


class JobCollector(Collector):
    def __init__(self):
        super().__init__()
        self.adapter = JobSourceAdapter()

    async def collect(self, session, sources: list[Source]):
        new_after_baseline = []
        now = utcnow()
        filter_rule = await session.scalar(select(AutomationRule).where(
            AutomationRule.enabled.is_(True), AutomationRule.rule_type == "filter",
            AutomationRule.category.in_(["jobs", "job"])).order_by(AutomationRule.id.asc()))
        job_filter = (filter_rule.conditions if filter_rule and filter_rule.conditions else DEFAULT_FRESHER_CYBER_RULE)
        for source in sources:
            # Defense in depth: disabled sources never run, even if a caller passed one.
            if not source.enabled or source.category != "jobs":
                continue
            if not source_retry_due(source.failure_count, source.last_failure, now):
                log.info("[JOB] Source circuit open name=%s failures=%s retry_delay_minutes=%s",
                         source.name, source.failure_count,
                         int(source_retry_delay(source.failure_count).total_seconds() // 60))
                continue
            result = await self.adapter.fetch(self, source)
            source.last_fetch = now
            source.response_time_ms = result.response_time_ms
            source.http_status = result.http_status or None
            source.rate_limit_status = result.rate_limit
            source.items_found = len(result.jobs)
            source.parser_status = "FAILED" if result.error else "OK" if not result.parse_errors else "PARTIAL"
            source.last_error = result.error or (f"{result.parse_errors} job record(s) could not be normalized" if result.parse_errors else "")
            if result.error:
                source.failure_count = (source.failure_count or 0) + 1
                source.healthy = source.failure_count < 5
                source.last_failure = now
                log.warning("[JOB] Source fetch failed name=%s reason=%s", source.name, result.error)
                continue

            baseline = not bool(source.baseline_complete)
            if source.baseline_complete and not source.baseline_items:
                # Backfill previously completed baselines without treating their records as new.
                source.baseline_items = source.items_found or len(result.jobs)
            relevant = [job for job in result.jobs if is_cyber_job(job)]
            source.relevant_items = len(relevant)
            source.entry_level_items = sum(bool(job.get("is_entry_level")) for job in relevant)
            source.fresh_items = sum(job.get("freshness_status") == "FRESH" for job in relevant)
            source.closed_items = sum(job["listing_status"] == "CLOSED" for job in relevant)
            source.failure_count = 0
            source.healthy = True
            source.last_success = now
            source.last_error = "" if not result.parse_errors else source.last_error
            created = duplicates = 0

            for item in relevant:
                values = {
                    "title": item["title"][:300], "company": item["company"][:200],
                    "location": item["location"][:200], "experience": item["experience"][:200],
                    "employment_type": item["employment_type"][:100], "work_mode": item["work_mode"][:100],
                    "remote_status": item.get("remote_status", item["work_mode"])[:100], "salary": item["salary"][:200],
                    "salary_min": item.get("salary_min"), "salary_max": item.get("salary_max"), "currency": item.get("currency", "")[:12],
                    "experience_min": item.get("experience_min"), "experience_max": item.get("experience_max"), "skills": item["skills"],
                    "description": item["description"][:12000], "source": source.name[:100],
                    "source_type": source.source_type, "source_url": item["source_url"], "apply_url": item["apply_url"],
                    "published_at": item["published_at"], "match_category": item["match_category"][:50],
                    "freshness_status": item["freshness_status"], "listing_status": item["listing_status"],
                    "match_score": item["match_score"], "score_breakdown": item["score_breakdown"],
                    "source_id": source.id, "posting_id": item["posting_id"], "external_id": item.get("external_id", item["posting_id"]),
                    "discovered_at": item.get("discovered_at", now), "is_cybersecurity": item.get("is_cybersecurity", True),
                    "is_entry_level": item.get("is_entry_level", item.get("match_category") in {"Internship", "Fresher", "INTERNSHIP", "FRESHER", "ENTRY_LEVEL", "JUNIOR"}),
                    "alert_eligible": (not baseline and item["listing_status"] != "CLOSED"
                                       and matches_fresher_cyber_rule(item, job_filter)),
                }
                job, is_new = await save_job(session, values)
                if is_new:
                    created += 1
                    if not baseline and values["alert_eligible"]:
                        new_after_baseline.append(job)
                else:
                    duplicates += 1
                    # A closed listing should no longer wait in the alert backlog.
                    if item["listing_status"] == "CLOSED":
                        job.alert_eligible = False
                    # Re-observing a baseline vacancy cannot promote it to
                    # a new production alert. Only new rows may be eligible.

            source.new_items = 0 if baseline else created
            if baseline:
                source.baseline_items = len(result.jobs)
            source.duplicate_items = duplicates
            if created and not baseline:
                source.last_new_job = now
            if baseline:
                source.baseline_complete = True
                log.info("[JOB] Baseline stored source=%s listings=%d relevant=%d", source.name, len(result.jobs), len(relevant))
            else:
                log.info("[JOB] Source fetch source=%s listings=%d relevant=%d new=%d duplicates=%d", source.name, len(result.jobs), len(relevant), created, duplicates)

        await session.commit()
        return new_after_baseline

    async def pending_alerts(self, session, limit: int = 5):
        return list((await session.scalars(select(Job).where(
            Job.alert_eligible.is_(True), Job.posted_to_discord.is_(False),
            Job.listing_status != "CLOSED", Job.freshness_status != "OLD", Job.suppressed.is_(False)
        ).order_by(Job.match_score.desc(), Job.published_at.desc().nullslast(), Job.id.asc()).limit(max(1, min(5, limit))))).all())
