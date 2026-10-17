from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from collectors.jobs.adapters import JobSourceAdapter
from collectors.jobs.collector import JobCollector
from collectors.jobs.normalize import MISSING, freshness, is_cyber_job, minimum_experience_years, normalize_job, score_job
from database.models import Base, Job, Source
from database.repository import normalize_url
from services.job_rules import DEFAULT_FRESHER_CYBER_RULE, matches_fresher_cyber_rule


def test_normalized_job_missing_fields_are_unknown_not_fabricated():
    source = SimpleNamespace(name="Public board", company_name="Acme", url="https://jobs.example.org")
    item = normalize_job({"title": "SOC Analyst Intern", "apply_url": "https://jobs.example.org/1"}, source)
    assert item["company"] == "Acme"
    assert item["location"] == MISSING
    assert item["experience"] == MISSING
    assert item["salary"] == MISSING
    assert item["published_at"] is None
    assert item["freshness_status"] == "UNKNOWN"


def test_date_only_job_publication_is_preserved_for_local_display():
    source = SimpleNamespace(name="Public board", company_name="Acme", url="https://jobs.example.org")
    item = normalize_job({"title": "SOC Analyst Intern", "published_at": "2026-10-01"}, source)
    assert item["published_at"].isoformat() == "2026-10-01T00:00:00+00:00"
    assert item["published_at_date_only"] is True


def test_freshness_boundaries_and_tracking_url_dedupe():
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert freshness(now - timedelta(hours=24), now) == "FRESH"
    assert freshness(now - timedelta(days=7), now) == "ACCEPTABLE"
    assert freshness(now - timedelta(days=20), now) == "OLD"
    assert freshness(None, now) == "UNKNOWN"
    assert normalize_url("https://jobs.example.org/1?utm_source=mail&gh_src=abc") == "https://jobs.example.org/1"


def test_default_fresher_rule_requires_present_fresh_cyber_entry_evidence():
    item = {"title": "SOC Analyst Intern", "experience": MISSING, "published_at": datetime.now(timezone.utc),
            "match_score": 80, "location": "Remote", "freshness_status": "FRESH"}
    assert matches_fresher_cyber_rule(item, DEFAULT_FRESHER_CYBER_RULE)
    assert not matches_fresher_cyber_rule({**item, "title": "Senior SOC Analyst Intern"})
    assert not matches_fresher_cyber_rule({**item, "published_at": None})
    assert not matches_fresher_cyber_rule({**item, "experience": "Minimum 3 years of SOC experience"})


def test_job_normalization_maps_status_and_expiry_without_optional_key_errors():
    source = SimpleNamespace(name="Public careers", company_name="Example", url="https://careers.example.org")
    item = normalize_job({"title": "SOC Analyst", "listing_status": "active",
                          "valid_through": "2026-09-30T00:00:00Z"}, source,
                         now=datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert item["listing_status"] == "CLOSED"
    assert item["location"] == MISSING
    assert item["salary"] == MISSING
    assert item["freshness_status"] == "UNKNOWN"
    score, breakdown = score_job(item)
    assert 0 <= score <= 100
    assert "freshness" not in breakdown


def test_new_job_sources_default_to_disabled():
    from api.app import SourcePayload
    payload = SourcePayload(name="Example jobs", url="https://jobs.lever.co/example", category="jobs",
                            source_type="lever", company_name="Example")
    assert payload.enabled is False


def test_remote_ok_source_is_first_class_and_disabled_by_default():
    from api.app import SourcePayload
    payload = SourcePayload(name="Remote OK", url="https://remoteok.com/api", category="jobs", source_type="remote_ok")
    assert payload.enabled is False


def test_cyber_relevance_requires_job_title_evidence():
    assert is_cyber_job({"title": "Security Operations Analyst", "description": "Investigate alerts"})
    assert not is_cyber_job({"title": "Channel Account Manager II", "description": "Huntress provides cybersecurity tools"})


def test_explicit_experience_and_internship_are_extracted_without_guessing():
    source = SimpleNamespace(name="Board", company_name="Acme", url="https://jobs.example.org")
    item = normalize_job({"title": "Security Consultant Intern", "description": "Minimum 3 years of SOC experience"}, source)
    assert item["employment_type"] == "Internship"
    assert item["experience"].lower().startswith("minimum 3 years")
    assert minimum_experience_years(item["experience"]) == 3
    assert minimum_experience_years("2-6 years of experience") == 2
    missing = normalize_job({"title": "SOC Analyst", "description": "Monitor alerts"}, source)
    assert missing["experience"] == MISSING


class FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}

    def json(self):
        return [{"id": "p1", "text": "Security Intern", "categories": {"location": "Remote", "commitment": "Internship"},
                 "workplaceType": "remote", "createdAt": 1790812800000, "hostedUrl": "https://jobs.lever.co/acme/p1",
                 "descriptionPlain": "SOC SIEM monitoring"}]


class FakeCollector:
    async def get(self, url, **kwargs):
        self.url = url
        return FakeResponse()


class RemoteOkResponse(FakeResponse):
    def json(self):
        return [{"legal": "metadata"}, {"id": "rok-1", "position": "SOC Analyst Intern",
                 "company": "Remote Security", "location": "Worldwide", "tags": ["cybersecurity", "siem"],
                 "date": "2026-10-01T12:00:00Z", "url": "https://remoteok.com/remote-jobs/rok-1",
                 "apply_url": "https://remote-security.example/apply/rok-1", "description": "Monitor SOC alerts"}]


class RemoteOkCollector(FakeCollector):
    async def get(self, url, **kwargs):
        self.url = url
        return RemoteOkResponse()


class RemoteOkRssResponse(FakeResponse):
    headers = {"content-type": "application/rss+xml"}
    content = b"""<?xml version='1.0'?><rss><channel><item><title>SOC Analyst Intern</title><link>https://remoteok.com/remote-jobs/rok-rss</link><description>Remote cybersecurity internship</description><pubDate>Thu, 01 Oct 2026 12:00:00 GMT</pubDate><guid>rok-rss</guid></item></channel></rss>"""


class RemoteOkRssCollector(FakeCollector):
    async def get(self, url, **kwargs):
        self.url = url
        return RemoteOkRssResponse()


@pytest.mark.asyncio
async def test_remote_ok_json_adapter_filters_metadata_and_normalizes_public_fields():
    source = SimpleNamespace(source_type="remote_ok", url="https://remoteok.com/api", company_name="",
                             name="Remote OK", max_response_bytes=5_000_000)
    result = await JobSourceAdapter().fetch(RemoteOkCollector(), source)
    assert result.http_status == 200
    assert result.parser == "REMOTE_OK_JSON"
    assert len(result.jobs) == 1
    assert result.jobs[0]["title"] == "SOC Analyst Intern"
    assert result.jobs[0]["posting_id"] == "rok-1"
    assert result.jobs[0]["apply_url"].endswith("rok-1")
    assert is_cyber_job(result.jobs[0])


@pytest.mark.asyncio
async def test_remote_ok_rss_fallback_normalizes_public_feed():
    source = SimpleNamespace(source_type="remote_ok", url="https://remoteok.com/remote-jobs.rss", company_name="",
                             name="Remote OK RSS", max_response_bytes=2_000_000)
    result = await JobSourceAdapter().fetch(RemoteOkRssCollector(), source)
    assert result.parser == "REMOTE_OK_RSS"
    assert result.jobs[0]["title"] == "SOC Analyst Intern"


@pytest.mark.asyncio
async def test_reference_sources_never_fetch_automatically():
    source = SimpleNamespace(source_type="linkedin_reference", url="https://www.linkedin.com/jobs/view/1",
                             company_name="", name="LinkedIn reference", max_response_bytes=2_000_000)
    result = await JobSourceAdapter().fetch(FakeCollector(), source)
    assert result.parser == "REFERENCE_ONLY"
    assert result.jobs == []
    assert "Reference-only" in result.error


@pytest.mark.asyncio
async def test_lever_adapter_normalizes_public_postings():
    source = SimpleNamespace(source_type="lever", url="https://jobs.lever.co/acme", company_name="Acme Security",
                             name="Acme Lever", max_response_bytes=2_000_000)
    result = await JobSourceAdapter().fetch(FakeCollector(), source)
    assert result.http_status == 200
    assert result.parser == "LEVER"
    assert result.jobs[0]["title"] == "Security Intern"
    assert result.jobs[0]["company"] == "Acme Security"
    assert result.jobs[0]["posting_id"] == "p1"
    assert result.jobs[0]["apply_url"].endswith("p1")


@pytest.mark.asyncio
async def test_greenhouse_adapter_normalizes_public_board_api(monkeypatch):
    class GreenhouseResponse(FakeResponse):
        def json(self):
            return {"jobs": [{"id": 44, "title": "Cybersecurity Analyst", "location": {"name": "India"},
                              "updated_at": "2026-09-30T12:00:00Z", "absolute_url": "https://boards.greenhouse.io/acme/jobs/44",
                              "content": "SOC SIEM"}]}
    class GHCollector(FakeCollector):
        async def get(self, url, **kwargs):
            self.url = url
            return GreenhouseResponse()
    source = SimpleNamespace(source_type="greenhouse", url="https://boards.greenhouse.io/acme", company_name="Acme",
                             name="Acme GH", max_response_bytes=2_000_000)
    result = await JobSourceAdapter().fetch(GHCollector(), source)
    assert result.http_status == 200
    assert result.jobs[0]["posting_id"] == "44"
    assert result.jobs[0]["location"] == "India"
    assert result.jobs[0]["listing_status"] == "OPEN"


@pytest.mark.asyncio
async def test_job_source_preview_reports_http_status_without_raising():
    class ForbiddenResponse(FakeResponse):
        status_code = 403
    class ForbiddenCollector(FakeCollector):
        async def get(self, url, **kwargs):
            if url.endswith("/robots.txt"):
                response = ForbiddenResponse()
                response.status_code = 404
                return response
            return ForbiddenResponse()
    source = SimpleNamespace(source_type="public_career_page", url="https://careers.example.org/jobs",
                             name="Blocked board", company_name="Example", parser_config={})
    result = await JobSourceAdapter().fetch(ForbiddenCollector(), source)
    assert result.http_status == 403
    assert result.error == "HTTP 403"
    assert result.jobs == []


@pytest.mark.asyncio
async def test_company_career_jsonld_respects_robots_and_normalizes():
    class RobotsResponse(FakeResponse):
        status_code = 404

    class CareerResponse(FakeResponse):
        headers = {"content-type": "text/html"}
        text = '''<script type="application/ld+json">{"@type":"JobPosting","title":"SOC Analyst",
        "hiringOrganization":{"name":"Example Security"},"datePosted":"2026-10-02",
        "jobLocation":{"address":{"addressLocality":"Jaipur","addressCountry":"India"}},
        "employmentType":"FULL_TIME","description":"SIEM incident response",
        "url":"https://careers.example.org/jobs/soc-1"}</script>'''

    class CareerCollector(FakeCollector):
        async def get(self, url, **kwargs):
            return RobotsResponse() if url.endswith("/robots.txt") else CareerResponse()

    source = SimpleNamespace(source_type="company_careers", url="https://careers.example.org/jobs",
                             name="Example careers", company_name="Example Security", parser_config={})
    result = await JobSourceAdapter().fetch(CareerCollector(), source)
    assert result.parser == "PUBLIC_CAREER_PAGE / JSON-LD"
    assert result.jobs[0]["title"] == "SOC Analyst"
    assert result.jobs[0]["location"] == "Jaipur, India"


@pytest.mark.asyncio
async def test_job_collector_baselines_and_never_runs_disabled_sources(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        source = Source(name="Public test board", url="https://jobs.example.org", company_name="Example Security",
                        category="jobs", source_type="lever", enabled=True)
        disabled = Source(name="Disabled board", url="https://disabled.example.org", company_name="No Run",
                          category="jobs", source_type="lever", enabled=False)
        session.add_all([source, disabled]); await session.commit()
        source_id, disabled_id = source.id, disabled.id
    job_data = {"title": "SOC Analyst Intern", "company": "Example Security", "location": "Remote",
                "experience": MISSING, "employment_type": "Internship", "work_mode": "Remote", "salary": MISSING,
                "skills": ["SIEM"], "description": "", "source": "Public test board",
                "source_url": "https://jobs.example.org/1?utm_source=mail", "apply_url": "https://jobs.example.org/1?utm_source=mail",
                "published_at": datetime.now(timezone.utc), "posting_id": "one", "freshness_status": "FRESH",
                "listing_status": "OPEN", "match_score": 80, "score_breakdown": {}, "match_category": "Internship"}
    from collectors.jobs.adapters import JobFetchResult
    collector = JobCollector()
    collector.adapter.fetch = AsyncMock(return_value=JobFetchResult([job_data], "LEVER", 200, 5))
    try:
        async with sessions() as session:
            source = await session.get(Source, source_id)
            disabled = await session.get(Source, disabled_id)
            assert await collector.collect(session, [source, disabled]) == []
            assert source.baseline_complete is True
            assert source.baseline_items == 1
            assert source.new_items == 0
            assert source.last_new_job is None
            assert disabled.last_fetch is None
            baseline_job = await session.scalar(select(Job).where(Job.source_id == source_id))
            assert baseline_job and not baseline_job.alert_eligible
        async with sessions() as session:
            source = await session.get(Source, source_id)
            updated = {**job_data, "title": "SOC Analyst Intern", "apply_url": "https://jobs.example.org/1?utm_campaign=duplicate"}
            new = {**job_data, "title": "Cybersecurity Analyst Intern", "apply_url": "https://jobs.example.org/2", "source_url": "https://jobs.example.org/2", "posting_id": "two"}
            collector.adapter.fetch = AsyncMock(return_value=JobFetchResult([updated, new], "LEVER", 200, 8))
            inserted = await collector.collect(session, [source])
            assert source.new_items == 1
            assert source.duplicate_items == 1
            assert len(inserted) == 1
            assert inserted[0].title == "Cybersecurity Analyst Intern"
            jobs = (await session.scalars(select(Job).where(Job.source_id == source_id))).all()
            assert len(jobs) == 2
            assert not next(job for job in jobs if job.title == 'SOC Analyst Intern').alert_eligible
            assert next(job for job in jobs if job.title == 'Cybersecurity Analyst Intern').alert_eligible
    finally:
        await collector.close(); await engine.dispose()
