from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from collectors.jobs.discovery import ats_type, discover_ats_links
from collectors.jobs.normalize import classify_experience, normalize_job, score_job
from collectors.jobs.source_catalog import source_catalog
from database.models import Base, Job
from database.repository import normalize_url, save_job


def test_experience_classifier_covers_all_requested_levels():
    assert classify_experience("Cybersecurity Intern", "") == "INTERNSHIP"
    assert classify_experience("SOC Analyst", "0-1 years") == "FRESHER"
    assert classify_experience("Entry Level Security Analyst", "") == "ENTRY_LEVEL"
    assert classify_experience("Junior Security Engineer", "") == "JUNIOR"
    assert classify_experience("Security Engineer", "3+ years") == "MID"
    assert classify_experience("Principal Security Engineer", "8 years") == "SENIOR"
    assert classify_experience("SOC Analyst", "") == "UNKNOWN"


def test_match_score_explains_location_employment_and_experience_penalty():
    source = SimpleNamespace(name="Board", company_name="Acme", url="https://jobs.example.org")
    item = normalize_job({"title": "SOC Analyst", "location": "Remote India", "experience": "2 years",
                          "employment_type": "Full-time", "published_at": datetime.now(timezone.utc),
                          "apply_url": "https://jobs.example.org/1"}, source)
    score, reasons = score_job(item)
    assert 0 <= score <= 100
    assert reasons["location"]["earned"] > 0
    assert reasons["employment_type"]["earned"] > 0
    assert reasons["experience_penalty"]["points"] == -10


def test_source_matrix_has_explicit_capabilities_and_reference_modes():
    rows = {row["source"]: row for row in source_catalog()}
    assert rows["Remote OK"]["automation_available"] == "YES"
    assert rows["Remote OK"]["api_key_required"] is False
    assert rows["LinkedIn"]["recommended_mode"] == "REFERENCE"
    assert rows["Wellfound"]["official_api"] == "NO_PUBLIC_JOBS_API"
    assert rows["Naukri"]["recommended_mode"] == "REFERENCE"


def test_source_api_redacts_credential_reference_and_value(monkeypatch):
    from api.app import _safe_source
    from database.models import Source
    monkeypatch.setenv("UNIT_TEST_SOURCE_KEY", "never-return-this-value")
    source = Source(name="Credential source", url="https://jobs.example.org", category="jobs",
                    source_type="public_job_api", auth_mode="api_key", auth_env_var="UNIT_TEST_SOURCE_KEY")
    data = _safe_source(source)
    assert data["credential_status"] == "Configured"
    assert "auth_env_var" not in data
    assert "never-return-this-value" not in str(data)


def test_ats_discovery_only_accepts_supported_public_board_links():
    html = '<a href="https://boards.greenhouse.io/acme/jobs/1">Jobs</a><a href="/login">Login</a>'
    found = discover_ats_links(html, "https://acme.example/careers")
    assert found == [{"source_type": "greenhouse", "url": "https://boards.greenhouse.io/acme",
                      "evidence": "Linked from the supplied public company page"}]
    assert ats_type("https://jobs.lever.co/acme") == "lever"
    assert ats_type("https://example.org/jobs") is None


@pytest.mark.asyncio
async def test_cross_source_dedupe_preserves_provenance_and_prefers_ats_apply_url():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    base = {"title": "SOC Analyst", "company": "Acme", "location": "Remote", "experience": "Entry level",
            "employment_type": "Full-time", "work_mode": "Remote", "remote_status": "Remote", "salary": "Unknown",
            "skills": ["SIEM"], "description": "", "published_at": datetime.now(timezone.utc),
            "freshness_status": "FRESH", "listing_status": "OPEN", "match_score": 80, "score_breakdown": {},
            "match_category": "ENTRY_LEVEL", "is_cybersecurity": True, "is_entry_level": True,
            "external_id": "remote-1", "posting_id": "remote-1", "alert_eligible": False}
    try:
        async with sessions() as session:
            first, created = await save_job(session, {**base, "source": "Remote OK", "source_type": "remote_ok",
                "source_url": "https://remoteok.com/jobs/1?utm_source=x", "apply_url": "https://remoteok.com/jobs/1"})
            assert created
            second, created = await save_job(session, {**base, "source": "Acme Greenhouse", "source_type": "greenhouse",
                "external_id": "gh-9", "posting_id": "gh-9", "source_url": "https://boards.greenhouse.io/acme/jobs/9",
                "apply_url": "https://boards.greenhouse.io/acme/jobs/9"})
            await session.commit()
            assert not created and second.id == first.id
            row = await session.scalar(select(Job))
            assert row.apply_url == normalize_url("https://boards.greenhouse.io/acme/jobs/9")
            assert {item["source_type"] for item in row.source_provenance} == {"remote_ok", "greenhouse"}
    finally:
        await engine.dispose()
