from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from database.models import Base, Job, NewsArticle, SecurityTool, utcnow
from services.daily_digest import _dedupe, digest_fields, recent_digest_sections


@pytest.mark.asyncio
async def test_digest_separates_recent_research_and_technology_from_tools():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = utcnow()
    async with factory() as session:
        session.add_all([
            NewsArticle(title="Recent research", category="Security Research", source_url="https://example.test/research",
                        content_hash="research-recent", created_at=now - timedelta(hours=2)),
            NewsArticle(title="Old research", category="Security Research", source_url="https://example.test/old-research",
                        content_hash="research-old", created_at=now - timedelta(hours=30)),
            NewsArticle(title="Recent news", category="Cybersecurity News", source_url="https://example.test/news",
                        content_hash="news-recent", created_at=now - timedelta(hours=1)),
            SecurityTool(name="Recent technology", category="Cybersecurity Technology", source_url="https://example.test/tech",
                         content_hash="tech-recent", created_at=now - timedelta(hours=3)),
            SecurityTool(name="Recent tool", category="Security Tool", source_url="https://example.test/tool",
                         content_hash="tool-recent", created_at=now - timedelta(hours=4)),
        ])
        await session.commit()
        result = await recent_digest_sections(session, now=now)
    assert [item.title for item in result["research"]] == ["Recent research"]
    assert [item.title for item in result["news"]] == ["Recent news"]
    assert [item.name for item in result["technology"]] == ["Recent technology"]
    assert [item.name for item in result["tools"]] == ["Recent tool"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_digest_deduplicates_jobs_before_limit_and_uses_exact_application_url():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = utcnow()
    board = "https://jobs.lever.co/anomali"
    posting = "https://jobs.lever.co/anomali/abc-123"
    async with factory() as session:
        session.add_all([
            Job(title="Senior Technical Account Manager - SIEM/Security Analytics (US Remote)",
                company="Anomali", location="US Remote", source="Anomali", source_url=board,
                apply_url=posting, external_id="", source_provenance=[{"source_type":"lever","rank":3}],
                fingerprint="anomali-1", alert_eligible=True, is_cybersecurity=True,
                listing_status="OPEN", freshness_status="FRESH", created_at=now),
            Job(title="  SENIOR  Technical Account Manager - SIEM/Security Analytics (US Remote) ",
                company="ANOMALI", location="US   Remote", source="Anomali mirror", source_url=board,
                apply_url=posting + "?utm_source=mirror#apply", external_id="", source_provenance=[{"source_type":"remote_ok","rank":2}],
                fingerprint="anomali-2", alert_eligible=True, is_cybersecurity=True,
                listing_status="OPEN", freshness_status="FRESH", created_at=now - timedelta(minutes=1)),
            Job(title="Security Engineer", company="Anomali", location="US Remote", source="Anomali",
                source_url=board, apply_url="https://jobs.lever.co/anomali/def-456", external_id="",
                source_provenance=[{"source_type":"lever","rank":3}], fingerprint="anomali-3",
                alert_eligible=True, is_cybersecurity=True, listing_status="OPEN", freshness_status="FRESH",
                created_at=now - timedelta(minutes=2)),
        ])
        await session.commit()
        result = await recent_digest_sections(session, now=now)
    assert len(result["jobs"]) == 2
    assert result["jobs"][0].apply_url == posting
    jobs_field = next(field for field in digest_fields(result) if field["name"] == "💼 Jobs")
    assert "Senior Technical Account Manager" in jobs_field["value"]
    assert "Apply: <https://jobs.lever.co/anomali/abc-123>" in jobs_field["value"]
    assert "jobs.lever.co/anomali>" not in jobs_field["value"]
    assert jobs_field["value"].count("Senior Technical Account Manager") == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_digest_excludes_baseline_and_old_jobs():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = utcnow()
    common = dict(company='Example Security', location='Remote',
                  is_cybersecurity=True, listing_status='OPEN',
                  created_at=now - timedelta(hours=1))
    async with factory() as session:
        session.add_all([
            Job(title='Imported baseline', source_url='https://example.test/baseline',
                fingerprint='baseline', alert_eligible=False, freshness_status='FRESH', **common),
            Job(title='Old listing', source_url='https://example.test/old',
                fingerprint='old', alert_eligible=True, freshness_status='OLD', **common),
            Job(title='Fresh alert', source_url='https://example.test/fresh',
                fingerprint='fresh', alert_eligible=True, freshness_status='FRESH', **common),
        ])
        await session.commit()
        result = await recent_digest_sections(session, now=now)
    assert [item.title for item in result['jobs']] == ['Fresh alert']
    await engine.dispose()


@pytest.mark.asyncio
async def test_digest_deduplicates_news_by_normalized_title_and_omits_empty_format_sections():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = utcnow()
    async with factory() as session:
        session.add_all([
            NewsArticle(title="New Ransomware Campaign", category="Cyber News", source_url="https://one.test/item",
                        content_hash="news-one", created_at=now),
            NewsArticle(title="  NEW   RANSOMWARE CAMPAIGN  ", category="Cyber News", source_url="https://two.test/item",
                        content_hash="news-two", created_at=now - timedelta(minutes=1)),
        ])
        await session.commit()
        result = await recent_digest_sections(session, now=now)
    assert len(result["news"]) == 1
    fields = digest_fields(result)
    assert [field["name"] for field in fields] == ["📰 Cyber News"]
    assert "No new verified updates" not in fields[0]["value"]
    await engine.dispose()


def test_digest_item_identity_rules_cover_pulse_categories():
    assert len(_dedupe([SimpleNamespace(cve_id="CVE-2026-1234"),
                        SimpleNamespace(cve_id="cve-2026-1234")], "cve")) == 1
    assert len(_dedupe([SimpleNamespace(title="Threat advisory", source_url="https://intel.test/a?utm_source=x"),
                        SimpleNamespace(title="different headline", source_url="https://INTEL.test/a/#section")], "threat")) == 1
    assert len(_dedupe([SimpleNamespace(name="Scanner", source_url="https://github.test/a", github_url="https://github.com/org/tool?utm_source=x"),
                        SimpleNamespace(name="Scanner clone", source_url="https://github.test/b", github_url="https://github.com/org/tool/#readme")], "tool")) == 1
    assert len(_dedupe([SimpleNamespace(title="Research paper", source_url="https://paper.test/doi/1"),
                        SimpleNamespace(title="Mirrored paper", source_url="https://PAPER.test/doi/1#abstract")], "research")) == 1
    assert len(_dedupe([SimpleNamespace(title="Zero Trust Platform", source_url="https://vendor.test/1"),
                        SimpleNamespace(title=" zero   trust platform ", source_url="https://vendor.test/2")], "technology")) == 1
