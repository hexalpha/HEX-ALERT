import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from database.models import Base, Job
from database.repository import save_job


@pytest.mark.asyncio
async def test_database_schema_and_job_deduplication():
    assert {"crawler_jobs","crawler_runs","crawler_pages","alerts","admin_users","automation_rules"} <= set(Base.metadata.tables)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    values = {"title": "SOC Analyst", "company": "Example", "location": "Remote", "source_url": "https://example.org/job/1", "source": "Test"}
    async with sessions() as session:
        first, fresh1 = await save_job(session, values)
        await session.commit()
        second, fresh2 = await save_job(session, values)
        assert fresh1 is True and fresh2 is False and first.id == second.id
    await engine.dispose()


@pytest.mark.asyncio
async def test_job_identity_uses_canonical_posting_url_when_title_changes():
    engine=create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
    sessions=async_sessionmaker(engine,expire_on_commit=False)
    url="https://jobs.lever.co/anomali/abc-123"
    async with sessions() as session:
        first,created=await save_job(session,{"title":"Senior Account Manager","company":"Anomali","location":"US Remote",
            "source":"Anomali","source_type":"lever","source_url":"https://jobs.lever.co/anomali",
            "apply_url":url,"external_id":"","posting_id":""})
        await session.flush()
        duplicate,created_again=await save_job(session,{"title":" Senior   ACCOUNT Manager ","company":"ANOMALI","location":"US Remote",
            "source":"Anomali feed mirror","source_type":"remote_ok","source_url":"https://jobs.lever.co/anomali",
            "apply_url":url+"?utm_source=mirror#apply","external_id":"","posting_id":""})
        await session.commit()
        assert created is True and created_again is False and first.id==duplicate.id
        assert duplicate.apply_url==url
    await engine.dispose()
