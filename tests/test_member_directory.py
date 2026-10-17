import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import select, func
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from database.models import Base, CommunityEngagementMember, DiscordMemberSyncState
from services import member_directory as directory


def fake_member(user_id, name, *, bot=False, roles=(), joined_at=None):
    return SimpleNamespace(id=user_id, name=name, display_name=name, bot=bot,
                           roles=[SimpleNamespace(id=role) for role in roles], joined_at=joined_at)


def run_with_db(tmp_path, monkeypatch, exercise):
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str((tmp_path / "members.db").resolve())))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(directory, "SessionLocal", factory)

    async def run():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            await exercise(factory)
        finally:
            await engine.dispose()
    asyncio.run(run())


def test_full_sync_upserts_identity_renames_and_marks_departed_inactive(tmp_path, monkeypatch):
    async def exercise(factory):
        first = fake_member(100, "before", roles=(7,), joined_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
        departed = fake_member(200, "departed")
        guild = SimpleNamespace(id=900, name="Test guild", members=[first, departed])
        async def fetch_members(limit=None):
            for item in guild.members:
                yield item
        guild.fetch_members = fetch_members
        result = await directory.sync_guild(guild, members_intent=True)
        assert result["status"] == "ready" and result["full_sync"] is True
        renamed = fake_member(100, "after", roles=(8,))
        guild.members = [renamed]
        async def fetch_again(limit=None):
            for item in guild.members:
                yield item
        guild.fetch_members = fetch_again
        await directory.sync_guild(guild, members_intent=True)
        async with factory() as session:
            rows = (await session.scalars(select(CommunityEngagementMember).order_by(CommunityEngagementMember.user_id))).all()
            assert len(rows) == 2
            assert rows[0].username == "after" and rows[0].display_name == "after"
            assert rows[0].role_ids == ["8"]
            assert rows[1].is_active is False
            state = await session.get(DiscordMemberSyncState, "900")
            assert state.status == "ready" and state.human_members == 1
    run_with_db(tmp_path, monkeypatch, exercise)


def test_limited_cache_sync_does_not_deactivate_unseen_members(tmp_path, monkeypatch):
    async def exercise(factory):
        one, two = fake_member(10, "one"), fake_member(20, "two")
        guild = SimpleNamespace(id=901, name="Limited", members=[one, two])
        await directory.sync_guild(guild, members_intent=False)
        guild.members = [one]
        await directory.sync_guild(guild, members_intent=False)
        async with factory() as session:
            row = await session.scalar(select(CommunityEngagementMember).where(CommunityEngagementMember.user_id == "20"))
            state = await session.get(DiscordMemberSyncState, "901")
            assert row.is_active is True
            assert state.status == "limited"
    run_with_db(tmp_path, monkeypatch, exercise)


def test_bot_filter_and_activity_metadata_are_persisted_without_content(tmp_path, monkeypatch):
    async def exercise(factory):
        human, bot = fake_member(11, "human"), fake_member(12, "bot", bot=True)
        guild = SimpleNamespace(id=902, name="Bots", members=[human, bot])
        result = await directory.sync_guild(guild, members_intent=False, bot_user_id=99)
        assert result["humans"] == 1 and result["bots_excluded"] == 1
        await directory.record_interaction(902, human)
        async with factory() as session:
            row = await session.scalar(select(CommunityEngagementMember).where(CommunityEngagementMember.user_id == "11"))
            assert row.last_seen_at and row.last_interaction_at and row.last_activity_at
            assert not hasattr(row, "message_content")
            assert await session.scalar(select(func.count()).select_from(CommunityEngagementMember)) == 2
    run_with_db(tmp_path, monkeypatch, exercise)


def test_join_leave_upsert_preserves_optout_and_roles(tmp_path, monkeypatch):
    async def exercise(factory):
        user = fake_member(33, "member", roles=(4,))
        await directory.upsert_member(903, user, active=True)
        async with factory() as session:
            row = await session.scalar(select(CommunityEngagementMember))
            row.opted_out = True
            await session.commit()
        await directory.mark_left(903, user)
        async with factory() as session:
            row = await session.scalar(select(CommunityEngagementMember))
            assert row.is_active is False and row.opted_out is True and row.role_ids == ["4"]
    run_with_db(tmp_path, monkeypatch, exercise)
