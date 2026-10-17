from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from config.settings import get_settings
from database.models import Base

settings = get_settings()
engine_options = {"pool_pre_ping": True}
# SQLite is used by the isolated test suite and chooses StaticPool/NullPool on its
# own. QueuePool sizing is valid for the production PostgreSQL driver only.
if not settings.database_url.startswith("sqlite"):
    engine_options.update(pool_size=5, max_overflow=10)
engine = create_async_engine(settings.database_url, **engine_options)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await engine.dispose()
