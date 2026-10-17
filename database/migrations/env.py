from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool
from config.settings import get_settings
from database.models import Base

config = context.config
if config.config_file_name: fileConfig(config.config_file_name)
target_metadata = Base.metadata


def url(): return get_settings().database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://")


def run_migrations_offline():
    context.configure(url=url(), target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"}, compare_type=True)
    with context.begin_transaction(): context.run_migrations()


def run_migrations_online():
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction(): context.run_migrations()
    connectable.dispose()


if context.is_offline_mode(): run_migrations_offline()
else: run_migrations_online()
