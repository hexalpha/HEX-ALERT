from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from config.settings import get_settings
from database.models import Base


def test_alembic_empty_upgrade_existing_upgrade_and_safe_downgrade(monkeypatch):
    database_path = Path(__file__).parent / ".migration-test.db"
    database_url = "sqlite:///" + database_path.resolve().as_posix()
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    try:
        command.upgrade(config, "head")
        engine = create_engine(database_url)
        try:
            assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())
        finally:
            engine.dispose()

        command.downgrade(config, "0001_initial")
        command.upgrade(config, "head")
        engine = create_engine(database_url)
        try:
            assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())
        finally:
            engine.dispose()
    finally:
        get_settings.cache_clear()
        database_path.unlink(missing_ok=True)
