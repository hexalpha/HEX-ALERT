"""Add source controls, crawler, dashboard and automation tables."""
from alembic import op
from sqlalchemy import Column, DateTime, Integer, JSON, String, Text, inspect, text
from database.models import Base

revision = "0002_sources_crawler_admin"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    # Extend older installations without depending on PostgreSQL-only ALTER syntax.
    missing = {
        "source_type": (String(40), False, "'rss'"),
        "description": (Text(), False, "''"),
        "priority": (Integer(), False, "3"),
        "tags": (JSON(), False, "'[]'"),
        "parser_type": (String(40), False, "'feed'"),
        "auth_mode": (String(20), False, "'none'"),
        "auth_env_var": (String(100), False, "''"),
        "timeout_seconds": (Integer(), False, "20"),
        "max_response_bytes": (Integer(), False, "2000000"),
        "requests_per_minute": (Integer(), False, "6"),
        "last_success": (DateTime(timezone=True), True, None),
        "last_failure": (DateTime(timezone=True), True, None),
        "response_time_ms": (Integer(), True, None),
        "items_found": (Integer(), False, "0"),
        "last_item_date": (DateTime(timezone=True), True, None),
    }
    existing = {column["name"] for column in inspect(bind).get_columns("sources")}
    for name, (kind, nullable, default) in missing.items():
        if name not in existing:
            op.add_column("sources", Column(name, kind, nullable=nullable,
                                             server_default=text(default) if default is not None else None))


def downgrade():
    # New tables are intentionally retained to avoid destructive data loss during rollback.
    pass
