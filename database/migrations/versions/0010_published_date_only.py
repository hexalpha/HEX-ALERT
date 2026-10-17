"""Preserve source publication values that contain a calendar date only."""
from alembic import op
from sqlalchemy import Boolean, Column, inspect, text

revision = "0010_published_date_only"
down_revision = "0009_job_date_only"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    default = text("false" if bind.dialect.name == "postgresql" else "0")
    for table in ("news_articles", "cves", "threats", "tools"):
        if table not in tables:
            continue
        columns = {item["name"] for item in inspect(bind).get_columns(table)}
        if "published_at_date_only" not in columns:
            op.add_column(table, Column("published_at_date_only", Boolean(), nullable=False, server_default=default))


def downgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    for table in ("tools", "threats", "cves", "news_articles"):
        if table in tables:
            columns = {item["name"] for item in inspect(bind).get_columns(table)}
            if "published_at_date_only" in columns:
                op.drop_column(table, "published_at_date_only")
