"""Preserve date-only job publication values independently of timezone."""
from alembic import op
from sqlalchemy import Boolean, Column, inspect, text

revision = "0009_job_date_only"
down_revision = "0008_admin_sessions"
branch_labels = None
depends_on = None


def upgrade():
    if "jobs" in inspect(op.get_bind()).get_table_names():
        columns = {item["name"] for item in inspect(op.get_bind()).get_columns("jobs")}
        if "published_at_date_only" not in columns:
            op.add_column("jobs", Column("published_at_date_only", Boolean(), nullable=False,
                                          server_default=text("false" if op.get_bind().dialect.name == "postgresql" else "0")))


def downgrade():
    if "jobs" in inspect(op.get_bind()).get_table_names():
        columns = {item["name"] for item in inspect(op.get_bind()).get_columns("jobs")}
        if "published_at_date_only" in columns:
            op.drop_column("jobs", "published_at_date_only")
