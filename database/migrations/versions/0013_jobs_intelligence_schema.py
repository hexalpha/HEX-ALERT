"""Complete the normalized jobs intelligence schema without replacing records."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text

revision = "0013_jobs_intelligence_schema"
down_revision = "0012_community_automation"
branch_labels = None
depends_on = None


def _columns(table):
    bind = op.get_bind()
    if table not in inspect(bind).get_table_names():
        return set()
    return {column["name"] for column in inspect(bind).get_columns(table)}


def _add(table, name, column):
    if name not in _columns(table):
        op.add_column(table, column)


def upgrade():
    bind = op.get_bind()
    false = text("false" if bind.dialect.name == "postgresql" else "0")
    if "jobs" in inspect(bind).get_table_names():
        definitions = (
            ("apply_url", sa.Column("apply_url", sa.Text(), nullable=False, server_default=text("''"))),
            ("external_id", sa.Column("external_id", sa.String(150), nullable=False, server_default=text("''"))),
            ("remote_status", sa.Column("remote_status", sa.String(100), nullable=False, server_default=text("'Not publicly available'"))),
            ("experience_min", sa.Column("experience_min", sa.Integer(), nullable=True)),
            ("experience_max", sa.Column("experience_max", sa.Integer(), nullable=True)),
            ("salary_min", sa.Column("salary_min", sa.Float(), nullable=True)),
            ("salary_max", sa.Column("salary_max", sa.Float(), nullable=True)),
            ("currency", sa.Column("currency", sa.String(12), nullable=False, server_default=text("''"))),
            ("discovered_at", sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))),
            ("canonical_job_key", sa.Column("canonical_job_key", sa.String(64), nullable=False, server_default=text("''"))),
            ("source_provenance", sa.Column("source_provenance", sa.JSON(), nullable=False, server_default=text("'[]'"))),
            ("is_cybersecurity", sa.Column("is_cybersecurity", sa.Boolean(), nullable=False, server_default=false)),
            ("is_entry_level", sa.Column("is_entry_level", sa.Boolean(), nullable=False, server_default=false)),
        )
        for name, column in definitions:
            _add("jobs", name, column)
        op.execute(text("UPDATE jobs SET apply_url = source_url WHERE apply_url = ''"))
        op.execute(text("UPDATE jobs SET external_id = posting_id WHERE external_id = ''"))
        op.execute(text("UPDATE jobs SET remote_status = work_mode WHERE remote_status = 'Not publicly available'"))
        op.execute(text("UPDATE jobs SET canonical_job_key = fingerprint WHERE canonical_job_key = ''"))
        indexes = {item["name"] for item in inspect(bind).get_indexes("jobs")}
        for name, column in (
            ("ix_jobs_external_id", "external_id"),
            ("ix_jobs_canonical_job_key", "canonical_job_key"),
            ("ix_jobs_is_cybersecurity", "is_cybersecurity"),
            ("ix_jobs_is_entry_level", "is_entry_level"),
        ):
            if name not in indexes:
                op.create_index(name, "jobs", [column])
    if "sources" in inspect(bind).get_table_names():
        _add("sources", "entry_level_items", sa.Column("entry_level_items", sa.Integer(), nullable=False, server_default=text("0")))
        _add("sources", "fresh_items", sa.Column("fresh_items", sa.Integer(), nullable=False, server_default=text("0")))
        _add("sources", "http_status", sa.Column("http_status", sa.Integer(), nullable=True))
        _add("sources", "rate_limit_status", sa.Column("rate_limit_status", sa.String(80), nullable=False, server_default=text("'UNKNOWN'")))


def downgrade():
    # Deliberately preserve normalized records, provenance, baselines and health history.
    pass
