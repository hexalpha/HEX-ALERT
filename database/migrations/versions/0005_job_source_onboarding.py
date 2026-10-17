"""Add public job source adapters, freshness, score and baseline state."""
from alembic import op
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text, inspect, text

revision = "0005_job_source_onboarding"
down_revision = "0004_alert_routing"
branch_labels = None
depends_on = None


def _columns(table):
    bind = op.get_bind()
    if table not in inspect(bind).get_table_names():
        return set()
    return {col["name"] for col in inspect(bind).get_columns(table)}


def _add(table, name, column):
    if name not in _columns(table):
        op.add_column(table, column)


def upgrade():
    bind = op.get_bind()
    if "sources" in inspect(bind).get_table_names():
        _add("sources", "company_name", Column("company_name", String(200), nullable=False, server_default=text("''")))
        _add("sources", "parser_config", Column("parser_config", JSON, nullable=False, server_default=text("'{}'")))
        _add("sources", "baseline_complete", Column("baseline_complete", Boolean, nullable=False, server_default=text("false" if bind.dialect.name == "postgresql" else "0")))
        for name in ("relevant_items", "new_items", "duplicate_items", "closed_items"):
            _add("sources", name, Column(name, Integer, nullable=False, server_default=text("0")))
        _add("sources", "parser_status", Column("parser_status", String(40), nullable=False, server_default=text("'UNKNOWN'")))
        _add("sources", "last_new_job", Column("last_new_job", DateTime(timezone=True), nullable=True))
    if "jobs" in inspect(bind).get_table_names():
        _add("jobs", "work_mode", Column("work_mode", String(100), nullable=False, server_default=text("'Not publicly available'")))
        _add("jobs", "first_seen_at", Column("first_seen_at", DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")))
        _add("jobs", "last_seen_at", Column("last_seen_at", DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")))
        _add("jobs", "freshness_status", Column("freshness_status", String(20), nullable=False, server_default=text("'UNKNOWN'")))
        _add("jobs", "listing_status", Column("listing_status", String(20), nullable=False, server_default=text("'UNKNOWN'")))
        _add("jobs", "match_score", Column("match_score", Float, nullable=False, server_default=text("0")))
        _add("jobs", "score_breakdown", Column("score_breakdown", JSON, nullable=False, server_default=text("'{}'")))
        _add("jobs", "alert_eligible", Column("alert_eligible", Boolean, nullable=False, server_default=text("false" if bind.dialect.name == "postgresql" else "0")))
        _add("jobs", "source_id", Column("source_id", Integer, ForeignKey("sources.id", ondelete="SET NULL"), nullable=True))
        _add("jobs", "posting_id", Column("posting_id", String(150), nullable=False, server_default=text("''")))
        _add("jobs", "suppressed", Column("suppressed", Boolean, nullable=False, server_default=text("false" if bind.dialect.name == "postgresql" else "0")))
        names = {idx["name"] for idx in inspect(bind).get_indexes("jobs")}
        for name, column in (("ix_jobs_freshness_status", "freshness_status"), ("ix_jobs_listing_status", "listing_status"), ("ix_jobs_match_score", "match_score"), ("ix_jobs_source_id", "source_id"), ("ix_jobs_posting_id", "posting_id"), ("ix_jobs_alert_eligible", "alert_eligible"), ("ix_jobs_suppressed", "suppressed")):
            if name not in names:
                op.create_index(name, "jobs", [column])
    if "automation_rules" in inspect(bind).get_table_names():
        _add("automation_rules", "rule_type", Column("rule_type", String(20), nullable=False, server_default=text("'route'")))
        _add("automation_rules", "logic", Column("logic", String(8), nullable=False, server_default=text("'AND'")))
        _add("automation_rules", "conditions", Column("conditions", JSON, nullable=False, server_default=text("'{}'")))


def downgrade():
    # Preserve collected records and source health data on downgrade.
    pass
