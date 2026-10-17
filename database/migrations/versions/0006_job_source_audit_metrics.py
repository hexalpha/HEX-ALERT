"""Persist source test metrics and classify historical logs."""
from alembic import op
from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, inspect, text

revision = "0006_job_source_audit_metrics"
down_revision = "0005_job_source_onboarding"
branch_labels = None
depends_on = None

def _columns(table):
    return {c["name"] for c in inspect(op.get_bind()).get_columns(table)} if table in inspect(op.get_bind()).get_table_names() else set()

def upgrade():
    bind = op.get_bind()
    if "sources" in inspect(bind).get_table_names():
        if "baseline_items" not in _columns("sources"):
            op.add_column("sources", Column("baseline_items", Integer(), nullable=False, server_default=text("0")))
        if "last_test_at" not in _columns("sources"):
            op.add_column("sources", Column("last_test_at", DateTime(timezone=True), nullable=True))
        if "last_test_metrics" not in _columns("sources"):
            op.add_column("sources", Column("last_test_metrics", JSON(), nullable=False, server_default=text("'{}'")))
        op.execute(text("UPDATE sources SET baseline_items = items_found WHERE baseline_complete = :yes AND baseline_items = 0").bindparams(yes=(True if bind.dialect.name == "postgresql" else 1)))
        op.execute(text("UPDATE sources SET new_items = 0 WHERE baseline_complete = :yes").bindparams(yes=(True if bind.dialect.name == "postgresql" else 1)))
    if "system_logs" in inspect(bind).get_table_names() and "status" not in _columns("system_logs"):
        op.add_column("system_logs", Column("status", String(20), nullable=False, server_default=text("'HISTORICAL'")))
        op.create_index("ix_system_logs_status", "system_logs", ["status"])
        op.execute(text("UPDATE system_logs SET status = 'HISTORICAL' WHERE component = 'jobs' AND message LIKE '%KeyError%'"))

def downgrade():
    pass
