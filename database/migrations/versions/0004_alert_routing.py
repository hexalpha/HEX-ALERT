"""Store verified zero-day state and resolved Discord channel names."""
from alembic import op
from sqlalchemy import Boolean, Column, String, inspect, text

revision = "0004_alert_routing"
down_revision = "0003_admin_mfa"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "cves" in tables:
        cve_columns = {column["name"] for column in inspect(bind).get_columns("cves")}
        if "verified_zero_day" not in cve_columns:
            default = "false" if bind.dialect.name == "postgresql" else "0"
            op.add_column("cves", Column("verified_zero_day", Boolean(), nullable=False, server_default=text(default)))
    if "alerts" in tables:
        alert_columns = {column["name"] for column in inspect(bind).get_columns("alerts")}
        if "channel_name" not in alert_columns:
            op.add_column("alerts", Column("channel_name", String(150), nullable=False, server_default=text("''")))


def downgrade():
    # Keep alert routing metadata on downgrade; removing it loses delivery audit history.
    pass
