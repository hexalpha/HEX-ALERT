"""Add protected local admin recovery and custom Discord routes."""
from alembic import op
from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, Text, inspect, text

revision = "0007_admin_recovery_routes"
down_revision = "0006_job_source_audit_metrics"
branch_labels = None
depends_on = None


def _columns(table):
    inspector = inspect(op.get_bind())
    return {c["name"] for c in inspector.get_columns(table)} if table in inspector.get_table_names() else set()


def upgrade():
    bind = op.get_bind()
    admin_cols = _columns("admin_users")
    additions = [
        ("session_version", Column("session_version", Integer(), nullable=False, server_default=text("0"))),
        ("password_changed_at", Column("password_changed_at", DateTime(timezone=True), nullable=True)),
        ("reset_token_hash", Column("reset_token_hash", String(64), nullable=False, server_default=text("''"))),
        ("reset_token_expires_at", Column("reset_token_expires_at", DateTime(timezone=True), nullable=True)),
    ]
    for name, column in additions:
        if name not in admin_cols:
            op.add_column("admin_users", column)
    if "password_changed_at" not in admin_cols:
        op.execute(text("UPDATE admin_users SET password_changed_at = CURRENT_TIMESTAMP WHERE password_changed_at IS NULL"))

    rule_cols = _columns("automation_rules")
    if "route_key" not in rule_cols:
        op.add_column("automation_rules", Column("route_key", String(64), nullable=False, server_default=text("''")))

    if "custom_discord_routes" not in inspect(bind).get_table_names():
        op.create_table(
            "custom_discord_routes",
            Column("id", Integer(), primary_key=True),
            Column("route_name", String(100), nullable=False),
            Column("route_key", String(64), nullable=False),
            Column("description", Text(), nullable=False, server_default=text("''")),
            Column("guild_id", String(32), nullable=False),
            Column("channel_id", String(32), nullable=False),
            Column("category", String(50), nullable=False, server_default=text("'custom'")),
            Column("keywords", JSON(), nullable=False, server_default=text("'[]'")),
            Column("priority", Integer(), nullable=False, server_default=text("3")),
            Column("enabled", Boolean(), nullable=False, server_default=text("false" if bind.dialect.name == "postgresql" else "0")),
            Column("last_used", DateTime(timezone=True), nullable=True),
            Column("status", String(30), nullable=False, server_default=text("'UNKNOWN'")),
            Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")),
            Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")),
        )
        op.create_index("ix_custom_discord_routes_route_key", "custom_discord_routes", ["route_key"], unique=True)
        op.create_index("ix_custom_discord_routes_guild_id", "custom_discord_routes", ["guild_id"])
        op.create_index("ix_custom_discord_routes_channel_id", "custom_discord_routes", ["channel_id"])


def downgrade():
    bind = op.get_bind()
    if "custom_discord_routes" in inspect(bind).get_table_names():
        op.drop_table("custom_discord_routes")
    for table, name in (("automation_rules", "route_key"), ("admin_users", "reset_token_expires_at"),
                        ("admin_users", "reset_token_hash"), ("admin_users", "password_changed_at"),
                        ("admin_users", "session_version")):
        if name in _columns(table):
            op.drop_column(table, name)
