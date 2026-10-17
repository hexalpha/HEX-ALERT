"""Add encrypted TOTP and hashed recovery-code fields to admin users."""
from alembic import op
from sqlalchemy import Boolean, JSON, Text, inspect, text
from database.models import Base

revision = "0003_admin_mfa"
down_revision = "0002_sources_crawler_admin"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    existing = {column["name"] for column in inspect(bind).get_columns("admin_users")}
    columns = {
        "totp_secret_encrypted": (Text(), "''"),
        "totp_pending_encrypted": (Text(), "''"),
        "mfa_enabled": (Boolean(), "false" if bind.dialect.name == "postgresql" else "0"),
        "recovery_code_hashes": (JSON(), "'[]'"),
    }
    for name, (kind, default) in columns.items():
        if name not in existing:
            op.add_column("admin_users", __import__("sqlalchemy").Column(name, kind, nullable=False, server_default=text(default)))


def downgrade():
    # Keep account security fields during rollback; dropping them could lock out admins.
    pass
