"""Track revocable administrator sessions without storing cookie values."""
from alembic import op
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, inspect, text

revision = "0008_admin_sessions"
down_revision = "0007_admin_recovery_routes"
branch_labels = None
depends_on = None


def upgrade():
    inspector=inspect(op.get_bind())
    if "admin_sessions" not in inspector.get_table_names():
        op.create_table(
            "admin_sessions",
            Column("id",Integer(),primary_key=True),
            Column("admin_user_id",Integer(),ForeignKey("admin_users.id",ondelete="CASCADE"),nullable=False),
            Column("session_id",String(64),nullable=False),
            Column("session_version",Integer(),nullable=False,server_default=text("0")),
            Column("created_at",DateTime(timezone=True),nullable=False,server_default=text("CURRENT_TIMESTAMP")),
            Column("expires_at",DateTime(timezone=True),nullable=False),
            Column("revoked_at",DateTime(timezone=True),nullable=True),
        )
        op.create_index("ix_admin_sessions_admin_user_id","admin_sessions",["admin_user_id"])
        op.create_index("ix_admin_sessions_session_id","admin_sessions",["session_id"],unique=True)


def downgrade():
    if "admin_sessions" in inspect(op.get_bind()).get_table_names():
        op.drop_table("admin_sessions")
