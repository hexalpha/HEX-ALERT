"""Expand observed engagement members into a persistent Discord directory."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0017_discord_member_directory"
down_revision = "0016_member_engagement"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "community_engagement_members" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("community_engagement_members")}
    additions = [
        ("username", sa.String(80), ""),
        ("is_bot", sa.Boolean(), False),
        ("is_active", sa.Boolean(), True),
        ("joined_at", sa.DateTime(timezone=True), None),
        ("last_seen_at", sa.DateTime(timezone=True), None),
        ("last_interaction_at", sa.DateTime(timezone=True), None),
        ("last_engagement_at", sa.DateTime(timezone=True), None),
        ("role_ids", sa.JSON(), []),
        ("created_at", sa.DateTime(timezone=True), None),
        ("updated_at", sa.DateTime(timezone=True), None),
    ]
    for name, kind, default in additions:
        if name not in columns:
            op.add_column("community_engagement_members", sa.Column(name, kind, nullable=True, default=default))
    op.execute(sa.text("UPDATE community_engagement_members SET is_active = TRUE WHERE is_active IS NULL"))
    op.execute(sa.text("UPDATE community_engagement_members SET is_bot = FALSE WHERE is_bot IS NULL"))
    op.execute(sa.text("UPDATE community_engagement_members SET role_ids = '[]' WHERE role_ids IS NULL"))
    op.execute(sa.text("UPDATE community_engagement_members SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
    op.execute(sa.text("UPDATE community_engagement_members SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"))
    indexes = {index["name"] for index in inspect(bind).get_indexes("community_engagement_members")}
    if "ix_community_engagement_members_is_active" not in indexes:
        op.create_index("ix_community_engagement_members_is_active", "community_engagement_members", ["is_active"])
    tables = set(inspect(bind).get_table_names())
    if "discord_member_sync_state" not in tables:
        op.create_table("discord_member_sync_state",
            sa.Column("guild_id", sa.String(32), primary_key=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="unavailable"),
            sa.Column("total_members", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("human_members", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("bots_excluded", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("opted_out", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("eligible_members", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table("discord_member_sync_state")
    op.drop_index("ix_community_engagement_members_is_active", table_name="community_engagement_members")
    for name in ("updated_at", "created_at", "role_ids", "last_engagement_at", "last_interaction_at",
                 "last_seen_at", "joined_at", "is_active", "is_bot", "username"):
        op.drop_column("community_engagement_members", name)
