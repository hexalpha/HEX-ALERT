"""Add content-free smart social interaction preferences and history."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0018_smart_social"
down_revision = "0017_discord_member_directory"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(inspect(op.get_bind()).get_table_names())
    if "social_interaction_members" not in tables:
        op.create_table(
            "social_interaction_members",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("guild_id", sa.String(32), nullable=False),
            sa.Column("user_id", sa.String(32), nullable=False),
            sa.Column("opted_out", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("last_reaction_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_social_reply_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("reaction_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reply_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("guild_id", "user_id", name="uq_social_member_guild_user"),
        )
        op.create_index("ix_social_interaction_members_guild_id", "social_interaction_members", ["guild_id"])
        op.create_index("ix_social_interaction_members_user_id", "social_interaction_members", ["user_id"])
    tables = set(inspect(op.get_bind()).get_table_names())
    if "social_interaction_events" not in tables:
        op.create_table(
            "social_interaction_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("guild_id", sa.String(32), nullable=False),
            sa.Column("channel_id", sa.String(32), nullable=False),
            sa.Column("user_id", sa.String(32), nullable=False),
            sa.Column("source_message_id", sa.String(32), nullable=False, server_default=""),
            sa.Column("delivery_message_id", sa.String(32), nullable=False, server_default=""),
            sa.Column("event_kind", sa.String(24), nullable=False),
            sa.Column("reaction", sa.String(16), nullable=False, server_default=""),
            sa.Column("status", sa.String(16), nullable=False, server_default="sent"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        for column in ("guild_id", "channel_id", "user_id", "event_kind", "status", "created_at"):
            op.create_index(f"ix_social_interaction_events_{column}", "social_interaction_events", [column])


def downgrade():
    op.drop_table("social_interaction_events")
    op.drop_table("social_interaction_members")
