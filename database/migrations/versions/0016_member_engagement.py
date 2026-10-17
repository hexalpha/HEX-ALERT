"""Persist member activity consent and engagement delivery metadata."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0016_member_engagement"
down_revision = "0015_admin_reset_used_at"
branch_labels = None
depends_on = None

def upgrade():
    bind=op.get_bind()
    tables=set(inspect(bind).get_table_names())
    if "community_engagement_members" not in tables:
        op.create_table("community_engagement_members",
            sa.Column("id",sa.Integer(),primary_key=True),
            sa.Column("guild_id",sa.String(32),nullable=False),
            sa.Column("user_id",sa.String(32),nullable=False),
            sa.Column("display_name",sa.String(80),nullable=False,server_default=""),
            sa.Column("opted_out",sa.Boolean(),nullable=False,server_default=sa.false()),
            sa.Column("last_activity_at",sa.DateTime(timezone=True),nullable=True),
            sa.Column("last_nudged_at",sa.DateTime(timezone=True),nullable=True),
            sa.Column("last_nudged_date",sa.String(10),nullable=False,server_default=""),
            sa.Column("last_response_at",sa.DateTime(timezone=True),nullable=True),
            sa.UniqueConstraint("guild_id","user_id"))
        op.create_index("ix_community_engagement_members_guild_id","community_engagement_members",["guild_id"])
        op.create_index("ix_community_engagement_members_user_id","community_engagement_members",["user_id"])
    if "community_engagement_events" not in tables:
        op.create_table("community_engagement_events",
            sa.Column("id",sa.Integer(),primary_key=True),
            sa.Column("guild_id",sa.String(32),nullable=False),
            sa.Column("channel_id",sa.String(32),nullable=False),
            sa.Column("target_user_id",sa.String(32),nullable=False,server_default=""),
            sa.Column("message_id",sa.String(32),nullable=False,server_default=""),
            sa.Column("event_type",sa.String(20),nullable=False),
            sa.Column("style",sa.String(32),nullable=False,server_default=""),
            sa.Column("content_hash",sa.String(64),nullable=False),
            sa.Column("status",sa.String(20),nullable=False,server_default="sent"),
            sa.Column("sent_at",sa.DateTime(timezone=True),nullable=False))
        for col in ("guild_id","channel_id","event_type","content_hash","sent_at"):
            op.create_index("ix_community_engagement_events_"+col,"community_engagement_events",[col])

def downgrade():
    op.drop_table("community_engagement_events")
    op.drop_table("community_engagement_members")

