"""Persist opt-in community automation and duplicate history."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0012_community_automation"
down_revision = "0011_ai_retrieval_indexes"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    definitions = {
        "community_configs": (
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("guild_id", sa.String(32), nullable=False, unique=True),
            sa.Column("settings", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        ),
        "community_posts": (
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("guild_id", sa.String(32), nullable=False),
            sa.Column("channel_id", sa.String(32), nullable=False),
            sa.Column("kind", sa.String(24), nullable=False),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column("message_id", sa.String(32), nullable=False, server_default=""),
            sa.Column("status", sa.String(20), nullable=False, server_default="sent"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        ),
    }
    for name, columns in definitions.items():
        if name not in tables:
            op.create_table(name, *columns)

    indexes = (
        ("community_configs", "ix_community_configs_guild_id", ("guild_id",)),
        ("community_posts", "ix_community_posts_guild_id", ("guild_id",)),
        ("community_posts", "ix_community_posts_channel_id", ("channel_id",)),
        ("community_posts", "ix_community_posts_kind", ("kind",)),
        ("community_posts", "ix_community_posts_content_hash", ("content_hash",)),
        ("community_posts", "ix_community_posts_created_at", ("created_at",)),
    )
    for table, name, columns in indexes:
        if name not in {item["name"] for item in inspect(bind).get_indexes(table)}:
            op.create_index(name, table, list(columns))


def downgrade():
    tables = set(inspect(op.get_bind()).get_table_names())
    for table in ("community_posts", "community_configs"):
        if table in tables:
            op.drop_table(table)
