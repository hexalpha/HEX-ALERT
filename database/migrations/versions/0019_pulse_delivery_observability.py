"""Add content-free Pulse delivery outcome history."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0019_pulse_delivery"
down_revision = "0018_smart_social"
branch_labels = None
depends_on = None


def upgrade():
    if "pulse_delivery_events" not in set(inspect(op.get_bind()).get_table_names()):
        op.create_table(
            "pulse_delivery_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("guild_id", sa.String(32), nullable=False),
            sa.Column("category", sa.String(40), nullable=False),
            sa.Column("channel_id", sa.String(32), nullable=False, server_default=""),
            sa.Column("content_hash", sa.String(64), nullable=False, server_default=""),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("reason", sa.String(180), nullable=False, server_default=""),
            sa.Column("message_id", sa.String(32), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        for name in ("guild_id", "category", "content_hash", "status", "created_at"):
            op.create_index(f"ix_pulse_delivery_events_{name}", "pulse_delivery_events", [name])


def downgrade():
    if "pulse_delivery_events" in set(inspect(op.get_bind()).get_table_names()):
        op.drop_table("pulse_delivery_events")
