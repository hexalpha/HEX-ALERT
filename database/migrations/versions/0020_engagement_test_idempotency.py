"""Add durable idempotency keys for manual engagement tests."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0020_engagement_test_idempotency"
down_revision = "0019_pulse_delivery"
branch_labels = None
depends_on = None


def upgrade():
    inspector = inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("community_engagement_events")}
    with op.batch_alter_table("community_engagement_events") as batch:
        if "test_run_id" not in columns:
            batch.add_column(sa.Column("test_run_id", sa.String(36), nullable=True))
        if "action_type" not in columns:
            batch.add_column(sa.Column("action_type", sa.String(32), nullable=False, server_default=""))
    constraints = {item.get("name") for item in inspect(op.get_bind()).get_unique_constraints("community_engagement_events")}
    if "uq_engagement_test_action" not in constraints:
        with op.batch_alter_table("community_engagement_events") as batch:
            batch.create_unique_constraint("uq_engagement_test_action", ["test_run_id", "action_type"])


def downgrade():
    inspector = inspect(op.get_bind())
    constraints = {item.get("name") for item in inspector.get_unique_constraints("community_engagement_events")}
    if "uq_engagement_test_action" in constraints:
        with op.batch_alter_table("community_engagement_events") as batch:
            batch.drop_constraint("uq_engagement_test_action", type_="unique")
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("community_engagement_events")}
    with op.batch_alter_table("community_engagement_events") as batch:
        if "action_type" in columns:
            batch.drop_column("action_type")
        if "test_run_id" in columns:
            batch.drop_column("test_run_id")
