"""Record when an administrator recovery token was consumed."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0015_admin_reset_used_at"
down_revision = "0014_admin_pin_login"
branch_labels = None
depends_on = None


def upgrade():
    if "admin_users" not in inspect(op.get_bind()).get_table_names():
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("admin_users")}
    if "reset_token_used_at" not in columns:
        op.add_column("admin_users", sa.Column("reset_token_used_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    if "admin_users" not in inspect(op.get_bind()).get_table_names():
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("admin_users")}
    if "reset_token_used_at" in columns:
        op.drop_column("admin_users", "reset_token_used_at")
