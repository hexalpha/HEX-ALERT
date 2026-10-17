"""Add optional hashed six-digit PIN login for dashboard administrator accounts."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0014_admin_pin_login"
down_revision = "0013_jobs_intelligence_schema"
branch_labels = None
depends_on = None


def upgrade():
    if "admin_users" not in inspect(op.get_bind()).get_table_names():
        return
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("admin_users")}
    if "pin_hash" not in columns:
        op.add_column("admin_users", sa.Column("pin_hash", sa.String(length=300), nullable=True))


def downgrade():
    # Keep PIN hashes during rollback to avoid unexpectedly removing login access.
    pass
