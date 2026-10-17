"""Index publication dates and CVSS for bounded latest-record AI lookups."""
from alembic import op
from sqlalchemy import inspect

revision = "0011_ai_retrieval_indexes"
down_revision = "0010_published_date_only"
branch_labels = None
depends_on = None

INDEXES = (
    ("jobs", "ix_jobs_published_at", ("published_at",)),
    ("news_articles", "ix_news_articles_published_at", ("published_at",)),
    ("cves", "ix_cves_published_at", ("published_at",)),
    ("cves", "ix_cves_cvss", ("cvss",)),
    ("threats", "ix_threats_published_at", ("published_at",)),
    ("tools", "ix_tools_published_at", ("published_at",)),
)


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())
    for table, name, columns in INDEXES:
        if table not in tables:
            continue
        existing = {item["name"] for item in inspect(bind).get_indexes(table)}
        available = {item["name"] for item in inspect(bind).get_columns(table)}
        if name not in existing and set(columns) <= available:
            op.create_index(name, table, list(columns))


def downgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    for table, name, _ in reversed(INDEXES):
        if table in tables and name in {item["name"] for item in inspect(bind).get_indexes(table)}:
            op.drop_index(name, table_name=table)
