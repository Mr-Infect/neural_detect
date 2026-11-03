"""Add registered telemetry sources."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_telemetry_sources"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "telemetry_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("dataset", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("configuration", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.create_index("ix_telemetry_sources_kind", "telemetry_sources", ["kind"])

def downgrade() -> None:
    op.drop_index("ix_telemetry_sources_kind", table_name="telemetry_sources")
    op.drop_table("telemetry_sources")
