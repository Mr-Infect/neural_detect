"""Add persisted AI detection engineering jobs and provenance."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_detection_agent_jobs"
down_revision = "0005_model_evaluations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_agent_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=20), nullable=False),
        sa.Column("input_type", sa.String(length=40), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("current_step", sa.String(length=80), nullable=False, server_default="queued"),
        sa.Column("provider", sa.String(length=40), nullable=True),
        sa.Column("model_name", sa.String(length=160), nullable=True),
        sa.Column("model_version", sa.String(length=256), nullable=True),
        sa.Column("steps", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("candidate", sa.JSON(), nullable=True),
        sa.Column("validation", sa.JSON(), nullable=True),
        sa.Column("benchmark", sa.JSON(), nullable=True),
        sa.Column("explanation", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_detection_agent_jobs_tenant_id", "detection_agent_jobs", ["tenant_id"])
    op.create_index("ix_detection_agent_jobs_status", "detection_agent_jobs", ["status"])
    op.create_index("ix_detection_agent_jobs_tenant_created", "detection_agent_jobs", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_detection_agent_jobs_tenant_created", table_name="detection_agent_jobs")
    op.drop_index("ix_detection_agent_jobs_status", table_name="detection_agent_jobs")
    op.drop_index("ix_detection_agent_jobs_tenant_id", table_name="detection_agent_jobs")
    op.drop_table("detection_agent_jobs")
