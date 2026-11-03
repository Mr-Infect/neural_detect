"""Phase 8 AI security assurance evaluations."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_ai_security_assurance"
down_revision = "0008_intelligence_rag"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_security_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False, server_default="platform"),
        sa.Column("benchmark_version", sa.String(40), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="completed"),
        sa.Column("overall_status", sa.String(32), nullable=False),
        sa.Column("run_live_model", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("model_name", sa.String(160)),
        sa.Column("metrics", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("results", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("findings", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_ai_security_evaluations_tenant_id", "ai_security_evaluations", ["tenant_id"])
    op.create_index("ix_ai_security_evaluations_status", "ai_security_evaluations", ["status"])
    op.create_index("ix_ai_security_tenant_created", "ai_security_evaluations", ["tenant_id", "created_at"])
    op.create_index("ix_ai_security_agent_created", "ai_security_evaluations", ["agent_id", "created_at"])


def downgrade():
    op.drop_table("ai_security_evaluations")
