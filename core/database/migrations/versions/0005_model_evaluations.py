"""Persist model inference evaluations without prompts or completions."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_model_evaluations"
down_revision = "0004_approval_rule_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("model_name", sa.String(length=160), nullable=False),
        sa.Column("model_version", sa.String(length=256), nullable=True),
        sa.Column("output_kind", sa.String(length=40), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("output_valid", sa.Boolean(), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("evaluation_result", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_model_evaluations_tenant_id", "model_evaluations", ["tenant_id"])
    op.create_index("ix_model_evaluations_provider", "model_evaluations", ["provider"])
    op.create_index("ix_model_evaluations_created_at", "model_evaluations", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_model_evaluations_created_at", table_name="model_evaluations")
    op.drop_index("ix_model_evaluations_provider", table_name="model_evaluations")
    op.drop_index("ix_model_evaluations_tenant_id", table_name="model_evaluations")
    op.drop_table("model_evaluations")


