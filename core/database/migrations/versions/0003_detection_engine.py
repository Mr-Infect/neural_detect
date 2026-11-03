"""Add versioned detection rules and deployment approvals."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_detection_engine"
down_revision = "0002_telemetry_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("rule_format", sa.String(20), nullable=False),
        sa.Column("source_yaml", sa.Text(), nullable=True),
        sa.Column("native_query", sa.JSON(), nullable=True),
        sa.Column("compiled_query", sa.JSON(), nullable=True),
        sa.Column("deployment", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"], unique=True)
    op.create_index("ix_detection_rules_title", "detection_rules", ["title"])
    op.create_index("ix_detection_rules_rule_format", "detection_rules", ["rule_format"])
    op.create_table(
        "detection_rule_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("detection_rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source_yaml", sa.Text(), nullable=True),
        sa.Column("native_query", sa.JSON(), nullable=True),
        sa.Column("compiled_query", sa.JSON(), nullable=True),
        sa.Column("deployment", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("detection_rule_id", "version", name="uq_detection_rule_version"),
    )
    op.create_index("ix_detection_rule_versions_detection_rule_id", "detection_rule_versions", ["detection_rule_id"])
    op.create_table(
        "detection_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("detection_rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("reviewer", sa.String(256), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detection_approvals_detection_rule_id", "detection_approvals", ["detection_rule_id"])
    op.create_index("ix_detection_approvals_status", "detection_approvals", ["status"])


def downgrade() -> None:
    op.drop_table("detection_approvals")
    op.drop_table("detection_rule_versions")
    op.drop_table("detection_rules")