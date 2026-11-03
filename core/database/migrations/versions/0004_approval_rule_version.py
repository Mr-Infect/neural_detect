"""Bind detection deployment approvals to the requested version."""
import sqlalchemy as sa
from alembic import op

revision = "0004_approval_rule_version"
down_revision = "0003_detection_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "detection_approvals",
        sa.Column("rule_version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("detection_approvals", "rule_version")