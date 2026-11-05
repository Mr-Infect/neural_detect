"""Scope detection rules to a tenant; a rule ID is now unique per tenant."""
import sqlalchemy as sa
from alembic import op

revision = "0011_detection_tenancy"
down_revision = "0010_security_automation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing rules belong to the default tenant.
    op.add_column("detection_rules", sa.Column("tenant_id", sa.String(128), nullable=False, server_default="default"))
    op.create_index("ix_detection_rules_tenant_id", "detection_rules", ["tenant_id"])
    op.drop_index("ix_detection_rules_rule_id", table_name="detection_rules")
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"])
    op.create_unique_constraint("uq_detection_rules_tenant_rule", "detection_rules", ["tenant_id", "rule_id"])


def downgrade() -> None:
    op.drop_constraint("uq_detection_rules_tenant_rule", "detection_rules", type_="unique")
    op.drop_index("ix_detection_rules_rule_id", table_name="detection_rules")
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"], unique=True)
    op.drop_index("ix_detection_rules_tenant_id", table_name="detection_rules")
    op.drop_column("detection_rules", "tenant_id")
