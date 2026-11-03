"""Phase 9 identity, approvals, and generic audit trail."""
import re
import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010_security_automation"
down_revision = "0009_ai_security_assurance"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tenants", sa.Column("slug", sa.String(100), nullable=True))
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, name FROM tenants ORDER BY name, id")).fetchall()
    used = set()
    for row in rows:
        base = re.sub(r"[^a-z0-9]+", "-", (row.name or "tenant").lower()).strip("-")[:70] or "tenant"
        slug = "default" if base == "default" and "default" not in used else base
        if slug in used:
            slug = f"{base}-{str(row.id).replace('-', '')[:8]}"
        used.add(slug)
        bind.execute(sa.text("UPDATE tenants SET slug=:slug WHERE id=:id"), {"slug": slug, "id": row.id})
    if "default" not in used:
        bind.execute(sa.text(
            "INSERT INTO tenants (id, name, slug, is_active) VALUES (:id, 'Default', 'default', true)"
        ), {"id": uuid.UUID("00000000-0000-0000-0000-000000000001")})
    op.alter_column("tenants", "slug", nullable=False)
    op.create_index("uq_tenants_slug", "tenants", ["slug"], unique=True)

    op.add_column("users", sa.Column("role", sa.String(40), nullable=False, server_default="analyst"))
    op.create_index("ix_users_role", "users", ["role"])

    op.create_table(
        "approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("action_type", sa.String(48), nullable=False),
        sa.Column("risk_level", sa.String(24), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.String(320), nullable=False),
        sa.Column("reviewer", sa.String(320)),
        sa.Column("rejection_reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("execution_result", sa.JSON()),
    )
    op.create_index("ix_approval_requests_tenant_id", "approval_requests", ["tenant_id"])
    op.create_index("ix_approval_requests_action_type", "approval_requests", ["action_type"])
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])
    op.create_index("ix_approval_tenant_status", "approval_requests", ["tenant_id", "status"])

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128)),
        sa.Column("actor", sa.String(320), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(128)),
        sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade():
    op.drop_table("audit_events")
    op.drop_table("approval_requests")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_column("users", "role")
    op.drop_index("uq_tenants_slug", table_name="tenants")
    op.drop_column("tenants", "slug")
