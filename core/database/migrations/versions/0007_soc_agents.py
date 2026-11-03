"""Phase 6 SOC hunt, incident, and investigation records."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision="0007_soc_agents"
down_revision="0006_detection_agent_jobs"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("hunt_jobs",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("tenant_id",sa.String(128),nullable=False),
        sa.Column("request_sha256",sa.String(64),nullable=False),
        sa.Column("status",sa.String(32),nullable=False,server_default="queued"),
        sa.Column("current_step",sa.String(64),nullable=False,server_default="queued"),
        sa.Column("query_language",sa.String(12)),
        sa.Column("query_text",sa.Text()),
        sa.Column("model_name",sa.String(160)),
        sa.Column("provider",sa.String(40)),
        sa.Column("model_version",sa.String(256)),
        sa.Column("time_range_hours",sa.Integer(),nullable=False),
        sa.Column("result_count",sa.Integer(),nullable=False,server_default="0"),
        sa.Column("evidence_references",sa.JSON(),nullable=False,server_default=sa.text("'[]'")),
        sa.Column("report",sa.JSON()),
        sa.Column("error_code",sa.String(80)),
        sa.Column("error_message",sa.Text()),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_hunt_jobs_tenant_id","hunt_jobs",["tenant_id"])
    op.create_index("ix_hunt_jobs_status","hunt_jobs",["status"])
    op.create_index("ix_hunt_jobs_tenant_created","hunt_jobs",["tenant_id","created_at"])
    op.create_table("security_incidents",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("tenant_id",sa.String(128),nullable=False),
        sa.Column("source_alert_id",sa.String(256),nullable=False),
        sa.Column("title",sa.String(256),nullable=False),
        sa.Column("status",sa.String(24),nullable=False,server_default="open"),
        sa.Column("severity",sa.String(24),nullable=False,server_default="medium"),
        sa.Column("category",sa.String(80),nullable=False,server_default="unclassified"),
        sa.Column("attack_techniques",sa.JSON(),nullable=False,server_default=sa.text("'[]'")),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id","source_alert_id",name="uq_security_incident_tenant_alert"))
    op.create_index("ix_security_incidents_tenant_id","security_incidents",["tenant_id"])
    op.create_index("ix_security_incidents_status","security_incidents",["status"])
    op.create_index("ix_security_incidents_tenant_created","security_incidents",["tenant_id","created_at"])
    op.create_table("investigation_records",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("incident_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("security_incidents.id",ondelete="CASCADE"),nullable=False),
        sa.Column("tenant_id",sa.String(128),nullable=False),
        sa.Column("status",sa.String(24),nullable=False,server_default="running"),
        sa.Column("duplicate_of",postgresql.UUID(as_uuid=True)),
        sa.Column("alert_snapshot",sa.JSON(),nullable=False,server_default=sa.text("'{}'")),
        sa.Column("event_references",sa.JSON(),nullable=False,server_default=sa.text("'[]'")),
        sa.Column("report",sa.JSON()),
        sa.Column("provider",sa.String(40)),
        sa.Column("model_name",sa.String(160)),
        sa.Column("error_message",sa.Text()),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_investigation_records_incident_id","investigation_records",["incident_id"])
    op.create_index("ix_investigation_records_tenant_id","investigation_records",["tenant_id"])
    op.create_index("ix_investigation_records_tenant_created","investigation_records",["tenant_id","created_at"])
    op.create_table("incident_notes",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("incident_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("security_incidents.id",ondelete="CASCADE"),nullable=False),
        sa.Column("tenant_id",sa.String(128),nullable=False),
        sa.Column("author",sa.String(128),nullable=False),
        sa.Column("note",sa.Text(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_incident_notes_incident_id","incident_notes",["incident_id"])
    op.create_index("ix_incident_notes_tenant_id","incident_notes",["tenant_id"])
    op.create_table("incident_audit_events",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("incident_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("security_incidents.id",ondelete="CASCADE"),nullable=False),
        sa.Column("tenant_id",sa.String(128),nullable=False),
        sa.Column("actor",sa.String(128),nullable=False),
        sa.Column("action",sa.String(64),nullable=False),
        sa.Column("details",sa.JSON(),nullable=False,server_default=sa.text("'{}'")),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_incident_audit_events_incident_id","incident_audit_events",["incident_id"])
    op.create_index("ix_incident_audit_events_tenant_id","incident_audit_events",["tenant_id"])

def downgrade():
    op.drop_table("incident_audit_events")
    op.drop_table("incident_notes")
    op.drop_table("investigation_records")
    op.drop_table("security_incidents")
    op.drop_table("hunt_jobs")

