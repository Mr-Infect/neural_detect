from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from core.database.models import Base


class HuntJob(Base):
    __tablename__="hunt_jobs"
    id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),primary_key=True,default=uuid4)
    tenant_id:Mapped[str]=mapped_column(String(128),nullable=False,index=True)
    request_sha256:Mapped[str]=mapped_column(String(64),nullable=False)
    status:Mapped[str]=mapped_column(String(32),nullable=False,default="queued",index=True)
    current_step:Mapped[str]=mapped_column(String(64),nullable=False,default="queued")
    query_language:Mapped[str|None]=mapped_column(String(12))
    query_text:Mapped[str|None]=mapped_column(Text)
    model_name:Mapped[str|None]=mapped_column(String(160))
    provider:Mapped[str|None]=mapped_column(String(40))
    model_version:Mapped[str|None]=mapped_column(String(256))
    time_range_hours:Mapped[int]=mapped_column(nullable=False)
    result_count:Mapped[int]=mapped_column(nullable=False,default=0)
    evidence_references:Mapped[list]=mapped_column(JSON,nullable=False,default=list)
    report:Mapped[dict|None]=mapped_column(JSON)
    error_code:Mapped[str|None]=mapped_column(String(80))
    error_message:Mapped[str|None]=mapped_column(Text)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    __table_args__=(Index("ix_hunt_jobs_tenant_created","tenant_id","created_at"),)

class SecurityIncident(Base):
    __tablename__="security_incidents"
    id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),primary_key=True,default=uuid4)
    tenant_id:Mapped[str]=mapped_column(String(128),nullable=False,index=True)
    source_alert_id:Mapped[str]=mapped_column(String(256),nullable=False)
    title:Mapped[str]=mapped_column(String(256),nullable=False)
    status:Mapped[str]=mapped_column(String(24),nullable=False,default="open",index=True)
    severity:Mapped[str]=mapped_column(String(24),nullable=False,default="medium")
    category:Mapped[str]=mapped_column(String(80),nullable=False,default="unclassified")
    attack_techniques:Mapped[list]=mapped_column(JSON,nullable=False,default=list)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now(),onupdate=func.now())
    __table_args__=(UniqueConstraint("tenant_id","source_alert_id",name="uq_security_incident_tenant_alert"),Index("ix_security_incidents_tenant_created","tenant_id","created_at"))

class InvestigationRecord(Base):
    __tablename__="investigation_records"
    id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),primary_key=True,default=uuid4)
    incident_id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),ForeignKey("security_incidents.id",ondelete="CASCADE"),nullable=False,index=True)
    tenant_id:Mapped[str]=mapped_column(String(128),nullable=False,index=True)
    status:Mapped[str]=mapped_column(String(24),nullable=False,default="running")
    duplicate_of:Mapped[UUID|None]=mapped_column(PGUUID(as_uuid=True))
    alert_snapshot:Mapped[dict]=mapped_column(JSON,nullable=False,default=dict)
    event_references:Mapped[list]=mapped_column(JSON,nullable=False,default=list)
    report:Mapped[dict|None]=mapped_column(JSON)
    provider:Mapped[str|None]=mapped_column(String(40))
    model_name:Mapped[str|None]=mapped_column(String(160))
    error_message:Mapped[str|None]=mapped_column(Text)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    __table_args__=(Index("ix_investigation_records_tenant_created","tenant_id","created_at"),)

class IncidentNote(Base):
    __tablename__="incident_notes"
    id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),primary_key=True,default=uuid4)
    incident_id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),ForeignKey("security_incidents.id",ondelete="CASCADE"),nullable=False,index=True)
    tenant_id:Mapped[str]=mapped_column(String(128),nullable=False,index=True)
    author:Mapped[str]=mapped_column(String(128),nullable=False)
    note:Mapped[str]=mapped_column(Text,nullable=False)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class IncidentAuditEvent(Base):
    __tablename__="incident_audit_events"
    id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),primary_key=True,default=uuid4)
    incident_id:Mapped[UUID]=mapped_column(PGUUID(as_uuid=True),ForeignKey("security_incidents.id",ondelete="CASCADE"),nullable=False,index=True)
    tenant_id:Mapped[str]=mapped_column(String(128),nullable=False,index=True)
    actor:Mapped[str]=mapped_column(String(128),nullable=False)
    action:Mapped[str]=mapped_column(String(64),nullable=False)
    details:Mapped[dict]=mapped_column(JSON,nullable=False,default=dict)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

