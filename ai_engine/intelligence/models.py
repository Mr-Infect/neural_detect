from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from core.database.models import Base


class IntelDocument(Base):
    __tablename__ = "intelligence_documents"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    source_object_id: Mapped[str] = mapped_column(String(512), nullable=False)
    object_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_version: Mapped[str | None] = mapped_column(String(128))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    raw_object: Mapped[dict] = mapped_column(JSON, nullable=False)
    __table_args__ = (
        Index("ix_intel_doc_tenant_source_id", "tenant_id", "source_object_id"),
        Index("ix_intel_doc_tenant_hash", "tenant_id", "content_hash"),
    )


class IntelChunk(Base):
    __tablename__ = "intelligence_chunks"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("intelligence_documents.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    point_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    __table_args__ = (UniqueConstraint("document_id", "ordinal", name="uq_intel_chunk_document_ordinal"),)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    document_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("intelligence_documents.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    stix_id: Mapped[str] = mapped_column(String(512), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[int | None] = mapped_column(Integer)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    labels: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    related_objects: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    __table_args__ = (
        UniqueConstraint("tenant_id", "stix_id", name="uq_threat_indicator_tenant_stix"),
        Index("ix_threat_indicator_lookup", "tenant_id", "indicator_type", "normalized_value"),
    )


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    attack_domain: Mapped[str] = mapped_column(String(40), nullable=False, default="enterprise-attack")
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False)
    stix_id: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tactics: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    platforms: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    data_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    external_url: Mapped[str | None] = mapped_column(Text)
    source_version: Mapped[str | None] = mapped_column(String(128))
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    __table_args__ = (
        UniqueConstraint("attack_domain", "technique_id", name="uq_attack_technique_domain_id"),
        Index("ix_attack_technique_tenantless_name", "name"),
    )


class IntelSyncRun(Base):
    __tablename__ = "intelligence_sync_runs"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="running", index=True)
    source_version: Mapped[str | None] = mapped_column(String(128))
    bundle_hash: Mapped[str | None] = mapped_column(String(64))
    objects_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    documents_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indicators_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    techniques_written: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntelDatasetVersion(Base):
    __tablename__ = "intelligence_dataset_versions"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    dataset: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    __table_args__ = (
        UniqueConstraint("dataset", "version", "content_hash", name="uq_intel_dataset_version_hash"),
    )
