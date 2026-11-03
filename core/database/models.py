from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

class User(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

class TelemetrySource(Base):
    __tablename__ = "telemetry_sources"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    dataset: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    configuration: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rule_format: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    native_query: Mapped[dict | str | None] = mapped_column(JSON, nullable=True)
    compiled_query: Mapped[str | dict | None] = mapped_column(JSON, nullable=True)
    deployment: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rule_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    detection_rule_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    native_query: Mapped[dict | str | None] = mapped_column(JSON, nullable=True)
    compiled_query: Mapped[str | dict | None] = mapped_column(JSON, nullable=True)
    deployment: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rule_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    __table_args__ = ({"sqlite_autoincrement": False},)


class DetectionApproval(Base):
    __tablename__ = "detection_approvals"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    detection_rule_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    reviewer: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)