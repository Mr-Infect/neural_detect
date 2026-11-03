from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from core.database.models import Base


class DetectionAgentJob(Base):
    __tablename__ = "detection_agent_jobs"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    operation: Mapped[str] = mapped_column(String(20), nullable=False)
    input_type: Mapped[str] = mapped_column(String(40), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    current_step: Mapped[str] = mapped_column(String(80), nullable=False, default="queued")
    provider: Mapped[str | None] = mapped_column(String(40), nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    candidate: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    validation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    benchmark: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    __table_args__ = (Index("ix_detection_agent_jobs_tenant_created", "tenant_id", "created_at"),)
