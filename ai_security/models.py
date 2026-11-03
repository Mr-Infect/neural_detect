from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from core.database.models import Base


class AIAssuranceRun(Base):
    __tablename__ = "ai_security_evaluations"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, default="platform")
    benchmark_version: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="completed", index=True)
    overall_status: Mapped[str] = mapped_column(String(32), nullable=False)
    run_live_model: Mapped[bool] = mapped_column(nullable=False, default=False)
    model_name: Mapped[str | None] = mapped_column(String(160))
    metrics: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    results: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_ai_security_tenant_created", "tenant_id", "created_at"),
        Index("ix_ai_security_agent_created", "agent_id", "created_at"),
    )
