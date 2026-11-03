from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from core.database.models import Base


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(160), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    output_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_valid: Mapped[bool] = mapped_column(nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    evaluation_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
