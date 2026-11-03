from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from ai_engine.detection_agent.schemas import (
    ExplainDetectionRequest,
    GenerateDetectionRequest,
    ImproveDetectionRequest,
)
from ai_engine.detection_agent.service import agent
from core.database.models import DetectionRule
from core.database.session import SessionFactory

router = APIRouter(prefix="/ai/detection", tags=["ai-detection-engineer"])


async def _rule_source(source_text: str | None, rule_id: str | None) -> str:
    if source_text:
        return source_text
    if not rule_id:
        raise HTTPException(422, detail="Provide source_text or rule_id.")
    async with SessionFactory() as session:
        rule = await session.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    if not rule or not rule.source_yaml:
        raise HTTPException(404, detail="Sigma source for this rule was not found.")
    return rule.source_yaml


@router.post("/generate")
async def generate(payload: GenerateDetectionRequest) -> dict[str, Any]:
    try:
        return await agent.submit(
            "generate",
            payload.tenant_id,
            payload.source_type,
            payload.source_text,
            payload.model_dump(exclude={"tenant_id", "source_type", "source_text"}),
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(503, detail=str(exc)) from exc


@router.post("/improve")
async def improve(payload: ImproveDetectionRequest) -> dict[str, Any]:
    source = await _rule_source(payload.source_text, payload.rule_id)
    try:
        return await agent.submit(
            "improve",
            payload.tenant_id,
            "existing_sigma",
            source,
            payload.model_dump(
                exclude={
                    "tenant_id",
                    "source_type",
                    "source_text",
                    "rule_id",
                    "requested_change",
                    "positive_fixtures",
                    "negative_fixtures",
                }
            ),
            payload.requested_change,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(503, detail=str(exc)) from exc


@router.post("/explain")
async def explain(payload: ExplainDetectionRequest) -> dict[str, Any]:
    source = await _rule_source(payload.source_text, payload.rule_id)
    try:
        return await agent.submit(
            "explain",
            payload.tenant_id,
            "existing_sigma",
            source,
            payload.model_dump(exclude={"tenant_id", "source_type", "source_text", "rule_id"}),
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(503, detail=str(exc)) from exc


@router.get("/jobs/{job_id}")
async def job(job_id: UUID, tenant_id: str = Query("default", min_length=1, max_length=128)):
    try:
        return await agent.get(str(job_id), tenant_id)
    except LookupError as exc:
        raise HTTPException(404, detail="Job not found.") from exc
