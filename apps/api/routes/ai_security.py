from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from ai_security.schemas import AgentTestRequest, EvaluationRequest
from ai_security.service import AGENT_IDS, assurance

router = APIRouter(prefix="/ai-security", tags=["ai-security-assurance"])


@router.post("/evaluations")
async def create_evaluation(payload: EvaluationRequest) -> dict[str, Any]:
    try:
        return await assurance.evaluate(payload.tenant_id, "platform", payload.run_live_model)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@router.get("/evaluations")
async def list_evaluations(
    tenant_id: str = Query(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    return {"items": await assurance.list_runs(tenant_id, limit)}


@router.get("/results/{run_id}")
async def get_result(
    run_id: UUID,
    tenant_id: str = Query(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
) -> dict[str, Any]:
    row = await assurance.get_run(run_id, tenant_id)
    if not row:
        raise HTTPException(404, detail="AI security evaluation was not found.")
    return row


@router.post("/agents/{agent_id}/test")
async def test_agent(agent_id: str, payload: AgentTestRequest) -> dict[str, Any]:
    if agent_id not in AGENT_IDS - {"platform"}:
        raise HTTPException(404, detail="Unsupported agent identifier.")
    try:
        return await assurance.evaluate(payload.tenant_id, agent_id, payload.run_live_model)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
