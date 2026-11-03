from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from integrations.elasticsearch.detection_api import create_detection_rule, list_detection_rules

router = APIRouter(prefix="/detections", tags=["detections"])

class DetectionRuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    rule_id: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3, max_length=1000)
    query: str = Field(min_length=1, max_length=10000)
    language: Literal["kuery", "eql", "esql"] = "kuery"
    index: list[str] = Field(default_factory=lambda: ["neural-detect-*"], min_length=1, max_length=10)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    risk_score: int = Field(default=47, ge=0, le=100)
    interval: str = "5m"
    from_: str = Field(default="now-6m", alias="from")
    tags: list[str] = Field(default_factory=list, max_length=20)

@router.get("/rules")
async def get_rules(page: int = 1, per_page: int = 50) -> dict[str, Any]:
    try:
        return await list_detection_rules(page=max(page, 1), per_page=min(max(per_page, 1), 100))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Kibana detection rules are unavailable.") from exc

@router.post("/rules", status_code=201)
async def post_rule(rule: DetectionRuleCreate) -> dict[str, Any]:
    # Phase 2 creates disabled rules only; deployment and enablement need a later approval flow.
    payload = rule.model_dump(by_alias=True)
    payload.update({"type": "query", "enabled": False, "max_signals": 100})
    try:
        return await create_detection_rule(payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Kibana could not save the detection rule.") from exc
