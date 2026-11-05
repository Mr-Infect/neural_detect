from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, select

from core.config.settings import get_settings
from core.database.models import ApprovalRequest, AuditEvent, DetectionRule
from core.database.session import SessionFactory
from detection_engine.deployment import build_kibana_payload
from integrations.elasticsearch.detection_api import create_detection_rule
from integrations.soar.provider import soar_provider

router = APIRouter(prefix="/automation", tags=["automation and approvals"])
ACTION_RISK = {
    "detection_deploy": "high",
    "ip_block": "high",
    "account_disable": "high",
    "endpoint_isolation": "critical",
    "incident_close": "high",
}
APPROVAL_ACTIONS = set(ACTION_RISK)


class ApprovalCreate(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    action_type: Literal["detection_deploy", "ip_block", "account_disable", "endpoint_isolation", "incident_close"]
    title: str = Field(min_length=4, max_length=240)
    description: str = Field(default="", max_length=4000)
    payload: dict = Field(default_factory=dict)
    expires_in_hours: int = Field(default=24, ge=1, le=72)


class ApprovalDecision(BaseModel):
    decision: Literal["approved", "rejected"]
    rejection_reason: str | None = Field(default=None, max_length=2000)


class SOARDispatchRequest(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    payload: dict = Field(default_factory=dict)


def _view(row: ApprovalRequest) -> dict:
    return {
        "id": str(row.id), "tenant_id": row.tenant_id, "action_type": row.action_type,
        "risk_level": row.risk_level, "title": row.title, "description": row.description,
        "payload": row.payload, "status": row.status, "requested_by": row.requested_by,
        "reviewer": row.reviewer, "rejection_reason": row.rejection_reason,
        "created_at": row.created_at.isoformat(), "expires_at": row.expires_at.isoformat(),
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "executed_at": row.executed_at.isoformat() if row.executed_at else None,
        "execution_result": row.execution_result,
    }


async def _audit(session, principal: dict, action: str, row: ApprovalRequest, details: dict | None = None):
    session.add(AuditEvent(
        id=uuid4(), tenant_id=row.tenant_id, actor=principal["email"], action=action,
        resource_type="approval_request", resource_id=str(row.id), details=details or {},
    ))


async def _expire_pending(session, tenant_id: str) -> None:
    now = datetime.now(UTC)
    rows = (await session.scalars(select(ApprovalRequest).where(
        ApprovalRequest.tenant_id == tenant_id,
        ApprovalRequest.status == "pending",
        ApprovalRequest.expires_at <= now,
    ))).all()
    for row in rows:
        row.status = "expired"
        session.add(AuditEvent(
            id=uuid4(), tenant_id=tenant_id, actor="system", action="approval.expired",
            resource_type="approval_request", resource_id=str(row.id), details={},
        ))


@router.get("/summary")
async def automation_summary(tenant_id: str = Query(default="default")) -> dict:
    async with SessionFactory() as session:
        await _expire_pending(session, tenant_id)
        rows = (await session.scalars(select(ApprovalRequest).where(
            ApprovalRequest.tenant_id == tenant_id
        ).order_by(desc(ApprovalRequest.created_at)).limit(200))).all()
        await session.commit()
    counts = {status: sum(row.status == status for row in rows)
              for status in ("pending", "approved", "rejected", "expired", "executed")}
    return {"tenant_id": tenant_id, "counts": counts, "recent": [_view(row) for row in rows[:20]],
            "consequential_actions_require_approval": True,
            "soar_configured": bool(get_settings().soar_webhook_url)}


@router.get("/approvals")
async def list_approvals(tenant_id: str = Query(default="default"), limit: int = Query(default=100, ge=1, le=500)) -> list[dict]:
    async with SessionFactory() as session:
        await _expire_pending(session, tenant_id)
        rows = (await session.scalars(select(ApprovalRequest).where(
            ApprovalRequest.tenant_id == tenant_id
        ).order_by(desc(ApprovalRequest.created_at)).limit(limit))).all()
        await session.commit()
        return [_view(row) for row in rows]


@router.post("/approvals", status_code=201)
async def request_approval(payload: ApprovalCreate, request: Request) -> dict:
    principal = request.state.principal
    if payload.tenant_id != principal["tenant_id"]:
        raise HTTPException(status_code=403, detail="Approval tenant must match the authenticated tenant.")
    async with SessionFactory() as session:
        row = ApprovalRequest(
            id=uuid4(), tenant_id=payload.tenant_id, action_type=payload.action_type,
            risk_level=ACTION_RISK[payload.action_type], title=payload.title,
            description=payload.description, payload=payload.payload, status="pending",
            requested_by=principal["email"],
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=payload.expires_in_hours),
        )
        session.add(row)
        await _audit(session, principal, "approval.requested", row, {"risk_level": row.risk_level})
        await session.commit()
        await session.refresh(row)
        return _view(row)


@router.post("/approvals/{approval_id}/review")
async def review_approval(approval_id: UUID, payload: ApprovalDecision, request: Request) -> dict:
    principal = request.state.principal
    async with SessionFactory() as session:
        row = await session.get(ApprovalRequest, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Approval request not found.")
        if row.requested_by.lower() == principal["email"].lower():
            raise HTTPException(status_code=403, detail="A different human reviewer must decide this request.")
        if row.status != "pending":
            raise HTTPException(status_code=409, detail="Only pending requests can be reviewed.")
        if row.expires_at <= datetime.now(UTC):
            row.status = "expired"
            await _audit(session, principal, "approval.expired", row)
            await session.commit()
            raise HTTPException(status_code=410, detail="The approval request has expired.")
        if payload.decision == "rejected" and not (payload.rejection_reason or "").strip():
            raise HTTPException(status_code=422, detail="A rejection reason is required.")
        row.status = payload.decision
        row.reviewer = principal["email"]
        row.rejection_reason = payload.rejection_reason.strip() if payload.rejection_reason else None
        row.reviewed_at = datetime.now(UTC)
        await _audit(session, principal, "approval." + payload.decision, row,
                     {"reason": row.rejection_reason} if row.rejection_reason else {})
        await session.commit()
        await session.refresh(row)
        return _view(row)


@router.post("/approvals/{approval_id}/execute")
async def execute_approved_action(approval_id: UUID, request: Request) -> dict:
    principal = request.state.principal
    async with SessionFactory() as session:
        row = await session.get(ApprovalRequest, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Approval request not found.")
        if row.status != "approved":
            raise HTTPException(status_code=409, detail="Only approved requests can be dispatched.")
        if row.expires_at <= datetime.now(UTC):
            row.status = "expired"
            await _audit(session, principal, "approval.expired", row)
            await session.commit()
            raise HTTPException(status_code=410, detail="The approval request has expired.")
        event = {
            "approval_id": str(row.id), "tenant_id": row.tenant_id, "action_type": row.action_type,
            "risk_level": row.risk_level, "title": row.title, "payload": row.payload,
            "requested_by": row.requested_by, "reviewer": row.reviewer,
        }
        if row.action_type == "detection_deploy":
            rule_id = row.payload.get("rule_id")
            if not rule_id:
                raise HTTPException(status_code=422, detail="detection_deploy approvals require payload.rule_id.")
            rule = await session.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
            if rule is None:
                raise HTTPException(status_code=404, detail="The approved detection rule no longer exists.")
            if row.payload.get("version") != rule.current_version:
                raise HTTPException(status_code=409, detail="The detection changed after approval; request a fresh approval.")
            try:
                dispatch_payload = build_kibana_payload(
                    rule_id=rule.rule_id, title=rule.title, description=rule.description,
                    deployment=rule.deployment or {}, metadata=rule.rule_metadata,
                )
            except (KeyError, ValueError) as exc:
                raise HTTPException(status_code=422, detail=f"Stored deployment is invalid: {exc}") from exc
            try:
                result = {"accepted": True, "status": "deployed", "deployment": await create_detection_rule(dispatch_payload)}
            except Exception as exc:
                raise HTTPException(status_code=502, detail="Kibana could not deploy the approved detection.") from exc
        else:
            try:
                result = await soar_provider.dispatch("approved_response_action", event)
            except Exception as exc:
                raise HTTPException(status_code=502, detail="Configured SOAR provider rejected the action.") from exc
            if not result.get("accepted"):
                raise HTTPException(status_code=409, detail="No SOAR action provider is configured; the request remains approved.")
        row.status = "executed"
        row.executed_at = datetime.now(UTC)
        row.execution_result = result
        await _audit(session, principal, "approval.executed", row, {"provider_status": result.get("provider_status")})
        await session.commit()
        await session.refresh(row)
        return _view(row)


@router.post("/soar/{operation}")
async def dispatch_soar(operation: Literal["incidents", "notifications", "enrichment"], payload: SOARDispatchRequest, request: Request) -> dict:
    event_types = {"incidents": "incident_create", "notifications": "notification", "enrichment": "threat_enrichment"}
    result = await soar_provider.dispatch(event_types[operation], {
        "tenant_id": payload.tenant_id, "requested_by": request.state.principal["email"],
        "payload": payload.payload,
    })
    async with SessionFactory() as session:
        session.add(AuditEvent(
            id=uuid4(), tenant_id=payload.tenant_id, actor=request.state.principal["email"],
            action="soar." + operation, resource_type="soar_dispatch",
            resource_id=None, details={"accepted": result.get("accepted", False), "status": result.get("status")},
        ))
        await session.commit()
    return result
