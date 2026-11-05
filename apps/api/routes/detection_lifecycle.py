from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.database.models import AuditEvent, DetectionApproval, DetectionRule, DetectionRuleVersion
from core.database.session import get_session
from detection_engine.compiler.native import compile_native
from detection_engine.converters.pysigma import compile_sigma
from detection_engine.deployment import build_kibana_payload
from detection_engine.testing.runner import run_fixture_tests
from detection_engine.validators.sigma import validate_sigma_source
from integrations.elasticsearch.detection_api import create_detection_rule

router = APIRouter(prefix="/detections", tags=["detection-as-code"])
FORMATS = {"sigma", "esql", "eql", "kql", "threshold"}


class DetectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_yaml: str | None = Field(default=None, max_length=64_000)
    format: Literal["sigma", "esql", "eql", "kql", "threshold"] = "sigma"
    rule_id: str | None = Field(default=None, min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    title: str | None = Field(default=None, min_length=3, max_length=256)
    description: str | None = Field(default=None, min_length=3, max_length=2000)
    query: str | dict[str, Any] | None = None
    index: list[str] = Field(default_factory=lambda: ["neural-detect-*"], min_length=1, max_length=10)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_yaml: str | None = Field(default=None, max_length=64_000)
    query: str | dict[str, Any] | None = None
    title: str | None = Field(default=None, min_length=3, max_length=256)
    description: str | None = Field(default=None, min_length=3, max_length=2000)
    metadata: dict[str, Any] | None = None


class FixtureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    positive: list[dict[str, Any]] = Field(min_length=1, max_length=20)
    negative: list[dict[str, Any]] = Field(min_length=1, max_length=20)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requested_by: str = Field(min_length=2, max_length=256)


class ApprovalReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reviewer: str | None = Field(default=None, min_length=2, max_length=256)
    decision: Literal["approved", "rejected"]
    note: str | None = Field(default=None, max_length=2000)


def _compile(payload: DetectionCreate | DetectionPatch, current: DetectionRule | None = None) -> dict[str, Any]:
    rule_format = current.rule_format if current else payload.format
    source = payload.source_yaml if payload.source_yaml is not None else (current.source_yaml if current else None)
    query = payload.query if payload.query is not None else (current.native_query if current else None)
    if rule_format == "sigma":
        if source is None:
            raise ValueError("Sigma rules require source_yaml.")
        document, stable_id = validate_sigma_source(source)
        compiled = compile_sigma(source)
        metadata = {**document, **(payload.metadata or {})}
        title = payload.title or document["title"]
        description = payload.description or document["description"]
        index = payload.index if not current else current.deployment.get("index", ["neural-detect-*"])
        deployment = {**compiled["deployment"], "index": index, "enabled": False}
        rule_id = current.rule_id if current else stable_id
        if current and stable_id != current.rule_id:
            raise ValueError("A rule update cannot change its stable Sigma UUID.")
    else:
        if query is None:
            raise ValueError(f"{rule_format} rules require query.")
        metadata = {**(current.rule_metadata if current else {}), **(payload.metadata or {})}
        if current:
            title = payload.title or current.title
            description = payload.description or current.description
            index = current.deployment.get("index", ["neural-detect-*"])
            rule_id = current.rule_id
        else:
            if not payload.rule_id or not payload.title or not payload.description:
                raise ValueError("Native rules require rule_id, title, and description.")
            title, description, index, rule_id = payload.title, payload.description, payload.index, payload.rule_id
        result = compile_native(rule_format, query, index)
        compiled_query = result["compiled_query"]
        deployment = result["deployment"]
        metadata.setdefault("index", index)
        metadata.setdefault("severity", "medium")
        metadata.setdefault("tags", [])
        return {
            "rule_id": rule_id, "title": title, "description": description, "rule_format": rule_format,
            "source_yaml": None, "native_query": query, "compiled_query": compiled_query,
            "deployment": deployment, "rule_metadata": metadata,
        }
    return {
        "rule_id": rule_id, "title": title, "description": description, "rule_format": "sigma",
        "source_yaml": source, "native_query": None, "compiled_query": compiled["compiled_query"],
        "deployment": deployment, "rule_metadata": metadata,
    }


def _serialize(rule: DetectionRule) -> dict[str, Any]:
    return {
        "id": str(rule.id), "rule_id": rule.rule_id, "title": rule.title, "description": rule.description,
        "format": rule.rule_format, "source_yaml": rule.source_yaml, "query": rule.native_query,
        "compiled_query": rule.compiled_query, "deployment": rule.deployment, "metadata": rule.rule_metadata,
        "version": rule.current_version, "created_at": rule.created_at.isoformat(), "updated_at": rule.updated_at.isoformat(),
    }


async def _load(rule_id: UUID, session: AsyncSession) -> DetectionRule:
    rule = await session.scalar(select(DetectionRule).where(DetectionRule.id == rule_id))
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found.")
    return rule


async def _save_version(rule: DetectionRule, session: AsyncSession) -> None:
    session.add(DetectionRuleVersion(
        detection_rule_id=rule.id, version=rule.current_version, source_yaml=rule.source_yaml,
        native_query=rule.native_query, compiled_query=rule.compiled_query, deployment=rule.deployment,
        rule_metadata=rule.rule_metadata,
    ))


@router.get("")
async def list_detections(session: Annotated[AsyncSession, Depends(get_session)]) -> list[dict[str, Any]]:
    rules = (await session.scalars(select(DetectionRule).order_by(DetectionRule.title))).all()
    return [_serialize(rule) for rule in rules]


@router.post("", status_code=201)
async def create_detection(payload: DetectionCreate, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    try:
        fields = _compile(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    rule = DetectionRule(**fields)
    session.add(rule)
    try:
        await session.flush()
        await _save_version(rule, session)
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="A detection with that stable rule ID already exists.") from exc
    await session.refresh(rule)
    return _serialize(rule)


@router.get("/{rule_id}")
async def get_detection(rule_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    return _serialize(await _load(rule_id, session))


@router.patch("/{rule_id}")
async def patch_detection(rule_id: UUID, payload: DetectionPatch, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    rule = await _load(rule_id, session)
    values = _compile(payload, rule)
    rule.current_version += 1
    for field, value in values.items():
        setattr(rule, field if field != "metadata" else "rule_metadata", value)
    try:
        await _save_version(rule, session)
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Detection update conflicts with a stored rule.") from exc
    await session.refresh(rule)
    return _serialize(rule)


@router.post("/{rule_id}/validate")
async def validate_detection(rule_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    rule = await _load(rule_id, session)
    try:
        if rule.rule_format == "sigma":
            _, stable_id = validate_sigma_source(rule.source_yaml or "")
            if stable_id != rule.rule_id:
                raise ValueError("Stored Sigma id no longer matches the stable rule ID.")
            compiled = compile_sigma(rule.source_yaml or "")
        else:
            compiled = compile_native(rule.rule_format, rule.native_query, rule.deployment["index"])
        return {"valid": True, "rule_id": rule.rule_id, "format": rule.rule_format, "compiled_query": compiled.get("compiled_query", compiled.get("compiled_query"))}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{rule_id}/compile")
async def compile_detection(rule_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    rule = await _load(rule_id, session)
    return {"rule_id": rule.rule_id, "format": rule.rule_format, "source": rule.source_yaml, "query": rule.compiled_query, "deployment": rule.deployment}


@router.get("/{rule_id}/export")
async def export_detection(rule_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]) -> Response:
    rule = await _load(rule_id, session)
    if not rule.source_yaml:
        raise HTTPException(status_code=409, detail="Only Sigma rules have a YAML source export.")
    return Response(rule.source_yaml, media_type="application/yaml", headers={"Content-Disposition": f'attachment; filename="{rule.rule_id}.yml"'})


@router.post("/{rule_id}/test")
async def test_detection(rule_id: UUID, fixtures: FixtureRequest, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    rule = await _load(rule_id, session)
    compiled = rule.compiled_query
    if rule.rule_format == "sigma":
        compiled = str(compiled)
    try:
        return await run_fixture_tests(rule.rule_format, compiled, fixtures.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{rule_id}/approvals")
async def list_approvals(rule_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]) -> list[dict[str, Any]]:
    rule = await _load(rule_id, session)
    rows = (await session.scalars(
        select(DetectionApproval).where(DetectionApproval.detection_rule_id == rule.id)
        .order_by(DetectionApproval.created_at.desc()).limit(20)
    )).all()
    now = datetime.now(UTC)
    return [{
        "id": str(row.id), "status": "expired" if row.status in {"pending", "approved"} and row.expires_at <= now else row.status,
        "rule_version": row.rule_version, "current_version": rule.current_version,
        "requested_by": row.requested_by, "reviewer": row.reviewer, "decision_note": row.decision_note,
        "created_at": row.created_at.isoformat(), "expires_at": row.expires_at.isoformat(),
    } for row in rows]


@router.post("/{rule_id}/approvals", status_code=201)
async def request_approval(rule_id: UUID, payload: ApprovalRequest, request: Request, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    rule = await _load(rule_id, session)
    approval = DetectionApproval(
        detection_rule_id=rule.id, requested_by=request.state.principal["email"],
        rule_version=rule.current_version, status="pending",
        expires_at=datetime.now(UTC) + timedelta(hours=24),
    )
    session.add(approval)
    await session.flush()
    session.add(AuditEvent(
        actor=request.state.principal["email"], tenant_id=request.state.principal["tenant_id"],
        action="detection.approval_requested", resource_type="detection_approval",
        resource_id=str(approval.id), details={"rule_id": rule.rule_id, "version": rule.current_version},
    ))
    await session.commit()
    await session.refresh(approval)
    return {"id": str(approval.id), "rule_id": rule.rule_id, "status": approval.status, "rule_version": approval.rule_version, "expires_at": approval.expires_at.isoformat()}


@router.post("/approvals/{approval_id}/review")
async def review_approval(
    approval_id: UUID,
    payload: ApprovalReview,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    approval = await session.get(DetectionApproval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    principal = request.state.principal
    if approval.requested_by.lower() == principal["email"].lower():
        raise HTTPException(status_code=403, detail="A different human reviewer must decide this request.")
    if approval.status != "pending" or approval.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=409, detail="Approval is no longer pending or has expired.")
    if payload.decision == "rejected" and not (payload.note or "").strip():
        raise HTTPException(status_code=422, detail="A rejection reason is required.")
    approval.status = payload.decision
    approval.reviewer = principal["email"]
    approval.decision_note = payload.note
    approval.reviewed_at = datetime.now(UTC)
    session.add(AuditEvent(actor=principal["email"], tenant_id=principal["tenant_id"],
        action="detection.approval_" + payload.decision, resource_type="detection_approval",
        resource_id=str(approval.id), details={"reason": payload.note}))
    await session.commit()
    return {"id": str(approval.id), "status": approval.status, "reviewer": approval.reviewer, "reviewed_at": approval.reviewed_at.isoformat()}


@router.post("/{rule_id}/deploy")
async def deploy_detection(rule_id: UUID, approval_id: UUID, request: Request, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    rule = await _load(rule_id, session)
    approval = await session.get(DetectionApproval, approval_id)
    if approval is None or approval.detection_rule_id != rule.id:
        raise HTTPException(status_code=403, detail="A matching approved deployment request is required.")
    if approval.status != "approved" or approval.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=403, detail="A non-expired approved deployment request is required.")
    if approval.rule_version != rule.current_version:
        raise HTTPException(status_code=409, detail="Approval was issued for an older rule version; request a new approval.")
    try:
        payload = build_kibana_payload(
            rule_id=rule.rule_id, title=rule.title, description=rule.description,
            deployment=rule.deployment or {}, metadata=rule.rule_metadata,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Stored deployment is invalid: {exc}") from exc
    try:
        deployed = await create_detection_rule(payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Kibana could not deploy the approved detection.") from exc
    approval.status = "deployed"
    session.add(AuditEvent(actor=request.state.principal["email"],
        tenant_id=request.state.principal["tenant_id"], action="detection.deployed",
        resource_type="detection_rule", resource_id=str(rule.id),
        details={"approval_id": str(approval.id), "rule_id": rule.rule_id}))
    await session.commit()
    return {"rule_id": rule.rule_id, "approval_id": str(approval.id), "deployment": deployed}