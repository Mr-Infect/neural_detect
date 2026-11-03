from typing import Annotated, Any, Literal

from elastic_transport import TransportError
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config.settings import get_settings
from core.database.models import TelemetrySource
from core.database.session import get_session
from integrations.elasticsearch import (
    alert_service,
    dashboard_service,
    health,
    index_manager,
    search_service,
)
from integrations.elasticsearch.authentication import auth_configured
from integrations.elasticsearch.eql_service import execute_eql
from integrations.elasticsearch.esql_service import execute_esql

router = APIRouter(prefix="/telemetry", tags=["telemetry"])
SourceKind = Literal["windows_sysmon", "windows_eventlog", "linux_auditd", "linux_auth", "zeek", "suricata", "custom_beats"]

class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    kind: SourceKind
    dataset: str = Field(min_length=2, max_length=120, pattern=r"^[a-zA-Z0-9_.-]+$")
    configuration: dict[str, Any] = Field(default_factory=dict)

    @field_validator("configuration")
    @classmethod
    def reject_inline_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden = {"password", "token", "secret", "api_key", "apikey", "credential", "credentials"}
        def inspect(item: Any) -> None:
            if isinstance(item, dict):
                for key, nested in item.items():
                    if str(key).lower() in forbidden:
                        raise ValueError("Store credentials in a secret manager, not source configuration.")
                    inspect(nested)
            elif isinstance(item, list):
                for nested in item:
                    inspect(nested)
        inspect(value)
        return value

class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    index: str = "neural-detect-*"
    query: dict[str, Any] = Field(default_factory=lambda: {"match_all": {}})
    size: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=100000)

class EqlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    index: str = "neural-detect-*"
    query: str = Field(min_length=1, max_length=10000)

class EsqlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=10000)

@router.get("/sources")
async def get_sources(session: Annotated[AsyncSession, Depends(get_session)]) -> list[dict[str, Any]]:
    rows = (await session.scalars(select(TelemetrySource).order_by(TelemetrySource.created_at.desc()))).all()
    return [{"id": str(row.id), "name": row.name, "kind": row.kind, "dataset": row.dataset, "enabled": row.enabled, "created_at": row.created_at.isoformat()} for row in rows]

@router.post("/sources", status_code=201)
async def create_source(payload: SourceCreate, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    source = TelemetrySource(name=payload.name, kind=payload.kind, dataset=payload.dataset, configuration=payload.configuration)
    session.add(source)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="A telemetry source with that name already exists.") from exc
    await session.refresh(source)
    return {"id": str(source.id), "name": source.name, "kind": source.kind, "dataset": source.dataset, "enabled": source.enabled, "created_at": source.created_at.isoformat()}

@router.get("/indices")
async def telemetry_indices() -> list[dict[str, Any]]:
    try:
        return await index_manager.list_indices(get_settings().elasticsearch_index_pattern)
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Elasticsearch index discovery is unavailable.") from exc

@router.post("/search")
async def telemetry_search(payload: SearchRequest) -> dict[str, Any]:
    try:
        return await search_service.search(payload.index, payload.query, size=payload.size, offset=payload.offset)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Elasticsearch search is unavailable.") from exc

@router.post("/eql")
async def telemetry_eql(payload: EqlRequest) -> dict[str, Any]:
    try:
        return await execute_eql(payload.index, payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Elasticsearch EQL is unavailable.") from exc

@router.post("/esql")
async def telemetry_esql(payload: EsqlRequest) -> dict[str, Any]:
    try:
        return await execute_esql(payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Elasticsearch ES|QL is unavailable.") from exc

@router.get("/alerts")
async def telemetry_alerts(limit: int = Query(default=20, ge=1, le=100)) -> list[dict[str, Any]]:
    try:
        return await alert_service.recent_alerts(limit)
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Elasticsearch alert retrieval is unavailable.") from exc

@router.get("/health")
async def telemetry_health() -> dict[str, Any]:
    try:
        cluster = await health.cluster_health()
        indices = await index_manager.list_indices(get_settings().elasticsearch_index_pattern)
        return {"status": "ok", "authenticated": auth_configured(get_settings()), "cluster": cluster, "indices": len(indices)}
    except TransportError:
        return {"status": "unavailable", "authenticated": auth_configured(get_settings()), "cluster": None, "indices": 0}

@router.get("/dashboard/summary")
async def summary() -> dict[str, Any]:
    try:
        return await dashboard_service.dashboard_summary()
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Dashboard data is unavailable from Elasticsearch.") from exc
