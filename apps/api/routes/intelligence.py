from typing import Any

from fastapi import APIRouter, HTTPException, Query
from httpx import HTTPError
from sqlalchemy import desc, select

from ai_engine.intelligence.models import IntelDatasetVersion, IntelSyncRun
from ai_engine.intelligence.schemas import IntelIngestRequest, IntelSearchRequest, IntelSyncRequest
from ai_engine.intelligence.service import intelligence
from core.database.session import SessionFactory

router = APIRouter(prefix="/intelligence", tags=["threat-intelligence"])


@router.post("/ingest")
async def ingest(payload: IntelIngestRequest) -> dict[str, Any]:
    try:
        return await intelligence.ingest(payload)
    except (ValueError, HTTPError) as exc:
        raise HTTPException(422 if isinstance(exc, ValueError) else 503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, detail="Threat intelligence ingestion failed.") from exc


@router.post("/sync")
async def sync(payload: IntelSyncRequest) -> dict[str, Any]:
    try:
        return await intelligence.sync(payload)
    except (ValueError, HTTPError) as exc:
        raise HTTPException(422 if isinstance(exc, ValueError) else 502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, detail="Threat intelligence sync failed.") from exc


@router.get("/indicators")
async def indicators(
    tenant_id: str = Query(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
    indicator_type: str | None = Query(default=None, max_length=32),
    value: str | None = Query(default=None, max_length=2048),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    return {"items": await intelligence.indicators(tenant_id, indicator_type, value, limit)}


@router.get("/techniques")
async def techniques(
    q: str | None = Query(default=None, max_length=200),
    tactic: str | None = Query(default=None, max_length=80),
    domain: str = Query(default="enterprise-attack", pattern=r"^[a-z-]{3,40}$"),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    return {"items": await intelligence.techniques(q, tactic, domain, limit)}


@router.post("/search")
async def search(payload: IntelSearchRequest) -> dict[str, Any]:
    try:
        return await intelligence.search(payload)
    except HTTPError as exc:
        raise HTTPException(503, detail="Local embedding, Qdrant, or Elasticsearch search is unavailable.") from exc
    except Exception as exc:
        raise HTTPException(503, detail="Threat intelligence search is unavailable.") from exc


@router.get("/versions")
async def versions() -> dict[str, Any]:
    async with SessionFactory() as session:
        rows = (await session.scalars(select(IntelDatasetVersion).where(IntelDatasetVersion.current.is_(True)).order_by(desc(IntelDatasetVersion.retrieved_at)))).all()
        runs = (await session.scalars(select(IntelSyncRun).order_by(desc(IntelSyncRun.started_at)).limit(20))).all()
    return {
        "datasets": [{"dataset": r.dataset, "version": r.version, "content_hash": r.content_hash,
                      "source_url": r.source_url, "retrieved_at": r.retrieved_at} for r in rows],
        "recent_syncs": [{"id": str(r.id), "source": r.source_name, "status": r.status,
                          "version": r.source_version, "objects_seen": r.objects_seen,
                          "documents_written": r.documents_written, "error": r.error_message,
                          "started_at": r.started_at, "completed_at": r.completed_at} for r in runs],
    }
