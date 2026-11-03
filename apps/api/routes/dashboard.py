from typing import Any

from elastic_transport import TransportError
from fastapi import APIRouter, HTTPException, Query

from integrations.elasticsearch.dashboard_service import dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/summary")
async def get_dashboard_summary(tenant_id: str = Query(default="default", min_length=1, max_length=128)) -> dict[str, Any]:
    try:
        return await dashboard_summary(tenant_id)
    except TransportError as exc:
        raise HTTPException(status_code=503, detail="Dashboard data is unavailable from Elasticsearch.") from exc
