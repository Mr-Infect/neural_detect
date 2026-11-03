from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from ai_engine.soc_agents.schemas import (
    HuntRequest,
    IncidentNoteRequest,
    IncidentStatusRequest,
    InvestigationRequest,
)
from ai_engine.soc_agents.service import soc_agent

router = APIRouter(tags=["soc-agents"])

@router.post("/hunt/query")
async def hunt(payload: HuntRequest):
    try: return await soc_agent.submit_hunt(payload)
    except (ValueError, ValidationError) as exc: raise HTTPException(422, detail=str(exc)) from exc
    except Exception as exc: raise HTTPException(503, detail="Hunt failed validation, model generation, or read-only execution.") from exc

@router.get("/hunt/jobs/{job_id}")
async def hunt_job(job_id: UUID, tenant_id: str = Query(default="default")):
    row = await soc_agent.get_hunt(job_id, tenant_id)
    if not row: raise HTTPException(404, detail="Hunt job not found.")
    return row

@router.get("/alerts")
async def alerts(limit: int = Query(default=25, ge=1, le=100), tenant_id: str = Query(default="default")):
    try: return {"items": await soc_agent.list_alerts(limit, tenant_id)}
    except Exception as exc: raise HTTPException(503, detail="Elastic Security alerts are unavailable.") from exc

@router.post("/alerts/{alert_id}/investigate")
async def investigate_alert(alert_id: str, payload: InvestigationRequest):
    try: return await soc_agent.investigate(payload.model_copy(update={"alert_id": alert_id}))
    except LookupError as exc: raise HTTPException(404, detail=str(exc)) from exc
    except (ValueError, ValidationError) as exc: raise HTTPException(422, detail=str(exc)) from exc
    except Exception as exc: raise HTTPException(503, detail="Alert investigation failed.") from exc

@router.post("/investigations")
async def create_investigation(payload: InvestigationRequest):
    try: return await soc_agent.investigate(payload)
    except LookupError as exc: raise HTTPException(404, detail=str(exc)) from exc
    except (ValueError, ValidationError) as exc: raise HTTPException(422, detail=str(exc)) from exc
    except Exception as exc: raise HTTPException(503, detail="Alert investigation failed.") from exc

@router.get("/investigations")
async def investigations(tenant_id: str = Query(default="default"), limit: int = Query(default=50, ge=1, le=100)):
    return {"items": await soc_agent.list_investigations(tenant_id, limit)}

@router.get("/investigations/{incident_id}")
async def investigation(incident_id: UUID, tenant_id: str = Query(default="default")):
    row = await soc_agent.get_investigation(incident_id, tenant_id)
    if not row: raise HTTPException(404, detail="Incident not found.")
    return row

@router.post("/investigations/{incident_id}/notes")
async def add_note(incident_id: UUID, payload: IncidentNoteRequest):
    row = await soc_agent.add_note(incident_id, payload.tenant_id, payload.author, payload.note)
    if not row: raise HTTPException(404, detail="Incident not found.")
    return row

@router.patch("/investigations/{incident_id}/status")
async def update_status(incident_id: UUID, payload: IncidentStatusRequest):
    row = await soc_agent.update_status(incident_id, payload.tenant_id, payload.actor, payload.status, payload.note)
    if not row: raise HTTPException(404, detail="Incident not found.")
    return row
