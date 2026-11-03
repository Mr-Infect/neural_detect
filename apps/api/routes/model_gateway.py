import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ai_engine.model_gateway.models import ModelEvaluation
from ai_engine.model_gateway.providers.openai_compatible import ProviderError
from ai_engine.model_gateway.router import RateLimitExceeded, gateway
from ai_engine.model_gateway.schemas import InferenceRequest
from core.database.session import get_session

router = APIRouter(prefix="/ai/models", tags=["ai-model-gateway"])


@router.get("/providers")
async def get_providers() -> list[dict[str, Any]]:
    return await gateway.provider_status()


@router.post("/infer")
async def infer_model(
    payload: InferenceRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    started = time.perf_counter()
    provider_name = payload.provider or "configured-default"
    model_name = payload.model or "configured-default"
    try:
        result = await gateway.infer(
            tenant_id=payload.tenant_id,
            prompt=payload.prompt,
            output_kind=payload.output_kind,
            provider_name=payload.provider,
            model=payload.model,
            fallback_providers=payload.fallback_providers,
            cloud_consent=payload.cloud_consent,
            contains_raw_telemetry=payload.contains_raw_telemetry,
            max_response_tokens=payload.max_response_tokens,
        )
        provider_name, model_name = result.provider, result.model
        session.add(ModelEvaluation(
            tenant_id=payload.tenant_id,
            provider=result.provider,
            model_name=result.model,
            model_version=result.model_version,
            output_kind=payload.output_kind,
            latency_ms=result.latency_ms,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            output_valid=True,
            evaluation_result={"redacted_categories": list(result.redacted_categories), "cost_usd": result.cost.estimated_usd},
        ))
        await session.commit()
        return {
            "provider": result.provider,
            "model": result.model,
            "model_version": result.model_version,
            "latency_ms": result.latency_ms,
            "usage": {"prompt_tokens": result.prompt_tokens, "completion_tokens": result.completion_tokens},
            "cost_usd": result.cost.estimated_usd,
            "redacted_categories": list(result.redacted_categories),
            "output": result.output.model_dump(),
        }
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ProviderError as exc:
        await session.rollback()
        session.add(ModelEvaluation(
            tenant_id=payload.tenant_id,
            provider=provider_name,
            model_name=model_name,
            model_version=None,
            output_kind=payload.output_kind,
            latency_ms=int((time.perf_counter() - started) * 1000),
            prompt_tokens=None,
            completion_tokens=None,
            output_valid=False,
            error_code=exc.code,
            evaluation_result={},
        ))
        await session.commit()
        raise HTTPException(status_code=502, detail={"code": exc.code, "message": str(exc)}) from exc


@router.get("/evaluations")
async def get_evaluations(
    session: Annotated[AsyncSession, Depends(get_session)],
    tenant_id: str = Query(default="default", min_length=1, max_length=128),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    rows = (await session.scalars(
        select(ModelEvaluation).where(ModelEvaluation.tenant_id == tenant_id)
        .order_by(ModelEvaluation.created_at.desc()).limit(limit)
    )).all()
    return [{
        "id": str(row.id), "provider": row.provider, "model": row.model_name,
        "model_version": row.model_version, "output_kind": row.output_kind,
        "latency_ms": row.latency_ms, "prompt_tokens": row.prompt_tokens,
        "completion_tokens": row.completion_tokens, "output_valid": row.output_valid,
        "error_code": row.error_code, "evaluation_result": row.evaluation_result,
        "created_at": row.created_at.isoformat(),
    } for row in rows]
