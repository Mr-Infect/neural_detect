import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ai_engine.detection_agent.service import agent
from ai_engine.model_gateway.router import gateway
from apps.api.routes.ai_security import router as ai_security_router
from apps.api.routes.dashboard import router as dashboard_router
from apps.api.routes.detection_agent import router as detection_agent_router
from apps.api.routes.detection_lifecycle import router as detection_lifecycle_router
from apps.api.routes.detections import router as detections_router
from apps.api.routes.intelligence import router as intelligence_router
from apps.api.routes.model_gateway import router as model_gateway_router
from apps.api.routes.soc_agents import router as soc_agents_router
from apps.api.routes.telemetry import router as telemetry_router
from core.config.settings import get_settings
from core.database.session import SessionFactory, engine
from integrations.elasticsearch.client import close_client

settings = get_settings()
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(_: FastAPI):
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level.upper(), logging.INFO)
        )
    )
    await agent.start(settings.database_url, settings.secret_key.get_secret_value())
    yield
    await agent.close()
    await close_client()
    await gateway.close()
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    version="0.8.0",
    description="Local-first AI detection engineering platform API.",
    lifespan=lifespan,
)
app.include_router(telemetry_router, prefix=settings.api_prefix)
app.include_router(dashboard_router, prefix=settings.api_prefix)
app.include_router(detections_router, prefix=settings.api_prefix)
app.include_router(detection_lifecycle_router, prefix=settings.api_prefix)
app.include_router(model_gateway_router, prefix=settings.api_prefix)
app.include_router(detection_agent_router, prefix=settings.api_prefix)
app.include_router(soc_agents_router, prefix=settings.api_prefix)
app.include_router(intelligence_router, prefix=settings.api_prefix)
app.include_router(ai_security_router, prefix=settings.api_prefix)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    request_id = request.headers.get("x-request-id", "unassigned")
    log.exception("unhandled_request_error", request_id=request_id, path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "Request failed.",
                "request_id": request_id,
            }
        },
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get(f"{settings.api_prefix}/health")
async def api_health() -> dict[str, str]:
    return {"status": "ok", "version": app.version}


@app.get(f"{settings.api_prefix}/system/info")
async def system_info() -> dict[str, str]:
    return {"name": settings.app_name, "version": app.version, "environment": settings.environment}


@app.get(f"{settings.api_prefix}/health/dependencies")
async def dependency_health() -> dict[str, str]:
    try:
        async with SessionFactory() as session:
            await session.execute(text("SELECT 1"))
        database = "ok"
    except SQLAlchemyError:
        database = "unavailable"
    return {"database": database}
