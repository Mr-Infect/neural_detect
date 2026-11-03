from __future__ import annotations

import json
from uuid import UUID

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from core.authentication.service import decode_token
from core.config.settings import get_settings
from core.database.models import Tenant, User
from core.database.session import SessionFactory

PUBLIC_PATHS={"/health","/api/v1/health","/api/v1/health/dependencies","/api/v1/system/info","/api/v1/auth/login","/openapi.json","/docs","/docs/oauth2-redirect","/redoc"}
def _category(method:str,path:str)->str:
    if path.startswith("/api/v1/auth/"):
        return "admin" if any(x in path for x in ("/users","/roles","/tenants","/integrations","/audit")) else "read"
    if "/approvals/" in path and path.endswith("/review"): return "approval_review"
    if path.startswith("/api/v1/detections/") and path.endswith("/approvals"): return "approval_request"
    if path.startswith("/api/v1/automation/approvals"):
        if path.endswith("/review"): return "approval_review"
        if path.endswith("/execute"): return "response_execute"
        return "approval_request" if method=="POST" else "read"
    if path.startswith("/api/v1/automation/soar"): return "soar"
    if path.startswith(("/api/v1/detections","/api/v1/detection-lifecycle")): return "detection_write" if method in {"POST","PATCH","DELETE"} else "read"
    if path.startswith("/api/v1/soc-agents"): return "incident_write" if method in {"POST","PATCH","DELETE"} else "read"
    if path.startswith("/api/v1/ai-security"): return "ai_eval" if method=="POST" else "read"
    if path.startswith("/api/v1/ai/detection"): return "detection_write"
    if path.startswith("/api/v1/ai/"): return "ai_eval" if method=="POST" else "read"
    if path.startswith("/api/v1/intelligence"): return "intel_write" if method=="POST" else "read"
    if path.startswith("/api/v1/telemetry"): return "telemetry_write" if method in {"POST","PATCH","DELETE"} else "read"
    return "read" if method in {"GET","HEAD","OPTIONS"} else "operator_write"
def _request_tenant(path:str,query:dict,body:object)->str|None:
    vals=[]
    if query.get("tenant_id"): vals.append(query["tenant_id"])
    if isinstance(body,dict) and isinstance(body.get("tenant_id"),str): vals.append(body["tenant_id"])
    scoped = ("/api/v1/ai-security", "/api/v1/ai/", "/api/v1/soc-agents",
              "/api/v1/intelligence", "/api/v1/automation", "/api/v1/auth/audit",
              "/api/v1/telemetry", "/api/v1/dashboard")
    if not vals and path.startswith(scoped): vals.append("default")
    return vals[-1] if vals else None
async def authorize_request(request:Request,call_next):
    path=request.url.path
    if path in PUBLIC_PATHS or path.startswith("/assets/"): return await call_next(request)
    authorization=request.headers.get("authorization","")
    if not authorization.lower().startswith("bearer "): return JSONResponse({"detail":"Sign in is required."},status_code=401)
    try: claims=decode_token(authorization[7:].strip()); user_id=UUID(claims["sub"])
    except ValueError: return JSONResponse({"detail":"The access token is invalid or expired."},status_code=401)
    async with SessionFactory() as session:
        user=await session.scalar(select(User).where(User.id==user_id,User.is_active.is_(True)))
        if user is None: return JSONResponse({"detail":"The account is disabled or no longer exists."},status_code=401)
        tenant=await session.get(Tenant,user.tenant_id)
        if tenant is None or not tenant.is_active: return JSONResponse({"detail":"The account tenant is disabled."},status_code=403)
    body={}
    if request.method not in {"GET","HEAD","OPTIONS"} and "application/json" in request.headers.get("content-type",""):
        try:
            raw=await request.body(); body=json.loads(raw) if raw else {}
            sent=False
            async def replay():
                nonlocal sent
                if sent: return {"type":"http.request","body":b"","more_body":False}
                sent=True; return {"type":"http.request","body":raw,"more_body":False}
            request._receive=replay
        except (json.JSONDecodeError,UnicodeDecodeError): body={}
    tenant_scope=_request_tenant(path,dict(request.query_params),body) or tenant.slug
    if tenant_scope!=tenant.slug and user.role!="admin": return JSONResponse({"detail":"The requested tenant is outside your authenticated scope."},status_code=403)
    payload={"input":{"principal":{"sub":str(user.id),"email":user.email,"role":user.role,"tenant_id":tenant.slug},"action":{"method":request.method,"path":path,"category":_category(request.method,path)},"resource":{"tenant_id":tenant_scope}}}
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            response=await client.post(f"{get_settings().opa_url}/v1/data/neural_detect/authz/allow",json=payload)
            response.raise_for_status(); allowed=response.json().get("result") is True
    except (httpx.HTTPError,ValueError): return JSONResponse({"detail":"Authorization service is unavailable; request denied."},status_code=503)
    if not allowed: return JSONResponse({"detail":"Your role is not allowed to perform this action."},status_code=403)
    request.state.principal={"id":str(user.id),"email":user.email,"role":user.role,"tenant_id":tenant.slug}
    return await call_next(request)
