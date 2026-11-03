from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError

from core.authentication.service import hash_password, issue_token, verify_password
from core.database.models import AuditEvent, Tenant, User
from core.database.session import SessionFactory

router = APIRouter(prefix="/auth", tags=["identity and administration"])
ROLE_DESCRIPTIONS = {
    "admin": "Manage identity, policy, integrations, and all tenant operations.",
    "security_engineer": "Manage detections, intelligence, AI workflows, and request consequential actions.",
    "analyst": "Read telemetry, hunt, investigate, and request consequential actions.",
    "approver": "Review requests, investigate incidents, and dispatch configured SOAR work.",
    "auditor": "Read platform data and run security assurance evaluations.",
}


class LoginRequest(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=20, max_length=256)
    role: Literal["admin", "security_engineer", "analyst", "approver", "auditor"]
    tenant_id: str = Field(default="default", min_length=1, max_length=100)


class UserUpdate(BaseModel):
    role: Literal["admin", "security_engineer", "analyst", "approver", "auditor"] | None = None
    is_active: bool | None = None


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _user_view(user: User, tenant_slug: str) -> dict:
    return {"id": str(user.id), "email": user.email, "role": user.role, "tenant_id": tenant_slug, "is_active": user.is_active}


async def _audit(session, actor: str, action: str, resource_type: str, resource_id: str | None, tenant_id: str | None, details: dict | None = None):
    session.add(AuditEvent(id=uuid4(), actor=actor, action=action, resource_type=resource_type,
                           resource_id=resource_id, tenant_id=tenant_id, details=details or {}))


@router.post("/login")
async def login(payload: LoginRequest) -> dict:
    email = str(payload.email).strip().lower()
    async with SessionFactory() as session:
        user = await session.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
        if user is None or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Email or password is incorrect.")
        tenant = await session.get(Tenant, user.tenant_id)
        if tenant is None or not tenant.is_active:
            raise HTTPException(status_code=403, detail="This account's tenant is disabled.")
        token, expires_in = issue_token(user, tenant.slug)
        await _audit(session, email, "auth.login", "user", str(user.id), tenant.slug)
        await session.commit()
        return {"access_token": token, "token_type": "bearer", "expires_in": expires_in, "user": _user_view(user, tenant.slug)}


@router.get("/me")
async def me(request: Request) -> dict:
    return request.state.principal


@router.get("/users")
async def list_users(tenant_id: str = Query(default="default")) -> list[dict]:
    async with SessionFactory() as session:
        rows = (await session.execute(select(User, Tenant.slug).join(Tenant, Tenant.id == User.tenant_id)
                  .where(Tenant.slug == tenant_id).order_by(User.email))).all()
        return [_user_view(user, slug) for user, slug in rows]


@router.post("/users", status_code=201)
async def create_user(payload: UserCreate, request: Request) -> dict:
    async with SessionFactory() as session:
        tenant = await session.scalar(select(Tenant).where(Tenant.slug == payload.tenant_id, Tenant.is_active.is_(True)))
        if tenant is None:
            raise HTTPException(status_code=404, detail="Active tenant not found.")
        user = User(id=uuid4(), tenant_id=tenant.id, email=str(payload.email).lower(),
                    password_hash=hash_password(payload.password), role=payload.role, is_active=True)
        session.add(user)
        try:
            await session.flush()
            await _audit(session, request.state.principal["email"], "identity.user_created",
                         "user", str(user.id), tenant.slug, {"role": user.role})
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="An account with that email already exists.") from exc
        return _user_view(user, tenant.slug)


@router.patch("/users/{user_id}")
async def update_user(user_id: UUID, payload: UserUpdate, request: Request) -> dict:
    if str(user_id) == request.state.principal["id"]:
        raise HTTPException(status_code=409, detail="Administrators cannot change their own role or status.")
    async with SessionFactory() as session:
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        tenant = await session.get(Tenant, user.tenant_id)
        changes = payload.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=422, detail="Specify a role or active status change.")
        for key, value in changes.items():
            setattr(user, key, value)
        await _audit(session, request.state.principal["email"], "identity.user_updated",
                     "user", str(user.id), tenant.slug if tenant else None, changes)
        await session.commit()
        return _user_view(user, tenant.slug if tenant else "unknown")


@router.get("/roles")
async def list_roles() -> list[dict]:
    return [{"name": name, "description": description} for name, description in ROLE_DESCRIPTIONS.items()]


@router.get("/tenants")
async def list_tenants() -> list[dict]:
    async with SessionFactory() as session:
        rows = (await session.scalars(select(Tenant).order_by(Tenant.slug))).all()
        return [{"id": str(row.id), "slug": row.slug, "name": row.name, "is_active": row.is_active} for row in rows]


@router.post("/tenants", status_code=201)
async def create_tenant(payload: TenantCreate, request: Request) -> dict:
    async with SessionFactory() as session:
        tenant = Tenant(id=uuid4(), name=payload.name, slug=payload.slug, is_active=True)
        session.add(tenant)
        try:
            await session.flush()
            await _audit(session, request.state.principal["email"], "identity.tenant_created",
                         "tenant", str(tenant.id), tenant.slug)
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="A tenant with that name or slug already exists.") from exc
        return {"id": str(tenant.id), "slug": tenant.slug, "name": tenant.name, "is_active": tenant.is_active}


@router.get("/integrations")
async def list_integrations() -> list[dict]:
    from core.config.settings import get_settings
    settings = get_settings()
    return [
        {"name": "OPA policy engine", "kind": "authorization", "configured": True, "status": "enforcing"},
        {"name": "Generic SOAR webhook", "kind": "soar", "configured": bool(settings.soar_webhook_url),
         "status": "ready" if settings.soar_webhook_url else "not_configured"},
        {"name": "Elasticsearch", "kind": "data", "configured": bool(settings.elasticsearch_url), "status": "configured"},
        {"name": "Ollama", "kind": "model_provider", "configured": True, "status": "local"},
    ]


@router.get("/audit")
async def list_audit_events(tenant_id: str = Query(default="default"), limit: int = Query(default=100, ge=1, le=500)) -> list[dict]:
    async with SessionFactory() as session:
        rows = (await session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
                   .order_by(desc(AuditEvent.created_at)).limit(limit))).all()
        return [{"id": str(row.id), "tenant_id": row.tenant_id, "actor": row.actor, "action": row.action,
                 "resource_type": row.resource_type, "resource_id": row.resource_id,
                 "details": row.details, "created_at": row.created_at.isoformat()} for row in rows]
