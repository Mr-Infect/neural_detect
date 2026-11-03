from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from core.config.settings import get_settings
from core.database.models import Tenant, User
from core.database.session import SessionFactory

TOKEN_TTL_SECONDS = 8 * 60 * 60
PBKDF2_ITERATIONS = 310_000
def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
def hash_password(password: str) -> str:
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,PBKDF2_ITERATIONS)
    return "pbkdf2_sha256:"+str(PBKDF2_ITERATIONS)+":"+_b64(salt)+":"+_b64(digest)
def verify_password(password: str,encoded: str) -> bool:
    try:
        scheme,iterations,salt,expected=encoded.split(":",3)
        if scheme!="pbkdf2_sha256": return False
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),_unb64(salt),int(iterations))
        return hmac.compare_digest(_b64(actual),expected)
    except (ValueError,TypeError): return False
def issue_token(user: User,tenant_slug: str) -> tuple[str,int]:
    now=int(datetime.now(UTC).timestamp())
    payload={"sub":str(user.id),"email":user.email,"role":user.role,"tenant_id":tenant_slug,"iat":now,"exp":now+TOKEN_TTL_SECONDS}
    header=_b64(b'{"alg":"HS256","typ":"JWT"}')
    message=header+"."+_b64(json.dumps(payload,separators=(",",":")).encode())
    secret=get_settings().secret_key.get_secret_value().encode()
    return message+"."+_b64(hmac.new(secret,message.encode(),hashlib.sha256).digest()),TOKEN_TTL_SECONDS
def decode_token(token: str) -> dict:
    try:
        header,payload,signature=token.split("."); message=header+"."+payload
        secret=get_settings().secret_key.get_secret_value().encode()
        expected=_b64(hmac.new(secret,message.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(signature,expected): raise ValueError
        claims=json.loads(_unb64(payload)); now=int(datetime.now(UTC).timestamp())
        if claims.get("exp",0)<=now or claims.get("iat",now+1)>now: raise ValueError
        UUID(claims["sub"]); return claims
    except (ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        raise ValueError("Invalid or expired access token.") from exc
async def ensure_bootstrap_admin() -> None:
    settings=get_settings(); email=settings.bootstrap_admin_email.strip().lower()
    password=settings.bootstrap_admin_password.get_secret_value()
    if not email or len(password)<20:
        raise RuntimeError("Configure ND_BOOTSTRAP_ADMIN_EMAIL and a generated ND_BOOTSTRAP_ADMIN_PASSWORD (20+ characters).")
    async with SessionFactory() as session:
        tenant=await session.scalar(select(Tenant).where(Tenant.slug=="default"))
        if tenant is None:
            tenant=Tenant(name="Default",slug="default",is_active=True); session.add(tenant); await session.flush()
        user=await session.scalar(select(User).where(User.email==email))
        if user is None:
            session.add(User(email=email,password_hash=hash_password(password),tenant_id=tenant.id,role="admin",is_active=True))
            await session.commit()
        elif not user.is_active:
            raise RuntimeError("Bootstrap administrator is disabled; enable it through an administrator account.")
