from __future__ import annotations

from typing import Any, Protocol

import httpx

from core.config.settings import get_settings


class SOARProvider(Protocol):
    async def dispatch(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class WebhookSOARProvider:
    """Generic signed webhook adapter. It sends no action unless configured."""

    async def dispatch(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        settings = get_settings()
        if not settings.soar_webhook_url:
            return {"accepted": False, "status": "not_configured", "event_type": event_type}
        headers = {"Content-Type": "application/json", "X-Neural-Detect-Event": event_type}
        if settings.soar_webhook_token:
            headers["Authorization"] = "Bearer " + settings.soar_webhook_token.get_secret_value()
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                settings.soar_webhook_url,
                json={"event_type": event_type, "payload": payload},
                headers=headers,
            )
        response.raise_for_status()
        return {"accepted": True, "status": "dispatched", "event_type": event_type,
                "provider_status": response.status_code}


soar_provider: SOARProvider = WebhookSOARProvider()
