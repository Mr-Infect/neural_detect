from typing import Any

import httpx

from core.config.settings import get_settings


def _client_options() -> dict[str, Any]:
    settings = get_settings()
    if settings.elasticsearch_api_key:
        return {"headers": {"Authorization": f"ApiKey {settings.elasticsearch_api_key.get_secret_value()}"}}
    if settings.elasticsearch_username and settings.elasticsearch_password:
        return {"auth": (settings.elasticsearch_username, settings.elasticsearch_password.get_secret_value())}
    return {}


async def list_detection_rules(page: int = 1, per_page: int = 50) -> dict[str, Any]:
    settings = get_settings()
    async with httpx.AsyncClient(base_url=settings.kibana_url, timeout=15, **_client_options()) as client:
        response = await client.get(
            "/api/detection_engine/rules/_find",
            params={"page": page, "per_page": per_page},
            headers={"kbn-xsrf": "neural-detect"},
        )
        response.raise_for_status()
        return response.json()


async def create_detection_rule(payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    async with httpx.AsyncClient(base_url=settings.kibana_url, timeout=15, **_client_options()) as client:
        response = await client.post(
            "/api/detection_engine/rules", json=payload, headers={"kbn-xsrf": "neural-detect"}
        )
        response.raise_for_status()
        return response.json()