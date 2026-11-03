from typing import Any

from core.config.settings import Settings


def client_auth_kwargs(settings: Settings) -> dict[str, Any]:
    if settings.elasticsearch_api_key:
        return {"api_key": settings.elasticsearch_api_key.get_secret_value()}
    if settings.elasticsearch_username and settings.elasticsearch_password:
        return {"basic_auth": (settings.elasticsearch_username, settings.elasticsearch_password.get_secret_value())}
    return {}

def auth_configured(settings: Settings) -> bool:
    return bool(settings.elasticsearch_api_key or (settings.elasticsearch_username and settings.elasticsearch_password))
