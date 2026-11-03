from core.config.settings import get_settings
from elasticsearch import AsyncElasticsearch
from integrations.elasticsearch.authentication import client_auth_kwargs

_client: AsyncElasticsearch | None = None

def get_client() -> AsyncElasticsearch:
    global _client
    if _client is None:
        settings = get_settings()
        _client = AsyncElasticsearch(settings.elasticsearch_url, verify_certs=settings.elasticsearch_verify_certs, request_timeout=15, **client_auth_kwargs(settings))
    return _client

async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
