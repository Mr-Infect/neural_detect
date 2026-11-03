from typing import Any

from integrations.elasticsearch.client import get_client
from integrations.elasticsearch.search_service import validate_index


async def execute_eql(
    index: str,
    query: str,
    *,
    size: int = 100,
    filter_query: dict[str, Any] | None = None,
    tenant_id: str = "default",
    timeout: str = "10s",
) -> dict[str, Any]:
    validate_index(index)
    response = await get_client().eql.search(
        index=index,
        query=query,
        timestamp_field="@timestamp",
        size=min(max(size, 1), 100),
        filter={"bool": {"filter": [{"term": {"tenant.id": tenant_id}}] + ([filter_query] if filter_query else [])}},
        wait_for_completion_timeout=timeout,
    )
    return response.body

