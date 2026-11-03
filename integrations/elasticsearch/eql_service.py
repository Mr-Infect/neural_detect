from typing import Any

from integrations.elasticsearch.client import get_client
from integrations.elasticsearch.search_service import validate_index


async def execute_eql(
    index: str,
    query: str,
    *,
    size: int = 100,
    filter_query: dict[str, Any] | None = None,
    timeout: str = "10s",
) -> dict[str, Any]:
    validate_index(index)
    response = await get_client().eql.search(
        index=index,
        query=query,
        timestamp_field="@timestamp",
        size=min(max(size, 1), 100),
        filter=filter_query,
        wait_for_completion_timeout=timeout,
    )
    return response.body

