from typing import Any

from integrations.elasticsearch.client import get_client


async def cluster_health() -> dict[str, Any]:
    response = await get_client().cluster.health()
    body = response.body
    return {"status": body.get("status", "unknown"), "number_of_nodes": body.get("number_of_nodes", 0), "active_shards": body.get("active_shards", 0)}
