from typing import Any

from integrations.elasticsearch.client import get_client


async def recent_alerts(limit: int = 10) -> list[dict[str, Any]]:
    response = await get_client().options(ignore_status=404).search(index=".alerts-security.alerts-default*", query={"match_all": {}}, size=limit, sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], allow_no_indices=True, ignore_unavailable=True)
    body = response.body
    return [hit.get("_source", {}) for hit in body.get("hits", {}).get("hits", [])]
