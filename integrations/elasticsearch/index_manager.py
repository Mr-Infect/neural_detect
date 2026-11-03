from typing import Any

from integrations.elasticsearch.client import get_client


async def list_indices(pattern: str = "neural-detect-*") -> list[dict[str, Any]]:
    response = await get_client().cat.indices(index=pattern, format="json")
    items = response.body if hasattr(response, "body") else response
    return [{"index": row.get("index"), "health": row.get("health"), "status": row.get("status"), "documents": int(row.get("docs.count") or 0), "size": row.get("store.size")} for row in items]
