import re
from typing import Any

from integrations.elasticsearch.client import get_client

_ALLOWED_INDEX = re.compile(r"^neural-detect-[A-Za-z0-9_.*,-]+$")

def validate_index(index: str) -> str:
    if not _ALLOWED_INDEX.fullmatch(index):
        raise ValueError("Index must match the neural-detect-* namespace.")
    return index

async def search(index: str, query: dict[str, Any], *, tenant_id: str = "default", size: int = 50, offset: int = 0, sort: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    validate_index(index)
    scoped_query = {"bool": {"must": [query], "filter": [{"term": {"tenant.id": tenant_id}}]}}
    response = await get_client().search(index=index, query=scoped_query, size=size, from_=offset, sort=sort or [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], track_total_hits=True)
    body = response.body
    return {"total": body.get("hits", {}).get("total", {}).get("value", 0), "events": [hit.get("_source", {}) for hit in body.get("hits", {}).get("hits", [])]}
