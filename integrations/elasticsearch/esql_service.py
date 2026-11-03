import re
from typing import Any

from integrations.elasticsearch.client import get_client
from integrations.elasticsearch.search_service import validate_index

_FROM = re.compile(r"^\s*FROM\s+([^|\n]+)", re.IGNORECASE)


def validate_esql(query: str) -> str:
    match = _FROM.match(query)
    if match is None:
        raise ValueError("ES|QL queries must start with FROM neural-detect-*.")
    indices = [item.strip() for item in match.group(1).split(",")]
    if not indices or any(not item for item in indices):
        raise ValueError("ES|QL FROM must name neural-detect-* indices.")
    for index in indices:
        validate_index(index)
    return query


async def execute_esql(query: str) -> dict[str, Any]:
    validate_esql(query)
    response = await get_client().esql.query(query=query, format="json")
    return response.body
