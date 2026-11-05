from typing import Any

from integrations.elasticsearch.client import get_client

_SCAN_LIMIT = 500


def _alert_tenant(source: dict[str, Any]) -> Any:
    tenant = source.get("tenant")
    if isinstance(tenant, dict):
        return tenant.get("id")
    return source.get("tenant.id")


async def recent_alerts(limit: int = 10, tenant_id: str = "default") -> list[dict[str, Any]]:
    # Kibana's alerts index maps fields strictly (dynamic: false), so tenant.id is stored in
    # _source but is not searchable. Fetch the newest alerts and scope them by tenant here.
    response = await get_client().options(ignore_status=404).search(
        index=".alerts-security.alerts-default*", query={"match_all": {}},
        size=_SCAN_LIMIT, sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        allow_no_indices=True, ignore_unavailable=True,
    )
    sources = [hit.get("_source", {}) for hit in response.body.get("hits", {}).get("hits", [])]
    return [source for source in sources if _alert_tenant(source) == tenant_id][:limit]
