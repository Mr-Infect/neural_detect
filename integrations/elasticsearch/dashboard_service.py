from typing import Any

from core.config.settings import get_settings
from integrations.elasticsearch.alert_service import recent_alerts
from integrations.elasticsearch.client import get_client


async def dashboard_summary(tenant_id: str = "default") -> dict[str, Any]:
    index = get_settings().elasticsearch_index_pattern
    query = {
        "index": index,
        "size": 0,
        "track_total_hits": True,
        "query": {"term": {"tenant.id": tenant_id}},
        "allow_no_indices": True,
        "ignore_unavailable": True,
        "aggs": {
            "categories": {"terms": {"field": "event.category", "size": 12}},
            "auth_failures": {"filter": {"bool": {"filter": [
                {"term": {"event.category": "authentication"}},
                {"term": {"event.outcome": "failure"}},
            ]}}},
            "suspicious_processes": {"filter": {"bool": {"filter": [
                {"term": {"event.category": "process"}},
                {"terms": {"process.name": ["powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe"]}},
            ]}}},
            "network_activity": {"filter": {"term": {"event.category": "network"}}},
        },
    }
    response = await get_client().options(ignore_status=404).search(**query)
    body = response.body
    aggregations = body.get("aggregations", {})
    total = body.get("hits", {}).get("total", 0)
    count = total.get("value", 0) if isinstance(total, dict) else int(total)
    categories = [
        {"name": row.get("key"), "count": row.get("doc_count", 0)}
        for row in aggregations.get("categories", {}).get("buckets", [])
    ]
    return {
        "data_available": bool(body.get("_shards", {}).get("total", 0)),
        "total_events": count,
        "events_by_category": categories,
        "authentication_failures": aggregations.get("auth_failures", {}).get("doc_count", 0),
        "suspicious_processes": aggregations.get("suspicious_processes", {}).get("doc_count", 0),
        "network_events": aggregations.get("network_activity", {}).get("doc_count", 0),
        "recent_alerts": await recent_alerts(8, tenant_id),
    }
