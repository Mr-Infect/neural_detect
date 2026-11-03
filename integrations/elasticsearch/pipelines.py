from integrations.elasticsearch.client import get_client

_PIPELINES = {
    "auth": {"event.category": ["authentication"], "event.kind": "event"},
    "process": {"event.category": ["process"], "event.kind": "event"},
    "network": {"event.category": ["network"], "event.kind": "event"},
    "dns": {"event.category": ["network"], "event.kind": "event", "event.type": ["protocol"]},
    "endpoint-alert": {"event.category": ["intrusion_detection"], "event.kind": "alert"},
}

def _pipeline(name: str, fields: dict[str, object]) -> dict[str, object]:
    processors: list[dict[str, object]] = [
        {"set": {"field": "ecs.version", "value": "8.17.0", "override": False}},
        {"set": {"field": "event.kind", "value": fields["event.kind"], "override": False}},
        {"set": {"field": "event.category", "value": fields["event.category"], "override": False}},
    ]
    if "event.type" in fields:
        processors.append({"set": {"field": "event.type", "value": fields["event.type"], "override": False}})
    processors.extend([
        {"set": {"field": "event.original", "copy_from": "message", "override": False, "ignore_failure": True}},
        {"set": {"field": "event.module", "value": "neural_detect", "override": False}},
        {"set": {"field": "event.dataset", "value": f"neural_detect.{name}", "override": False}},
    ])
    return {"description": f"NEURAL DETECT ECS normalization: {name}", "processors": processors}

async def install_ingest_pipelines() -> list[str]:
    client = get_client()
    installed = []
    for name, fields in _PIPELINES.items():
        await client.ingest.put_pipeline(id=f"neural-detect-{name}", **_pipeline(name, fields))
        installed.append(f"neural-detect-{name}")
    return installed

async def install_ecs_index_template() -> str:
    template = {
        "index_patterns": ["neural-detect-*"],
        "priority": 500,
        "template": {
            "settings": {"number_of_shards": 1},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "ecs": {"properties": {"version": {"type": "keyword"}}},
                    "event": {"properties": {
                        "kind": {"type": "keyword"}, "category": {"type": "keyword"},
                        "type": {"type": "keyword"}, "outcome": {"type": "keyword"},
                        "action": {"type": "keyword"}, "module": {"type": "keyword"},
                        "dataset": {"type": "keyword"}, "original": {"type": "match_only_text"},
                    }},
                    "host": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}, "ip": {"type": "ip"}}},
                    "user": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}},
                    "process": {"properties": {
                        "name": {"type": "keyword"}, "executable": {"type": "keyword"},
                        "pid": {"type": "long"}, "command_line": {"type": "wildcard"},
                    }},
                    "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}, "domain": {"type": "keyword"}}},
                    "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}, "domain": {"type": "keyword"}}},
                    "network": {"properties": {
                        "protocol": {"type": "keyword"}, "transport": {"type": "keyword"},
                        "direction": {"type": "keyword"}, "bytes": {"type": "long"}, "packets": {"type": "long"},
                    }},
                    "dns": {"properties": {"question": {"properties": {"name": {"type": "keyword"}, "type": {"type": "keyword"}}}}},
                    "rule": {"properties": {
                        "id": {"type": "keyword"}, "name": {"type": "keyword"},
                        "severity": {"type": "keyword"}, "risk_score": {"type": "integer"},
                    }},
                    "observer": {"properties": {
                        "type": {"type": "keyword"}, "vendor": {"type": "keyword"}, "product": {"type": "keyword"},
                    }},
                    "message": {"type": "match_only_text"},
                },
            },
        },
    }
    await get_client().indices.put_index_template(name="neural-detect-ecs", **template)
    return "neural-detect-ecs"