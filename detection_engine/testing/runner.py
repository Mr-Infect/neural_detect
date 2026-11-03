from __future__ import annotations

from typing import Any
from uuid import uuid4

from integrations.elasticsearch.client import get_client
from integrations.elasticsearch.search_service import validate_index


async def run_fixture_tests(
    rule_format: str,
    compiled: str | dict[str, Any],
    fixtures: dict[str, Any],
) -> dict[str, Any]:
    positive = fixtures.get("positive", [])
    negative = fixtures.get("negative", [])
    if not isinstance(positive, list) or not isinstance(negative, list) or not positive or not negative:
        raise ValueError("Fixtures require non-empty positive and negative lists.")
    groups = [(item, True) for item in positive] + [(item, False) for item in negative]
    documents: list[dict[str, Any]] = []
    for position, (fixture, expected) in enumerate(groups):
        if not isinstance(fixture, dict) or not isinstance(fixture.get("events"), list) or not fixture["events"]:
            raise ValueError("Each fixture case must contain a non-empty events list.")
        if len(fixture["events"]) > 100:
            raise ValueError("Each fixture case may contain at most 100 events.")
        for event in fixture["events"]:
            if not isinstance(event, dict):
                raise TypeError("Fixture events must be JSON objects.")
            documents.append({
                **event,
                "@timestamp": event.get("@timestamp", f"2026-01-01T00:{position:02d}:00Z"),
                "nd_test": {"fixture": str(fixture.get("name", position)), "expected": expected},
            })
    client = get_client()
    index = validate_index(f"neural-detect-rule-tests-{uuid4().hex}")
    matched: set[str] = set()
    try:
        await client.indices.create(index=index)
        for document in documents:
            await client.index(index=index, document=document)
        await client.indices.refresh(index=index)
        if rule_format == "threshold":
            if not isinstance(compiled, dict):
                raise ValueError("Threshold query is not compiled.")
            filter_query = compiled.get("filter", "*")
            group_field = (compiled.get("group_by") or [compiled["field"]])[0]
            response = await client.search(
                index=index,
                size=0,
                query={"query_string": {"query": filter_query}},
                aggs={
                    "groups": {
                        "terms": {"field": group_field, "size": 100},
                        "aggs": {"matches": {"value_count": {"field": compiled["field"]}}},
                    }
                },
            )
            for bucket in response.body.get("aggregations", {}).get("groups", {}).get("buckets", []):
                if bucket.get("doc_count", 0) >= compiled["value"]:
                    matching = await client.search(
                        index=index, size=100, query={"term": {group_field: bucket["key"]}}
                    )
                    matched.update(
                        hit["_source"]["nd_test"]["fixture"] for hit in matching.body["hits"]["hits"]
                    )
        elif rule_format == "eql":
            response = await client.eql.search(index=index, query=str(compiled), timestamp_field="@timestamp")
            eql_hits = response.body.get("hits", {})
            for event in eql_hits.get("events", []):
                matched.add(event["_source"]["nd_test"]["fixture"])
            for sequence in eql_hits.get("sequences", []):
                for event in sequence.get("events", []):
                    matched.add(event["_source"]["nd_test"]["fixture"])
        else:
            response = await client.search(
                index=index,
                size=500,
                query={"query_string": {"query": str(compiled)}},
                source=["nd_test.fixture"],
            )
            matched.update(
                hit["_source"]["nd_test"]["fixture"] for hit in response.body["hits"]["hits"]
            )
    finally:
        await client.options(ignore_status=404).indices.delete(index=index)
    cases = []
    failures = []
    for fixture, expected in groups:
        name = str(fixture.get("name", "unnamed"))
        detected = name in matched
        passed = detected is expected
        cases.append({"name": name, "expected_detection": expected, "detected": detected, "passed": passed})
        if not passed:
            failures.append(name)
    return {"passed": not failures, "cases": cases, "failures": failures}