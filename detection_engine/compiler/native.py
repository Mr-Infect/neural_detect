from __future__ import annotations

import re
from typing import Any

from integrations.elasticsearch.esql_service import validate_esql
from integrations.elasticsearch.search_service import validate_index


def compile_native(
    rule_format: str,
    query: str | dict[str, Any],
    index: list[str],
) -> dict[str, Any]:
    if not index or len(index) > 10:
        raise ValueError("Provide between one and ten index patterns.")
    for pattern in index:
        validate_index(pattern)
    if rule_format in {"eql", "kql", "esql"}:
        if not isinstance(query, str) or not query.strip() or len(query) > 10_000:
            raise ValueError("Native rule query must be a non-empty string of at most 10,000 characters.")
        if rule_format == "esql":
            validate_esql(query)
        compiled = query.strip()
        language = rule_format
        rule_type = "esql" if rule_format == "esql" else "query"
    elif rule_format == "threshold":
        if not isinstance(query, dict):
            raise ValueError("Threshold rules require a JSON object.")
        field = query.get("field")
        threshold = query.get("threshold")
        window = query.get("window")
        if not isinstance(field, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", field):
            raise ValueError("Threshold field must be an ECS field name.")
        if not isinstance(threshold, int) or not 1 <= threshold <= 100_000:
            raise ValueError("Threshold must be between 1 and 100,000.")
        if not isinstance(window, str) or not re.fullmatch(r"[1-9][0-9]{0,2}[smhd]", window):
            raise ValueError("Threshold window must look like 5m or 1h.")
        group_by = query.get("group_by", [])
        if not isinstance(group_by, list) or len(group_by) > 5 or any(
            not isinstance(item, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", item)
            for item in group_by
        ):
            raise ValueError("Threshold group_by must contain up to five ECS field names.")
        filter_query = query.get("filter", "*")
        if not isinstance(filter_query, str) or len(filter_query) > 2000:
            raise ValueError("Threshold filter must be a string under 2,000 characters.")
        compiled = {"field": field, "value": threshold, "window": window, "group_by": group_by, "filter": filter_query}
        language = "kuery"
        rule_type = "threshold"
    else:
        raise ValueError("Format must be sigma, esql, eql, kql, or threshold.")
    deployment = {
        "type": rule_type,
        "language": language,
        "index": index,
        "query": compiled if isinstance(compiled, str) else compiled["filter"],
        "enabled": False,
    }
    if rule_type == "threshold":
        deployment["threshold"] = {"field": compiled["group_by"], "value": compiled["value"], "cardinality": []}
    return {"compiled_query": compiled, "deployment": deployment}