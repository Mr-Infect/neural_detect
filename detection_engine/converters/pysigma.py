from __future__ import annotations

from typing import Any

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

from detection_engine.validators.sigma import validate_sigma_source


def compile_sigma(source: str) -> dict[str, Any]:
    document, stable_id = validate_sigma_source(source)
    try:
        collection = SigmaCollection.from_yaml(source)
        queries = LuceneBackend().convert(collection)
    except Exception as exc:
        raise ValueError(f"pySigma Elasticsearch compilation failed: {exc}") from exc
    if len(queries) != 1 or not isinstance(queries[0], str) or not queries[0].strip():
        raise ValueError("The Elasticsearch backend did not produce one usable query.")
    query = queries[0]
    deployment = {
        "type": "query",
        "language": "lucene",
        "index": ["neural-detect-*"],
        "query": query,
        "enabled": False,
        "rule_id": stable_id,
    }
    return {
        "rule_id": stable_id,
        "title": document["title"],
        "format": "sigma",
        "compiled_query": query,
        "deployment": deployment,
    }