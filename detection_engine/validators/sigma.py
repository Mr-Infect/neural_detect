from __future__ import annotations

from typing import Any
from uuid import UUID

import yaml
from sigma.collection import SigmaCollection

_ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
_REQUIRED = {"title", "id", "description", "logsource", "detection", "level"}


def validate_sigma_source(source: str) -> tuple[dict[str, Any], str]:
    if not source.strip() or len(source.encode("utf-8")) > 64_000:
        raise ValueError("Sigma source must contain 1–64,000 UTF-8 bytes.")
    try:
        document = yaml.safe_load(source)
        collection = SigmaCollection.from_yaml(source)
    except Exception as exc:
        raise ValueError(f"Invalid Sigma YAML or schema: {exc}") from exc
    if not isinstance(document, dict):
        raise TypeError("A Sigma rule must be a YAML mapping.")
    missing = sorted(_REQUIRED - document.keys())
    if missing:
        raise ValueError(f"Missing required Sigma fields: {', '.join(missing)}")
    try:
        stable_id = str(UUID(str(document["id"])))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Sigma id must be a stable UUID.") from exc
    if len(collection.rules) != 1:
        raise ValueError("Import exactly one Sigma rule per request.")
    if not isinstance(document["title"], str) or not document["title"].strip() or len(document["title"]) > 256:
        raise ValueError("Sigma title must be 1–256 characters.")
    if not isinstance(document["description"], str) or not document["description"].strip():
        raise ValueError("Sigma description is required.")
    if not isinstance(document["logsource"], dict) or not document["logsource"]:
        raise TypeError("Sigma logsource must be a non-empty mapping.")
    detection = document["detection"]
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), (str, list)):
        raise TypeError("Sigma detection must include a condition.")
    if document["level"] not in _ALLOWED_LEVELS:
        raise ValueError(f"Sigma level must be one of: {', '.join(sorted(_ALLOWED_LEVELS))}.")
    tags = document.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("Sigma tags must be a list of strings.")
    techniques = [tag for tag in tags if tag.lower().startswith("attack.t")]
    if not techniques:
        raise ValueError("At least one ATT&CK technique tag (attack.t####) is required.")
    return document, stable_id