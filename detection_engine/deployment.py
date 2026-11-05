from __future__ import annotations

from typing import Any

# Sigma levels are wider than Kibana's severity enum.
_SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_DEFAULT_RISK = {"low": 21, "medium": 47, "high": 73, "critical": 99}


def kibana_severity(metadata: dict[str, Any]) -> str:
    raw = str(metadata.get("level", metadata.get("severity", "medium"))).lower()
    return _SEVERITY.get(raw, "medium")


def build_kibana_payload(
    *, rule_id: str, title: str, description: str, deployment: dict[str, Any], metadata: dict[str, Any],
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Single source of truth for the Kibana rule body used by every deploy path."""
    severity = kibana_severity(metadata)
    payload: dict[str, Any] = {
        # Kibana rule IDs are global; namespace non-default tenants so the same Sigma UUID can exist in two tenants.
        "rule_id": rule_id if tenant_id == "default" else f"{tenant_id}.{rule_id}",
        "name": title,
        "description": description,
        "type": deployment["type"],
        "language": deployment["language"],
        "index": deployment.get("index", ["neural-detect-*"]),
        "query": deployment["query"],
        "enabled": True,
        "severity": severity,
        "risk_score": metadata.get("risk_score", _DEFAULT_RISK[severity]),
        "interval": "5m",
        "from": "now-6m",
        "max_signals": 100,
        "tags": [*(tag for tag in metadata.get("tags", []) if isinstance(tag, str)), f"tenant:{tenant_id}"],
    }
    if deployment["type"] == "threshold":
        threshold = deployment.get("threshold")
        if not isinstance(threshold, dict) or "value" not in threshold:
            raise ValueError("Threshold rules require a threshold configuration.")
        payload["threshold"] = {
            "field": threshold.get("field", []),
            "value": threshold["value"],
            "cardinality": threshold.get("cardinality", []),
        }
    return payload
