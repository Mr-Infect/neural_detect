from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from detection_engine.library import LibraryRule


@dataclass
class Change:
    action: str  # create | update | unchanged | remote-only
    rule_id: str
    title: str
    local: LibraryRule | None = None
    remote: dict[str, Any] | None = None


def _differs(local: LibraryRule, remote: dict[str, Any]) -> bool:
    if local.rule_format == "sigma":
        return (remote.get("source_yaml") or "") != (local.fields["source_yaml"] or "")
    return (
        remote.get("query") != local.fields["native_query"]
        or remote.get("title") != local.fields["title"]
        or remote.get("description") != local.fields["description"]
    )


def make_plan(local_rules: list[LibraryRule], remote_rules: list[dict[str, Any]]) -> list[Change]:
    """Compare repository rules with the server, like a Terraform plan. Nothing is ever deleted."""
    remote_by_id = {rule["rule_id"]: rule for rule in remote_rules}
    changes: list[Change] = []
    for rule in local_rules:
        remote = remote_by_id.pop(rule.rule_id, None)
        if remote is None:
            changes.append(Change("create", rule.rule_id, rule.title, rule))
        elif _differs(rule, remote):
            changes.append(Change("update", rule.rule_id, rule.title, rule, remote))
        else:
            changes.append(Change("unchanged", rule.rule_id, rule.title, rule, remote))
    for remote in remote_by_id.values():
        changes.append(Change("remote-only", remote["rule_id"], remote["title"], None, remote))
    return changes


def update_payload(rule: LibraryRule) -> dict[str, Any]:
    if rule.rule_format == "sigma":
        return {"source_yaml": rule.fields["source_yaml"]}
    return {
        "query": rule.fields["native_query"], "title": rule.fields["title"],
        "description": rule.fields["description"], "metadata": rule.fields["rule_metadata"],
    }
