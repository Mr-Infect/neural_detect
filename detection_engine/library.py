"""Load a directory of detection rules (Sigma YAML or native JSON) plus their fixtures.

Shared by the seed script and the ndctl command-line tool so both read rules the same way.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from detection_engine.compiler.native import compile_native
from detection_engine.converters.pysigma import compile_sigma
from detection_engine.validators.sigma import validate_sigma_source

RULE_SUFFIXES = {".json", ".yml", ".yaml"}


@dataclass
class LibraryRule:
    path: Path
    rule_id: str
    title: str
    rule_format: str
    fields: dict[str, Any]  # database-shaped, compiled
    create_payload: dict[str, Any]  # body for POST /detections
    fixtures: dict[str, Any] | None = None
    problems: list[str] = field(default_factory=list)


def rule_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in RULE_SUFFIXES)


def load_rule(path: Path) -> dict[str, Any]:
    """Validate and compile one rule file into database-shaped fields."""
    if path.suffix == ".json":
        document = json.loads(path.read_text(encoding="utf-8"))
        result = compile_native(document["format"], document["query"], document.get("index", ["neural-detect-*"]))
        return {
            "rule_id": document["rule_id"],
            "title": document["title"],
            "description": document["description"],
            "rule_format": document["format"],
            "source_yaml": None,
            "native_query": document["query"],
            "compiled_query": result["compiled_query"],
            "deployment": result["deployment"],
            "rule_metadata": document.get("metadata", {}),
        }
    source = path.read_text(encoding="utf-8")
    document, stable_id = validate_sigma_source(source)
    compiled = compile_sigma(source)
    return {
        "rule_id": stable_id,
        "title": document["title"],
        "description": document["description"],
        "rule_format": "sigma",
        "source_yaml": source,
        "native_query": None,
        "compiled_query": compiled["compiled_query"],
        "deployment": compiled["deployment"],
        "rule_metadata": document,
    }


def _create_payload(path: Path, fields: dict[str, Any]) -> dict[str, Any]:
    if fields["rule_format"] == "sigma":
        return {"source_yaml": fields["source_yaml"]}
    document = json.loads(path.read_text(encoding="utf-8"))
    return {
        "format": document["format"], "rule_id": document["rule_id"], "title": document["title"],
        "description": document["description"], "query": document["query"],
        "index": document.get("index", ["neural-detect-*"]), "metadata": document.get("metadata", {}),
    }


def check_fixtures(fixtures: Any) -> list[str]:
    """Structural checks that need no Elasticsearch."""
    if not isinstance(fixtures, dict):
        return ["fixtures must be a JSON object"]
    problems: list[str] = []
    names: list[str] = []
    for group in ("positive", "negative"):
        cases = fixtures.get(group)
        if not isinstance(cases, list) or not cases:
            problems.append(f"'{group}' needs at least one case")
            continue
        for index, case in enumerate(cases):
            name = str(case.get("name") or f"{group}-{index}") if isinstance(case, dict) else ""
            if name.upper().startswith("TODO"):
                problems.append(f"fixture case '{name}' is a placeholder; write a real event")
            if not isinstance(case, dict) or not isinstance(case.get("events"), list) or not case["events"]:
                problems.append(f"{group}[{index}] needs a non-empty 'events' list")
            elif name in names:
                problems.append(f"fixture case name '{name}' is repeated")
            names.append(name)
    return problems


def load_library(directory: Path, fixtures_dir: Path | None = None) -> list[LibraryRule]:
    """Load every rule; problems are recorded on each rule instead of raising."""
    fixtures_dir = fixtures_dir or directory.parent / "fixtures"
    rules: list[LibraryRule] = []
    for path in rule_files(directory):
        try:
            fields = load_rule(path)
        except Exception as exc:  # noqa: BLE001 - report any rule problem per file
            rules.append(LibraryRule(path, path.stem, path.stem, "unknown", {}, {}, None, [f"{exc}"]))
            continue
        rule = LibraryRule(path, fields["rule_id"], fields["title"], fields["rule_format"], fields,
                           _create_payload(path, fields))
        fixture_path = fixtures_dir / f"{path.stem}.json"
        if not fixture_path.exists():
            rule.problems.append(f"missing fixtures file {fixture_path.name}")
        else:
            try:
                rule.fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
                rule.problems.extend(check_fixtures(rule.fixtures))
            except json.JSONDecodeError as exc:
                rule.problems.append(f"fixtures are not valid JSON: {exc}")
        rules.append(rule)
    return rules
