"""Import community Sigma rules (for example a SigmaHQ checkout) into a NEURAL DETECT rules directory.

Only rules that will actually work against ECS data are imported. A rule that compiles but uses field
names we cannot translate would never match, so it is skipped with a reason instead of silently imported.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from detection_engine.converters.pysigma import SIGMA_TO_ECS, compile_sigma
from detection_engine.validators.sigma import validate_sigma_source

_SKIP_KEYS = {"condition", "timeframe"}
_IP_FIELDS = {"source.ip", "destination.ip", "host.ip"}
_INT_FIELDS = {"source.port", "destination.port", "process.pid"}
_SIMPLE_MODIFIERS = {"contains", "startswith", "endswith", "all", "windash"}
_CONDITION = re.compile(r"^\w+(\s+and\s+\w+)*$", re.IGNORECASE)
_RESERVED = {"not", "or", "of", "them", "all", "1"}
DEFAULT_STATUSES = {"stable", "test"}


@dataclass
class Filters:
    product: str | None = None
    category: str | None = None
    service: str | None = None
    levels: set[str] = field(default_factory=set)
    statuses: set[str] = field(default_factory=lambda: set(DEFAULT_STATUSES))
    tag_prefixes: list[str] = field(default_factory=list)
    allow_unmapped: bool = False
    generated_only: bool = False
    limit: int | None = None


@dataclass
class ImportResult:
    path: Path
    outcome: str  # imported | skipped | filtered
    reason: str = ""
    title: str = ""
    rule_id: str = ""
    slug: str = ""
    source: str = ""
    fixtures: dict[str, Any] | None = None
    synthesized: bool = False


def slugify(title: str, fallback: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:80]
    return slug or fallback


def field_names(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key, selection in document["detection"].items():
        if key in _SKIP_KEYS:
            continue
        for item in selection if isinstance(selection, list) else [selection]:
            if isinstance(item, dict):
                names.update(str(k).split("|")[0] for k in item)
            else:
                names.add("(keywords)")
    return names


def unmapped_fields(document: dict[str, Any]) -> list[str]:
    return sorted(n for n in field_names(document) if n not in SIGMA_TO_ECS and "." not in n)


def _set_nested(event: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node = event
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _literal(value: Any) -> str:
    """Turn a Sigma value into a plain string: escaped characters are literal, bare wildcards become filler text."""
    text, out, i = str(value), [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text) and text[i + 1] in "\\*?":
            out.append(text[i + 1])
            i += 2
            continue
        out.append("demo" if text[i] == "*" else "x" if text[i] == "?" else text[i])
        i += 1
    return "".join(out)


def _compose(need: dict[str, list[str]]) -> str | None:
    """One string that satisfies every startswith/contains/endswith/equals requirement on a field."""
    starts, ends, equals = set(need["starts"]), set(need["ends"]), set(need["equals"])
    if len(starts) > 1 or len(ends) > 1 or len(equals) > 1:
        return None
    if equals:
        value = equals.pop()
        ok = all(c in value for c in need["contains"]) and all(value.startswith(x) for x in starts)
        return value if ok and all(value.endswith(x) for x in ends) else None
    body = next(iter(starts), "")
    for fragment in need["contains"]:
        body += "demo" + fragment
    if ends:
        end = next(iter(ends))
        body += ("C:\\demo" if not body and end.startswith("\\") else "demo") + end
    else:
        body += "demo"
    return body


def _benign_value(ecs_field: str) -> Any:
    if ecs_field in _INT_FIELDS:
        return 1
    if ecs_field in _IP_FIELDS:
        return "10.0.0.1"
    return "benign-value"


def synthesize_events(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Build one event that matches the rule and one that does not, for simple AND-only rules.

    Returns None when the rule is too complex to do safely (or, not, filters, regex, lists of keywords).
    """
    detection = document["detection"]
    condition = detection.get("condition")
    if not isinstance(condition, str) or not _CONDITION.match(condition.strip()):
        return None
    names = [n for n in re.split(r"\s+and\s+", condition.strip(), flags=re.IGNORECASE)]
    if any(n.lower() in _RESERVED or n not in detection for n in names):
        return None
    needs: dict[str, dict[str, list[str]]] = {}
    typed: dict[str, Any] = {}
    for name in names:
        selection = detection[name]
        item = selection[0] if isinstance(selection, list) and selection else selection
        if not isinstance(item, dict) or not item:
            return None
        for key, raw in item.items():
            base, *modifiers = str(key).split("|")
            if any(m not in _SIMPLE_MODIFIERS for m in modifiers):
                return None
            values = raw if isinstance(raw, list) else [raw]
            if not values or any(v is None or isinstance(v, (dict, list, bool)) for v in values):
                return None
            ecs_field = SIGMA_TO_ECS.get(base, base)
            if ecs_field in _INT_FIELDS | _IP_FIELDS:
                try:
                    value = int(values[0]) if ecs_field in _INT_FIELDS else str(values[0])
                except (ValueError, TypeError):
                    return None
                if typed.setdefault(ecs_field, value) != value:
                    return None
                continue
            chosen = values if "all" in modifiers else values[:1]  # a list without |all means any one value
            kind = "contains" if "contains" in modifiers else "starts" if "startswith" in modifiers \
                else "ends" if "endswith" in modifiers else "equals"
            need = needs.setdefault(ecs_field, {"starts": [], "contains": [], "ends": [], "equals": []})
            need[kind].extend(_literal(v) for v in chosen)
    positive: dict[str, Any] = {}
    negative: dict[str, Any] = {}
    for ecs_field, value in typed.items():
        _set_nested(positive, ecs_field, value)
        _set_nested(negative, ecs_field, _benign_value(ecs_field))
    for ecs_field, need in needs.items():
        value = _compose(need)
        if value is None:
            return None
        _set_nested(positive, ecs_field, value)
        _set_nested(negative, ecs_field, _benign_value(ecs_field))
    return positive, negative


def _template_fixtures() -> dict[str, Any]:
    return {
        "positive": [{"name": "TODO-positive", "events": [{}]}],
        "negative": [{"name": "TODO-negative", "events": [{}]}],
        "_note": "Placeholder: write an event the rule must alert on and one it must not, then rename the cases.",
    }


def _matches(document: dict[str, Any], filters: Filters) -> str | None:
    """Return the reason a rule is filtered out, or None to keep it."""
    logsource = document.get("logsource") or {}
    status = str(document.get("status", "")).lower()
    if filters.statuses and status not in filters.statuses:
        return f"status {status or 'missing'}"
    if filters.levels and str(document.get("level", "")).lower() not in filters.levels:
        return "level"
    for attribute in ("product", "category", "service"):
        wanted = getattr(filters, attribute)
        if wanted and str(logsource.get(attribute, "")).lower() != wanted.lower():
            return attribute
    if filters.tag_prefixes:
        tags = [str(t).lower() for t in document.get("tags", []) if isinstance(t, str)]
        if not any(tag.startswith(prefix.lower()) for prefix in filters.tag_prefixes for tag in tags):
            return "tag"
    return None


def _inspect(path: Path, filters: Filters, existing_ids: set[str]) -> ImportResult:
    try:
        text = path.read_text(encoding="utf-8")
        documents = [d for d in yaml.safe_load_all(text) if d is not None]
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return ImportResult(path, "skipped", f"unreadable: {str(exc)[:80]}")
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return ImportResult(path, "skipped", "multi-document or non-rule file")
    document = documents[0]
    if "correlation" in document or not isinstance(document.get("detection"), dict):
        return ImportResult(path, "skipped", "correlation or non-detection rule")
    filtered = _matches(document, filters)
    if filtered:
        return ImportResult(path, "filtered", filtered)
    title = str(document.get("title", path.stem))
    try:
        _, stable_id = validate_sigma_source(text)
        compile_sigma(text)
    except (ValueError, TypeError) as exc:
        return ImportResult(path, "skipped", f"not importable: {str(exc)[:110]}", title)
    if stable_id in existing_ids:
        return ImportResult(path, "skipped", "already in destination", title, stable_id)
    missing = unmapped_fields(document)
    if missing and not filters.allow_unmapped:
        return ImportResult(path, "skipped", "unmapped fields: " + ", ".join(missing[:4]), title, stable_id)
    events = synthesize_events(document)
    if filters.generated_only and not events:
        return ImportResult(path, "filtered", "needs hand-written fixtures")
    fixtures = _template_fixtures()
    if events:
        fixtures = {
            "positive": [{"name": "synthetic-positive", "events": [events[0]]}],
            "negative": [{"name": "synthetic-negative", "events": [events[1]]}],
            "_note": "Generated from the rule's own conditions by ndctl import. Review and add realistic cases.",
        }
    return ImportResult(path, "imported", "", title, stable_id, slugify(title, stable_id[:8]), text, fixtures,
                        synthesized=bool(events))


def scan(source: Path, filters: Filters, existing_ids: set[str]) -> list[ImportResult]:
    files = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.suffix in {".yml", ".yaml"})
    results: list[ImportResult] = []
    taken = set(existing_ids)
    imported = 0
    for path in files:
        if filters.limit is not None and imported >= filters.limit:
            break
        result = _inspect(path, filters, taken)
        if result.outcome == "imported":
            taken.add(result.rule_id)
            imported += 1
        results.append(result)
    return results


def write(results: list[ImportResult], dest: Path) -> list[Path]:
    library, fixtures = dest / "library", dest / "fixtures"
    library.mkdir(parents=True, exist_ok=True)
    fixtures.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for result in results:
        if result.outcome != "imported":
            continue
        slug = result.slug
        if (library / f"{slug}.yml").exists():
            slug = f"{slug}_{result.rule_id[:8]}"
        (library / f"{slug}.yml").write_text(result.source, encoding="utf-8")
        (fixtures / f"{slug}.json").write_text(json.dumps(result.fixtures, indent=2) + "\n", encoding="utf-8")
        written.append(library / f"{slug}.yml")
    return written
