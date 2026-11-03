from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select

from core.database.models import DetectionRule, DetectionRuleVersion
from core.database.session import SessionFactory, engine
from detection_engine.compiler.native import compile_native
from detection_engine.converters.pysigma import compile_sigma
from detection_engine.validators.sigma import validate_sigma_source

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "detection_rules" / "library"


def load_rule(path: Path) -> dict[str, Any]:
    if path.suffix == ".json":
        document = json.loads(path.read_text(encoding="utf-8"))
        result = compile_native(document["format"], document["query"], document.get("index", ["neural-detect-*"]))
        metadata = document.get("metadata", {})
        return {
            "rule_id": document["rule_id"],
            "title": document["title"],
            "description": document["description"],
            "rule_format": document["format"],
            "source_yaml": None,
            "native_query": document["query"],
            "compiled_query": result["compiled_query"],
            "deployment": result["deployment"],
            "rule_metadata": metadata,
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


async def main() -> None:
    created = 0
    async with SessionFactory() as session:
        for path in sorted(LIBRARY.iterdir()):
            if path.suffix not in {".json", ".yml", ".yaml"}:
                continue
            fields = load_rule(path)
            existing = await session.scalar(select(DetectionRule).where(DetectionRule.rule_id == fields["rule_id"]))
            if existing:
                continue
            rule = DetectionRule(**fields)
            session.add(rule)
            await session.flush()
            session.add(DetectionRuleVersion(
                detection_rule_id=rule.id, version=1, source_yaml=rule.source_yaml,
                native_query=rule.native_query, compiled_query=rule.compiled_query,
                deployment=rule.deployment, rule_metadata=rule.rule_metadata,
            ))
            created += 1
        await session.commit()
    await engine.dispose()
    print(json.dumps({"seeded": created, "library_path": "detection_rules/library"}))


if __name__ == "__main__":
    asyncio.run(main())