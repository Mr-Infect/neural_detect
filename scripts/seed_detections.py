from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select

from core.database.models import DetectionRule, DetectionRuleVersion
from core.database.session import SessionFactory, engine
from detection_engine.library import load_rule, rule_files

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "detection_rules" / "library"


_COMPARED = ("title", "description", "rule_format", "source_yaml", "native_query", "compiled_query", "deployment", "rule_metadata")


def _changed(existing: DetectionRule, fields: dict[str, Any]) -> bool:
    return any(getattr(existing, name) != fields[name] for name in _COMPARED)


async def main(tenant: str = "default") -> None:
    created = updated = 0
    async with SessionFactory() as session:
        for path in rule_files(LIBRARY):
            fields = load_rule(path)
            existing = await session.scalar(select(DetectionRule).where(
                DetectionRule.rule_id == fields["rule_id"], DetectionRule.tenant_id == tenant))
            if existing:
                if _changed(existing, fields):
                    # Git is the source of truth: apply the library change as a new immutable version.
                    for name, value in fields.items():
                        setattr(existing, name, value)
                    existing.current_version += 1
                    session.add(DetectionRuleVersion(
                        detection_rule_id=existing.id, version=existing.current_version,
                        source_yaml=existing.source_yaml, native_query=existing.native_query,
                        compiled_query=existing.compiled_query, deployment=existing.deployment,
                        rule_metadata=existing.rule_metadata,
                    ))
                    updated += 1
                continue
            rule = DetectionRule(**fields, tenant_id=tenant)
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
    print(json.dumps({"tenant": tenant, "seeded": created, "updated": updated, "library_path": "detection_rules/library"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the starter detection library into a tenant.")
    parser.add_argument("--tenant", default="default", help="tenant slug that will own the rules")
    asyncio.run(main(parser.parse_args().tenant))