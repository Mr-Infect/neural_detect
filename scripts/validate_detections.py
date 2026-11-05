from __future__ import annotations

import json
import sys
from pathlib import Path

from detection_engine.compiler.native import compile_native
from detection_engine.converters.pysigma import compile_sigma
from detection_engine.validators.sigma import validate_sigma_source

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "detection_rules" / "library"
FIXTURES = ROOT / "detection_rules" / "fixtures"


def _run_live(rule_format: str, compiled: object, fixtures: dict, name: str) -> None:
    import asyncio

    from detection_engine.testing.runner import run_fixture_tests

    outcome = asyncio.run(run_fixture_tests(rule_format, compiled, fixtures))
    if not outcome["passed"]:
        raise SystemExit(f"{name}: fixture failures: {', '.join(outcome['failures'])}")


def main() -> None:
    live = "--live" in sys.argv  # execute fixtures against a disposable Elasticsearch (ELASTICSEARCH_URL)
    validated = 0
    for path in sorted(LIBRARY.iterdir()):
        if path.suffix == ".json":
            rule = json.loads(path.read_text(encoding="utf-8"))
            result = compile_native(rule["format"], rule["query"], rule.get("index", ["neural-detect-*"]))
            if result.get("compiled_query") is None:
                raise SystemExit(f"{path.name}: native compiler returned no query")
        elif path.suffix in {".yml", ".yaml"}:
            source = path.read_text(encoding="utf-8")
            validate_sigma_source(source)
            result = compile_sigma(source)
            if not result["compiled_query"].strip():
                raise SystemExit(f"{path.name}: Sigma compiler returned an empty query")
        else:
            continue
        fixture_path = FIXTURES / f"{path.stem}.json"
        if not fixture_path.exists():
            raise SystemExit(f"{path.name}: missing positive/negative fixtures")
        fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
        if not fixtures.get("positive") or not fixtures.get("negative"):
            raise SystemExit(f"{fixture_path.name}: positive and negative cases are required")
        if live:
            _run_live(rule["format"] if path.suffix == ".json" else "sigma", result["compiled_query"], fixtures, path.name)
        validated += 1
    if validated == 0:
        raise SystemExit("No detections found in detection_rules/library")
    print(f"Validated and compiled {validated} detections with positive/negative fixtures.")


if __name__ == "__main__":
    main()