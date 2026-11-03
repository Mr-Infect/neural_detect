from __future__ import annotations

import json
from pathlib import Path

import pytest

from detection_engine.compiler.native import compile_native
from detection_engine.converters.pysigma import compile_sigma
from detection_engine.validators.sigma import validate_sigma_source

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "detection_rules" / "library"


def test_sigma_source_has_stable_uuid_and_compiles() -> None:
    source = (LIBRARY / "suspicious_powershell.yml").read_text(encoding="utf-8")
    document, stable_id = validate_sigma_source(source)
    compiled = compile_sigma(source)
    assert stable_id == "32f59121-8ad8-4a0d-917c-b213445e8f02"
    assert document["title"] == "Suspicious PowerShell Encoded Command"
    assert compiled["compiled_query"]


@pytest.mark.parametrize(
    "source",
    [
        "title: incomplete",
        "title: Missing ID\nid: unstable\n",
        (LIBRARY / "windows_failed_authentication.yml").read_text(encoding="utf-8").replace(
            "  - attack.t1110\n", ""
        ),
    ],
)
def test_sigma_metadata_validation_rejects_incomplete_rules(source: str) -> None:
    with pytest.raises(ValueError):
        validate_sigma_source(source)


def test_native_threshold_compilation_is_separate_from_deployment() -> None:
    result = compile_native(
        "threshold",
        {"field": "source.ip", "group_by": ["source.ip"], "threshold": 5, "window": "5m", "filter": "event.outcome:failure"},
        ["neural-detect-*"],
    )
    assert result["compiled_query"]["value"] == 5
    assert result["deployment"]["type"] == "threshold"
    assert result["deployment"]["enabled"] is False


def test_rejects_native_indices_outside_platform_namespace() -> None:
    with pytest.raises(ValueError):
        compile_native("kql", "event.category:process", ["logs-*"])


def test_all_initial_rules_have_positive_and_negative_fixtures() -> None:
    fixture_dir = ROOT / "detection_rules" / "fixtures"
    rule_files = list(LIBRARY.glob("*.yml")) + list(LIBRARY.glob("*.json"))
    assert len(rule_files) == 10
    for rule in rule_files:
        fixtures = json.loads((fixture_dir / f"{rule.stem}.json").read_text(encoding="utf-8"))
        assert fixtures["positive"]
        assert fixtures["negative"]