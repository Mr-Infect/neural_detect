from __future__ import annotations

import json
from pathlib import Path

import pytest

from detection_engine.compiler.native import compile_native
from detection_engine.converters.pysigma import compile_sigma
from detection_engine.deployment import build_kibana_payload, kibana_severity

ROOT = Path(__file__).resolve().parents[1]

COMMUNITY_RULE = """title: Community style rule
id: 11111111-2222-4333-8444-555555555555
description: Uses Sysmon-style field names.
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: sel
level: high
tags: [attack.t1059.001]
"""


def test_community_sigma_fields_are_mapped_to_ecs() -> None:
    query = compile_sigma(COMMUNITY_RULE)["compiled_query"]
    assert "process.executable" in query and "process.command_line" in query
    assert "CommandLine" not in query


def test_ecs_native_sigma_rules_are_unchanged_by_pipeline() -> None:
    source = (ROOT / "detection_rules/library/suspicious_powershell.yml").read_text(encoding="utf-8")
    assert "process.command_line" in compile_sigma(source)["compiled_query"]


@pytest.mark.parametrize(("level", "expected"), [("informational", "low"), ("HIGH", "high"), ("weird", "medium")])
def test_severity_is_mapped_to_kibana_enum(level: str, expected: str) -> None:
    assert kibana_severity({"level": level}) == expected


def test_threshold_payload_includes_threshold_block() -> None:
    rule = json.loads((ROOT / "detection_rules/library/ssh_brute_force.json").read_text(encoding="utf-8"))
    native = compile_native(rule["format"], rule["query"], rule["index"])
    payload = build_kibana_payload(
        rule_id=rule["rule_id"], title=rule["title"], description=rule["description"],
        deployment=native["deployment"], metadata=rule["metadata"],
    )
    assert payload["type"] == "threshold"
    assert payload["threshold"]["value"] == 5
    assert payload["threshold"]["field"] == ["source.ip"]
    assert payload["risk_score"] == 73


def test_threshold_without_config_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_kibana_payload(
            rule_id="x-rule", title="t", description="d", metadata={},
            deployment={"type": "threshold", "language": "kuery", "query": "*"},
        )


def test_query_payload_has_no_threshold_block() -> None:
    native = compile_native("kql", "event.category:process", ["neural-detect-*"])
    payload = build_kibana_payload(
        rule_id="x-rule", title="t", description="d", metadata={"severity": "critical"},
        deployment=native["deployment"],
    )
    assert "threshold" not in payload and payload["severity"] == "critical" and payload["risk_score"] == 99


def test_fixture_runner_rejects_duplicate_case_names() -> None:
    import asyncio

    from detection_engine.testing.runner import run_fixture_tests

    case = {"name": "same", "events": [{"a": 1}]}
    with pytest.raises(ValueError, match="unique"):
        asyncio.run(run_fixture_tests("kql", "a:1", {"positive": [case], "negative": [case]}))
