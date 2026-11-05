from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from detection_engine import attack, sigma_import
from ndctl import cli

HEAD = "status: {status}\ndescription: d\nauthor: a\ndate: 2026/01/01\n"
TAGS = "tags:\n    - attack.execution\n    - attack.t1059\n"
LOGSOURCE = "logsource:\n    category: process_creation\n    product: windows\n"


def rule(uid: int, title: str, detection: str, status: str = "test", tags: str = TAGS) -> str:
    return (f"title: {title}\nid: aaaaaaaa-{uid:04d}-4000-8000-{uid:012d}\n" + HEAD.format(status=status)
            + tags + LOGSOURCE + "detection:\n" + detection + "level: high\n")


SIMPLE = "    selection:\n        Image|endswith: '\\certutil.exe'\n        CommandLine|contains|all: ['urlcache', 'http']\n    condition: selection\n"
FILTERED = ("    selection:\n        Image|endswith: '\\whoami.exe'\n    filter:\n        ParentImage|endswith: '\\ok.exe'\n"
            "    condition: selection and not filter\n")
UNMAPPED = "    selection:\n        EventID: 1102\n    condition: selection\n"


@pytest.fixture
def source(tmp_path: Path) -> Path:
    src = tmp_path / "sigma"
    src.mkdir()
    (src / "simple.yml").write_text(rule(1, "Certutil Download", SIMPLE))
    (src / "filtered.yml").write_text(rule(2, "Whoami Outside Admin", FILTERED))
    (src / "unmapped.yml").write_text(rule(3, "Log Cleared", UNMAPPED, tags="tags:\n    - attack.t1070.001\n"))
    (src / "experimental.yml").write_text(rule(4, "Experimental", SIMPLE.replace("certutil", "x"), status="experimental"))
    (src / "multi.yml").write_text(rule(5, "One", SIMPLE) + "---\ntitle: Two\n")
    (src / "correlation.yml").write_text("title: C\nid: aaaaaaaa-0006-4000-8000-000000000006\ncorrelation:\n  type: event_count\n")
    (src / "notag.yml").write_text(rule(7, "No Technique", SIMPLE, tags="tags:\n    - custom.x\n"))
    return src


def outcomes(results: list[sigma_import.ImportResult]) -> dict[str, str]:
    return {r.path.name: (r.outcome + ":" + r.reason.split(":")[0]) for r in results}


def test_scan_classifies_every_kind_of_community_rule(source: Path) -> None:
    got = outcomes(sigma_import.scan(source, sigma_import.Filters(), set()))
    assert got["simple.yml"] == "imported:"
    assert got["filtered.yml"] == "imported:"
    assert got["unmapped.yml"] == "skipped:unmapped fields"
    assert got["experimental.yml"].startswith("filtered")
    assert got["multi.yml"].startswith("skipped:multi-document")
    assert got["correlation.yml"].startswith("skipped:correlation")
    assert got["notag.yml"].startswith("skipped:not importable")


def test_duplicate_ids_and_limit_are_respected(source: Path) -> None:
    again = sigma_import.scan(source, sigma_import.Filters(), {"aaaaaaaa-0001-4000-8000-000000000001"})
    assert outcomes(again)["simple.yml"] == "skipped:already in destination"
    limited = sigma_import.scan(source, sigma_import.Filters(limit=1), set())
    assert sum(r.outcome == "imported" for r in limited) == 1


def test_filters_by_level_tag_and_status(source: Path) -> None:
    assert not [r for r in sigma_import.scan(source, sigma_import.Filters(levels={"low"}), set()) if r.outcome == "imported"]
    kept = sigma_import.scan(source, sigma_import.Filters(tag_prefixes=["attack.t1059"]), set())
    assert sum(r.outcome == "imported" for r in kept) == 2
    anything = sigma_import.scan(source, sigma_import.Filters(statuses=set()), set())
    assert outcomes(anything)["experimental.yml"].startswith("imported")


def test_simple_rules_get_working_generated_fixtures(source: Path) -> None:
    (result,) = [r for r in sigma_import.scan(source, sigma_import.Filters(), set()) if r.path.name == "simple.yml"]
    assert result.synthesized
    positive = result.fixtures["positive"][0]["events"][0]["process"]
    assert positive["executable"].endswith("\\certutil.exe")
    assert "urlcache" in positive["command_line"] and "http" in positive["command_line"]
    assert result.fixtures["negative"][0]["events"][0]["process"]["executable"] == "benign-value"


def test_complex_rules_get_placeholder_fixtures_that_fail_validate(source: Path, tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    sigma_import.write(sigma_import.scan(source, sigma_import.Filters(), set()), dest)
    assert cli.main(["validate", str(dest / "library")]) == 1  # whoami rule still has TODO fixtures
    (dest / "library" / "whoami_outside_admin.yml").unlink()
    (dest / "fixtures" / "whoami_outside_admin.json").unlink()
    assert cli.main(["validate", str(dest / "library")]) == 0


def test_write_never_overwrites_a_different_rule(source: Path, tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    results = sigma_import.scan(source, sigma_import.Filters(), set())
    sigma_import.write(results, dest)
    (dest / "library" / "certutil_download.yml").write_text("# someone else's rule\n")
    clash = [r for r in results if r.slug == "certutil_download"]
    clash[0].rule_id = "ffffffff-0000-4000-8000-000000000000"
    written = sigma_import.write(clash, dest)
    assert written[0].name == "certutil_download_ffffffff.yml"
    assert (dest / "library" / "certutil_download.yml").read_text().startswith("# someone")


def test_import_dry_run_writes_nothing(source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dest = tmp_path / "dest"
    assert cli.main(["import", str(source), "--dest", str(dest), "--dry-run"]) == 0
    assert not dest.exists() and "Dry run" in capsys.readouterr().out


def test_tags_are_parsed_into_tactics_and_techniques() -> None:
    tactics, techniques = attack.parse_tags(["attack.execution", "attack.t1059.001", "attack.command-and-control", "x.y"])
    assert tactics == {"execution", "command_and_control"} and techniques == {"T1059.001"}


def test_coverage_with_and_without_the_official_bundle(tmp_path: Path) -> None:
    def pattern(tid: str, name: str, phase: str, sub: bool = False, **flags: bool) -> dict:
        return {"type": "attack-pattern", "name": name, "x_mitre_is_subtechnique": sub, **flags,
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                "kill_chain_phases": [{"phase_name": phase}]}

    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps({"objects": [
        pattern("T1059", "Command Interpreter", "execution"), pattern("T1059.001", "PowerShell", "execution", True),
        pattern("T1047", "WMI", "execution"), pattern("T9999", "Old", "execution", revoked=True),
        pattern("T1110", "Brute Force", "credential-access"),
    ]}))
    bundle = attack.load_bundle(bundle_file)
    assert set(bundle) == {"T1059", "T1059.001", "T1047", "T1110"}
    rules = [("PowerShell rule", ["attack.execution", "attack.t1059.001"]), ("Untagged", ["custom"])]
    plain = attack.build_coverage(rules)
    assert plain["tactics"]["execution"]["techniques"] == ["T1059.001"] and plain["untagged_rules"] == ["Untagged"]
    full = attack.build_coverage(rules, bundle)
    assert full["tactics"]["execution"]["covered_techniques"] == 1  # sub-technique rolls up to T1059
    assert full["tactics"]["execution"]["total_techniques"] == 2
    assert full["overall"]["total_techniques"] == 3 and "credential_access" in full["overall"]["uncovered_tactics"]


def test_coverage_command_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["coverage", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["rule_count"] == 10 and "credential_access" in report["tactics"]


def test_ecs_template_makes_matching_case_insensitive() -> None:
    from integrations.elasticsearch import pipelines

    client = MagicMock()
    client.indices.put_index_template = AsyncMock()
    with patch.object(pipelines, "get_client", return_value=client):
        asyncio.run(pipelines.install_ecs_index_template())
    body = client.indices.put_index_template.call_args.kwargs["template"]
    assert "nd_lowercase" in body["settings"]["analysis"]["normalizer"]
    process = body["mappings"]["properties"]["process"]["properties"]
    assert process["executable"]["normalizer"] == "nd_lowercase"
    assert process["command_line"]["normalizer"] == "nd_lowercase"
    assert process["parent"]["properties"]["executable"]["normalizer"] == "nd_lowercase"


def test_sigma_escapes_and_wildcards_become_literal_text() -> None:
    assert sigma_import._literal(r"a\\b\*c*d?e") == "a\\b*c" + "demo" + "d" + "x" + "e"


def test_two_conditions_on_one_field_are_both_satisfied() -> None:
    detection = ("    selection:\n        Image|contains: ['\\Framework\\', '\\Framework64\\']\n"
                 "        Image|endswith: '\\aspnet_compiler.exe'\n"
                 "        CommandLine|contains|all: [' tunnel ', ' run ']\n"
                 "        CommandLine|contains: ['-config ', '-token ']\n    condition: selection\n")
    import yaml

    document = yaml.safe_load(rule(1, "Combined", detection))
    positive, negative = sigma_import.synthesize_events(document)
    exe = positive["process"]["executable"]
    assert "\\Framework\\" in exe and exe.endswith("\\aspnet_compiler.exe")
    command = positive["process"]["command_line"]
    assert " tunnel " in command and " run " in command and "-config " in command
    assert negative["process"]["executable"] == "benign-value"


def test_contradictory_conditions_fall_back_to_placeholder_fixtures() -> None:
    import yaml

    detection = "    selection:\n        Image|endswith: '\\a.exe'\n    other:\n        Image|endswith: '\\b.exe'\n    condition: selection and other\n"
    assert sigma_import.synthesize_events(yaml.safe_load(rule(2, "Impossible", detection))) is None
