from __future__ import annotations

import json
import shutil
import stat
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from apps.api.routes.detection_lifecycle import _tenant
from detection_engine.deployment import build_kibana_payload
from detection_engine.library import load_library
from ndctl import cli
from ndctl.client import Client
from ndctl.plan import make_plan

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "detection_rules" / "library"


def test_validate_passes_for_the_shipped_library(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["validate", str(LIBRARY)]) == 0
    assert "10/10 rules valid" in capsys.readouterr().out


def test_validate_fails_for_a_rule_without_fixtures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    library = tmp_path / "library"
    library.mkdir()
    shutil.copy(LIBRARY / "suspicious_powershell.yml", library)
    (library / "broken.yml").write_text("title: incomplete\n", encoding="utf-8")
    assert cli.main(["validate", str(library)]) == 1
    out = capsys.readouterr().out
    assert "FAIL  broken.yml" in out and "FAIL  suspicious_powershell.yml" in out
    assert "missing fixtures file" in out


def test_validate_rejects_repeated_fixture_names(tmp_path: Path) -> None:
    library, fixtures = tmp_path / "library", tmp_path / "fixtures"
    library.mkdir()
    fixtures.mkdir()
    shutil.copy(LIBRARY / "suspicious_powershell.yml", library)
    case = {"name": "same", "events": [{"a": 1}]}
    (fixtures / "suspicious_powershell.json").write_text(json.dumps({"positive": [case], "negative": [case]}))
    (rule,) = load_library(library, fixtures)
    assert any("repeated" in problem for problem in rule.problems)


def _remote(rule_id: str, **overrides: object) -> dict:
    return {"id": f"uuid-{rule_id}", "tenant_id": "default", "rule_id": rule_id, "title": "t", "version": 1,
            "format": "sigma", "source_yaml": "", "query": None, "description": "d", **overrides}


def test_plan_classifies_create_update_unchanged_and_remote_only() -> None:
    local = {r.path.name: r for r in load_library(LIBRARY)}
    powershell, sudo, ssh = local["suspicious_powershell.yml"], local["privilege_escalation_indicators.yml"], local["ssh_brute_force.json"]
    remote = [
        _remote(powershell.rule_id, source_yaml=powershell.fields["source_yaml"]),
        _remote(sudo.rule_id, source_yaml="title: old"),
        _remote("only-on-server"),
    ]
    actions = {change.rule_id: change.action for change in make_plan([powershell, sudo, ssh], remote)}
    assert actions[powershell.rule_id] == "unchanged"
    assert actions[sudo.rule_id] == "update"
    assert actions[ssh.rule_id] == "create"
    assert actions["only-on-server"] == "remote-only"


class FakeApi:
    def __init__(self, rules: list[dict]) -> None:
        self.rules, self.calls = rules, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path, json.loads(request.content) if request.content else None))
        if request.method == "GET":
            return httpx.Response(200, json=self.rules)
        return httpx.Response(201 if request.method == "POST" else 200, json={"id": "new", "rule_version": 1, "expires_at": "x"})


def _patch_client(monkeypatch: pytest.MonkeyPatch, api: FakeApi) -> None:
    monkeypatch.setattr(cli, "_client", lambda _args: Client("http://api", "tok", httpx.MockTransport(api)))


def test_apply_creates_and_updates_but_never_deploys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    library, fixtures = tmp_path / "library", tmp_path / "fixtures"
    library.mkdir()
    fixtures.mkdir()
    for name in ("suspicious_powershell.yml", "ssh_brute_force.json"):
        shutil.copy(LIBRARY / name, library)
        shutil.copy(ROOT / "detection_rules" / "fixtures" / f"{Path(name).stem}.json", fixtures)
    (powershell,) = [r for r in load_library(library, fixtures) if r.path.suffix == ".yml"]
    api = FakeApi([_remote(powershell.rule_id, source_yaml="title: old")])
    _patch_client(monkeypatch, api)
    assert cli.main(["apply", str(library), "--fixtures", str(fixtures)]) == 0
    writes = [(m, p) for m, p, _ in api.calls if m != "GET"]
    assert ("PATCH", f"/api/v1/detections/uuid-{powershell.rule_id}") in writes
    assert ("POST", "/api/v1/detections") in writes
    assert not any("deploy" in path for _, path in writes)
    created = next(body for m, p, body in api.calls if m == "POST")
    assert created["rule_id"] == "nd-ssh-brute-force" and created["format"] == "threshold"


def test_apply_dry_run_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    api = FakeApi([])
    _patch_client(monkeypatch, api)
    assert cli.main(["apply", str(LIBRARY), "--dry-run"]) == 0
    assert all(method == "GET" for method, _, _ in api.calls)


def test_login_saves_a_private_token_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = tmp_path / "ndctl" / "config.json"
    monkeypatch.setenv("NDCTL_CONFIG", str(config))
    monkeypatch.setenv("NDCTL_PASSWORD", "pw")
    monkeypatch.setattr(Client, "login", lambda _self, email, _pw: {
        "access_token": "tok-123", "user": {"email": email, "role": "admin", "tenant_id": "default"}})
    assert cli.main(["login", "--url", "http://api", "--email", "a@b.co"]) == 0
    assert json.loads(config.read_text())["token"] == "tok-123"
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


def _request(role: str, tenant: str, query: dict[str, str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(principal={"role": role, "tenant_id": tenant}), query_params=query or {})


def test_rules_belong_to_the_callers_tenant_unless_an_admin_asks() -> None:
    assert _tenant(_request("security_engineer", "blue")) == "blue"
    assert _tenant(_request("security_engineer", "blue", {"tenant_id": "red"})) == "blue"
    assert _tenant(_request("admin", "default", {"tenant_id": "red"})) == "red"


def test_kibana_rule_ids_are_namespaced_for_non_default_tenants() -> None:
    args = {"title": "t", "description": "d", "metadata": {},
            "deployment": {"type": "query", "language": "kuery", "query": "*"}}
    default = build_kibana_payload(rule_id="abc", **args)
    blue = build_kibana_payload(rule_id="abc", tenant_id="blue", **args)
    assert default["rule_id"] == "abc" and "tenant:default" in default["tags"]
    assert blue["rule_id"] == "blue.abc" and "tenant:blue" in blue["tags"]
