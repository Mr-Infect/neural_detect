from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from detection_engine.library import LibraryRule, load_library
from ndctl.client import ApiError, Client
from ndctl.plan import Change, make_plan, update_payload

DEFAULT_RULES = Path("detection_rules/library")
SYMBOLS = {"create": "+", "update": "~", "unchanged": "=", "remote-only": "?"}


def _config_path() -> Path:
    return Path(os.environ.get("NDCTL_CONFIG", Path.home() / ".config" / "ndctl" / "config.json"))


def _read_config() -> dict[str, str]:
    try:
        return json.loads(_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _client(args: argparse.Namespace) -> Client:
    config = _read_config()
    url = args.url or os.environ.get("NDCTL_URL") or config.get("url") or "http://localhost:8001"
    token = os.environ.get("NDCTL_TOKEN") or config.get("token")
    client = Client(url, token)
    if not token and os.environ.get("NDCTL_EMAIL") and os.environ.get("NDCTL_PASSWORD"):
        # Non-interactive use (CI): sign in on the fly with credentials from the environment.
        token = client.login(os.environ["NDCTL_EMAIL"], os.environ["NDCTL_PASSWORD"])["access_token"]
        client = Client(url, token)
    if not token:
        raise SystemExit("Not signed in. Run `ndctl login`, or set NDCTL_TOKEN (or NDCTL_EMAIL and NDCTL_PASSWORD).")
    return client


def _load(args: argparse.Namespace) -> list[LibraryRule]:
    directory = Path(args.path)
    if not directory.is_dir():
        raise SystemExit(f"Rules directory not found: {directory}")
    fixtures = Path(args.fixtures) if args.fixtures else None
    return load_library(directory, fixtures)


def _report_problems(rules: list[LibraryRule]) -> int:
    failed = 0
    for rule in rules:
        if rule.problems:
            failed += 1
            print(f"FAIL  {rule.path.name}")
            for problem in rule.problems:
                print(f"        {problem}")
        else:
            cases = len(rule.fixtures["positive"]) + len(rule.fixtures["negative"]) if rule.fixtures else 0
            print(f"ok    {rule.path.name}  ({rule.rule_format}, {cases} fixture cases)")
    return failed


def cmd_validate(args: argparse.Namespace) -> int:
    rules = _load(args)
    if not rules:
        print(f"No rules found in {args.path}")
        return 1
    failed = _report_problems(rules)
    print(f"\n{len(rules) - failed}/{len(rules)} rules valid.")
    return 1 if failed else 0


async def _run_live(rules: list[LibraryRule]) -> list[str]:
    from detection_engine.testing.runner import run_fixture_tests
    from integrations.elasticsearch.client import close_client
    from integrations.elasticsearch.pipelines import install_ecs_index_template

    failures: list[str] = []
    try:
        await install_ecs_index_template()  # same ECS mapping production uses
        for rule in rules:
            outcome = await run_fixture_tests(rule.rule_format, rule.fields["compiled_query"], rule.fixtures or {})
            print(f"  fixtures {'ok' if outcome['passed'] else 'FAILED'}: {rule.path.name}")
            if not outcome["passed"]:
                failures.append(f"{rule.path.name}: {', '.join(outcome['failures'])}")
    finally:
        await close_client()
    return failures


def cmd_test(args: argparse.Namespace) -> int:
    rules = _load(args)
    if not rules:
        print(f"No rules found in {args.path}")
        return 1
    if _report_problems(rules):
        return 1
    print("\nRunning fixtures against Elasticsearch (ND_ELASTICSEARCH_URL and credentials from the environment)...")
    failures = asyncio.run(_run_live(rules))
    if failures:
        print("\nFixture failures:\n  " + "\n  ".join(failures))
        return 1
    print(f"\nAll {len(rules)} rules passed their fixtures.")
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    url = args.url or os.environ.get("NDCTL_URL") or "http://localhost:8001"
    email = args.email or input("Email: ")
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = os.environ.get("NDCTL_PASSWORD") or getpass.getpass("Password: ")
    client = Client(url)
    try:
        session = client.login(email, password)
    except ApiError as exc:
        print(f"Sign-in failed: {exc.detail}")
        return 2
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"url": url, "token": session["access_token"]}), encoding="utf-8")
    path.chmod(0o600)
    user = session["user"]
    print(f"Signed in to {url} as {user['email']} (role {user['role']}, tenant {user['tenant_id']}).")
    return 0


def _print_plan(changes: list[Change]) -> None:
    for change in changes:
        print(f"  {SYMBOLS[change.action]} {change.action:<12} {change.rule_id}  {change.title}")
    counts = {name: sum(c.action == name for c in changes) for name in SYMBOLS}
    print(f"\n{counts['create']} to create, {counts['update']} to update, {counts['unchanged']} unchanged, "
          f"{counts['remote-only']} only on the server (never deleted).")


def _plan(args: argparse.Namespace) -> tuple[Client, list[LibraryRule], list[Change]]:
    rules = _load(args)
    if not rules:
        raise SystemExit(f"No rules found in {args.path}")
    if any(rule.problems for rule in rules):
        _report_problems(rules)
        raise SystemExit("\nFix the problems above first (see `ndctl validate`).")
    client = _client(args)
    return client, rules, make_plan(rules, client.list_rules(args.tenant))


def cmd_plan(args: argparse.Namespace) -> int:
    _, _, changes = _plan(args)
    _print_plan(changes)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    client, _, changes = _plan(args)
    _print_plan(changes)
    todo = [c for c in changes if c.action in {"create", "update"}]
    if not todo:
        print("Nothing to apply.")
        return 0
    if args.dry_run:
        print("Dry run: nothing was changed.")
        return 0
    errors = 0
    for change in todo:
        try:
            if change.action == "create" and change.local:
                client.create_rule(change.local.create_payload, args.tenant)
            elif change.local and change.remote:
                client.update_rule(change.remote["id"], update_payload(change.local), args.tenant)
            print(f"applied {change.action}: {change.rule_id}")
        except ApiError as exc:
            errors += 1
            print(f"FAILED {change.action}: {change.rule_id}: {exc.detail}")
    print("\nRules are stored, not live. Request approval, then a second person approves and someone deploys.")
    return 1 if errors else 0


def cmd_status(args: argparse.Namespace) -> int:
    rules = _client(args).list_rules(args.tenant)
    for rule in rules:
        print(f"  {rule['rule_id']}  v{rule['version']}  {rule['format']:<9} {rule['title']}")
    print(f"\n{len(rules)} rules in tenant {rules[0]['tenant_id'] if rules else args.tenant or '(yours)'}.")
    return 0


def _rule_uuid(client: Client, rule_id: str, tenant: str | None) -> str:
    for rule in client.list_rules(tenant):
        if rule["rule_id"] == rule_id:
            return rule["id"]
    raise SystemExit(f"No rule with ID {rule_id} on the server. Run `ndctl apply` first.")


def cmd_request_approval(args: argparse.Namespace) -> int:
    client = _client(args)
    approval = client.request_approval(_rule_uuid(client, args.rule_id, args.tenant), "ndctl", args.tenant)
    print(f"Approval {approval['id']} requested for version {approval['rule_version']} (expires {approval['expires_at']}).")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    client = _client(args)
    try:
        client.deploy(_rule_uuid(client, args.rule_id, args.tenant), args.approval, args.tenant)
    except ApiError as exc:
        print(f"Deploy refused: {exc.detail}")
        return 1
    print(f"Deployed {args.rule_id} to Kibana.")
    return 0


def _common(parser: argparse.ArgumentParser, rules: bool = False, server: bool = False) -> None:
    if rules:
        parser.add_argument("path", nargs="?", default=str(DEFAULT_RULES), help="directory of rule files")
        parser.add_argument("--fixtures", help="fixtures directory (default: ../fixtures next to the rules)")
    if server:
        parser.add_argument("--url", help="API base URL (default: $NDCTL_URL or the saved login)")
        parser.add_argument("--tenant", help="tenant slug (administrators only; default: your own tenant)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ndctl", description="Detection-as-code for NEURAL DETECT.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="check rules and fixtures offline").set_defaults(run=cmd_validate)
    sub.add_parser("test", help="validate, then run fixtures on Elasticsearch").set_defaults(run=cmd_test)
    login = sub.add_parser("login", help="sign in and save a token")
    login.add_argument("--url")
    login.add_argument("--email")
    login.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    login.set_defaults(run=cmd_login)
    sub.add_parser("plan", help="show what apply would change").set_defaults(run=cmd_plan)
    apply = sub.add_parser("apply", help="create or update rules on the server (never deploys)")
    apply.add_argument("--dry-run", action="store_true")
    apply.set_defaults(run=cmd_apply)
    sub.add_parser("status", help="list rules on the server").set_defaults(run=cmd_status)
    approval = sub.add_parser("request-approval", help="ask for deployment approval of a rule")
    approval.add_argument("rule_id")
    approval.set_defaults(run=cmd_request_approval)
    deploy = sub.add_parser("deploy", help="deploy a rule using an approved request")
    deploy.add_argument("rule_id")
    deploy.add_argument("--approval", required=True, help="approval ID that was approved")
    deploy.set_defaults(run=cmd_deploy)
    for name, child in sub.choices.items():
        _common(child, rules=name in {"validate", "test", "plan", "apply"},
                server=name not in {"validate", "test", "login"})
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result: Any = args.run(args)
    except ApiError as exc:
        print(f"Error: {exc.detail}", file=sys.stderr)
        return 2
    return int(result)
