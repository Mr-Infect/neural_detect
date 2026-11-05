"""MITRE ATT&CK helpers: read tags from rules, build a coverage report, parse the official STIX bundle."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

TACTICS = [
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def parse_tags(tags: list[str]) -> tuple[set[str], set[str]]:
    """Return (tactics, technique IDs such as T1059.001) found in Sigma-style tags."""
    tactics, techniques = set(), set()
    for tag in tags:
        text = str(tag).strip().lower()
        match = _TECHNIQUE.match(text)
        if match:
            techniques.add(match.group(1).upper())
        elif text.startswith("attack.") and text[7:].replace("-", "_") in TACTICS:
            tactics.add(text[7:].replace("-", "_"))
    return tactics, techniques


def load_bundle(path: Path) -> dict[str, dict[str, Any]]:
    """Parse an ATT&CK STIX bundle into {technique ID: {name, tactics, sub}}; revoked and deprecated are skipped."""
    objects = json.loads(path.read_text(encoding="utf-8")).get("objects", [])
    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or not str(ref.get("external_id", "")).startswith("T"):
            continue
        techniques[ref["external_id"]] = {
            "name": obj.get("name", ""),
            "tactics": sorted(p["phase_name"].replace("-", "_") for p in obj.get("kill_chain_phases", [])),
            "sub": bool(obj.get("x_mitre_is_subtechnique")),
        }
    return techniques


def _base(technique: str) -> str:
    return technique.split(".")[0]


def build_coverage(rules: list[tuple[str, list[str]]], bundle: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """rules: [(title, tags)]. Sub-techniques roll up to their parent when counting coverage."""
    by_tactic: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"techniques": set(), "rules": set()})
    technique_rules: dict[str, set[str]] = defaultdict(set)
    untagged: list[str] = []
    for title, tags in rules:
        tactics, techniques = parse_tags(tags)
        if not tactics and not techniques:
            untagged.append(title)
            continue
        for technique in techniques:
            technique_rules[technique].add(title)
        for tactic in tactics:
            by_tactic[tactic]["rules"].add(title)
        for technique in techniques:
            if bundle and technique in bundle and bundle[technique]["tactics"]:
                targets = set(bundle[technique]["tactics"])
            else:
                targets = tactics  # without the bundle, attribute to the tactics tagged on the same rule
            for tactic in targets:
                by_tactic[tactic]["techniques"].add(technique)
                by_tactic[tactic]["rules"].add(title)
    covered_base = {_base(t) for t in technique_rules}
    report: dict[str, Any] = {
        "rule_count": len(rules), "untagged_rules": sorted(untagged),
        "techniques": {t: sorted(r) for t, r in sorted(technique_rules.items())},
        "tactics": {},
    }
    ordered = [t for t in TACTICS if t in by_tactic] + sorted(set(by_tactic) - set(TACTICS))
    for tactic in ordered:
        entry: dict[str, Any] = {
            "techniques": sorted(by_tactic[tactic]["techniques"]), "rules": len(by_tactic[tactic]["rules"]),
        }
        if bundle:
            total = {t for t, info in bundle.items() if not info["sub"] and tactic in info["tactics"]}
            hit = total & covered_base
            entry.update(total_techniques=len(total), covered_techniques=len(hit),
                         percent=round(100 * len(hit) / len(total), 1) if total else 0.0)
        report["tactics"][tactic] = entry
    if bundle:
        all_base = {t for t, info in bundle.items() if not info["sub"]}
        report["overall"] = {
            "covered_techniques": len(all_base & covered_base), "total_techniques": len(all_base),
            "percent": round(100 * len(all_base & covered_base) / len(all_base), 1) if all_base else 0.0,
            "uncovered_tactics": [t for t in TACTICS if t not in by_tactic],
        }
    return report


def render_text(report: dict[str, Any], title: str, bundle: bool) -> str:
    lines = [f"ATT&CK coverage for {title} ({report['rule_count']} rules)", ""]
    header = f"{'Tactic':<22}{'Rules':>6}{'Techniques':>12}" + (f"{'Coverage':>14}" if bundle else "") + "  IDs"
    lines.append(header)
    for tactic, entry in report["tactics"].items():
        row = f"{tactic:<22}{entry['rules']:>6}{len(entry['techniques']):>12}"
        if bundle:
            row += f"{entry['covered_techniques']:>7}/{entry['total_techniques']:<4}{entry['percent']:>5.0f}%".rjust(14)
        lines.append(row + "  " + ", ".join(entry["techniques"]))
    if bundle:
        overall = report["overall"]
        summary = (
            f"Overall: {overall['covered_techniques']} of {overall['total_techniques']} techniques "
            f"({overall['percent']}%). No rules for: {', '.join(overall['uncovered_tactics']) or 'none'}."
        )
        lines += ["", summary]
    else:
        lines += ["", f"{len(report['techniques'])} techniques covered. Add --attack-bundle FILE for percentages and gaps."]
    if report["untagged_rules"]:
        lines.append("Rules without ATT&CK tags: " + ", ".join(report["untagged_rules"]))
    return "\n".join(lines)


def render_markdown(report: dict[str, Any], bundle: bool) -> str:
    cols = "| Tactic | Rules | Techniques |" + (" Coverage |" if bundle else "") + " IDs |"
    lines = [cols, "|" + "---|" * (cols.count("|") - 1)]
    for tactic, entry in report["tactics"].items():
        cov = f" {entry['covered_techniques']}/{entry['total_techniques']} ({entry['percent']:.0f}%) |" if bundle else ""
        lines.append(f"| {tactic} | {entry['rules']} | {len(entry['techniques'])} |{cov} {', '.join(entry['techniques'])} |")
    return "\n".join(lines)
