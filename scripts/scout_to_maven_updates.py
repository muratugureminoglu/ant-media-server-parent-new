#!/usr/bin/env python3
"""Extract Maven update candidates from Docker Scout SARIF output."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

PURL_PATTERN = re.compile(r"pkg:maven/([^/\s]+)/([^@\s]+)@([^\s?#\"']+)")
FIXED_VERSION_PATTERNS = [
    re.compile(r"fixed\s+in\s+([0-9A-Za-z_.\-+]+)", re.IGNORECASE),
    re.compile(r"upgrade\s+to\s+([0-9A-Za-z_.\-+]+)", re.IGNORECASE),
    re.compile(r"patched\s+in\s+([0-9A-Za-z_.\-+]+)", re.IGNORECASE),
]
VERSION_TOKEN_RE = re.compile(r"^[0-9][0-9A-Za-z_.\-+]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True, help="Path to Scout SARIF file")
    parser.add_argument("--output", required=True, help="JSON output with update candidates")
    parser.add_argument(
        "--summary",
        required=True,
        help="Markdown summary output used in PR description",
    )
    return parser.parse_args()


def walk_json(node: Any) -> Iterable[Any]:
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from walk_json(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_json(item)


def extract_purls(node: Any) -> Set[str]:
    found: Set[str] = set()
    for item in walk_json(node):
        if isinstance(item, str):
            for match in PURL_PATTERN.finditer(item):
                found.add(match.group(0))
    return found


def split_purl(purl: str) -> Optional[Tuple[str, str, str]]:
    match = PURL_PATTERN.search(purl)
    if not match:
        return None
    group_id = unquote(match.group(1))
    artifact_id = unquote(match.group(2))
    version = unquote(match.group(3))
    return group_id, artifact_id, version


def extract_fixed_candidates(node: Any) -> Set[str]:
    candidates: Set[str] = set()
    preferred_keys = {
        "fixedVersion",
        "fixVersion",
        "fixed_version",
        "firstPatchedVersion",
        "patchedVersion",
        "nearestFixedInVersion",
    }
    for item in walk_json(node):
        if isinstance(item, dict):
            for key, value in item.items():
                if key in preferred_keys and isinstance(value, str) and VERSION_TOKEN_RE.match(value):
                    candidates.add(value)
        elif isinstance(item, str):
            for pattern in FIXED_VERSION_PATTERNS:
                match = pattern.search(item)
                if match:
                    version = match.group(1)
                    if VERSION_TOKEN_RE.match(version):
                        candidates.add(version)
    return candidates


def choose_target_version(current: str, candidates: Set[str]) -> Optional[str]:
    if not candidates:
        return None
    if current in candidates and len(candidates) == 1:
        return None
    sorted_candidates = sorted(candidates)
    for candidate in sorted_candidates:
        if candidate != current:
            return candidate
    return None


def normalize_rule_id(result: Dict[str, Any]) -> str:
    rule_id = str(result.get("ruleId", "")).strip()
    if rule_id:
        return rule_id
    message = (
        result.get("message", {}).get("text")
        or result.get("message", {}).get("markdown")
        or "UNKNOWN-CVE"
    )
    cve_match = re.search(r"CVE-\d{4}-\d+", message)
    return cve_match.group(0) if cve_match else "UNKNOWN-CVE"


def build_updates(sarif: Dict[str, Any]) -> Dict[str, Any]:
    updates_by_ga: Dict[Tuple[str, str], Dict[str, Any]] = {}
    cves_by_ga: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    runs = sarif.get("runs", [])

    for run in runs:
        results = run.get("results", [])
        for result in results:
            purls = extract_purls(result)
            if not purls:
                continue
            rule_id = normalize_rule_id(result)
            fixed_candidates = extract_fixed_candidates(result)

            for purl in purls:
                parsed = split_purl(purl)
                if not parsed:
                    continue
                group_id, artifact_id, current_version = parsed
                target_version = choose_target_version(current_version, fixed_candidates)
                if not target_version:
                    continue

                key = (group_id, artifact_id)
                existing = updates_by_ga.get(key)
                if existing:
                    existing_target = existing["toVersion"]
                    if target_version > existing_target:
                        existing["toVersion"] = target_version
                else:
                    updates_by_ga[key] = {
                        "groupId": group_id,
                        "artifactId": artifact_id,
                        "fromVersion": current_version,
                        "toVersion": target_version,
                    }
                cves_by_ga[key].add(rule_id)

    updates = []
    for key, update in sorted(updates_by_ga.items()):
        update["cves"] = sorted(cves_by_ga.get(key, set()))
        updates.append(update)

    return {"updates": updates}


def write_summary(summary_path: Path, updates: List[Dict[str, Any]]) -> None:
    lines = [
        "## Docker Scout Maven Update Summary",
        "",
    ]
    if not updates:
        lines.extend(
            [
                "No fixed High/Critical Maven CVE candidate was detected in this run.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                f"Detected `{len(updates)}` updatable Maven dependency candidate(s).",
                "",
                "| Dependency | From | To | CVEs |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in updates:
            dependency = f"{item['groupId']}:{item['artifactId']}"
            cves = ", ".join(item.get("cves") or ["UNKNOWN-CVE"])
            lines.append(f"| `{dependency}` | `{item['fromVersion']}` | `{item['toVersion']}` | {cves} |")
        lines.append("")
    summary_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    sarif_path = Path(args.sarif)
    output_path = Path(args.output)
    summary_path = Path(args.summary)

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    data = build_updates(sarif)
    output_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    write_summary(summary_path, data["updates"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
