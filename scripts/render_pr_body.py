#!/usr/bin/env python3
"""Render pull request body for Scout Maven autofix runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True, help="Markdown summary path")
    parser.add_argument("--changes", required=True, help="JSON changes report path")
    parser.add_argument("--output", required=True, help="PR markdown output path")
    return parser.parse_args()


def load_changes(path: Path) -> List[Dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("changes", [])


def main() -> int:
    args = parse_args()
    summary = Path(args.summary).read_text(encoding="utf-8").strip()
    changes = load_changes(Path(args.changes))
    output_path = Path(args.output)

    lines = [
        "## Summary",
        "",
        "Automated dependency fix generated from Docker Scout findings.",
        "",
        summary,
        "",
        "## Applied pom.xml changes",
        "",
    ]

    if not changes:
        lines.extend(["No pom.xml change was required.", ""])
    else:
        lines.extend(
            [
                "| Dependency | Location | From | To |",
                "| --- | --- | --- | --- |",
            ]
        )
        for change in changes:
            lines.append(
                f"| `{change['dependency']}` | `{change['location']}` | "
                f"`{change['from']}` | `{change['to']}` |"
            )
        lines.append("")

    lines.extend(
        [
            "## Validation",
            "",
            "- [x] Docker Scout scan (only-fixed, critical/high)",
            "- [x] Maven validate (`-DskipTests`)",
            "- [x] Manual merge required (automerge disabled)",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
