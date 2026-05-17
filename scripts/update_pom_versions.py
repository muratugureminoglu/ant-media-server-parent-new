#!/usr/bin/env python3
"""Apply Maven version updates to root pom.xml deterministically."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROPERTY_REF_RE = re.compile(r"^\$\{([^}]+)\}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-pom", required=True, help="Root pom.xml file path")
    parser.add_argument("--updates", required=True, help="Update JSON from scout_to_maven_updates.py")
    parser.add_argument("--report", required=True, help="Output JSON report path")
    return parser.parse_args()


def detect_namespace(root: ET.Element) -> str:
    if root.tag.startswith("{") and "}" in root.tag:
        return root.tag[1 : root.tag.index("}")]
    return ""


def qname(namespace: str, local: str) -> str:
    return f"{{{namespace}}}{local}" if namespace else local


def get_child_text(node: ET.Element, namespace: str, child: str) -> str:
    found = node.find(qname(namespace, child))
    return found.text.strip() if found is not None and found.text else ""


def set_child_text(node: ET.Element, namespace: str, child: str, value: str) -> bool:
    found = node.find(qname(namespace, child))
    if found is None:
        return False
    old = (found.text or "").strip()
    if old == value:
        return False
    found.text = value
    return True


def collect_property_nodes(root: ET.Element, namespace: str) -> Dict[str, ET.Element]:
    props: Dict[str, ET.Element] = {}
    properties = root.find(qname(namespace, "properties"))
    if properties is None:
        return props
    for prop in properties:
        tag = prop.tag
        if tag.startswith("{") and "}" in tag:
            tag = tag[tag.index("}") + 1 :]
        props[tag] = prop
    return props


def dependency_blocks(root: ET.Element, namespace: str) -> List[ET.Element]:
    blocks: List[ET.Element] = []
    blocks.extend(root.findall(f".//{qname(namespace, 'dependencyManagement')}/{qname(namespace, 'dependencies')}/{qname(namespace, 'dependency')}"))
    blocks.extend(root.findall(f".//{qname(namespace, 'dependencies')}/{qname(namespace, 'dependency')}"))
    return blocks


def update_with_properties(
    updates: List[Dict[str, Any]],
    dependencies: List[ET.Element],
    property_nodes: Dict[str, ET.Element],
    namespace: str,
) -> List[Dict[str, str]]:
    changes: List[Dict[str, str]] = []
    changed_properties: Dict[str, str] = {}

    for update in updates:
        group_id = update["groupId"]
        artifact_id = update["artifactId"]
        target = update["toVersion"]
        for dep in dependencies:
            dep_group = get_child_text(dep, namespace, "groupId")
            dep_artifact = get_child_text(dep, namespace, "artifactId")
            if dep_group != group_id or dep_artifact != artifact_id:
                continue
            version_text = get_child_text(dep, namespace, "version")
            match = PROPERTY_REF_RE.match(version_text)
            if not match:
                continue
            prop_name = match.group(1)
            if prop_name not in property_nodes:
                continue
            old_value = (property_nodes[prop_name].text or "").strip()
            if old_value == target:
                continue
            property_nodes[prop_name].text = target
            changed_properties[prop_name] = old_value
            changes.append(
                {
                    "type": "property",
                    "dependency": f"{group_id}:{artifact_id}",
                    "location": f"properties.{prop_name}",
                    "from": old_value,
                    "to": target,
                }
            )
            break
    return changes


def update_direct_versions(
    updates: List[Dict[str, Any]],
    dependencies: List[ET.Element],
    namespace: str,
) -> List[Dict[str, str]]:
    changes: List[Dict[str, str]] = []
    touched: set[Tuple[str, str]] = set()

    for update in updates:
        key = (update["groupId"], update["artifactId"])
        if key in touched:
            continue
        target = update["toVersion"]
        from_version = update["fromVersion"]
        updated = False
        for dep in dependencies:
            dep_group = get_child_text(dep, namespace, "groupId")
            dep_artifact = get_child_text(dep, namespace, "artifactId")
            if (dep_group, dep_artifact) != key:
                continue
            version_text = get_child_text(dep, namespace, "version")
            if not version_text:
                continue
            if PROPERTY_REF_RE.match(version_text):
                continue
            if version_text == target:
                updated = True
                break
            if set_child_text(dep, namespace, "version", target):
                changes.append(
                    {
                        "type": "dependencyVersion",
                        "dependency": f"{dep_group}:{dep_artifact}",
                        "location": "dependency.version",
                        "from": version_text or from_version,
                        "to": target,
                    }
                )
                updated = True
                break
        if updated:
            touched.add(key)
    return changes


def main() -> int:
    args = parse_args()
    root_pom = Path(args.root_pom)
    updates_path = Path(args.updates)
    report_path = Path(args.report)

    if not root_pom.exists():
        report = {"changes": [], "error": f"Root pom file not found: {root_pom}"}
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1

    updates_data = json.loads(updates_path.read_text(encoding="utf-8"))
    updates = updates_data.get("updates", [])
    if not updates:
        report_path.write_text(json.dumps({"changes": []}, indent=2) + "\n", encoding="utf-8")
        return 0

    tree = ET.parse(root_pom)
    root = tree.getroot()
    namespace = detect_namespace(root)
    dependencies = dependency_blocks(root, namespace)
    property_nodes = collect_property_nodes(root, namespace)

    changes = []
    changes.extend(update_with_properties(updates, dependencies, property_nodes, namespace))
    changes.extend(update_direct_versions(updates, dependencies, namespace))

    if changes:
        tree.write(root_pom, encoding="utf-8", xml_declaration=True)

    report = {"changes": changes}
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
