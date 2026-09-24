#!/usr/bin/env python3
"""Render aggregate real-sample coverage reports from per-sample evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
import sys
from typing import Any


def load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="?", default=Path("fixtures/real-samples/manifest.json"))
    parser.add_argument("--tier", required=True, choices=("pr", "nightly", "release"))
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    manifest = load(arguments.manifest, {})
    projects = manifest.get("corpus", {}).get("projects", []) if isinstance(manifest, dict) else []
    artifact_root = arguments.artifact_root or Path(".artifacts/real-samples") / arguments.tier
    output_json = arguments.output_json or artifact_root / "aggregate.json"
    output_markdown = arguments.output_markdown or artifact_root / "aggregate.md"

    layer_counts: dict[str, Counter[str]] = defaultdict(Counter)
    runtime_counts: Counter[str] = Counter()
    producer_counts: Counter[str] = Counter()
    feature_counts: Counter[str] = Counter()
    first_seen: list[dict[str, str]] = []
    unsupported: list[dict[str, str]] = []
    records: list[dict[str, Any]] = []
    declared_by_project: dict[str, set[str]] = {}

    for project in projects if isinstance(projects, list) else []:
        if not isinstance(project, dict):
            continue
        project_id = project.get("projectId")
        if not isinstance(project_id, str):
            continue
        declared_fingerprint = project.get("featureFingerprint", {})
        declared = set(declared_fingerprint.get("featureTags", [])) if isinstance(declared_fingerprint, dict) else set()
        declared_by_project[project_id] = {str(value) for value in declared}
        runtime = project.get("target", {}).get("runtime", "unknown") if isinstance(project.get("target"), dict) else "unknown"
        runtime_counts[str(runtime)] += 1
        producer = declared_fingerprint.get("producer", "unknown") if isinstance(declared_fingerprint, dict) else "unknown"
        producer_counts[str(producer)] += 1
        sample_root = artifact_root / project_id
        result = load(sample_root / "result.json", {})
        fingerprint = load(sample_root / "elf-fingerprint.json", {})
        layers = result.get("layers", {}) if isinstance(result, dict) else {}
        for layer in ("static", "baseline", "outerWrapper", "hostContext"):
            value = layers.get(layer, {}) if isinstance(layers, dict) else {}
            actual = value.get("actual", "environment-unavailable") if isinstance(value, dict) else "environment-unavailable"
            layer_counts[layer][str(actual)] += 1
        tags = fingerprint.get("featureTags", []) if isinstance(fingerprint, dict) else []
        for tag in tags if isinstance(tags, list) else []:
            feature = str(tag)
            feature_counts[feature] += 1
            if feature not in declared:
                first_seen.append({"projectId": project_id, "feature": feature})
                if "unsupported" in feature or "unknown" in feature:
                    unsupported.append({"projectId": project_id, "feature": feature})
        records.append(
            {
                "projectId": project_id,
                "runtime": runtime,
                "producer": producer,
                "artifact": f"{project_id}/result.json",
                "layers": {
                    layer: (layers.get(layer, {}) if isinstance(layers, dict) else {})
                    for layer in ("static", "baseline", "outerWrapper", "hostContext")
                },
            }
        )

    aggregate = {
        "schemaVersion": 1,
        "tier": arguments.tier,
        "requiredProjectCount": 20,
        "observedProjectCount": len(records),
        "projectIds": [record["projectId"] for record in records],
        "layerCounts": {layer: dict(sorted(counts.items())) for layer, counts in sorted(layer_counts.items())},
        "runtimeCoverage": dict(sorted(runtime_counts.items())),
        "producerCoverage": dict(sorted(producer_counts.items())),
        "featureCoverage": dict(sorted(feature_counts.items())),
        "firstSeenFeatures": first_seen,
        "unsupportedOrBoundaryFeatures": unsupported,
        "unexpectedOutcomes": [
            {
                "projectId": record["projectId"],
                "layer": layer,
                "expected": value.get("expected"),
                "actual": value.get("actual"),
                "artifact": record["artifact"],
            }
            for record in records
            for layer, value in record["layers"].items()
            if isinstance(value, dict) and value.get("expected") != value.get("actual")
        ],
        "records": records,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"# Public real-sample aggregate ({arguments.tier})",
        "",
        f"Locked projects: **{len(records)}/20** (the evidence gate requires all 20).",
        "",
        "## Layer outcomes",
        "",
        "| Layer | Status | Count |",
        "| --- | --- | ---: |",
    ]
    for layer, counts in sorted(layer_counts.items()):
        for status, count in sorted(counts.items()):
            lines.append(f"| {layer} | `{status}` | {count} |")
    lines.extend(["", "## Runtime and producer coverage", "", "| Dimension | Value | Count |", "| --- | --- | ---: |"])
    for dimension, counts in (("runtime", runtime_counts), ("producer", producer_counts)):
        for value, count in sorted(counts.items()):
            lines.append(f"| {dimension} | `{value}` | {count} |")
    lines.extend(["", "## First-seen and boundary features", ""])
    if first_seen:
        for item in first_seen:
            lines.append(f"- `{item['projectId']}`: `{item['feature']}`")
    else:
        lines.append("- None beyond the registry fingerprint declarations.")
    lines.extend(["", "## Unexpected outcomes", ""])
    if aggregate["unexpectedOutcomes"]:
        for item in aggregate["unexpectedOutcomes"]:
            lines.append(
                f"- `{item['projectId']}` / `{item['layer']}` expected "
                f"`{item['expected']}` but observed `{item['actual']}` "
                f"(`{item['artifact']}`)."
            )
    else:
        lines.append("- None recorded in the aggregate input.")
    lines.extend(["", "Per-sample evidence is linked by `projectId`; raw archives and binaries are never retained here.", ""])
    output_markdown.write_text("\n".join(lines), encoding="utf-8")
    print(f"PASS real-sample aggregate: {output_json} and {output_markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
