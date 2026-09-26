#!/usr/bin/env python3
"""Render bounded aggregate reports from public real-sample evidence.

The report groups by ``identityKey`` rather than libc/build variants and keeps
registry-only baseline output separate from CI observations.  It never reads
or copies an acquired ELF; only normalized JSON evidence is consumed.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from real_sample_schema import (  # noqa: E402
    FIRST_FAILURE_LAYERS,
    LAYERS,
    RESULTS,
    diagnostic_code,
    first_failure_layer,
    observed_features,
)

REPORT_SCHEMA_VERSION = 2
THRESHOLD_PERCENT = 5.0
MAX_PROJECTS = 1000


class ReportError(Exception):
    """The retained evidence cannot be normalized into an aggregate."""


def load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def load_required(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"could not read {label} {path}: {error}") from error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="?", default=Path("fixtures/real-samples/manifest.json"))
    parser.add_argument("--tier", required=True, choices=("pr", "nightly", "release"))
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    parser.add_argument(
        "--dispositions",
        type=Path,
        default=Path("fixtures/real-samples/feature-dispositions.json"),
        help="reviewed roadmap dispositions for aggregate features",
    )
    parser.add_argument(
        "--require-evidence",
        action="store_true",
        help="fail when a project lacks CI result/fingerprint evidence",
    )
    parser.add_argument(
        "--registry-only",
        action="store_true",
        help="render a metadata-only baseline and never read per-project evidence",
    )
    return parser.parse_args()


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def counter_json(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def percent(count: int, total: int) -> float:
    return round((count * 100.0 / total), 2) if total else 0.0


def disposition_for(
    feature: str,
    dispositions: dict[str, Any],
) -> dict[str, Any]:
    value = dispositions.get(feature)
    if isinstance(value, dict):
        status = value.get("status")
        reason = value.get("reason")
        if isinstance(status, str) and isinstance(reason, str) and reason.strip():
            return {
                "status": status,
                "reason": reason,
                "source": value.get("source", "reviewed-feature-dispositions"),
            }
    # A newly observed feature is recorded as deferred rather than silently
    # promoted.  It remains visible to the next review wave and never changes
    # a product support status.
    return {
        "status": "deferred",
        "reason": "Observed after the registry disposition freeze; queue for the next evidence review wave.",
        "source": "aggregate-default",
    }


def declared_fingerprint(project: dict[str, Any]) -> dict[str, Any]:
    value = project.get("featureFingerprint")
    return value if isinstance(value, dict) else {}


def project_identity(project: dict[str, Any]) -> tuple[str, str]:
    project_id = project.get("projectId")
    identity = project.get("identityKey")
    if not isinstance(project_id, str) or not project_id:
        raise ReportError("manifest project has no projectId")
    if not isinstance(identity, str) or not identity:
        raise ReportError(f"{project_id} has no identityKey")
    return project_id, identity


def expected_layers(project: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policy = as_mapping(project.get("executionPolicy"))
    values: dict[str, dict[str, Any]] = {}
    for layer in LAYERS:
        declaration = as_mapping(policy.get(layer))
        expected = declaration.get("expectedResult", "environment-unavailable")
        values[layer] = {
            "expected": expected,
            "actual": expected,
            "status": "metadata-only",
            "reason": "Registry policy baseline; CI oracle has not been acquired.",
        }
    return values


def load_project_evidence(
    artifact_root: Path,
    project: dict[str, Any],
    *,
    registry_only: bool,
    require_evidence: bool,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    project_id, _ = project_identity(project)
    if registry_only:
        return expected_layers(project), declared_fingerprint(project), "registry-baseline"
    sample_root = artifact_root / project_id
    result_path = sample_root / "result.json"
    fingerprint_path = sample_root / "elf-fingerprint.json"
    result = load(result_path, {})
    fingerprint = load(fingerprint_path, {})
    if require_evidence and (not isinstance(result, dict) or not isinstance(fingerprint, dict)):
        raise ReportError(f"{project_id}: result.json and elf-fingerprint.json are required")
    policy = as_mapping(project.get("executionPolicy"))
    if isinstance(result, dict) and isinstance(result.get("layers"), dict):
        layers: dict[str, Any] = {}
        for layer in LAYERS:
            value = result["layers"].get(layer)
            if isinstance(value, dict):
                layers[layer] = value
            else:
                layers[layer] = {
                    "expected": as_mapping(policy.get(layer)).get("expectedResult"),
                    "actual": "environment-unavailable",
                    "status": "failed",
                    "reason": "Layer result is missing from retained evidence.",
                }
    else:
        if require_evidence:
            raise ReportError(f"{project_id}: result.json has no layers")
        layers = expected_layers(project)
    if not isinstance(fingerprint, dict) or not fingerprint:
        if require_evidence:
            raise ReportError(f"{project_id}: fingerprint evidence is missing")
        return layers, declared_fingerprint(project), "registry-baseline"
    return layers, fingerprint, "ci-evidence"


def feature_observation(
    project: dict[str, Any], fingerprint: dict[str, Any], source: str
) -> list[str]:
    features = set(observed_features(fingerprint))
    if source == "registry-baseline":
        # Registry fields are immutable identity invariants, not inferred
        # feature support.  They are useful for the baseline only when clearly
        # labeled as declared metadata.
        for field, value in (
            ("elf.class", fingerprint.get("elfClass")),
            ("elf.data", fingerprint.get("data")),
            ("elf.machine", fingerprint.get("machine")),
        ):
            if isinstance(value, str) and value:
                features.add(f"{field}.{value}")
    return sorted(features)[:512]


def build_report(
    manifest: dict[str, Any],
    projects: list[dict[str, Any]],
    tier: str,
    artifact_root: Path,
    dispositions: dict[str, Any],
    *,
    registry_only: bool,
    require_evidence: bool,
) -> dict[str, Any]:
    if len(projects) > MAX_PROJECTS:
        raise ReportError(f"registry contains more than {MAX_PROJECTS} projects")
    corpus = as_mapping(manifest.get("corpus"))
    required_count = corpus.get("requiredProjectCount", len(projects))
    target_count = corpus.get("targetProjectCount", 100)
    if not isinstance(required_count, int) or required_count <= 0:
        raise ReportError("manifest corpus.requiredProjectCount must be a positive integer")
    if not isinstance(target_count, int) or target_count < required_count:
        raise ReportError("manifest corpus.targetProjectCount must cover the locked registry")

    layer_counts: dict[str, Counter[str]] = defaultdict(Counter)
    producer_counts: Counter[str] = Counter()
    runtime_counts: Counter[str] = Counter()
    loader_counts: Counter[str] = Counter()
    page_size_counts: Counter[str] = Counter()
    result_counts: Counter[str] = Counter()
    diagnostic_counts: Counter[str] = Counter()
    feature_projects: dict[str, set[str]] = defaultdict(set)
    feature_identities: dict[str, set[str]] = defaultdict(set)
    feature_variants: dict[str, set[str]] = defaultdict(set)
    feature_producers: dict[str, Counter[str]] = defaultdict(Counter)
    feature_runtimes: dict[str, Counter[str]] = defaultdict(Counter)
    feature_failures: dict[str, Counter[str]] = defaultdict(Counter)
    feature_diagnostics: dict[str, Counter[str]] = defaultdict(Counter)
    declared_feature_counts: Counter[str] = Counter()
    first_failure_counts: Counter[str] = Counter()
    records: list[dict[str, Any]] = []
    first_failures: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    seen_projects: set[str] = set()
    seen_identities: dict[str, list[str]] = defaultdict(list)
    observation_sources: Counter[str] = Counter()

    for project in projects:
        if not isinstance(project, dict):
            raise ReportError("manifest corpus.projects contains a non-object")
        project_id, identity = project_identity(project)
        if project_id in seen_projects:
            raise ReportError(f"duplicate projectId in aggregate input: {project_id}")
        seen_projects.add(project_id)
        normalized_identity = identity.casefold()
        seen_identities[normalized_identity].append(project_id)
        target = as_mapping(project.get("target"))
        runtime = str(target.get("runtime", "unknown"))
        loader = str(target.get("loader", "unknown"))
        declared = declared_fingerprint(project)
        declared_tags = declared.get("expectedFeatureTags", [])
        if isinstance(declared_tags, list):
            for value in declared_tags[:256]:
                if isinstance(value, str):
                    declared_feature_counts[value] += 1
        layers, fingerprint, source = load_project_evidence(
            artifact_root,
            project,
            registry_only=registry_only,
            require_evidence=require_evidence,
        )
        observation_sources[source] += 1
        runtime_value = str(fingerprint.get("runtime", runtime))
        producer = str(fingerprint.get("producer", declared.get("producer", "unknown")))
        loader_value = str(fingerprint.get("loader", fingerprint.get("interpreter", loader) or "unknown"))
        page_size_value = fingerprint.get("pageSize", target.get("pageSize", "unknown"))
        page_size = str(page_size_value if page_size_value is not None else "unknown")
        producer_counts[producer] += 1
        runtime_counts[runtime_value] += 1
        loader_counts[loader_value] += 1
        page_size_counts[page_size] += 1

        feature_list = feature_observation(project, fingerprint, source)
        for feature in feature_list:
            feature_projects[feature].add(project_id)
            feature_identities[feature].add(normalized_identity)
            feature_variants[feature].add(project_id)
            feature_producers[feature][producer] += 1
            feature_runtimes[feature][runtime_value] += 1

        for layer in LAYERS:
            value = layers.get(layer)
            value = value if isinstance(value, dict) else {}
            expected = value.get("expected")
            actual = value.get("actual", "environment-unavailable")
            layer_counts[layer][str(actual)] += 1
            if isinstance(actual, str):
                result_counts[actual] += 1
            code = diagnostic_code(layer, value)
            if code:
                diagnostic_counts[code] += 1
            if expected != actual:
                unexpected.append(
                    {
                        "projectId": project_id,
                        "identityKey": identity,
                        "layer": layer,
                        "expected": expected,
                        "actual": actual,
                        "diagnostic": code,
                        "artifact": f"{project_id}/result.json",
                    }
                )
            if code:
                for feature in feature_list:
                    feature_diagnostics[feature][code] += 1

        explicit_failure = None
        result_path = artifact_root / project_id / "result.json"
        if not registry_only:
            result = load(result_path, {})
            if isinstance(result, dict):
                explicit_failure = result.get("firstFailureLayer")
        failure = first_failure_layer(layers, explicit_failure)
        if failure:
            first_failure_counts[failure] += 1
            failure_record = {
                "projectId": project_id,
                "identityKey": identity,
                "firstFailureLayer": failure,
                "artifact": f"{project_id}/result.json",
            }
            first_failures.append(failure_record)
            for feature in feature_list:
                feature_failures[feature][failure] += 1
        records.append(
            {
                "projectId": project_id,
                "identityKey": identity,
                "runtime": runtime_value,
                "loader": loader_value,
                "producer": producer,
                "pageSize": page_size,
                "fingerprintSource": source,
                "features": feature_list,
                "artifact": f"{project_id}/result.json",
                "firstFailureLayer": failure,
                "layers": {layer: layers.get(layer, {}) for layer in LAYERS},
            }
        )

    identity_count = len(seen_identities)
    if identity_count == 0:
        raise ReportError("aggregate input has no project identities")
    feature_histogram: list[dict[str, Any]] = []
    for feature in sorted(feature_identities):
        identity_total = len(feature_identities[feature])
        identity_percent = percent(identity_total, identity_count)
        feature_histogram.append(
            {
                "feature": feature,
                "identityCount": identity_total,
                "identityPercent": identity_percent,
                "identityKeys": sorted(feature_identities[feature]),
                "projectIds": sorted(feature_projects[feature]),
                "variants": sorted(feature_variants[feature]),
                "producerCoverage": counter_json(feature_producers[feature]),
                "runtimeCoverage": counter_json(feature_runtimes[feature]),
                "firstFailureLayers": counter_json(feature_failures[feature]),
                "diagnostics": counter_json(feature_diagnostics[feature]),
                "thresholdTriggered": identity_percent >= THRESHOLD_PERCENT,
                "disposition": disposition_for(feature, dispositions),
            }
        )

    current_count = len(projects)
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "tier": tier,
        "evidenceMode": "registry-baseline" if registry_only else "ci-evidence",
        "observationSources": counter_json(observation_sources),
        "requiredProjectCount": required_count,
        "observedProjectCount": current_count,
        "identityCount": identity_count,
        "projectIds": sorted(seen_projects),
        "identityKeys": sorted({identity for values in seen_identities.values() for identity in values}),
        "coverage": {
            "approvedTargetProjectCount": target_count,
            "currentIdentityCount": identity_count,
            "shortfall": max(0, target_count - identity_count),
        },
        "layerCounts": {layer: counter_json(layer_counts[layer]) for layer in LAYERS},
        "firstFailureLayers": counter_json(first_failure_counts),
        "firstFailures": sorted(first_failures, key=lambda item: item["projectId"]),
        "runtimeCoverage": counter_json(runtime_counts),
        "loaderCoverage": counter_json(loader_counts),
        "pageSizeCoverage": counter_json(page_size_counts),
        "producerCoverage": counter_json(producer_counts),
        "diagnosticCoverage": counter_json(diagnostic_counts),
        "resultClassification": counter_json(result_counts),
        "featureCoverage": {
            item["feature"]: item["identityCount"] for item in feature_histogram
        },
        "featureHistogram": feature_histogram,
        "declaredFeatureCoverage": counter_json(declared_feature_counts),
        "unexpectedOutcomes": unexpected,
        "records": records,
        "projectIdentityGroups": {
            identity: sorted(project_ids)
            for identity, project_ids in sorted(seen_identities.items())
        },
    }


def markdown_report(aggregate: dict[str, Any]) -> str:
    current = aggregate["identityCount"]
    target = aggregate["coverage"]["approvedTargetProjectCount"]
    lines = [
        f"# Public real-sample aggregate ({aggregate['tier']})",
        "",
        f"Distinct project identities: **{current}/{target}** "
        f"(shortfall: **{aggregate['coverage']['shortfall']}**).",
        f"Evidence mode: `{aggregate['evidenceMode']}`; report schema: `{aggregate['schemaVersion']}`.",
        "",
        "## First-failure layers",
        "",
        "| Layer | Identity count |",
        "| --- | ---: |",
    ]
    for layer in FIRST_FAILURE_LAYERS:
        lines.append(f"| `{layer}` | {aggregate['firstFailureLayers'].get(layer, 0)} |")
    lines.extend(["", "## Feature frequency", "", "| Feature | Identities | Percent | Disposition |", "| --- | ---: | ---: | --- |"])
    for item in aggregate["featureHistogram"]:
        disposition = item["disposition"]["status"]
        lines.append(
            f"| `{item['feature']}` | {item['identityCount']} | "
            f"{item['identityPercent']:.2f}% | `{disposition}` |"
        )
    lines.extend(["", "## Runtime, loader, producer, and page-size coverage", ""])
    for title, key in (
        ("Runtime", "runtimeCoverage"),
        ("Loader", "loaderCoverage"),
        ("Producer", "producerCoverage"),
        ("Page size", "pageSizeCoverage"),
    ):
        lines.extend([f"### {title}", "", "| Value | Identities |", "| --- | ---: |"])
        for value, count in aggregate[key].items():
            lines.append(f"| `{value}` | {count} |")
        lines.append("")
    lines.extend(["## Unexpected outcomes", ""])
    if aggregate["unexpectedOutcomes"]:
        for item in aggregate["unexpectedOutcomes"]:
            lines.append(
                f"- `{item['projectId']}` / `{item['layer']}` expected "
                f"`{item['expected']}` but observed `{item['actual']}` "
                f"(diagnostic `{item.get('diagnostic') or 'none'}`)."
            )
    else:
        lines.append("- None recorded in the aggregate input.")
    lines.extend(
        [
            "",
            "Registry-only baseline facts are labeled metadata; they do not promote product support.",
            "Per-sample evidence is linked by `projectId`; raw archives and binaries are never retained here.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    arguments = parse_args()
    artifact_root = arguments.artifact_root or Path(".artifacts/real-samples") / arguments.tier
    output_json = arguments.output_json or artifact_root / "aggregate.json"
    output_markdown = arguments.output_markdown or artifact_root / "aggregate.md"
    try:
        manifest = load_required(arguments.manifest, "manifest")
        corpus = as_mapping(manifest.get("corpus"))
        raw_projects = corpus.get("projects")
        if not isinstance(raw_projects, list):
            raise ReportError("manifest corpus.projects must be an array")
        projects = [project for project in raw_projects if isinstance(project, dict)]
        dispositions_data = load(arguments.dispositions, {}) if arguments.dispositions else {}
        if isinstance(dispositions_data, dict):
            dispositions = as_mapping(dispositions_data.get("dispositions", dispositions_data))
        else:
            dispositions = {}
        aggregate = build_report(
            manifest,
            projects,
            arguments.tier,
            artifact_root.resolve(),
            dispositions,
            registry_only=arguments.registry_only,
            require_evidence=arguments.require_evidence,
        )
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_markdown.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output_markdown.write_text(markdown_report(aggregate), encoding="utf-8")
    except (OSError, ReportError, ValueError, TypeError) as error:
        print(f"FAIL real-sample aggregate: {error}", file=sys.stderr)
        return 1
    print(f"PASS real-sample aggregate: {output_json} and {output_markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
