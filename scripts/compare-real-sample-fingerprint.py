#!/usr/bin/env python3
"""Compare CI-generated ELF identity facts with locked registry invariants.

Feature fields are retained as observations in the comparison output, while
only the registry's explicit identity policy (class, data, machine, type, and
interpreter) is compared.  Observations do not change support status.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class ComparisonError(Exception):
    pass


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"could not read {path}: {error}") from error


def normal(field: str, value: Any) -> Any:
    if field == "data":
        value = str(value).lower()
        return "little-endian" if "little" in value else value
    if field == "type":
        value = str(value).split(" ", 1)[0].upper()
        return {
            "DYN": "ET_DYN",
            "ET_DYN": "ET_DYN",
            "EXEC": "ET_EXEC",
            "ET_EXEC": "ET_EXEC",
        }.get(value, value)
    if field == "machine":
        return "AArch64" if "aarch64" in str(value).lower() or "arm64" in str(value).lower() else str(value)
    return value


def observation_summary(actual: dict[str, Any]) -> dict[str, Any]:
    """Copy bounded, non-path feature projections into retained evidence."""
    summary: dict[str, Any] = {
        "schemaVersion": actual.get("schemaVersion"),
        "featureSchemaVersion": actual.get("featureSchemaVersion"),
        "producer": actual.get("producer", "unknown"),
        "runtime": actual.get("runtime", "unknown"),
        "loader": actual.get("loader", actual.get("interpreter")),
        "pageSize": actual.get("pageSize"),
        "featureTags": actual.get("featureTags", [])[:256] if isinstance(actual.get("featureTags"), list) else [],
    }
    for key in (
        "dependencies",
        "relocations",
        "symbolVersions",
        "tls",
        "gnuProperty",
        "relro",
        "gnuStack",
        "hardening",
        "sections",
        "unknownFields",
    ):
        value = actual.get(key)
        if isinstance(value, dict):
            summary[key] = value
        elif isinstance(value, list):
            summary[key] = value[:256]
        elif value is not None:
            summary[key] = value
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--fingerprint", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    mismatches: list[dict[str, Any]] = []
    try:
        manifest = load(arguments.manifest)
        projects = manifest["corpus"]["projects"]
        project = next((item for item in projects if item.get("projectId") == arguments.project_id), None)
        if not isinstance(project, dict):
            raise ComparisonError(f"project not found: {arguments.project_id}")
        policy = project.get("fingerprintPolicy")
        expected = project.get("featureFingerprint")
        actual = load(arguments.fingerprint)
        if not isinstance(policy, dict) or policy.get("mode") != "ci-discovery-lock":
            raise ComparisonError("registry fingerprintPolicy must be ci-discovery-lock")
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            raise ComparisonError("fingerprint roots must be objects")
        fields = policy.get("compare", ["elfClass", "data", "machine", "type", "interpreter"])
        if not isinstance(fields, list) or len(fields) > 32 or not all(isinstance(field, str) for field in fields):
            raise ComparisonError("fingerprint compare fields must be a bounded string array")
        observed: dict[str, Any] = {}
        for field in fields:
            expected_value = expected.get(field)
            actual_value = actual.get(field)
            observed[field] = actual_value
            if normal(field, actual_value) != normal(field, expected_value):
                mismatches.append({"field": field, "expected": expected_value, "actual": actual_value})
        expected_tags = expected.get("expectedFeatureTags", [])
        actual_tags = actual.get("featureTags", [])
        comparison = {
            "schemaVersion": 2,
            "projectId": arguments.project_id,
            "mode": policy["mode"],
            "status": "passed" if not mismatches else "failed",
            "comparedFields": observed,
            "mismatches": mismatches,
            "expectedFeatureTags": expected_tags,
            "observedFeatureTags": actual_tags[:256] if isinstance(actual_tags, list) else [],
            "featureTagPolicy": "record-only",
            "observation": observation_summary(actual),
        }
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (ComparisonError, KeyError, TypeError, ValueError) as error:
        print(f"FAIL fingerprint comparison: {error}", file=sys.stderr)
        return 1
    if mismatches:
        print(f"FAIL fingerprint comparison: {arguments.project_id}: {mismatches}", file=sys.stderr)
        return 1
    print(f"PASS fingerprint comparison: {arguments.project_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
