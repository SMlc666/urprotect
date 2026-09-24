#!/usr/bin/env python3
"""Gate registry-linked, non-empty real-sample CI evidence.

The gate is intentionally stricter than a directory-exists check: every locked
project and every declared layer needs a result classification, the result must
match the registry expectation, and no raw downloaded archive/binary may live
under the upload root.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

RESULTS = {
    "accepted-and-runs",
    "expected-rejected",
    "unexpected-rejection",
    "unexpected-acceptance",
    "runtime-failure",
    "environment-unavailable",
    "not-applicable",
}
LAYERS = ("static", "baseline", "outerWrapper", "hostContext")
REQUIRED_FILES = (
    "source.txt",
    "hashes.txt",
    "environment.txt",
    "elf-fingerprint.json",
    "fingerprint-comparison.json",
    "readelf.txt",
    "urprotect-report.json",
    "result.json",
)
FORBIDDEN_SUFFIXES = {
    ".deb",
    ".apk",
    ".bin",
    ".elf",
    ".so",
    ".tar",
    ".gz",
    ".zip",
    ".xz",
}


class EvidenceError(Exception):
    pass


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"could not read {label} {path}: {error}") from error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="?", default=Path("fixtures/real-samples/manifest.json"))
    parser.add_argument("--tier", required=True, choices=("pr", "nightly", "release"))
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--candidates", type=Path)
    return parser.parse_args()


def require_non_empty(path: Path, label: str) -> None:
    try:
        stat_result = path.lstat()
    except FileNotFoundError as error:
        raise EvidenceError(f"{label} is missing: {path}") from error
    except OSError as error:
        raise EvidenceError(f"{label} is unreadable: {path}: {error}") from error
    if path.is_symlink():
        raise EvidenceError(f"{label} is a symlink: {path}")
    if not path.is_file() or stat_result.st_size <= 0:
        raise EvidenceError(f"{label} is missing, non-regular, or empty: {path}")
    if stat_result.st_size > 16 * 1024 * 1024:
        raise EvidenceError(f"{label} exceeds the retained evidence size limit: {path}")


def ensure_tree_is_text(root: Path) -> None:
    if root.is_symlink():
        raise EvidenceError(f"artifact root is a symlink: {root}")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EvidenceError(f"artifact tree contains a symlink: {path}")
        if not path.is_file():
            continue
        # The runner legitimately retains text logs named `source.archive` and
        # an extracted-file audit named `sample-artifact.elf.txt`; reject raw
        # binaries by content and known package/archive suffixes only.
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise EvidenceError(f"raw sample/archive-like artifact is present: {path}")
        try:
            data = path.read_bytes()
        except OSError as error:
            raise EvidenceError(f"cannot read artifact {path}: {error}") from error
        if b"\x00" in data[:4096]:
            raise EvidenceError(f"artifact appears to be a raw binary: {path}")


def run_validator(manifest: Path, candidates: Path | None) -> None:
    validator = Path(__file__).resolve().with_name("validate-real-samples.py")
    command = [sys.executable, str(validator), str(manifest)]
    if candidates is not None:
        command.extend(("--candidates", str(candidates)))
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError(f"could not run registry validator: {error}") from error
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        raise EvidenceError(f"registry validation failed: {details}")


def manifest_projects(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    corpus = manifest.get("corpus")
    if not isinstance(corpus, dict) or not isinstance(corpus.get("projects"), list):
        raise EvidenceError("manifest corpus.projects must be an array")
    projects = [project for project in corpus["projects"] if isinstance(project, dict)]
    if len(projects) != 20:
        raise EvidenceError(f"manifest must contain exactly 20 projects, found {len(projects)}")
    return projects


def layer_expectations(project: dict[str, Any]) -> dict[str, str]:
    policy = project.get("executionPolicy")
    if not isinstance(policy, dict):
        raise EvidenceError(f"{project.get('projectId', '<unknown>')} has no executionPolicy")
    result: dict[str, str] = {}
    for layer in LAYERS:
        value = policy.get(layer)
        if not isinstance(value, dict) or value.get("expectedResult") not in RESULTS:
            raise EvidenceError(f"{project.get('projectId', '<unknown>')} has no valid {layer} policy")
        result[layer] = value["expectedResult"]
    return result


def check_sample(project: dict[str, Any], tier: str, root: Path) -> list[str]:
    project_id = project.get("projectId")
    if not isinstance(project_id, str) or not project_id:
        raise EvidenceError("manifest project has no projectId")
    sample_root = root / project_id
    errors: list[str] = []
    try:
        sample_root.relative_to(root)
    except ValueError:
        return [f"{project_id}: path escapes artifact root"]
    if not sample_root.is_dir() or sample_root.is_symlink():
        return [f"{project_id}: evidence directory is missing or a symlink"]
    for relative in REQUIRED_FILES:
        try:
            require_non_empty(sample_root / relative, f"{project_id}/{relative}")
        except EvidenceError as error:
            errors.append(str(error))
    logs = sample_root / "logs"
    if not logs.is_dir() or logs.is_symlink() or not any(path.is_file() and path.stat().st_size > 0 for path in logs.rglob("*")):
        errors.append(f"{project_id}: logs directory is missing or empty")

    result_path = sample_root / "result.json"
    if not result_path.is_file():
        return errors
    try:
        result = read_json(result_path, f"{project_id}/result.json")
    except EvidenceError as error:
        errors.append(str(error))
        return errors
    if not isinstance(result, dict):
        errors.append(f"{project_id}: result root must be an object")
        return errors
    if result.get("schemaVersion") != 1:
        errors.append(f"{project_id}: result schemaVersion must be 1")
    if result.get("tier") != tier:
        errors.append(f"{project_id}: result tier does not match {tier}")
    if result.get("projectId") != project_id:
        errors.append(f"{project_id}: result projectId does not match directory")
    expected = layer_expectations(project)
    layers = result.get("layers")
    if not isinstance(layers, dict):
        errors.append(f"{project_id}: result.layers must be an object")
        return errors
    for layer in LAYERS:
        layer_result = layers.get(layer)
        if not isinstance(layer_result, dict):
            errors.append(f"{project_id}: result.layers.{layer} is missing")
            continue
        actual = layer_result.get("actual")
        if actual not in RESULTS:
            errors.append(f"{project_id}/{layer}: unsupported actual result {actual!r}")
        if layer_result.get("expected") != expected[layer]:
            errors.append(f"{project_id}/{layer}: result expectation does not match registry")
        if actual != expected[layer]:
            errors.append(f"{project_id}/{layer}: expected {expected[layer]!r}, observed {actual!r}")
        if actual == "not-applicable" and not isinstance(layer_result.get("reason"), str):
            errors.append(f"{project_id}/{layer}: not-applicable result requires a reason")
        if actual == "environment-unavailable" and not isinstance(layer_result.get("reason"), str):
            errors.append(f"{project_id}/{layer}: environment-unavailable result requires a reason")

    fingerprint_path = sample_root / "elf-fingerprint.json"
    if fingerprint_path.is_file():
        try:
            fingerprint = read_json(fingerprint_path, f"{project_id}/elf-fingerprint.json")
            if not isinstance(fingerprint, dict) or fingerprint.get("projectId") != project_id:
                errors.append(f"{project_id}: fingerprint projectId does not match directory")
            result_hash = result.get("artifactSha256")
            fingerprint_hash = fingerprint.get("fileSha256") if isinstance(fingerprint, dict) else None
            if result_hash and result_hash != fingerprint_hash:
                errors.append(f"{project_id}: result artifactSha256 does not match fingerprint fileSha256")
        except EvidenceError as error:
            errors.append(str(error))
    comparison_path = sample_root / "fingerprint-comparison.json"
    if comparison_path.is_file():
        try:
            comparison = read_json(comparison_path, f"{project_id}/fingerprint-comparison.json")
            if not isinstance(comparison, dict) or comparison.get("projectId") != project_id:
                errors.append(f"{project_id}: fingerprint comparison projectId does not match directory")
            elif comparison.get("status") != "passed":
                errors.append(f"{project_id}: locked fingerprint comparison did not pass")
        except EvidenceError as error:
            errors.append(str(error))
    marker_path = sample_root / "raw-inputs-removed.txt"
    if marker_path.is_file():
        try:
            marker = marker_path.read_text(encoding="utf-8").strip()
            if marker != "raw-inputs-removed=true":
                errors.append(f"{project_id}: raw input cleanup marker is invalid")
        except (OSError, UnicodeError) as error:
            errors.append(f"{project_id}: raw input cleanup marker is unreadable: {error}")
    return errors


def main() -> int:
    arguments = parse_args()
    manifest = arguments.manifest.resolve()
    candidates = arguments.candidates
    if candidates is None:
        sibling = manifest.with_name("candidates.json")
        candidates = sibling if sibling.is_file() else None
    root = (arguments.artifact_root or Path(".artifacts/real-samples") / arguments.tier).resolve()
    try:
        run_validator(manifest, candidates)
        projects = manifest_projects(read_json(manifest, "manifest"))
        if not root.is_dir():
            raise EvidenceError(f"artifact root is missing: {root}")
        ensure_tree_is_text(root)
        errors: list[str] = []
        project_ids = {project.get("projectId") for project in projects}
        for project in projects:
            errors.extend(check_sample(project, arguments.tier, root))
        aggregate_json = root / "aggregate.json"
        aggregate_md = root / "aggregate.md"
        require_non_empty(aggregate_json, "aggregate.json")
        require_non_empty(aggregate_md, "aggregate.md")
        aggregate = read_json(aggregate_json, "aggregate.json")
        if not isinstance(aggregate, dict):
            errors.append("aggregate.json root must be an object")
        else:
            if aggregate.get("tier") != arguments.tier:
                errors.append("aggregate.json tier does not match requested tier")
            if aggregate.get("requiredProjectCount") != 20:
                errors.append("aggregate.json requiredProjectCount must be 20")
            aggregate_ids = set(aggregate.get("projectIds", [])) if isinstance(aggregate.get("projectIds"), list) else set()
            if aggregate_ids != project_ids:
                errors.append("aggregate.json projectIds do not match the locked registry")
            if aggregate.get("observedProjectCount") != 20:
                errors.append("aggregate.json observedProjectCount must be 20")
        if errors:
            raise EvidenceError("\n  ".join(errors))
    except EvidenceError as error:
        print(f"FAIL real-sample evidence gate: {error}", file=sys.stderr)
        return 1
    print(f"PASS real-sample evidence gate: tier={arguments.tier}; checked 20 projects and all layers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
