#!/usr/bin/env python3
"""Fail closed when selected matrix evidence was not retained after a run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import stat
import subprocess
import sys
from typing import Iterable


TIERS = {"pr", "nightly", "release"}


class EvidenceError(Exception):
    """A post-run evidence condition that cannot satisfy the matrix contract."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check selected fixture-matrix evidence paths after a CI run."
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=Path("fixtures/manifest.json"),
        help="matrix manifest (default: fixtures/manifest.json)",
    )
    parser.add_argument(
        "--tier",
        help="select cases declared in this run tier",
    )
    parser.add_argument(
        "--execution",
        help="select cases with this execution fact",
    )
    object_selector = parser.add_mutually_exclusive_group()
    object_selector.add_argument("--case", help="select one matrix case by id")
    object_selector.add_argument("--feature", help="select one matrix feature by id")
    arguments = parser.parse_args()

    selectors = (
        arguments.tier,
        arguments.execution,
        arguments.case,
        arguments.feature,
    )
    if not any(value is not None for value in selectors):
        parser.error("one of --tier, --execution, --case, or --feature is required")
    if arguments.tier is not None and arguments.tier not in TIERS:
        parser.error(f"unsupported tier: {arguments.tier}")
    if arguments.feature is not None and (
        arguments.tier is not None or arguments.execution is not None
    ):
        parser.error("--feature cannot be combined with --tier or --execution")
    return arguments


def load_manifest(manifest_argument: Path) -> tuple[Path, Path, dict[str, object]]:
    manifest_path = manifest_argument.resolve()
    if not manifest_path.is_file():
        raise EvidenceError(f"manifest does not exist: {manifest_argument}")

    repo_root = Path(__file__).resolve().parent.parent
    try:
        manifest_path.relative_to(repo_root)
    except ValueError as error:
        raise EvidenceError(
            f"manifest must remain inside the repository: {manifest_argument}"
        ) from error
    validator = Path(__file__).resolve().with_name("validate-fixtures.py")
    if not validator.is_file():
        raise EvidenceError(f"manifest validator is missing: {validator}")

    try:
        validation = subprocess.run(
            [sys.executable, str(validator), str(manifest_path), "--tier", "release"],
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError(f"could not run manifest validator: {error}") from error
    if validation.returncode != 0:
        details = (validation.stderr or validation.stdout).strip()
        raise EvidenceError(f"manifest validation failed: {details}")

    try:
        data = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"could not read manifest: {error}") from error
    if not isinstance(data, dict):
        raise EvidenceError("manifest root must be an object")
    return manifest_path, repo_root, data


def selected_records(
    data: dict[str, object], arguments: argparse.Namespace
) -> Iterable[tuple[str, object]]:
    if arguments.feature is not None:
        features = data.get("features")
        if not isinstance(features, list):
            raise EvidenceError("manifest features must be an array")
        matches = [
            feature
            for feature in features
            if isinstance(feature, dict) and feature.get("id") == arguments.feature
        ]
        if not matches:
            raise EvidenceError(f"feature was not found: {arguments.feature}")
        yield f"feature {arguments.feature}", matches[0]
        return

    cases = data.get("cases")
    if not isinstance(cases, list):
        raise EvidenceError("manifest cases must be an array")
    matches = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        if arguments.case is not None and case.get("id") != arguments.case:
            continue
        if arguments.tier is not None and case.get("tier") != arguments.tier:
            continue
        if arguments.execution is not None and case.get("execution") != arguments.execution:
            continue
        matches.append(case)

    if not matches:
        selection = []
        if arguments.case is not None:
            selection.append(f"case={arguments.case}")
        if arguments.tier is not None:
            selection.append(f"tier={arguments.tier}")
        if arguments.execution is not None:
            selection.append(f"execution={arguments.execution}")
        raise EvidenceError("no matrix cases matched " + ", ".join(selection))
    for case in matches:
        yield f"case {case.get('id', '<unknown>')}", case


def evidence_references(owner: str, record: object) -> Iterable[tuple[str, str]]:
    if not isinstance(record, dict):
        raise EvidenceError(f"{owner} is not an object")
    evidence = record.get("evidence")
    if owner.startswith("feature "):
        if not isinstance(evidence, list):
            raise EvidenceError(f"{owner} evidence must be a non-empty string array")
        if not evidence:
            raise EvidenceError(f"{owner} evidence is empty")
        for index, reference in enumerate(evidence):
            yield f"{owner}.evidence[{index}]", reference
        return

    if not isinstance(evidence, str):
        raise EvidenceError(f"{owner} evidence must be a non-empty path")
    yield f"{owner}.evidence", evidence


def resolve_evidence_path(
    reference: object, label: str, repo_root: Path
) -> tuple[Path, str]:
    if not isinstance(reference, str) or not reference.strip():
        raise EvidenceError(f"{label} is missing or empty")
    if "\x00" in reference:
        raise EvidenceError(f"{label} contains a NUL byte")

    reference_path = Path(reference)
    windows_reference = PureWindowsPath(reference)
    if reference_path.is_absolute() or windows_reference.is_absolute() or windows_reference.drive:
        raise EvidenceError(f"{label} must remain inside the repository: {reference}")

    try:
        resolved = (repo_root / reference_path).resolve(strict=False)
        resolved.relative_to(repo_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise EvidenceError(
            f"{label} must remain inside the repository: {reference}"
        ) from error

    relative = resolved.relative_to(repo_root)
    normalized_reference = Path(os.path.normpath(reference))
    named_artifact = normalized_reference.parts[:1] == (".artifacts",)
    resolved_artifact = relative.parts[:1] == (".artifacts",)
    if named_artifact and not resolved_artifact:
        raise EvidenceError(
            f"{label} must remain under .artifacts when declared as generated evidence: {reference}"
        )
    kind = "generated artifact" if named_artifact or resolved_artifact else "source"
    return resolved, kind


def directory_has_content(path: Path, visited: set[tuple[int, int]]) -> bool:
    try:
        directory_stat = path.stat()
    except OSError as error:
        raise EvidenceError(f"cannot inspect evidence directory {path}: {error}") from error
    identity = (directory_stat.st_dev, directory_stat.st_ino)
    if identity in visited:
        return False
    visited.add(identity)

    try:
        entries = list(os.scandir(path))
    except OSError as error:
        raise EvidenceError(f"cannot inspect evidence directory {path}: {error}") from error
    for entry in entries:
        if entry.is_symlink():
            raise EvidenceError(f"evidence directory contains a symlink: {entry.path}")
        try:
            if entry.is_file(follow_symlinks=False):
                if entry.stat(follow_symlinks=False).st_size > 0:
                    return True
            elif entry.is_dir(follow_symlinks=False) and directory_has_content(
                Path(entry.path), visited
            ):
                return True
        except OSError as error:
            raise EvidenceError(f"cannot inspect evidence entry {entry.path}: {error}") from error
    return False


def require_non_empty(path: Path, label: str, kind: str) -> None:
    try:
        path_stat = path.stat()
    except FileNotFoundError as error:
        raise EvidenceError(f"{label} {kind} path is missing: {path}") from error
    except OSError as error:
        raise EvidenceError(f"{label} {kind} path is unreadable: {path}: {error}") from error

    if stat.S_ISREG(path_stat.st_mode):
        has_content = path_stat.st_size > 0
    elif stat.S_ISDIR(path_stat.st_mode):
        has_content = directory_has_content(path, set())
    else:
        raise EvidenceError(f"{label} {kind} path is not a regular file or directory: {path}")
    if not has_content:
        raise EvidenceError(f"{label} {kind} path is empty: {path}")


def selector_description(arguments: argparse.Namespace) -> str:
    values = []
    for name in ("tier", "execution", "case", "feature"):
        value = getattr(arguments, name)
        if value is not None:
            values.append(f"{name}={value}")
    return ", ".join(values)


def main() -> int:
    arguments = parse_args()
    try:
        _, repo_root, data = load_manifest(arguments.manifest)
        checked = 0
        generated = 0
        source = 0
        for owner, record in selected_records(data, arguments):
            for label, reference in evidence_references(owner, record):
                path, kind = resolve_evidence_path(reference, label, repo_root)
                require_non_empty(path, label, kind)
                checked += 1
                if kind == "generated artifact":
                    generated += 1
                else:
                    source += 1
    except EvidenceError as error:
        print(f"FAIL evidence gate: {error}", file=sys.stderr)
        return 1

    print(
        f"PASS evidence gate: {selector_description(arguments)}; "
        f"checked {checked} paths ({generated} generated artifacts, {source} source paths)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
