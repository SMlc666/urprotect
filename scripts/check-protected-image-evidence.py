#!/usr/bin/env python3
"""Validate the closed evidence tree emitted by protect-image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def require_file(root: Path, name: str, allow_empty: bool = False) -> Path:
    path = root / name
    if not path.is_file() or (not allow_empty and path.stat().st_size == 0):
        fail(f"missing or empty protected-image evidence: {name}")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_under(root: Path, value: str, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} points outside the evidence root: {value}")
    return resolved


def check_manifest(root: Path, manifest_path: Path) -> None:
    entries: dict[Path, str] = {}
    for line_number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2 or not DIGEST.fullmatch(parts[0]):
            fail(f"invalid SHA256SUMS entry at line {line_number}")
        relative = Path(parts[1])
        if relative.is_absolute() or ".." in relative.parts:
            fail(f"SHA256SUMS entry escapes its directory: {parts[1]}")
        target = (manifest_path.parent / relative).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            fail(f"SHA256SUMS entry is outside the evidence root: {parts[1]}")
        if target in entries:
            fail(f"duplicate SHA256SUMS entry: {parts[1]}")
        if not target.is_file():
            fail(f"SHA256SUMS entry is missing: {parts[1]}")
        actual = digest(target)
        if actual.lower() != parts[0].lower():
            fail(f"SHA256SUMS digest mismatch: {parts[1]}")
        entries[target] = parts[1]

    if not entries:
        fail("SHA256SUMS is empty")

    files = {
        path.resolve()
        for path in root.rglob("*")
        if path.is_file() and path.resolve() != manifest_path.resolve()
    }
    if files != set(entries):
        missing = sorted(str(path.relative_to(root)) for path in files - set(entries))
        extra = sorted(str(path.relative_to(root)) for path in set(entries) - files)
        fail(f"SHA256SUMS is not closed (missing={missing}, extra={extra})")


def check_stage(stage: dict) -> None:
    required = {
        "schemaVersion",
        "stage",
        "status",
        "unitId",
        "profile",
        "producerId",
        "producerBuildSha256",
        "rehydratorConsumerId",
        "commandDigest",
        "environmentDigest",
        "artifactPath",
        "rolePath",
        "rawEvidenceManifestPath",
        "transformationStatus",
        "selectors",
        "passes",
        "diagnostics",
    }
    missing = sorted(required - stage.keys())
    if missing:
        fail(f"stage record is missing fields: {missing}")
    if stage["schemaVersion"] != 1 or stage["stage"] != "protected-image-producer":
        fail("stage record has an unsupported schema or stage")
    if stage["status"] not in ("passed", "failed"):
        fail("stage record has an unsupported status")
    for field in ("producerBuildSha256", "commandDigest", "environmentDigest"):
        if not isinstance(stage[field], str) or not DIGEST.fullmatch(stage[field]):
            fail(f"stage {field} is not a SHA-256 digest")
    if not isinstance(stage["selectors"], list) or not stage["selectors"]:
        fail("stage selectors are missing")
    if not isinstance(stage["passes"], list) or not stage["passes"]:
        fail("stage passes are missing")
    if not isinstance(stage["diagnostics"], list) or len(stage["diagnostics"]) > 128:
        fail("stage diagnostics are outside the bounded contract")
    if stage["status"] == "failed" and not stage["diagnostics"]:
        fail("failed stage has no retained diagnostics")
    for field in ("analysisDurationMilliseconds", "emissionDurationMilliseconds"):
        value = stage.get(field)
        if value is not None and (not isinstance(value, int) or value < 0):
            fail(f"stage {field} is not a non-negative integer")
    if stage["status"] == "passed":
        for field in ("sourceSha256", "requestSha256", "artifactSha256", "artifactRole", "abiId", "abiVersion"):
            if field not in stage or stage[field] in (None, ""):
                fail(f"passed stage is missing {field}")
        if stage["artifactRole"] != "protected-image" or stage["abiId"] != "urprotect.protected-image.v1":
            fail("passed stage does not bind the Protected Image ABI")
        if stage["abiVersion"] != 1 or stage.get("publicationComplete") is not True:
            fail("passed stage does not bind complete publication")
        if not isinstance(stage.get("artifactSize"), int) or stage["artifactSize"] <= 0:
            fail("passed stage has an invalid artifact size")
    elif stage.get("publicationComplete"):
        fail("failed stage claims complete publication")


def check_success(root: Path, stage: dict) -> None:
    artifact = require_file(root, "protected-image.bin")
    role_path = require_file(root, "protected-image.json")
    if stage["status"] != "passed":
        fail("success evidence tree requires a passed stage")
    role = json.loads(role_path.read_text(encoding="utf-8"))
    for field in (
        "schemaVersion",
        "artifactRole",
        "abiId",
        "abiVersion",
        "unitId",
        "profile",
        "sourceSha256",
        "artifactSha256",
        "artifactSize",
        "producerBuildSha256",
        "rehydratorConsumerId",
        "requestSha256",
        "rawArtifactPath",
        "rawArtifactRetained",
    ):
        if field not in role:
            fail(f"role record is missing {field}")
    if role["schemaVersion"] != 1 or role["artifactRole"] != "protected-image":
        fail("role record is not a Protected Image v1 record")
    if role["abiId"] != "urprotect.protected-image.v1" or role["abiVersion"] != 1:
        fail("role record ABI identity is unsupported")
    if role["rawArtifactRetained"] is not True:
        fail("role record does not retain its raw artifact")
    if resolve_under(root, role["rawArtifactPath"], "rawArtifactPath") != artifact.resolve():
        fail("role rawArtifactPath does not identify protected-image.bin")
    artifact_hash = digest(artifact)
    if role["artifactSha256"].lower() != artifact_hash or stage["artifactSha256"].lower() != artifact_hash:
        fail("artifact hash is not continuous across role and stage")
    if role["artifactSize"] != artifact.stat().st_size or stage["artifactSize"] != artifact.stat().st_size:
        fail("artifact size is not continuous across role and stage")
    if role["unitId"] != stage["unitId"] or role["profile"] != stage["profile"]:
        fail("role and stage unit/profile bindings differ")
    for field in ("sourceSha256", "requestSha256", "producerBuildSha256", "rehydratorConsumerId"):
        if role[field] != stage[field]:
            fail(f"role and stage {field} bindings differ")

    data = artifact.read_bytes()
    if data[:4] != b"UPPI":
        fail("artifact is not Protected Image v1 structured data")
    if len(data) < 52:
        fail("Protected Image artifact is truncated")
    declared_length = int.from_bytes(data[12:16], "little")
    if declared_length != len(data):
        fail("Protected Image declared length does not match the retained artifact")
    if hashlib.sha256(data[:-32]).digest() != data[-32:]:
        fail("Protected Image canonical digest does not match the retained artifact")
    if digest(artifact) == role["sourceSha256"].lower():
        fail("Protected Image artifact aliases its source digest")


def check_failure(root: Path, stage: dict) -> None:
    if stage["status"] != "failed":
        fail("failure evidence tree requires a failed stage")
    if (root / "protected-image.bin").exists() or (root / "protected-image.json").exists():
        fail("failed Protected Image emission retained a partial artifact or role")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"))
    parser.add_argument("--runtime", choices=("glibc", "musl", "bionic"))
    parser.add_argument("--unit")
    parser.add_argument("--expect-failure", action="store_true")
    args = parser.parse_args()
    root = args.artifact_root.resolve()
    if not root.is_dir():
        fail(f"protected-image evidence root is missing: {root}")
    if args.unit and root.name != args.unit:
        fail(f"protected-image evidence root does not end in unit {args.unit}")

    stdout = require_file(root, "stdout.txt", allow_empty=True)
    stderr = require_file(root, "stderr.txt", allow_empty=True)
    del stdout, stderr
    stage_path = require_file(root, "stage.json")
    stage = json.loads(stage_path.read_text(encoding="utf-8"))
    check_stage(stage)
    manifest_path = require_file(root, "SHA256SUMS")
    check_manifest(root, manifest_path)
    stage_manifest = resolve_under(root, stage["rawEvidenceManifestPath"], "rawEvidenceManifestPath")
    if stage_manifest != manifest_path.resolve():
        fail("stage rawEvidenceManifestPath does not identify SHA256SUMS")

    if stage["status"] == "passed":
        if args.expect_failure:
            fail("evidence unexpectedly passed")
        check_success(root, stage)
    else:
        check_failure(root, stage)
    print(f"PASS protected-image evidence: root={root} status={stage['status']}")


if __name__ == "__main__":
    main()
