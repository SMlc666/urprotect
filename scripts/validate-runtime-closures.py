#!/usr/bin/env python3
"""Validate the locked runtime-closure policy for the complete real corpus."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


RUNTIMES = {"glibc", "musl", "bionic"}


def fail(message: str) -> None:
    raise SystemExit(message)


def validate_package_policy(project_id: str | None, policy: dict) -> None:
    for field in ("includePackages", "excludeDependencies"):
        entries = policy.get(field, [])
        if entries is None:
            continue
        if not isinstance(entries, list):
            fail(f"{project_id}: {field} must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                fail(f"{project_id}: {field} entries must be objects")
            package = entry.get("package")
            if not isinstance(package, str) or not package or any(
                character.isspace() or ord(character) == 0 for character in package
            ):
                fail(f"{project_id}: {field} contains an invalid package name")
            reason = entry.get("reason", "")
            if not isinstance(reason, str) or any(
                ord(character) == 0 or ord(character) in (10, 13) for character in reason
            ):
                fail(f"{project_id}: {field} contains an invalid reason")


def validate(closure_path: Path, manifest_path: Path) -> None:
    try:
        closure = json.loads(closure_path.read_text())
        manifest = json.loads(manifest_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"could not read runtime closure inputs: {error}")
    if closure.get("schemaVersion") != 1:
        fail("runtime closure schemaVersion must be 1")
    if closure.get("registryName") != manifest.get("registryName"):
        fail("runtime closure registryName does not match the real-sample registry")
    runtimes = closure.get("runtimes")
    if not isinstance(runtimes, dict) or set(runtimes) != RUNTIMES:
        fail("runtime closures must define glibc, musl, and bionic")
    for runtime, entry in runtimes.items():
        if not isinstance(entry, dict):
            fail(f"{runtime}: runtime closure entry must be an object")
        for key in ("family", "loader", "archiveFormat", "resolver"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                fail(f"{runtime}: missing {key}")
        if runtime != "bionic":
            if not isinstance(entry.get("packageIndexUrl"), str):
                fail(f"{runtime}: packageIndexUrl is required")
            digest = entry.get("packageIndexSha256")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
                fail(f"{runtime}: packageIndexSha256 must be a SHA-256")
            if runtime == "glibc" and entry["archiveFormat"] != "deb":
                fail("glibc closure must resolve deb archives")
            if runtime == "musl" and entry["archiveFormat"] != "apk":
                fail("musl closure must resolve apk archives")
    projects = manifest.get("corpus", {}).get("projects")
    if not isinstance(projects, list) or len(projects) != 100:
        fail("the closure gate requires exactly 100 registry identities")
    project_ids = {project.get("projectId") for project in projects}
    if len(project_ids) != 100 or None in project_ids:
        fail("the real-sample registry must have 100 unique project IDs")
    policies = closure.get("projects")
    if not isinstance(policies, dict) or not isinstance(policies.get("*"), dict):
        fail("runtime closure default project policy is missing")
    default = policies["*"]
    for layer in ("baseline", "outerWrapper"):
        value = default.get(layer)
        if not isinstance(value, dict) or value.get("expectedResult") != "accepted-and-runs":
            fail(f"default {layer} policy must require accepted-and-runs")
    if default["outerWrapper"].get("mode") != "outer-execveat":
        fail("default outer-wrapper mode must be outer-execveat")
    for project in projects:
        project_id = project.get("projectId")
        policy = policies.get(project_id, default)
        if not isinstance(policy, dict):
            fail(f"{project_id}: runtime closure policy must be an object")
        validate_package_policy(project_id, policy)
        baseline = policy.get("baseline", {})
        if not isinstance(baseline, dict):
            fail(f"{project_id}: baseline policy must be an object")
        command = baseline.get("command")
        expected_status = baseline.get("expectedStatus", 0)
        if isinstance(expected_status, bool) or not isinstance(expected_status, int) or not 0 <= expected_status <= 255:
            fail(f"{project_id}: baseline expectedStatus must be an integer from 0 through 255")
        if command is not None:
            if not isinstance(command, list) or not command or any(not isinstance(item, str) for item in command):
                fail(f"{project_id}: baseline command must be a non-empty string list")
            artifact = "/" + project.get("provenance", {}).get("artifactPath", "").lstrip("/")
            if command[0] != artifact:
                fail(f"{project_id}: baseline command must launch declared artifact {artifact}")
    print(f"PASS runtime closures: 100 identities, {len(runtimes)} runtime families")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("closure_manifest", type=Path)
    parser.add_argument("registry_manifest", type=Path)
    args = parser.parse_args()
    validate(args.closure_manifest, args.registry_manifest)


if __name__ == "__main__":
    main()
