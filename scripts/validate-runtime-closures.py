#!/usr/bin/env python3
"""Validate the locked runtime-closure policy for the complete real corpus."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from real_sample_schema import RESERVED_HELPER_STATUSES, required_execution_policy_errors
from bionic_node_lock import lock_file_sha256, validate_lock_document


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


def _resolve_bionic_lock_path(closure_path: Path, lock_name: str) -> Path:
    if not isinstance(lock_name, str) or not lock_name or Path(lock_name).is_absolute() or ".." in Path(lock_name).parts:
        fail("bionic nodejsLock must be a safe relative path")
    local_path = closure_path.parent / lock_name
    if local_path.is_file():
        return local_path
    repository_path = Path(__file__).resolve().parents[1] / "fixtures" / "real-samples" / lock_name
    if repository_path.is_file():
        return repository_path
    fail(f"bionic runtime lock is missing: {lock_name}")


def validate_bionic_lock(closure_path: Path, manifest: dict, runtime: dict) -> dict:
    for key in ("packageRepository", "nodejsLock", "nodejsLockSha256"):
        if key not in runtime:
            fail(f"bionic runtime closure is missing {key}")
    if runtime.get("packageRepository") != "https://packages-cf.termux.dev/apt/termux-main":
        fail("bionic runtime closure packageRepository does not match the reviewed Termux repository")
    lock_path = _resolve_bionic_lock_path(closure_path, runtime["nodejsLock"])
    expected_sha = runtime["nodejsLockSha256"]
    if not isinstance(expected_sha, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None:
        fail("bionic nodejsLockSha256 must be a lowercase SHA-256")
    try:
        actual_sha = lock_file_sha256(lock_path)
    except OSError as error:
        fail(f"could not hash bionic runtime lock: {error}")
    if actual_sha != expected_sha:
        fail(f"bionic runtime lock SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"could not read bionic runtime lock: {error}")
    errors = validate_lock_document(lock, manifest=manifest, expected_lock_sha256=expected_sha)
    if errors:
        fail("bionic runtime lock validation failed: " + "; ".join(errors))
    return lock


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
    bionic_lock: dict | None = None
    for runtime, entry in runtimes.items():
        if not isinstance(entry, dict):
            fail(f"{runtime}: runtime closure entry must be an object")
        for key in ("family", "loader", "archiveFormat", "resolver"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                fail(f"{runtime}: missing {key}")
        if runtime == "bionic":
            if entry.get("family") != "termux-bionic-locked":
                fail("bionic runtime closure family is not the reviewed locked Termux family")
            if entry.get("loader") != "/system/bin/linker64":
                fail("bionic runtime closure loader must be /system/bin/linker64")
            if entry.get("archiveFormat") != "deb" or entry.get("resolver") != "termux-container-v1":
                fail("bionic runtime closure must use the locked Termux deb resolver")
            bionic_lock = validate_bionic_lock(closure_path, manifest, entry)
            expected_identity = {
                "image": bionic_lock.get("baseImage", {}).get("requestedRef"),
                "imageId": bionic_lock.get("baseImage", {}).get("id"),
                "loader": bionic_lock.get("execution", {}).get("loader"),
            }
            for field, expected in expected_identity.items():
                if entry.get(field) != expected:
                    fail(f"bionic runtime closure {field} does not match the reviewed runtime lock")
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
            fail(f"default {layer} policy must require accepted-and-runs; environment-unavailable is an observed failure")
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
        if expected_status in RESERVED_HELPER_STATUSES:
            fail(
                f"{project_id}: baseline expectedStatus {expected_status} is reserved for isolation helper outcomes"
            )
        invocation = baseline.get("invocation")
        if invocation is not None and (not isinstance(invocation, str) or not invocation.strip()):
            fail(f"{project_id}: baseline invocation must be a non-empty string when present")
        if command is not None:
            if not isinstance(command, list) or not command or any(
                not isinstance(item, str) or any(character in item for character in ("\0", "\n", "\r"))
                for item in command
            ):
                fail(f"{project_id}: baseline command must be a non-empty control-free string list")
            artifact = "/" + project.get("provenance", {}).get("artifactPath", "").lstrip("/")
            if command[0] != artifact:
                fail(f"{project_id}: baseline command must launch declared artifact {artifact}")
        elif invocation != "declared-artifact-version":
            fail(
                f"{project_id}: baseline without command must use the validated declared-artifact-version invocation"
            )
        outer = policy.get("outerWrapper", {})
        if not isinstance(outer, dict):
            fail(f"{project_id}: outerWrapper policy must be an object")
        outer_mode = outer.get("mode", "outer-execveat")
        if outer_mode not in {"outer-execveat", "outer-path-preserving"}:
            fail(f"{project_id}: outerWrapper mode is unsupported: {outer_mode!r}")
        outer_expected_status = outer.get("expectedStatus")
        if outer_expected_status is not None:
            if (
                isinstance(outer_expected_status, bool)
                or not isinstance(outer_expected_status, int)
                or not 0 <= outer_expected_status <= 255
            ):
                fail(f"{project_id}: outerWrapper expectedStatus must be an integer from 0 through 255")
            if outer_expected_status in RESERVED_HELPER_STATUSES:
                fail(
                    f"{project_id}: outerWrapper expectedStatus {outer_expected_status} is reserved for isolation helper outcomes"
                )
            if outer_expected_status != expected_status:
                fail(f"{project_id}: outerWrapper expectedStatus must equal the baseline expectedStatus")
        if project_id == "nodejs":
            if outer_mode != "outer-path-preserving":
                fail("nodejs outerWrapper mode must remain outer-path-preserving")
            locked_status = bionic_lock.get("execution", {}).get("expectedStatus") if isinstance(bionic_lock, dict) else None
            if expected_status != locked_status or outer_expected_status != locked_status:
                fail("nodejs baseline and outer expectedStatus must match the reviewed bionic runtime lock")
    for tier in ("nightly", "release"):
        policy_errors = required_execution_policy_errors(projects, tier, closure)
        if policy_errors:
            fail(f"{tier} execution policy coverage is incomplete: " + "; ".join(policy_errors))
    print(f"PASS runtime closures: 100 identities, {len(runtimes)} runtime families")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("closure_manifest", type=Path)
    parser.add_argument("registry_manifest", type=Path)
    args = parser.parse_args()
    validate(args.closure_manifest, args.registry_manifest)


if __name__ == "__main__":
    main()
