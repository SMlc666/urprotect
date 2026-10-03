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
import re
import subprocess
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from real_sample_schema import (
    FIRST_FAILURE_LAYERS,
    ISOLATION_ENVIRONMENT_STATUS,
    ISOLATION_TIMEOUT_STATUS,
    LAYERS,
    RESULTS,
    RUNTIME_EXECUTION_LAYERS,
    RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME,
    RUNNER_PREFLIGHT_OUTCOMES,
    STATIC_RESULTS,
    required_execution_policy_errors,
    validate_isolation_result,
    validate_runner_preflight,
)
REQUIRED_FILES = (
    "source.txt",
    "hashes.txt",
    "environment.txt",
    "elf-fingerprint.json",
    "fingerprint-comparison.json",
    "readelf.txt",
    "urprotect-report.json",
    "runtime-closure.json",
    "execution.json",
    "outer-pack.json",
    "result.json",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RESERVED_HELPER_STATUSES = {ISOLATION_TIMEOUT_STATUS, ISOLATION_ENVIRONMENT_STATUS}
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
    parser.add_argument("--runtime-closures", type=Path)
    parser.add_argument(
        "--dispositions",
        type=Path,
        help="reviewed feature dispositions; defaults beside the manifest",
    )
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


def run_validator(
    manifest: Path,
    candidates: Path | None,
    runtime_closures: Path | None,
) -> None:
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
    if runtime_closures is not None:
        closure_validator = Path(__file__).resolve().with_name("validate-runtime-closures.py")
        try:
            closure_result = subprocess.run(
                [sys.executable, str(closure_validator), str(runtime_closures), str(manifest)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvidenceError(f"could not run runtime closure validator: {error}") from error
        if closure_result.returncode != 0:
            details = (closure_result.stderr or closure_result.stdout).strip()
            raise EvidenceError(f"runtime closure validation failed: {details}")


def manifest_projects(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    corpus = manifest.get("corpus")
    if not isinstance(corpus, dict) or not isinstance(corpus.get("projects"), list):
        raise EvidenceError("manifest corpus.projects must be an array")
    projects = [project for project in corpus["projects"] if isinstance(project, dict)]
    required = corpus.get("requiredProjectCount")
    if not isinstance(required, int) or required <= 0:
        raise EvidenceError("manifest requiredProjectCount must be a positive integer")
    if len(projects) != required:
        raise EvidenceError(f"manifest must contain exactly {required} projects, found {len(projects)}")
    return projects


def layer_expectations(project: dict[str, Any], closures: dict[str, Any] | None = None) -> dict[str, str]:
    policy = project.get("executionPolicy")
    if not isinstance(policy, dict):
        raise EvidenceError(f"{project.get('projectId', '<unknown>')} has no executionPolicy")
    result: dict[str, str] = {}
    for layer in LAYERS:
        value = policy.get(layer)
        allowed_results = STATIC_RESULTS if layer == "static" else RESULTS
        if not isinstance(value, dict) or value.get("expectedResult") not in allowed_results:
            raise EvidenceError(f"{project.get('projectId', '<unknown>')} has no valid {layer} policy")
        result[layer] = value["expectedResult"]
    # Runtime closure validation is a separate gate. It supplies acquisition
    # and dependency facts, but it never rewrites a registry expectation. This
    # preserves explicit environment-unavailable boundaries such as bionic
    # while preventing a generic closure default from promoting them.
    return result


def effective_closure_policy(
    project: dict[str, Any], closures: dict[str, Any] | None
) -> dict[str, Any]:
    if not isinstance(closures, dict):
        return {}
    projects = closures.get("projects")
    if not isinstance(projects, dict):
        return {}
    project_id = project.get("projectId")
    override = projects.get(project_id)
    if isinstance(override, dict):
        return override
    default = projects.get("*")
    return default if isinstance(default, dict) else {}


def declared_artifact_path(project: dict[str, Any]) -> str | None:
    provenance = project.get("provenance")
    artifact_path = provenance.get("artifactPath") if isinstance(provenance, dict) else None
    if not isinstance(artifact_path, str) or not artifact_path or "\x00" in artifact_path:
        return None
    return "/" + artifact_path.lstrip("/")


def _command_value(value: Any, label: str) -> tuple[list[str] | None, list[str]]:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str)
            or not item
            or any(character in item for character in ("\x00", "\n", "\r"))
            for item in value
        )
    ):
        return None, [f"{label} must be a non-empty control-free string array"]
    return value, []


def effective_baseline_command(
    project: dict[str, Any], closures: dict[str, Any] | None
) -> tuple[list[str] | None, list[str]]:
    project_id = str(project.get("projectId", "<unknown>"))
    artifact_path = declared_artifact_path(project)
    if artifact_path is None:
        return None, [f"{project_id}: provenance.artifactPath is missing or invalid"]

    execution_policy = project.get("executionPolicy")
    manifest_baseline = execution_policy.get("baseline") if isinstance(execution_policy, dict) else None
    manifest_baseline = manifest_baseline if isinstance(manifest_baseline, dict) else {}
    closure_baseline = effective_closure_policy(project, closures).get("baseline")
    closure_baseline = closure_baseline if isinstance(closure_baseline, dict) else {}

    # The closure can intentionally override a registry argv; otherwise the
    # registry command is authoritative. The version-only recipe is permitted
    # only when the effective policy explicitly declares it.
    if "command" in closure_baseline:
        command, errors = _command_value(closure_baseline.get("command"), f"{project_id}: closure baseline command")
    elif "command" in manifest_baseline:
        command, errors = _command_value(manifest_baseline.get("command"), f"{project_id}: registry baseline command")
    else:
        invocation = closure_baseline.get("invocation", manifest_baseline.get("invocation"))
        if invocation != "declared-artifact-version":
            return None, [f"{project_id}: no declared baseline command or validated artifact-version invocation"]
        command, errors = [artifact_path, "--version"], []

    if command is not None and command[0] != artifact_path:
        errors.append(f"{project_id}: effective baseline command must launch provenance.artifactPath")
    return command, errors


def effective_outer_mode(project: dict[str, Any], closures: dict[str, Any] | None) -> str | None:
    execution_policy = project.get("executionPolicy")
    registry_outer = execution_policy.get("outerWrapper") if isinstance(execution_policy, dict) else None
    registry_outer = registry_outer if isinstance(registry_outer, dict) else {}
    closure_outer = effective_closure_policy(project, closures).get("outerWrapper")
    closure_outer = closure_outer if isinstance(closure_outer, dict) else {}
    mode = closure_outer.get("mode", registry_outer.get("mode", "outer-execveat"))
    return mode if isinstance(mode, str) and mode else None


def check_fingerprint_shape(fingerprint: dict[str, Any], project_id: str) -> list[str]:
    """Validate the normalized schema without interpreting feature support."""
    errors: list[str] = []
    if fingerprint.get("schemaVersion") != 2:
        return errors
    if "error" in fingerprint:
        unknown = fingerprint.get("unknownFields")
        if not isinstance(unknown, list) or not unknown:
            errors.append(f"{project_id}: failed fingerprint must declare unknownFields")
        return errors
    if fingerprint.get("featureSchemaVersion") != 2:
        errors.append(f"{project_id}: schema-2 fingerprint must declare featureSchemaVersion=2")
    for key in (
        "producer",
        "runtime",
        "loader",
        "dependencies",
        "relocations",
        "symbolVersions",
        "tls",
        "gnuProperty",
        "hardening",
        "unknownFields",
        "inspection",
    ):
        if key not in fingerprint:
            errors.append(f"{project_id}: fingerprint is missing normalized field {key}")
    for key in ("dependencies", "relocations", "symbolVersions", "tls", "gnuProperty", "hardening", "inspection"):
        if key in fingerprint and not isinstance(fingerprint[key], dict):
            errors.append(f"{project_id}: fingerprint.{key} must be an object")
    unknown = fingerprint.get("unknownFields")
    if not isinstance(unknown, list) or len(unknown) > 256 or not all(isinstance(value, str) for value in unknown):
        errors.append(f"{project_id}: fingerprint.unknownFields must be a bounded string array")
    inspection = fingerprint.get("inspection")
    if isinstance(inspection, dict) and inspection.get("bounded") is not True:
        errors.append(f"{project_id}: fingerprint inspection must assert bounded=true")
    return errors


def parse_key_value_file(path: Path, label: str) -> dict[str, str]:
    require_non_empty(path, label)
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise EvidenceError(f"{label} is unreadable: {error}") from error
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key or key in values:
            raise EvidenceError(f"{label} contains a duplicate or invalid key: {key!r}")
        values[key] = value.strip()
    return values


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a non-empty lowercase SHA-256 digest")
    return value


def require_evidence_file(
    sample_root: Path,
    relative: Any,
    label: str,
    *,
    allow_empty: bool,
) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise EvidenceError(f"{label} must be a safe relative evidence path")
    path = sample_root / relative
    try:
        path.relative_to(sample_root)
    except ValueError as error:
        raise EvidenceError(f"{label} escapes the sample evidence directory") from error
    require_non_empty(path, label) if not allow_empty else require_regular_text(path, label)
    return path


def require_regular_text(path: Path, label: str) -> None:
    try:
        stat_result = path.lstat()
    except (FileNotFoundError, OSError) as error:
        raise EvidenceError(f"{label} is missing or unreadable: {path}") from error
    if path.is_symlink() or not path.is_file() or stat_result.st_size > 16 * 1024 * 1024:
        raise EvidenceError(f"{label} is not a bounded regular evidence file: {path}")


def _optional_status(value: Any) -> int | None:
    if value in (None, "", "null") or isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 255:
        return value
    return None


def _check_optional_status(
    entry: dict[str, Any],
    sample_root: Path,
    project_id: str,
    layer: str,
    field: str,
    path_field: str,
) -> list[str]:
    errors: list[str] = []
    value = entry.get(field)
    if value is None:
        return errors
    status = _optional_status(value)
    if status is None:
        errors.append(f"{project_id}/{layer}: {field} must be an integer from 0 through 255")
        return errors
    path_value = entry.get(path_field)
    try:
        path = require_evidence_file(
            sample_root,
            path_value,
            f"{project_id}/{layer}/{path_field}",
            allow_empty=False,
        )
        if path.read_text(encoding="utf-8").strip() != str(status):
            errors.append(f"{project_id}/{layer}: {path_field} does not match {field}")
    except (EvidenceError, OSError, UnicodeError) as error:
        errors.append(str(error))
    return errors


def _read_helper_result(
    sample_root: Path,
    entry: dict[str, Any],
    project_id: str,
    layer: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    path_value = entry.get("helperResultPath")
    try:
        path = require_evidence_file(
            sample_root,
            path_value,
            f"{project_id}/{layer}/helperResultPath",
            allow_empty=False,
        )
        value = read_json(path, f"{project_id}/{layer}/helper result")
    except (EvidenceError, OSError, UnicodeError) as error:
        return None, [str(error)]
    if not isinstance(value, dict):
        return None, [f"{project_id}/{layer}: helper result must be an object"]
    errors.extend(
        f"{project_id}/{layer}: {message}"
        for message in validate_isolation_result(value)
    )
    return value, errors


def _read_preflight_result(
    sample_root: Path,
    entry: dict[str, Any],
    project_id: str,
    layer: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    path_value = entry.get("preflightResultPath")
    try:
        path = require_evidence_file(
            sample_root,
            path_value,
            f"{project_id}/{layer}/preflightResultPath",
            allow_empty=False,
        )
        value = read_json(path, f"{project_id}/{layer} preflight result")
    except (EvidenceError, OSError, UnicodeError) as error:
        return None, [str(error)]
    if not isinstance(value, dict):
        return None, [f"{project_id}/{layer}: preflight result must be an object"]
    errors.extend(
        f"{project_id}/{layer}: {message}"
        for message in validate_runner_preflight(value)
    )
    return value, errors


def check_execution_layer(
    sample_root: Path,
    execution: dict[str, Any],
    project_id: str,
    layer: str,
    expected: str,
    actual: str,
    *,
    expected_command: list[str] | None = None,
    expected_mode: str | None = None,
) -> list[str]:
    errors: list[str] = []
    entry = execution.get(layer)
    if not isinstance(entry, dict):
        return [f"{project_id}: execution.{layer} is missing"]
    if entry.get("result") != actual:
        errors.append(f"{project_id}/{layer}: execution result does not match result.json")
    if expected == "not-applicable":
        if entry.get("expectedResult") != expected:
            errors.append(f"{project_id}/{layer}: execution expectedResult does not preserve not-applicable")
        if (
            entry.get("applicable") is not False
            or entry.get("attempted") is not False
            or not isinstance(entry.get("reason"), str)
            or not entry["reason"].strip()
        ):
            errors.append(f"{project_id}/{layer}: execution record must preserve the not-applicable boundary")
        if entry.get("status") is not None or entry.get("targetStatus") is not None:
            errors.append(f"{project_id}/{layer}: not-applicable execution cannot retain a process status")
        if entry.get("helperStatus") is not None:
            errors.append(f"{project_id}/{layer}: not-applicable execution cannot retain helper status")
        if entry.get("helperResultPath") is not None or entry.get("preflightResultPath") is not None:
            errors.append(f"{project_id}/{layer}: not-applicable execution cannot retain execution evidence")
        if entry.get("outcome") != "not-applicable":
            errors.append(f"{project_id}/{layer}: not-applicable execution must declare outcome=not-applicable")
        return errors
    if entry.get("applicable") is not True:
        errors.append(f"{project_id}/{layer}: execution record must declare applicable=true")
    if entry.get("expectedResult") != expected:
        errors.append(f"{project_id}/{layer}: execution expectedResult does not match the registry/closure")

    attempted = entry.get("attempted")
    if not isinstance(attempted, bool):
        errors.append(f"{project_id}/{layer}: execution record must declare attempted=true or false")
        attempted = False

    helper_path_present = entry.get("helperResultPath") is not None
    preflight_path_present = entry.get("preflightResultPath") is not None
    if helper_path_present and preflight_path_present:
        errors.append(f"{project_id}/{layer}: execution cannot retain both helper and preflight evidence")
    elif not helper_path_present and not preflight_path_present:
        errors.append(f"{project_id}/{layer}: execution must retain helper or runner-preflight evidence")

    helper_result: dict[str, Any] | None = None
    preflight_result: dict[str, Any] | None = None
    if helper_path_present:
        helper_result, helper_result_errors = _read_helper_result(sample_root, entry, project_id, layer)
        errors.extend(helper_result_errors)
    elif preflight_path_present:
        preflight_result, preflight_errors = _read_preflight_result(sample_root, entry, project_id, layer)
        errors.extend(preflight_errors)

    if preflight_result is not None:
        helper_attempted = False
        helper_status = None
        target_status = None
        preflight_outcome = preflight_result.get("outcome")
        if preflight_result.get("layer") != layer:
            errors.append(f"{project_id}/{layer}: runner preflight layer does not match execution layer")
        if entry.get("outcome") != preflight_outcome:
            errors.append(f"{project_id}/{layer}: execution outcome does not match runner preflight result")
        if entry.get("reason") != preflight_result.get("reason"):
            errors.append(f"{project_id}/{layer}: execution reason does not match runner preflight result")
        if entry.get("attempted") is not False:
            errors.append(f"{project_id}/{layer}: runner preflight must declare attempted=false")
        if entry.get("helperStatus") is not None or entry.get("targetStatus") is not None:
            errors.append(f"{project_id}/{layer}: runner preflight must retain null helper and target statuses")
    elif helper_result is not None:
        helper_attempted = helper_result.get("attempted")
        helper_status = helper_result.get("helperStatus")
        target_status = helper_result.get("targetStatus")
        if entry.get("outcome") != helper_result.get("outcome"):
            errors.append(f"{project_id}/{layer}: execution outcome does not match helper result")
    else:
        helper_attempted = None
        helper_status = None
        target_status = None

    command = entry.get("resolvedCommand")
    if command is None:
        errors.append(f"{project_id}/{layer}: applicable execution must retain resolvedCommand")
    elif (
        not isinstance(command, list)
        or not command
        or any(not isinstance(value, str) or not value for value in command)
    ):
        errors.append(f"{project_id}/{layer}: resolvedCommand must be a non-empty string array")
    if isinstance(command, list) and command:
        if layer == "baseline":
            if command[0] != execution.get("artifactPath"):
                errors.append(f"{project_id}/baseline: resolvedCommand must launch the declared artifactPath")
            if expected_command is not None and command != expected_command:
                errors.append(f"{project_id}/baseline: resolvedCommand does not match the effective declared argv")
        elif layer == "outerWrapper":
            if command[0] != "/usr/local/bin/urprotect-packed":
                errors.append(f"{project_id}/outerWrapper: resolvedCommand must launch the packed wrapper")
            if expected_command is not None:
                expected_outer_command = ["/usr/local/bin/urprotect-packed", *expected_command[1:]]
                if command != expected_outer_command:
                    errors.append(f"{project_id}/outerWrapper: resolvedCommand must match baseline argv with only the executable replaced")
    invocation_source = entry.get("invocationSource")
    if invocation_source not in {"declared", "validated-wildcard", "runner-derived-wrapper", "runner-preflight", "not-applicable"}:
        errors.append(f"{project_id}/{layer}: invocationSource is missing or unsupported")
    if layer == "outerWrapper":
        if invocation_source != "runner-derived-wrapper":
            errors.append(f"{project_id}/outerWrapper: invocationSource must identify the runner-derived wrapper recipe")
        if expected_mode is not None and entry.get("mode") != expected_mode:
            errors.append(f"{project_id}/outerWrapper: execution mode does not match the resolved registry/closure policy")
    expected_status = entry.get("expectedStatus")
    if (
        isinstance(expected_status, bool)
        or not isinstance(expected_status, int)
        or not 0 <= expected_status <= 255
        or expected_status in RESERVED_HELPER_STATUSES
    ):
        errors.append(f"{project_id}/{layer}: expectedStatus must be a non-reserved status from 0 through 255")
    status = entry.get("status")
    target_status_field = entry.get("targetStatus")
    if target_status_field != status:
        errors.append(f"{project_id}/{layer}: targetStatus must match execution status")
    if status is not None and (
        isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255
    ):
        errors.append(f"{project_id}/{layer}: execution target status must be null or an integer from 0 through 255")
    if attempted is False and status is not None:
        errors.append(f"{project_id}/{layer}: execution status must be null when no process was attempted")
    if attempted is True and status is None and helper_status is None:
        errors.append(f"{project_id}/{layer}: attempted execution must retain a target or helper status")
    if target_status != status:
        errors.append(f"{project_id}/{layer}: execution status does not match helper/preflight targetStatus")
    if helper_attempted != attempted:
        errors.append(f"{project_id}/{layer}: execution attempted does not match helper/preflight result")
    if helper_status != entry.get("helperStatus"):
        errors.append(f"{project_id}/{layer}: execution helperStatus does not match helper/preflight result")
    if helper_status is None and entry.get("helperStatusPath") is not None:
        errors.append(f"{project_id}/{layer}: helperStatusPath must be null when helper status is absent")
    for stream in ("stdoutPath", "stderrPath"):
        try:
            require_evidence_file(
                sample_root,
                entry.get(stream),
                f"{project_id}/{layer}/{stream}",
                allow_empty=True,
            )
        except (EvidenceError, OSError, UnicodeError) as error:
            errors.append(str(error))
    status_path = entry.get("statusPath")
    if isinstance(status, int):
        try:
            stream_path = require_evidence_file(
                sample_root,
                status_path,
                f"{project_id}/{layer}/statusPath",
                allow_empty=False,
            )
            if stream_path.read_text(encoding="utf-8").strip() != str(status):
                errors.append(f"{project_id}/{layer}: status evidence does not match execution.json")
        except (EvidenceError, OSError, UnicodeError) as error:
            errors.append(str(error))
    elif status_path is not None:
        errors.append(f"{project_id}/{layer}: statusPath must be null when target status is absent")

    errors.extend(_check_optional_status(entry, sample_root, project_id, layer, "helperStatus", "helperStatusPath"))
    errors.extend(_check_optional_status(entry, sample_root, project_id, layer, "packStatus", "packStatusPath"))
    if expected == "accepted-and-runs" and attempted and isinstance(status, int) and status != expected_status:
        errors.append(f"{project_id}/{layer}: observed status does not match expectedStatus")
    if actual == "environment-unavailable":
        if preflight_result is not None:
            if preflight_result.get("outcome") != RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME:
                errors.append(
                    f"{project_id}/{layer}: environment-unavailable requires "
                    f"{RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME}"
                )
        elif helper_status != ISOLATION_ENVIRONMENT_STATUS:
            errors.append(
                f"{project_id}/{layer}: helper environment-unavailable must retain helper status "
                f"{ISOLATION_ENVIRONMENT_STATUS} when no process ran"
            )
        if target_status is not None:
            errors.append(f"{project_id}/{layer}: environment-unavailable cannot retain a target status")
        if attempted:
            errors.append(f"{project_id}/{layer}: environment-unavailable cannot claim a completed process attempt")
    if preflight_result is not None and actual == "accepted-and-runs":
        errors.append(f"{project_id}/{layer}: accepted-and-runs requires an actual helper result, not runner preflight")
    if preflight_result is not None and actual != "accepted-and-runs":
        if preflight_result.get("outcome") not in RUNNER_PREFLIGHT_OUTCOMES:
            errors.append(f"{project_id}/{layer}: unsupported runner preflight outcome")
        elif preflight_result.get("outcome") == RUNNER_PREFLIGHT_ENVIRONMENT_OUTCOME and actual != "environment-unavailable":
            errors.append(f"{project_id}/{layer}: environment preflight must produce environment-unavailable")
        elif preflight_result.get("outcome") == "preflight-product-failure" and actual == "environment-unavailable":
            errors.append(f"{project_id}/{layer}: product preflight must not be classified environment-unavailable")
    if target_status in RESERVED_HELPER_STATUSES and actual != "runtime-failure":
        errors.append(f"{project_id}/{layer}: target status {target_status} must remain runtime-failure")
    if helper_status == ISOLATION_TIMEOUT_STATUS and actual != "runtime-failure":
        errors.append(f"{project_id}/{layer}: helper timeout must remain runtime-failure")
    if helper_status == ISOLATION_ENVIRONMENT_STATUS and actual == "accepted-and-runs":
        errors.append(f"{project_id}/{layer}: helper environment outcome cannot be accepted-and-runs")
    if actual == "unexpected-rejection" and layer == "outerWrapper" and not attempted:
        if _optional_status(entry.get("packStatus")) is None:
            errors.append(f"{project_id}/outerWrapper: pack failure must retain packStatus without a wrapper status")
    return errors


def check_outer_equivalence(
    sample_root: Path,
    project_id: str,
    execution: dict[str, Any],
    expected: str,
    actual: str,
) -> list[str]:
    """Verify the retained outer oracle, independently of policy matching."""
    if expected != "accepted-and-runs" or actual != "accepted-and-runs":
        return []
    errors: list[str] = []
    baseline = execution.get("baseline")
    outer = execution.get("outerWrapper")
    if not isinstance(baseline, dict) or not isinstance(outer, dict):
        return [f"{project_id}: accepted outer execution requires baseline and outer execution records"]
    if baseline.get("attempted") is not True or outer.get("attempted") is not True:
        errors.append(f"{project_id}: accepted outer execution requires both processes to be attempted")
    if baseline.get("status") != outer.get("status"):
        errors.append(f"{project_id}: baseline and outer exit statuses differ")
    for stream in ("stdoutPath", "stderrPath"):
        try:
            baseline_path = require_evidence_file(
                sample_root,
                baseline.get(stream),
                f"{project_id}/baseline/{stream}",
                allow_empty=True,
            )
            outer_path = require_evidence_file(
                sample_root,
                outer.get(stream),
                f"{project_id}/outerWrapper/{stream}",
                allow_empty=True,
            )
            if baseline_path.read_bytes() != outer_path.read_bytes():
                errors.append(f"{project_id}: baseline and outer {stream.removesuffix('Path')} differ")
        except (EvidenceError, OSError) as error:
            errors.append(str(error))
    for key in ("signal", "signalName", "terminationSignal", "termination"):
        if key in baseline or key in outer:
            if baseline.get(key) != outer.get(key):
                errors.append(f"{project_id}: baseline and outer {key} differ")
    return errors


def check_product_report(
    sample_root: Path,
    project_id: str,
    source_hash: str,
    cli_success: bool | None,
) -> list[str]:
    errors: list[str] = []
    try:
        report = read_json(sample_root / "urprotect-report.json", f"{project_id}/urprotect-report.json")
    except EvidenceError as error:
        return [str(error)]
    if not isinstance(report, dict) or not report:
        return [f"{project_id}: UrProtect report must be a structured non-empty product report"]
    if not isinstance(report.get("schemaVersion"), int) or not isinstance(report.get("success"), bool):
        errors.append(f"{project_id}: UrProtect report is synthetic or missing schemaVersion/success")
    if not isinstance(cli_success, bool):
        errors.append(f"{project_id}: result must retain the actual UrProtect CLI success state")
    elif isinstance(report.get("success"), bool) and report["success"] != cli_success:
        errors.append(f"{project_id}: UrProtect report success does not match the actual CLI result")
    if not isinstance(report.get("toolVersion"), str) or not report["toolVersion"].strip():
        errors.append(f"{project_id}: UrProtect report is missing toolVersion")
    input_report = report.get("input")
    if not isinstance(input_report, dict):
        errors.append(f"{project_id}: UrProtect report is missing its input record")
    elif source_hash and input_report.get("sha256") != source_hash:
        errors.append(f"{project_id}: UrProtect input hash does not match source artifact hash")
    elif not source_hash and input_report.get("sha256") not in (None, ""):
        errors.append(f"{project_id}: failure report must not invent an input hash")
    if not isinstance(report.get("summary"), dict):
        errors.append(f"{project_id}: UrProtect report is missing its summary record")
    if not isinstance(report.get("diagnostics"), list):
        errors.append(f"{project_id}: UrProtect report diagnostics must be an array")
    return errors


def check_pack_report(
    sample_root: Path,
    project_id: str,
    expected: str,
    actual: str,
    execution: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    try:
        report = read_json(sample_root / "outer-pack.json", f"{project_id}/outer-pack.json")
    except EvidenceError as error:
        return [str(error)]
    if expected == "not-applicable":
        if not isinstance(report, dict) or report.get("status") != "not-applicable" or not isinstance(report.get("reason"), str):
            errors.append(f"{project_id}: outer pack report must preserve the not-applicable boundary")
        return errors
    if not isinstance(report, dict) or not report:
        return [f"{project_id}: outer pack report must be a structured non-empty pack report"]
    if not isinstance(report.get("schemaVersion"), int) or not isinstance(report.get("success"), bool):
        errors.append(f"{project_id}: outer pack report is synthetic or missing schemaVersion/success")
    if not isinstance(report.get("payload"), dict) or not isinstance(report.get("output"), dict):
        errors.append(f"{project_id}: outer pack report is missing payload/output records")
    if not isinstance(report.get("diagnostics"), list):
        errors.append(f"{project_id}: outer pack report diagnostics must be an array")
    output_published = report.get("output", {}).get("published")
    if not isinstance(output_published, bool):
        errors.append(f"{project_id}: outer pack report output.published must be boolean")
    elif output_published != report.get("success"):
        errors.append(f"{project_id}: outer pack publication status must match pack success")
    cli_status = report.get("cliExitCode")
    if cli_status is not None and (
        isinstance(cli_status, bool) or not isinstance(cli_status, int) or not 0 <= cli_status <= 255
    ):
        errors.append(f"{project_id}: outer pack cliExitCode must be an integer from 0 through 255")
    elif isinstance(cli_status, int) and ((report.get("success") and cli_status != 0) or (not report.get("success") and cli_status == 0)):
        errors.append(f"{project_id}: outer pack cliExitCode is inconsistent with pack success")
    outer_execution = execution.get("outerWrapper") if isinstance(execution, dict) else None
    if isinstance(outer_execution, dict):
        pack_status = outer_execution.get("packStatus")
        if pack_status is not None and not isinstance(cli_status, int):
            errors.append(f"{project_id}: outer pack status requires matching cliExitCode in the pack report")
        if isinstance(pack_status, int) and isinstance(cli_status, int) and pack_status != cli_status:
            errors.append(f"{project_id}: outer pack status does not match outer execution evidence")
        attempted = outer_execution.get("attempted")
        if report.get("success") is False and attempted is True:
            errors.append(f"{project_id}: failed outer pack must not claim wrapper execution")
        if report.get("success") is True and actual == "accepted-and-runs" and attempted is not True:
            errors.append(f"{project_id}: accepted outer execution requires the published wrapper to run")
    if actual == "accepted-and-runs" and (
        report.get("success") is not True or output_published is not True
    ):
        errors.append(f"{project_id}: accepted outer execution requires a successful published pack report")
    return errors

def check_sample(project: dict[str, Any], tier: str, root: Path, closures: dict[str, Any] | None = None) -> list[str]:
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
    if result.get("schemaVersion") != 2:
        errors.append(f"{project_id}: result schemaVersion must be 2")
    failure = result.get("firstFailureLayer")
    if failure is not None and failure not in FIRST_FAILURE_LAYERS:
        errors.append(f"{project_id}: unsupported firstFailureLayer {failure!r}")
    if result.get("tier") != tier:
        errors.append(f"{project_id}: result tier does not match {tier}")
    if result.get("projectId") != project_id:
        errors.append(f"{project_id}: result projectId does not match directory")
    cli_success = result.get("cliSuccess")
    if not isinstance(cli_success, bool):
        errors.append(f"{project_id}: result must retain cliSuccess as a boolean")
    early_failure = failure in {"acquisition", "fingerprint", "environment"}
    expected = layer_expectations(project, closures)
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
        allowed_results = STATIC_RESULTS if layer == "static" else RESULTS
        if actual not in allowed_results:
            errors.append(f"{project_id}/{layer}: unsupported actual result {actual!r}")
        if layer_result.get("expected") != expected[layer]:
            errors.append(f"{project_id}/{layer}: result expectation does not match registry")
        if actual != expected[layer]:
            errors.append(f"{project_id}/{layer}: expected {expected[layer]!r}, observed {actual!r}")
        if actual == "not-applicable" and not isinstance(layer_result.get("reason"), str):
            errors.append(f"{project_id}/{layer}: not-applicable result requires a reason")
        if actual == "environment-unavailable" and not isinstance(layer_result.get("reason"), str):
            errors.append(f"{project_id}/{layer}: environment-unavailable result requires a reason")

    fingerprint: dict[str, Any] | None = None
    fingerprint_path = sample_root / "elf-fingerprint.json"
    try:
        value = read_json(fingerprint_path, f"{project_id}/elf-fingerprint.json")
        if not isinstance(value, dict) or value.get("projectId") != project_id:
            errors.append(f"{project_id}: fingerprint projectId does not match directory")
        else:
            fingerprint = value
            if fingerprint.get("schemaVersion") != 2:
                errors.append(f"{project_id}: fingerprint schemaVersion must be 2")
            if "error" in fingerprint:
                if not early_failure or not isinstance(fingerprint.get("unknownFields"), list) or not fingerprint["unknownFields"]:
                    errors.append(f"{project_id}: generic fingerprint failure evidence is not a valid early-failure record")
            else:
                errors.extend(check_fingerprint_shape(fingerprint, project_id))
            if not (early_failure and "error" in fingerprint):
                try:
                    require_hash(fingerprint.get("fileSha256"), f"{project_id}: fingerprint fileSha256")
                except EvidenceError as error:
                    errors.append(str(error))
    except EvidenceError as error:
        errors.append(str(error))

    try:
        source_hash = require_hash(result.get("artifactSha256"), f"{project_id}: result artifactSha256")
    except EvidenceError as error:
        source_hash = ""
        if not early_failure:
            errors.append(str(error))
    if (
        fingerprint is not None
        and source_hash
        and "error" not in fingerprint
        and fingerprint.get("fileSha256") != source_hash
    ):
        errors.append(f"{project_id}: result artifactSha256 does not match fingerprint fileSha256")

    try:
        hash_values = parse_key_value_file(sample_root / "hashes.txt", f"{project_id}/hashes.txt")
    except EvidenceError as error:
        hash_values = {}
        errors.append(str(error))
    if source_hash and hash_values.get("sourceArtifactSha256") != source_hash:
        errors.append(f"{project_id}: hashes.txt sourceArtifactSha256 does not match result artifactSha256")
    try:
        source_hash_from_file = require_hash(hash_values.get("sourceArtifactSha256"), f"{project_id}: sourceArtifactSha256")
    except EvidenceError as error:
        source_hash_from_file = ""
        if not early_failure:
            errors.append(str(error))

    try:
        closure_record = read_json(sample_root / "runtime-closure.json", f"{project_id}/runtime-closure.json")
    except EvidenceError as error:
        closure_record = {}
        errors.append(str(error))
    runtime = project.get("target", {}).get("runtime") if isinstance(project.get("target"), dict) else None
    runtime_applicable = expected["baseline"] != "not-applicable" or expected["outerWrapper"] != "not-applicable"
    accepted_runtime_layers = [
        layer
        for layer in RUNTIME_EXECUTION_LAYERS
        if isinstance(layers.get(layer), dict)
        and layers[layer].get("actual") == "accepted-and-runs"
    ]
    if not isinstance(closure_record, dict) or not closure_record:
        errors.append(f"{project_id}: runtime closure record must be a structured non-empty object")
    else:
        if closure_record.get("schemaVersion") != 1:
            errors.append(f"{project_id}: runtime closure record schemaVersion must be 1")
        if closure_record.get("projectId") != project_id:
            errors.append(f"{project_id}: runtime closure projectId does not match directory")
        if closure_record.get("runtime") != runtime:
            errors.append(f"{project_id}: runtime closure runtime does not match registry")
        status = closure_record.get("status")
        if runtime_applicable and status not in {"assembled", "environment-unavailable"}:
            errors.append(f"{project_id}: applicable runtime closure must be assembled or retain an explicit environment failure")
        if not runtime_applicable and status not in {"assembled", "not-applicable", "environment-unavailable"}:
            errors.append(f"{project_id}: runtime closure status is unsupported")
        if accepted_runtime_layers and status != "assembled":
            errors.append(
                f"{project_id}: accepted {', '.join(accepted_runtime_layers)} execution requires "
                "runtime closure status=assembled"
            )
        closure_has_runtime_hash = isinstance(closure_record.get("runtimeArtifactSha256"), str) and bool(
            closure_record.get("runtimeArtifactSha256")
        )
        if runtime_applicable and (status == "assembled" or closure_has_runtime_hash or accepted_runtime_layers):
            try:
                runtime_hash = require_hash(
                    hash_values.get("runtimeArtifactSha256"), f"{project_id}: runtimeArtifactSha256"
                )
            except EvidenceError as error:
                runtime_hash = ""
                errors.append(str(error))
            if source_hash_from_file and runtime_hash and runtime_hash != source_hash_from_file:
                errors.append(f"{project_id}: source and reconstructed runtime artifact hashes differ")
            for key, actual in (
                ("sourceArtifactSha256", source_hash_from_file),
                ("runtimeArtifactSha256", runtime_hash),
            ):
                if actual and closure_record.get(key) != actual:
                    errors.append(f"{project_id}: runtime closure {key} does not match hashes.txt")

    comparison_path = sample_root / "fingerprint-comparison.json"
    try:
        comparison = read_json(comparison_path, f"{project_id}/fingerprint-comparison.json")
        if not isinstance(comparison, dict) or comparison.get("projectId") != project_id:
            errors.append(f"{project_id}: fingerprint comparison projectId does not match directory")
        elif comparison.get("schemaVersion") != 2:
            errors.append(f"{project_id}: fingerprint comparison schemaVersion must be 2")
        elif early_failure:
            if comparison.get("status") not in {"not-applicable", "failed"} or not isinstance(comparison.get("reason"), str):
                errors.append(f"{project_id}: early failure fingerprint comparison must retain a structured reason")
        elif comparison.get("status") != "passed":
            errors.append(f"{project_id}: fingerprint comparison must have status=passed")
    except EvidenceError as error:
        errors.append(str(error))

    errors.extend(check_product_report(sample_root, project_id, source_hash, cli_success))
    execution: dict[str, Any] | None = None
    try:
        execution_value = read_json(sample_root / "execution.json", f"{project_id}/execution.json")
        if not isinstance(execution_value, dict):
            errors.append(f"{project_id}: execution.json root must be an object")
        else:
            execution = execution_value
            registry_artifact_path = declared_artifact_path(project)
            if registry_artifact_path is None:
                errors.append(f"{project_id}: provenance.artifactPath is missing or invalid")
            elif execution.get("artifactPath") != registry_artifact_path:
                errors.append(f"{project_id}: execution artifactPath does not match provenance.artifactPath")
            if expected["baseline"] != "not-applicable" or expected["outerWrapper"] != "not-applicable":
                baseline_command, command_errors = effective_baseline_command(project, closures)
                errors.extend(command_errors)
            else:
                baseline_command = None
            outer_mode = effective_outer_mode(project, closures)
            if expected["outerWrapper"] != "not-applicable" and outer_mode is None:
                errors.append(f"{project_id}: resolved outer mode is missing from registry/closure policy")
            for layer in ("baseline", "outerWrapper"):
                layer_result = layers.get("baseline" if layer == "baseline" else "outerWrapper", {})
                actual_layer = layer_result.get("actual") if isinstance(layer_result, dict) else "environment-unavailable"
                errors.extend(
                    check_execution_layer(
                        sample_root,
                        execution,
                        project_id,
                        layer,
                        expected[layer],
                        actual_layer,
                        expected_command=baseline_command,
                        expected_mode=outer_mode if layer == "outerWrapper" else None,
                    )
                )
            if closures is not None:
                policy = effective_closure_policy(project, closures)
                baseline_policy = policy.get("baseline", {})
                outer_policy = policy.get("outerWrapper", {})
                if expected["baseline"] != "not-applicable" and isinstance(baseline_policy, dict):
                    expected_status = baseline_policy.get("expectedStatus", 0)
                    if execution.get("baseline", {}).get("expectedStatus") != expected_status:
                        errors.append(f"{project_id}: execution baseline expectedStatus does not match the locked closure")
                if expected["outerWrapper"] != "not-applicable" and isinstance(outer_policy, dict):
                    expected_status = outer_policy.get("expectedStatus", baseline_policy.get("expectedStatus", 0)) if isinstance(baseline_policy, dict) else outer_policy.get("expectedStatus", 0)
                    if execution.get("outerWrapper", {}).get("expectedStatus") != expected_status:
                        errors.append(f"{project_id}: execution outer expectedStatus does not match the locked closure")
    except EvidenceError as error:
        errors.append(str(error))
    if execution is not None:
        errors.extend(check_outer_equivalence(
            sample_root,
            project_id,
            execution,
            expected["outerWrapper"],
            layers.get("outerWrapper", {}).get("actual", "environment-unavailable"),
        ))
    errors.extend(check_pack_report(
        sample_root,
        project_id,
        expected["outerWrapper"],
        layers.get("outerWrapper", {}).get("actual", "environment-unavailable"),
        execution,
    ))
    marker_path = sample_root / "raw-inputs-removed.txt"
    if marker_path.is_file():
        try:
            marker = marker_path.read_text(encoding="utf-8").strip()
            if marker != "raw-inputs-removed=true":
                errors.append(f"{project_id}: raw input cleanup marker is invalid")
        except (OSError, UnicodeError) as error:
            errors.append(f"{project_id}: raw input cleanup marker is unreadable: {error}")
    elif result.get("schemaVersion") == 2:
        errors.append(f"{project_id}: schema-2 evidence must retain the raw input cleanup marker")
    return errors


def load_dispositions(path: Path) -> dict[str, dict[str, Any]]:
    value = read_json(path, "feature dispositions")
    raw = value.get("dispositions", value)
    if not isinstance(raw, dict):
        raise EvidenceError("feature dispositions must be an object")
    dispositions: dict[str, dict[str, Any]] = {}
    for feature, disposition in raw.items():
        if not isinstance(feature, str) or not isinstance(disposition, dict):
            raise EvidenceError("feature dispositions contain an invalid entry")
        status = disposition.get("status")
        reason = disposition.get("reason")
        if status not in {"support-candidate", "rejected", "deferred"} or not isinstance(reason, str) or not reason.strip():
            raise EvidenceError(f"feature disposition for {feature!r} is incomplete")
        dispositions[feature] = disposition
    return dispositions


def main() -> int:
    arguments = parse_args()
    manifest = arguments.manifest.resolve()
    candidates = arguments.candidates
    if candidates is None:
        sibling = manifest.with_name("candidates.json")
        candidates = sibling if sibling.is_file() else None
    dispositions_path = arguments.dispositions
    if dispositions_path is None:
        sibling = manifest.with_name("feature-dispositions.json")
        dispositions_path = sibling if sibling.is_file() else None
    root = (arguments.artifact_root or Path(".artifacts/real-samples") / arguments.tier).resolve()
    closures = None
    if arguments.runtime_closures is not None:
        try:
            closures = read_json(arguments.runtime_closures, "runtime closures")
        except EvidenceError as error:
            print(f"FAIL real-sample evidence gate: {error}", file=sys.stderr)
            return 1
    try:
        run_validator(manifest, candidates, arguments.runtime_closures)
        manifest_data = read_json(manifest, "manifest")
        projects = manifest_projects(manifest_data)
        dispositions = load_dispositions(dispositions_path) if dispositions_path is not None else {}
        if not root.is_dir():
            raise EvidenceError(f"artifact root is missing: {root}")
        coverage_errors = required_execution_policy_errors(projects, arguments.tier, closures)
        if coverage_errors:
            raise EvidenceError("tier runtime coverage policy is incomplete:\n  " + "\n  ".join(coverage_errors))
        ensure_tree_is_text(root)
        errors: list[str] = []
        project_ids = {project.get("projectId") for project in projects}
        for project in projects:
            errors.extend(check_sample(project, arguments.tier, root, closures))
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
            required_count = len(projects)
            if aggregate.get("requiredProjectCount") != required_count:
                errors.append(f"aggregate.json requiredProjectCount must be {required_count}")
            aggregate_ids = set(aggregate.get("projectIds", [])) if isinstance(aggregate.get("projectIds"), list) else set()
            if aggregate_ids != project_ids:
                errors.append("aggregate.json projectIds do not match the locked registry")
            if aggregate.get("observedProjectCount") != required_count:
                errors.append(f"aggregate.json observedProjectCount must be {required_count}")
            if aggregate.get("schemaVersion") != 2:
                errors.append("aggregate.json schemaVersion must be 2")
            else:
                if aggregate.get("identityCount") != required_count:
                    errors.append("aggregate.json identityCount must equal the locked distinct identity count")
                coverage = aggregate.get("coverage")
                target = manifest_data.get("corpus", {}).get("targetProjectCount")
                if not isinstance(coverage, dict) or not isinstance(coverage.get("approvedTargetProjectCount"), int):
                    errors.append("aggregate.json coverage must declare approvedTargetProjectCount")
                elif coverage.get("approvedTargetProjectCount") != target:
                    errors.append("aggregate.json coverage target does not match the manifest target")
                elif coverage.get("currentIdentityCount") != aggregate.get("identityCount"):
                    errors.append("aggregate.json coverage currentIdentityCount is inconsistent")
                elif coverage.get("shortfall") != max(0, target - aggregate.get("identityCount", 0)):
                    errors.append("aggregate.json coverage shortfall is inconsistent")
                histogram = aggregate.get("featureHistogram")
                if not isinstance(histogram, list):
                    errors.append("aggregate.json featureHistogram must be an array")
                else:
                    for index, item in enumerate(histogram):
                        if not isinstance(item, dict):
                            errors.append(f"aggregate.json featureHistogram[{index}] must be an object")
                            continue
                        disposition = item.get("disposition")
                        if not isinstance(disposition, dict) or not isinstance(disposition.get("status"), str) or not isinstance(disposition.get("reason"), str):
                            errors.append(f"aggregate.json featureHistogram[{index}] must record a disposition and reason")
                        feature = item.get("feature")
                        identity_count = item.get("identityCount")
                        identity_keys = item.get("identityKeys")
                        identity_percent = item.get("identityPercent")
                        if (
                            not isinstance(identity_count, int)
                            or identity_count <= 0
                            or not isinstance(identity_keys, list)
                            or len(identity_keys) != identity_count
                            or len(set(identity_keys)) != identity_count
                            or not all(isinstance(key, str) and key for key in identity_keys)
                        ):
                            errors.append(f"aggregate.json featureHistogram[{index}] has inconsistent identity counts")
                        elif (
                            not isinstance(identity_percent, (int, float))
                            or not isinstance(aggregate.get("identityCount"), int)
                            or round(identity_count * 100.0 / aggregate["identityCount"], 2) != identity_percent
                        ):
                            errors.append(f"aggregate.json featureHistogram[{index}] has inconsistent identityPercent")
                        if item.get("thresholdTriggered") is True:
                            reviewed = dispositions.get(feature)
                            if reviewed is None:
                                errors.append(f"aggregate.json featureHistogram[{index}] lacks a reviewed disposition for {feature!r}")
                            elif (
                                not isinstance(item.get("disposition"), dict)
                                or item["disposition"].get("status") != reviewed.get("status")
                                or item["disposition"].get("reason") != reviewed.get("reason")
                            ):
                                errors.append(f"aggregate.json featureHistogram[{index}] disposition does not match the reviewed record for {feature!r}")
                first_failure = aggregate.get("firstFailureLayers")
                if not isinstance(first_failure, dict) or not set(first_failure).issubset(set(FIRST_FAILURE_LAYERS)):
                    errors.append("aggregate.json firstFailureLayers contains an unsupported taxonomy layer")
        if errors:
            raise EvidenceError("\n  ".join(errors))
    except EvidenceError as error:
        print(f"FAIL real-sample evidence gate: {error}", file=sys.stderr)
        return 1
    print(f"PASS real-sample evidence gate: tier={arguments.tier}; checked {len(projects)} projects and all layers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
