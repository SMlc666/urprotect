#!/usr/bin/env python3
"""Shared, read-only validation and scoring rules for the independent evaluator.

This module contains policy only. It never builds product code, executes a target,
or writes a source/manifest/baseline file. The runner is responsible for writing a
separate evidence tree and the post-run checker reuses these pure validations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = 1
STATUS_OWNER = "independent-evaluator"
MAX_RELATIVE_PATH_LENGTH = 240
COMPATIBILITY_STAGES = (
    "protector",
    "protected-image",
    "rehydration",
    "native-image",
    "target-loader",
    "behavioral-oracle",
)
# A completed stage must bind the exact artifact/evidence role that the stage
# claims.  A generic evidence digest is not enough: otherwise a forged record
# could mark every stage passed with one unrelated hash.
STAGE_DIGEST_FIELDS = {
    "protector": ("outputSha256",),
    "protected-image": ("artifactSha256",),
    "rehydration": ("protectedImageSha256", "nativeImageSha256"),
    "native-image": ("sha256",),
    "target-loader": ("nativeImageSha256", "evidenceSha256"),
    "behavioral-oracle": ("comparisonSha256",),
}
STAGE_REQUIRED_FIELDS = {
    "protected-image": ("abiId", "abiVersion"),
    "rehydration": ("consumerId",),
    "target-loader": ("loaderId",),
}
STAGE_STATUSES = {
    "passed",
    "failed",
    "environment-unavailable",
    "not-applicable",
    "unknown",
    "protocol-failure",
}
ATTACK_CLASSIFICATIONS = {
    "attack-success",
    "attack-failed",
    "environment-unavailable",
    "tool-not-applicable",
    "unknown",
    "protocol-failure",
}
REQUIRED_FAMILIES = (
    "runtime_dump_reassembly",
    "patch_repack",
    "function_logic_recovery",
    "static_decomposition",
    "dynamic_instrumentation",
    "integrity_handoff",
)
COMPATIBILITY_STATUSES = {
    "baseline-zero",
    "measured",
    "environment-unavailable",
    "not-ready",
}
SCHEME_STATUSES = {
    "baseline-not-calibrated",
    "measured",
    "environment-unavailable",
    "not-ready",
    "pass",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PRODUCT_MAX_FILES = 1_000
PRODUCT_MAX_TREE_BYTES = 536_870_912
PRODUCT_MAX_RECORD_BYTES = 1_048_576
PRODUCT_MAX_STREAM_BYTES = 1_048_576
PRODUCT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
PRODUCT_MAX_SOURCE_IMAGE_BYTES = 128 * 1024 * 1024
PRODUCT_MAX_NATIVE_IMAGE_BYTES = 128 * 1024 * 1024
# These self-describing handoff records are emitted after the closed evidence
# inventory is derived.  Excluding them keeps the manifest digest content-
# addressed instead of creating a gate/manifest fixed-point cycle.
EVIDENCE_HANDOFF_FILES = frozenset({"gate.json", "analysis-input.json", "positive-baseline-v2-gate.json"})
FROZEN_V2_FIXED_ROW_SHA256 = "8f7f1e926c2f0e83a896356193bf8d47723830a81999f8de650f660565936af0"


class EvaluatorError(ValueError):
    """A malformed manifest or evidence record."""


class ProductEvidenceError(EvaluatorError):
    """A product evidence tree is absent, incomplete, or not hash-bound."""

    def __init__(
        self,
        message: str,
        *,
        stage: str = "protector",
        partial_stages: Mapping[str, Mapping[str, Any]] | None = None,
        source_root: Path | None = None,
        manifest_entries: Mapping[str, str] | None = None,
        source_image_sha256: str | None = None,
        product_manifest_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage if stage in COMPATIBILITY_STAGES else "protector"
        self.partial_stages = dict(partial_stages or {})
        self.source_root = source_root
        self.manifest_entries = dict(manifest_entries or {})
        self.source_image_sha256 = source_image_sha256
        self.product_manifest_sha256 = product_manifest_sha256


def project_product_failure(error: ProductEvidenceError) -> tuple[dict[str, dict[str, Any]], str]:
    """Project a verified prefix plus the first failed strict-chain stage.

    The runner and post-run checker must use the same projection for malformed
    or partial product evidence.  Keeping it in the shared policy module avoids
    a checker gap where an invalid product tree could be relabeled as ordinary
    baseline-zero evidence.
    """
    reason = f"strict Protected Image product evidence is invalid: {error}"
    partial = {name: dict(record) for name, record in error.partial_stages.items()}
    failure_index = COMPATIBILITY_STAGES.index(error.stage)
    stages: dict[str, dict[str, Any]] = {}
    for index, stage in enumerate(COMPATIBILITY_STAGES):
        if stage in partial:
            stages[stage] = partial[stage]
        elif index == failure_index:
            stages[stage] = {"status": "failed", "reason": reason}
        elif index > failure_index:
            stages[stage] = {
                "status": "not-applicable",
                "reason": f"not evaluated after strict-chain failure at {error.stage}",
            }
        else:
            stages[stage] = {"status": "failed", "reason": reason}
    return stages, reason


def fail(message: str) -> None:
    raise EvaluatorError(message)



def _environment_budget_and_sdk() -> tuple[dict[str, Any], str]:
    repo_root = Path(__file__).resolve().parent.parent
    protocol = json.loads((repo_root / "fixtures/evaluator/evaluator-protocol.json").read_text(encoding="utf-8"))
    global_config = json.loads((repo_root / "global.json").read_text(encoding="utf-8"))
    return dict(protocol["budgets"]), str(global_config["sdk"]["version"])


def _limit_is_bounded(limits: Mapping[str, Any], key: str, maximum: int) -> bool:
    item = limits.get(key)
    if not isinstance(item, Mapping):
        return False
    return all(
        isinstance(item.get(bound), int)
        and not isinstance(item.get(bound), bool)
        and 0 < item[bound] <= maximum
        for bound in ("soft", "hard")
    )


def command_search_path(command: str) -> str:
    """Build the deterministic lookup path shared by capture and verification.

    Restricted staged processes may inherit a reduced PATH. Keep its absolute
    entries, then include the selected dotnet root for the SDK probe and the
    platform's default executable directories. Empty and relative entries are
    omitted so the staged checkout is never searched implicitly as the current
    directory.
    """
    configured_paths = [os.environ.get("PATH", "")]
    if command == "dotnet":
        dotnet_root = os.environ.get("DOTNET_ROOT", "")
        configured_paths.extend((dotnet_root, os.path.join(dotnet_root, "bin") if dotnet_root else ""))
    configured_paths.append(os.defpath)
    directories: list[str] = []
    for configured in configured_paths:
        for directory in configured.split(os.pathsep):
            # A relative PATH entry (including ".") resolves against the
            # evaluator's current working directory.  In the staged fallback
            # that directory is the copied checkout, so accepting it would
            # make command identity depend on checkout contents rather than a
            # stable host/tool path.  Only absolute directories participate.
            if not directory or not os.path.isabs(directory):
                continue
            normalized = os.path.normpath(directory)
            if normalized not in directories:
                directories.append(normalized)
    return os.pathsep.join(directories)


def _tool_handoff_key(command: str, suffix: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]", "_", command).upper()
    return f"EVALUATOR_TOOL_{token}_{suffix}"


def resolve_command(command: str) -> str | None:
    """Resolve a real executable using the host-captured handoff when present."""
    handed_off = os.environ.get(_tool_handoff_key(command, "PATH"), "")
    if handed_off.startswith("/") and os.path.isfile(handed_off) and os.access(handed_off, os.X_OK):
        return handed_off
    return shutil.which(command, path=command_search_path(command))


def _current_tool_matches(tools: Mapping[str, Any], name: str, expected_version: str | None = None) -> bool:
    tool = tools.get(name)
    executable = resolve_command(name)
    if not isinstance(tool, Mapping) or executable is None or tool.get("available") is not True:
        return False
    if expected_version is not None and tool.get("version") != expected_version:
        return False
    digest = tool.get("binarySha256")
    try:
        return isinstance(digest, str) and HEX64.fullmatch(digest) is not None and sha256_file(Path(executable)) == digest
    except (OSError, EvaluatorError):
        return False


def evaluator_product_unit_bindings(units: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Project strict-unit build/evidence hashes for the environment ledger."""
    records: list[dict[str, str]] = []
    for unit in units:
        if unit.get("complete") is not True or unit.get("strictChainMeasured") is not True:
            continue
        stages = unit.get("stages")
        product_evidence = unit.get("productEvidence")
        if not isinstance(stages, Mapping) or not isinstance(product_evidence, Mapping):
            continue
        if any(
            not isinstance(stages.get(stage), Mapping) or stages[stage].get("status") != "passed"
            for stage in COMPATIBILITY_STAGES
        ):
            continue
        protected = stages["protected-image"]
        rehydration = stages["rehydration"]
        native = stages["native-image"]
        loader = stages["target-loader"]
        oracle = stages["behavioral-oracle"]
        fields = {
            "unitId": unit.get("unitId"),
            "productManifestSha256": product_evidence.get("manifestSha256"),
            "producerBuildSha256": protected.get("producerBuildSha256"),
            "rehydratorConsumerBuildSha256": rehydration.get("consumerBuildSha256"),
            "nativeImageSha256": native.get("sha256"),
            "loaderId": loader.get("loaderId"),
            "behaviorComparisonSha256": oracle.get("comparisonSha256"),
        }
        if all(isinstance(value, str) and value for value in fields.values()):
            records.append({key: str(value) for key, value in fields.items()})
    return sorted(records, key=lambda record: record["unitId"])


def derive_evaluator_environment_capabilities(environment: Mapping[str, Any]) -> dict[str, bool]:
    """Recompute evaluator capabilities from observed host, runner, and sandbox facts.

    Caller-provided EVALUATOR_* declarations are intentionally absent from this
    projection. Every positive isolation capability is derived from captured
    namespace, mount, prctl, and resource-limit observations.
    """
    try:
        expected_budget, expected_sdk = _environment_budget_and_sdk()
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return {}
    runner = environment.get("runner")
    host = environment.get("host")
    isolation = environment.get("isolation")
    mounts = environment.get("mountFacts")
    namespaces = environment.get("namespaces")
    security = environment.get("security")
    limits = environment.get("resourceLimits")
    tools = environment.get("tools")
    product = environment.get("productCapabilities")
    budget = environment.get("budget")
    if not all(isinstance(item, Mapping) for item in (runner, host, isolation, mounts, namespaces, security, limits, tools, product, budget)):
        return {}
    runner = dict(runner)
    host = dict(host)
    isolation = dict(isolation)
    mounts = dict(mounts)
    namespaces = dict(namespaces)
    security = dict(security)
    limits = dict(limits)
    tools = dict(tools)
    product = dict(product)

    github_runner = (
        runner.get("githubActions") is True
        and runner.get("runnerOS") == "Linux"
        and runner.get("runnerArch") == "ARM64"
        and isinstance(runner.get("runnerName"), str)
        and bool(runner.get("runnerName"))
        and isinstance(runner.get("runId"), str)
        and runner.get("runId", "").isdigit()
    )
    native_aarch64 = host.get("architecture") in {"aarch64", "arm64"} and github_runner
    pinned_runtime = (
        github_runner
        and host.get("distributionId") == "ubuntu"
        and host.get("distributionVersion") == "24.04"
        and host.get("glibcVersion") == "2.39"
        and host.get("architecture") in {"aarch64", "arm64"}
    )
    expected_runtime_cell = "glibc.current.native-arm64" if pinned_runtime else None
    dotnet = tools.get("dotnet")
    dotnet_sdk = (
        _current_tool_matches(tools, "dotnet", expected_sdk)
        and isinstance(dotnet, Mapping)
        and dotnet.get("version") == expected_sdk
    )
    repository_root = Path(__file__).resolve().parent.parent
    producer_script = repository_root / "scripts/run-protected-image-e2e.sh"
    producer_source = repository_root / "src/UrProtect.Core/Protect/ProtectionPlan.cs"
    rehydrator_source = repository_root / "src/UrProtect.Core/Rehydrate/GenericRehydrationEngine.cs"
    try:
        source_hashes_match = (
            product.get("producerScriptSha256") == sha256_file(producer_script)
            and product.get("producerSourceSha256") == sha256_file(producer_source)
            and product.get("rehydratorSourceSha256") == sha256_file(rehydrator_source)
        )
    except (OSError, EvaluatorError):
        source_hashes_match = False
    strict_units = product.get("strictUnits")
    valid_strict_units = (
        isinstance(strict_units, list)
        and bool(strict_units)
        and all(
            isinstance(item, Mapping)
            and isinstance(item.get("unitId"), str)
            and bool(item.get("unitId"))
            and all(
                isinstance(item.get(field), str) and HEX64.fullmatch(item[field]) is not None
                for field in (
                    "productManifestSha256",
                    "producerBuildSha256",
                    "rehydratorConsumerBuildSha256",
                    "nativeImageSha256",
                    "behaviorComparisonSha256",
                )
            )
            and item.get("loaderId") == "kernel.execveat-at-empty-path"
            for item in strict_units
        )
    )
    protected_image_producer = source_hashes_match and valid_strict_units
    rehydrator = protected_image_producer and valid_strict_units
    current_net = namespaces.get("currentNetwork")
    parent_net = namespaces.get("initialNetwork")
    network_disabled = (
        security.get("networkSyscallsDenied") is True
        and security.get("networkProbeErrno") == 1
        and _current_tool_matches(tools, "bwrap")
    )
    read_only_inputs = (
        mounts.get("repositoryReadOnly") is True
        and mounts.get("fixturesReadOnly") is True
        and mounts.get("productEvidenceReadOnly") is True
        and mounts.get("evaluatorOutputWritable") is True
    )
    no_new_privileges = security.get("noNewPrivileges") == 1
    dropped_capabilities = (
        isinstance(security.get("effectiveCapabilities"), str)
        and re.fullmatch(r"[0-9a-fA-F]+", security["effectiveCapabilities"]) is not None
        and int(security["effectiveCapabilities"], 16) == 0
    )
    bounded_processes = _limit_is_bounded(limits, "processes", expected_budget.get("processLimit", 0))
    bounded_memory = _limit_is_bounded(limits, "addressSpaceBytes", expected_budget.get("rssBytes", 0))
    bounded_cpu = _limit_is_bounded(limits, "cpuSeconds", expected_budget.get("cpuSeconds", 0))
    bounded_file = _limit_is_bounded(limits, "fileSizeBytes", expected_budget.get("rawArtifactBytes", 0))
    wall_limit = isolation.get("wallLimit")
    bounded_wall = (
        isinstance(wall_limit, Mapping)
        and wall_limit.get("seconds") == expected_budget.get("wallSeconds")
        and isinstance(wall_limit.get("alarmRemainingSeconds"), (int, float))
        and wall_limit.get("alarmRemainingSeconds", 0) > 0
    )
    budget_matches = dict(budget) == expected_budget
    return {
        "nativeAarch64": native_aarch64,
        "pinnedRuntimeCell": pinned_runtime and environment.get("runtimeCell") == expected_runtime_cell,
        "dotnetSdk": dotnet_sdk,
        "protectedImageProducer": protected_image_producer,
        "rehydrator": rehydrator,
        "schemeAttackToolset": False,
        "networkDisabled": network_disabled,
        "readOnlyInputs": read_only_inputs,
        "noNewPrivileges": no_new_privileges,
        "droppedCapabilities": dropped_capabilities,
        "boundedProcesses": bounded_processes,
        "boundedMemory": bounded_memory,
        "boundedCpu": bounded_cpu,
        "boundedFileSize": bounded_file,
        "boundedWall": bounded_wall,
        "frozenBudget": budget_matches,
    }


def validate_evaluator_environment(
    environment: Mapping[str, Any],
    units: Iterable[Mapping[str, Any]] | None = None,
) -> bool:
    """Verify a schema-v2 environment projection and return availability."""
    if environment.get("schemaVersion") != 2 or environment.get("kind") != "evaluator-environment":
        raise EvaluatorError("evaluator environment schema is invalid")
    capabilities = derive_evaluator_environment_capabilities(environment)
    if not capabilities:
        raise EvaluatorError("evaluator environment capability facts are malformed")
    if environment.get("requiredCapabilities") != capabilities:
        raise EvaluatorError("evaluator environment capabilities do not match observed facts")
    if units is not None:
        product = environment.get("productCapabilities")
        if not isinstance(product, Mapping) or product.get("strictUnits") != evaluator_product_unit_bindings(units):
            raise EvaluatorError("evaluator environment is not bound to the verified strict-unit evidence")
    unavailable = [name for name, value in capabilities.items() if name != "schemeAttackToolset" and value is not True]
    expected_status = "available" if not unavailable else "environment-unavailable"
    if environment.get("status") != expected_status:
        raise EvaluatorError("evaluator environment status does not match recomputed capabilities")
    return expected_status == "available"


def calculate_claimable(
    environment: Mapping[str, Any],
    compatibility: Mapping[str, Any],
    scheme_gate: Mapping[str, Any],
    anti_gaming: Mapping[str, bool],
    units: Iterable[Mapping[str, Any]] | None = None,
) -> bool:
    """Derive the final claim only from a verified environment and checked gate inputs."""
    return (
        validate_evaluator_environment(environment, units)
        and compatibility.get("status") == "measured"
        and compatibility.get("fixedViewPass") is True
        and compatibility.get("growthViewPass") is True
        and scheme_gate.get("status") == "pass"
        and scheme_gate.get("allRequiredPass") is True
        and all(value is True for value in anti_gaming.values())
    )


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvaluatorError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise EvaluatorError(f"non-finite JSON number is not allowed: {value}")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash {path}: {error}")
    return digest.hexdigest()


def read_json(path: Path, *, max_bytes: int = 1_048_576) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            fail(f"JSON file exceeds bound ({max_bytes} bytes): {path}")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, EvaluatorError) as error:
        fail(f"could not read JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root must be an object: {path}")
    return value


def require_string(value: Any, field: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        fail(f"{field} must be a non-empty string")
    return value


def require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        fail(f"{field} must be a boolean")
    return value


def require_int(value: Any, field: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        fail(f"{field} must be >= {minimum}")
    return value


def require_digest(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{field} must be a lowercase SHA-256 digest")
    return value


def require_id(value: Any, field: str) -> str:
    result = require_string(value, field)
    if ID.fullmatch(result) is None or "/" in result or "\\" in result:
        fail(f"{field} is not a safe evaluator identifier: {result!r}")
    return result


def safe_relative_path(value: Any, field: str) -> str:
    result = require_string(value, field)
    path = Path(result)
    windows = PureWindowsPath(result)
    if len(result) > MAX_RELATIVE_PATH_LENGTH:
        fail(f"{field} exceeds the maximum path length")
    if any(ord(character) < 0x20 for character in result) or "\x00" in result:
        fail(f"{field} contains a control character")
    if path.is_absolute() or windows.is_absolute() or windows.drive:
        fail(f"{field} must be a repository-relative path")
    if "\\" in result or ":" in result or any(part in {"", ".", ".."} for part in path.parts) or any(part in {"", ".", ".."} for part in windows.parts):
        fail(f"{field} contains an unsafe path component")
    return result


def _product_failure(message: str, stage: str) -> None:
    raise ProductEvidenceError(message, stage=stage)


def _product_file(
    root: Path,
    name: str,
    stage: str,
    *,
    allow_empty: bool = False,
    max_bytes: int | None = None,
) -> Path:
    try:
        relative = safe_relative_path(name, f"product.{stage}.path")
    except EvaluatorError as error:
        _product_failure(str(error), stage)
    path = root / relative
    try:
        if path.is_symlink() or not path.is_file():
            _product_failure(f"missing or non-regular product evidence file: {name}", stage)
        size = path.stat().st_size
    except OSError as error:
        _product_failure(f"cannot inspect product evidence file {name}: {error}", stage)
    if not allow_empty and size == 0:
        _product_failure(f"product evidence file is empty: {name}", stage)
    if max_bytes is not None and size > max_bytes:
        _product_failure(f"product evidence file exceeds its bound: {name}", stage)
    return path


def _product_json(root: Path, name: str, stage: str) -> dict[str, Any]:
    path = _product_file(root, name, stage, max_bytes=PRODUCT_MAX_RECORD_BYTES)
    try:
        return read_json(path, max_bytes=PRODUCT_MAX_RECORD_BYTES)
    except EvaluatorError as error:
        _product_failure(str(error), stage)
    raise AssertionError("unreachable")


def _product_digest(value: Any, field: str, stage: str, *, nullable: bool = False) -> str | None:
    try:
        return require_digest(value, field, nullable=nullable)
    except EvaluatorError as error:
        _product_failure(str(error), stage)
    raise AssertionError("unreachable")


def _product_string(value: Any, field: str, stage: str) -> str:
    try:
        return require_string(value, field)
    except EvaluatorError as error:
        _product_failure(str(error), stage)
    raise AssertionError("unreachable")


def _product_id(value: Any, field: str, stage: str) -> str:
    try:
        return require_id(value, field)
    except EvaluatorError as error:
        _product_failure(str(error), stage)
    raise AssertionError("unreachable")


def _product_path_reference(value: Any, field: str, expected_name: str, stage: str) -> None:
    """Validate a product record path without trusting it for file access.

    Product jobs may emit an absolute workspace path.  That path is retained as
    provenance when an artifact is downloaded into a fresh evaluator workspace;
    all reads below use the fixed evidence filename instead.  Relative paths must
    identify the expected file and absolute paths may not contain traversal,
    control characters, or a different basename.
    """
    try:
        reference = require_string(value, field)
        if "\x00" in reference or any(ord(character) < 0x20 for character in reference) or "\\" in reference:
            raise EvaluatorError(f"{field} contains an unsafe path")
        path = Path(reference)
        windows = PureWindowsPath(reference)
        if path.is_absolute() or windows.drive or windows.is_absolute():
            if any(part in {"", ".", ".."} for part in path.parts) or path.name != expected_name:
                raise EvaluatorError(f"{field} does not identify {expected_name}")
        else:
            relative = safe_relative_path(reference, field)
            if relative != expected_name:
                raise EvaluatorError(f"{field} does not identify {expected_name}")
    except EvaluatorError as error:
        _product_failure(str(error), stage)


def _product_reject_symlink_components(path: Path) -> None:
    """Reject symlink traversal before resolving an evidence root."""
    candidate = path if path.is_absolute() else Path.cwd() / path
    current = Path(candidate.anchor)
    for component in candidate.parts[1:] if candidate.anchor else candidate.parts:
        current /= component
        try:
            if current.is_symlink():
                _product_failure(f"product evidence path traverses a symlink: {current}", "protector")
        except OSError as error:
            _product_failure(f"cannot inspect product evidence path {current}: {error}", "protector")


def _product_manifest(root: Path) -> tuple[dict[str, str], str]:
    """Validate a bounded, closed product SHA256SUMS tree."""
    try:
        if root.is_symlink() or not root.is_dir():
            _product_failure(f"product evidence root is not a real directory: {root}", "protector")
        files: list[Path] = []
        total = 0
        for path in root.rglob("*"):
            if path.is_symlink():
                _product_failure(f"product evidence contains a symlink: {path}", "protector")
            if path.is_file():
                files.append(path)
                size = path.stat().st_size
                total += size
                if len(files) > PRODUCT_MAX_FILES:
                    _product_failure("product evidence file count exceeds its bound", "protector")
                if total > PRODUCT_MAX_TREE_BYTES:
                    _product_failure("product evidence tree exceeds its byte bound", "protector")
                relative_path = path.relative_to(root).as_posix()
                if relative_path.endswith(".tmp") or ".tmp." in relative_path:
                    _product_failure(f"product evidence retains a temporary file: {relative_path}", "protector")
                if len(relative_path) > MAX_RELATIVE_PATH_LENGTH:
                    _product_failure("product evidence path exceeds its bound", "protector")
            elif not path.is_dir():
                _product_failure(f"product evidence contains a non-regular path: {path}", "protector")
    except OSError as error:
        _product_failure(f"cannot inspect product evidence root: {error}", "protector")

    manifest = root / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file():
        _product_failure("product evidence is missing SHA256SUMS", "protector")
    try:
        manifest_bytes = manifest.read_bytes()
    except OSError as error:
        _product_failure(f"cannot read product SHA256SUMS: {error}", "protector")
    if len(manifest_bytes) > 16 * 1024 * 1024:
        _product_failure("product SHA256SUMS exceeds its bound", "protector")
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        _product_failure(f"product SHA256SUMS is not UTF-8: {error}", "protector")
    declared: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or HEX64.fullmatch(parts[0]) is None:
            _product_failure(f"product SHA256SUMS:{line_number} is not a normalized SHA-256 line", "protector")
        digest, relative_value = parts
        try:
            relative = safe_relative_path(relative_value, f"product SHA256SUMS:{line_number}")
        except EvaluatorError as error:
            _product_failure(str(error), "protector")
        relative_name = relative
        if relative_name == "SHA256SUMS" or relative_name in declared:
            _product_failure(f"product SHA256SUMS contains a duplicate or self path: {relative_name}", "protector")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            _product_failure(f"product SHA256SUMS references a missing/non-regular path: {relative_name}", "protector")
        size = path.stat().st_size
        if size > PRODUCT_MAX_ARTIFACT_BYTES:
            _product_failure(f"product evidence file exceeds its bound: {relative_name}", "protector")
        if sha256_file(path) != digest:
            _product_failure(f"product SHA256SUMS hash mismatch: {relative_name}", "protector")
        declared[relative_name] = digest
    expected = {
        path.relative_to(root).as_posix()
        for path in files
        if path != manifest
    }
    if set(declared) != expected:
        _product_failure(
            f"product SHA256SUMS is not closed (missing={sorted(expected - set(declared))}, extra={sorted(set(declared) - expected)})",
            "protector",
        )
    return declared, sha256_bytes(manifest_bytes)


def _product_equal(actual: Any, expected: Any, field: str, stage: str) -> None:
    if actual != expected:
        _product_failure(f"product {field} binding mismatch", stage)


def _product_status(record: Mapping[str, Any], stage_name: str, stage: str) -> None:
    if record.get("schemaVersion") != 1 or record.get("stage") != stage_name:
        _product_failure(f"product {stage} record schema or identity is unsupported", stage)
    if record.get("status") != "passed":
        _product_failure(f"product {stage} record is not passed", stage)


def _product_canonical_protected_image(
    data: bytes,
    *,
    source_sha256: str,
    request_sha256: str,
    unit_id: str,
    profile: str,
    producer_id: str,
    producer_build_sha256: str,
    consumer_id: str,
    stage: str,
) -> dict[str, Any]:
    """Decode the bounded Protected Image v1 metadata and operation stream.

    A self-hash and a role record are not sufficient evidence: both can be
    rewritten together.  This projection mirrors the product codec's bounded
    header, identity, request, and operation invariants so producer/role fields
    remain tied to the retained bytes.
    """
    if len(data) < 52 or len(data) > 16 * 1024 * 1024 or data[:4] != b"UPPI":
        _product_failure("Protected Image is not bounded canonical Protected Image v1 data", stage)
    if sha256_bytes(data[:-32]) != data[-32:].hex():
        _product_failure("Protected Image canonical integrity digest does not match its bytes", stage)

    def read_u16(cursor: int) -> tuple[int, int]:
        if cursor < 0 or cursor + 2 > len(data):
            _product_failure("Protected Image metadata is truncated", stage)
        return struct.unpack_from("<H", data, cursor)[0], cursor + 2

    def read_u32(cursor: int) -> tuple[int, int]:
        if cursor < 0 or cursor + 4 > len(data):
            _product_failure("Protected Image metadata is truncated", stage)
        return struct.unpack_from("<I", data, cursor)[0], cursor + 4

    def read_u64(cursor: int) -> tuple[int, int]:
        if cursor < 0 or cursor + 8 > len(data):
            _product_failure("Protected Image metadata is truncated", stage)
        return struct.unpack_from("<Q", data, cursor)[0], cursor + 8

    def read_bytes(cursor: int, count: int) -> tuple[bytes, int]:
        if count < 0 or cursor < 0 or cursor + count > len(data):
            _product_failure("Protected Image metadata is truncated", stage)
        return data[cursor : cursor + count], cursor + count

    def read_string(cursor: int, maximum: int, label: str) -> tuple[str, int]:
        count, cursor = read_u16(cursor)
        if count == 0 or count > maximum:
            _product_failure(f"Protected Image {label} string length is outside its bound", stage)
        encoded, cursor = read_bytes(cursor, count)
        try:
            value = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            _product_failure(f"Protected Image {label} is not valid UTF-8: {error}", stage)
        return value, cursor

    version, _ = read_u16(4)
    architecture, _ = read_u16(6)
    profile_value = data[8]
    reserved = data[9:12]
    declared_length, _ = read_u32(12)
    operation_count, _ = read_u32(16)
    if version != 1 or architecture != 183:
        _product_failure("Protected Image ABI version or architecture is unsupported", stage)
    if profile_value not in {1, 2}:
        _product_failure("Protected Image profile is unsupported", stage)
    if reserved != bytes(3) or declared_length != len(data) or operation_count > 1024:
        _product_failure("Protected Image header bounds or reserved bytes are invalid", stage)
    expected_profile_value = {"outer-execveat": 1, "host-context-entry": 2}.get(profile)
    if expected_profile_value != profile_value:
        _product_failure("Protected Image profile does not match the frozen unit", stage)

    embedded_source = data[20:52].hex()
    embedded_producer_build = data[52:84].hex()
    embedded_request = data[84:116].hex()
    if len(data) < 116:
        _product_failure("Protected Image identity metadata is truncated", stage)
    cursor = 116
    embedded_unit, cursor = read_string(cursor, 128, "unit")
    embedded_producer, cursor = read_string(cursor, 128, "producer")
    embedded_consumer, cursor = read_string(cursor, 128, "rehydrator consumer")
    selector_count, cursor = read_u16(cursor)
    if selector_count == 0 or selector_count > 64:
        _product_failure("Protected Image selector count is outside its bound", stage)
    selectors: list[str] = []
    for _ in range(selector_count):
        selector, cursor = read_string(cursor, 256, "selector")
        selectors.append(selector)
    if cursor >= len(data) - 32:
        _product_failure("Protected Image pass metadata is truncated", stage)
    pass_count = data[cursor]
    cursor += 1
    if pass_count == 0 or pass_count > 2:
        _product_failure("Protected Image pass count is outside its bound", stage)
    pass_values, cursor = read_bytes(cursor, pass_count)
    if any(value not in {0, 1} for value in pass_values) or list(pass_values) != sorted(set(pass_values)):
        _product_failure("Protected Image passes are unsupported or not canonical", stage)
    pass_names = ["control-flow-flattening" if value == 0 else "register-permutation" for value in pass_values]

    if embedded_source != source_sha256:
        _product_failure("Protected Image embedded Source Image hash does not match the retained source", stage)
    if embedded_producer_build != producer_build_sha256:
        _product_failure("Protected Image embedded producer build hash does not match the producer record", stage)
    if embedded_request != request_sha256:
        _product_failure("Protected Image embedded request hash does not match the producer record", stage)
    if (embedded_unit, embedded_producer, embedded_consumer) != (unit_id, producer_id, consumer_id):
        _product_failure("Protected Image embedded role identity does not match the producer record", stage)
    if sha256_bytes(
        b"URP-PROTECTION-REQUEST-V1" + bytes([0])
        + struct.pack("<H", len(selectors))
        + b"".join(struct.pack("<H", len(selector.encode("utf-8"))) + selector.encode("utf-8") for selector in selectors)
        + bytes([len(pass_values)])
        + pass_values
    ) != embedded_request:
        _product_failure("Protected Image request metadata is not canonically bound", stage)

    operation_end = len(data) - 32
    if operation_count < 2 or operation_count % 2 != 0:
        _product_failure("Protected Image operation count is outside its bound", stage)
    operations: list[tuple[int, int, dict[str, Any]]] = []
    regions: dict[int, dict[str, Any]] = {}
    source_ranges: list[tuple[int, int]] = []
    fixups: list[dict[str, Any]] = []
    for _ in range(operation_count):
        if cursor + 8 > operation_end:
            _product_failure("Protected Image operation header is truncated", stage)
        code = data[cursor]
        if data[cursor + 1 : cursor + 4] != bytes(3):
            _product_failure("Protected Image operation reserved bytes are nonzero", stage)
        record_size = struct.unpack_from("<I", data, cursor + 4)[0]
        if record_size < 8 or cursor + record_size > operation_end:
            _product_failure("Protected Image operation record length is invalid", stage)
        body = cursor + 8
        record_end = cursor + record_size
        if code == 1:
            if record_size < 32 or body + 24 > record_end:
                _product_failure("Protected Image emitted-region operation is truncated", stage)
            region_id = struct.unpack_from("<I", data, body)[0]
            source_address = struct.unpack_from("<Q", data, body + 4)[0]
            source_size = struct.unpack_from("<Q", data, body + 12)[0]
            code_length = struct.unpack_from("<I", data, body + 20)[0]
            if (
                region_id == 0
                or region_id in regions
                or source_address & 3
                or source_size < 4
                or source_size & 3
                or code_length < 4
                or code_length > 4 * 1024 * 1024
                or code_length & 3
                or body + 24 + code_length != record_end
                or source_address + source_size > (1 << 64) - 1
            ):
                _product_failure("Protected Image emitted-region bounds or identity are invalid", stage)
            source_end = source_address + source_size
            if any(source_address < end and start < source_end for start, end in source_ranges):
                _product_failure("Protected Image source regions overlap", stage)
            source_ranges.append((source_address, source_end))
            region = {"regionId": region_id, "sourceAddress": source_address, "sourceSize": source_size, "codeLength": code_length}
            regions[region_id] = region
            operations.append((region_id, code, region))
        elif code == 2:
            if record_size != 36 or body + 28 != record_end:
                _product_failure("Protected Image entry-fixup operation is truncated", stage)
            source_region_id = struct.unpack_from("<I", data, body)[0]
            target_region_id = struct.unpack_from("<I", data, body + 4)[0]
            source_address = struct.unpack_from("<Q", data, body + 8)[0]
            source_offset = struct.unpack_from("<I", data, body + 16)[0]
            target_offset = struct.unpack_from("<I", data, body + 20)[0]
            fixup_kind = data[body + 24]
            if fixup_kind != 1 or data[body + 25 : body + 28] != bytes(3):
                _product_failure("Protected Image entry-fixup kind or reserved bytes are invalid", stage)
            fixup = {
                "sourceRegionId": source_region_id,
                "targetRegionId": target_region_id,
                "sourceAddress": source_address,
                "sourceOffset": source_offset,
                "targetOffset": target_offset,
            }
            fixups.append(fixup)
            operations.append((source_region_id, code, fixup))
        else:
            _product_failure("Protected Image operation code is unsupported", stage)
        cursor = record_end
    if cursor != operation_end or len(regions) == 0 or len(regions) != len(fixups):
        _product_failure("Protected Image operation stream is incomplete", stage)
    fixed_sources: set[int] = set()
    fixup_sites: set[tuple[int, int]] = set()
    for fixup in fixups:
        source_region = regions.get(fixup["sourceRegionId"])
        target_region = regions.get(fixup["targetRegionId"])
        if source_region is None or target_region is None:
            _product_failure("Protected Image entry-fixup references an unknown region", stage)
        source_offset = fixup["sourceOffset"]
        if (
            fixup["sourceRegionId"] in fixed_sources
            or (fixup["sourceRegionId"], source_offset) in fixup_sites
            or fixup["sourceAddress"] != source_region["sourceAddress"]
            or source_offset > source_region["sourceSize"]
            or source_region["sourceSize"] - source_offset < 4
            or source_offset & 3
            or fixup["targetOffset"] >= target_region["codeLength"]
            or fixup["targetOffset"] & 3
        ):
            _product_failure("Protected Image entry-fixup binding is invalid", stage)
        fixed_sources.add(fixup["sourceRegionId"])
        fixup_sites.add((fixup["sourceRegionId"], source_offset))
    if fixed_sources != set(regions):
        _product_failure("Protected Image contains an unbound code region", stage)
    if [(region_id, code) for region_id, code, _ in operations] != sorted((region_id, code) for region_id, code, _ in operations):
        _product_failure("Protected Image operations are not in canonical order", stage)
    if sha256_bytes(data) == source_sha256:
        _product_failure("Protected Image aliases the Source Image", stage)
    return {"selectors": selectors, "passes": pass_names, "profileValue": profile_value}


def _product_native_image(data: bytes, source_sha256: str, protected_sha256: str, stage: str) -> None:
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        _product_failure("Native Image is not bounded ELF64 little-endian data", stage)
    if int.from_bytes(data[16:18], "little") not in {2, 3} or int.from_bytes(data[18:20], "little") != 183:
        _product_failure("Native Image is not an AArch64 ET_EXEC/ET_DYN image", stage)
    native_sha256 = sha256_bytes(data)
    if native_sha256 in {source_sha256, protected_sha256}:
        _product_failure("Native Image aliases an earlier chain artifact", stage)


def _product_stream(root: Path, name: str, stage: str) -> tuple[Path, str]:
    path = _product_file(root, name, stage, allow_empty=True, max_bytes=PRODUCT_MAX_STREAM_BYTES)
    return path, sha256_file(path)


def load_product_evidence(
    evidence_root: Path,
    row: Mapping[str, Any],
    *,
    tier: str = "pr",
    runtime: str = "glibc",
    require_unit_root_name: bool = True,
) -> dict[str, Any]:
    """Read and recompute one retained product Protected Image chain.

    The function performs no writes and never executes a product target.  It
    returns only digest-bound projections; all source files remain owned by the
    product evidence job.  A ``ProductEvidenceError`` carries any earlier,
    independently verified stage projections so the evaluator can retain an
    explicit first-failure record without treating later stages as passed.
    """
    root = Path(evidence_root)
    try:
        if any(part in {"", ".", ".."} for part in root.parts) or "\\" in str(root) or any(ord(character) < 0x20 for character in str(root)):
            raise ProductEvidenceError(f"product evidence root has an unsafe path: {root}")
        _product_reject_symlink_components(root)
        if root.is_symlink() or not root.is_dir():
            raise ProductEvidenceError(f"product evidence root is absent or not a real directory: {root}")
    except OSError as error:
        raise ProductEvidenceError(f"cannot inspect product evidence root {root}: {error}") from error
    root = root.resolve()
    unit_id = _product_id(row.get("unitId"), "row.unitId", "protector")
    profile = _product_string(row.get("profile"), "row.profile", "protector")
    oracle_id = _product_id(row.get("oracleId"), "row.oracleId", "protector")
    if require_unit_root_name and root.name != unit_id:
        raise ProductEvidenceError(f"product evidence root does not end in unit {unit_id}")
    if runtime not in {"glibc", "musl", "bionic"}:
        raise ProductEvidenceError(f"unsupported product evidence runtime: {runtime}")
    if tier not in {"pr", "nightly", "release"}:
        raise ProductEvidenceError(f"unsupported product evidence tier: {tier}")

    entries, product_manifest_sha256 = _product_manifest(root)
    partial: dict[str, Mapping[str, Any]] = {}
    source_root = root
    source_image_sha256: str | None = None

    def fail_with_context(error: ProductEvidenceError) -> None:
        raise ProductEvidenceError(
            str(error),
            stage=error.stage,
            partial_stages=partial,
            source_root=source_root,
            manifest_entries=entries,
            source_image_sha256=source_image_sha256,
            product_manifest_sha256=product_manifest_sha256,
        )

    try:
        environment = _product_json(root, "environment.json", "protector")
        if environment.get("schemaVersion") != 1 or environment.get("kind") != "rehydration-environment":
            _product_failure("product environment record schema is unsupported", "protector")
        if environment.get("tier") != tier:
            _product_failure("product environment tier does not match the evaluator tier", "protector")
        _product_equal(environment.get("runtime"), runtime, "environment.runtime", "protector")
        _product_equal(environment.get("unitId"), unit_id, "environment.unitId", "protector")
        if environment.get("architecture") not in {"aarch64", "arm64", "AArch64"}:
            _product_failure("product environment is not AArch64", "protector")
        if environment.get("strictLoader") != row.get("targetLoader"):
            _product_failure("product environment loader does not match the corpus target loader", "protector")

        source_path = _product_file(root, "source-image.bin", "protector", max_bytes=PRODUCT_MAX_SOURCE_IMAGE_BYTES)
        source_image_sha256 = sha256_file(source_path)
        producer_stage = _product_json(root, "stage.json", "protector")
        producer_role = _product_json(root, "protected-image.json", "protector")
        _product_status(producer_stage, "protected-image-producer", "protector")
        if producer_role.get("schemaVersion") != 1 or producer_role.get("artifactRole") != "protected-image":
            _product_failure("producer role is not a Protected Image role", "protector")
        if producer_role.get("architecture") != "AArch64":
            _product_failure("producer Protected Image architecture is unsupported", "protector")
        for field in ("commandDigest", "environmentDigest"):
            _product_digest(producer_stage.get(field), f"producer stage.{field}", "protector")
        for record, label in ((producer_stage, "producer stage"), (producer_role, "producer role")):
            _product_equal(record.get("unitId"), unit_id, f"{label}.unitId", "protector")
            _product_equal(record.get("profile"), profile, f"{label}.profile", "protector")
            _product_equal(record.get("sourceSha256"), source_image_sha256, f"{label}.sourceSha256", "protector")
            _product_digest(record.get("requestSha256"), f"{label}.requestSha256", "protector")
            _product_digest(record.get("producerBuildSha256"), f"{label}.producerBuildSha256", "protector")
        _product_equal(producer_stage.get("producerId"), producer_role.get("producerId"), "producerId", "protector")
        _product_equal(producer_stage.get("rehydratorConsumerId"), producer_role.get("rehydratorConsumerId"), "rehydratorConsumerId", "protector")
        _product_equal(producer_stage.get("requestSha256"), producer_role.get("requestSha256"), "requestSha256", "protector")
        _product_path_reference(producer_stage.get("artifactPath"), "stage.artifactPath", "protected-image.bin", "protector")
        _product_path_reference(producer_stage.get("rolePath"), "stage.rolePath", "protected-image.json", "protector")
        _product_path_reference(producer_stage.get("rawEvidenceManifestPath"), "stage.rawEvidenceManifestPath", "SHA256SUMS", "protector")
        _product_path_reference(producer_role.get("rawArtifactPath"), "role.rawArtifactPath", "protected-image.bin", "protector")
        if producer_role.get("rawArtifactRetained") is not True or producer_stage.get("publicationComplete") is not True:
            _product_failure("producer publication is not complete and retained", "protector")
        if producer_role.get("abiId") != "urprotect.protected-image.v1" or producer_role.get("abiVersion") != 1:
            _product_failure("producer Protected Image ABI identity is unsupported", "protector")
        if producer_stage.get("artifactRole") != "protected-image" or producer_stage.get("abiId") != "urprotect.protected-image.v1" or producer_stage.get("abiVersion") != 1:
            _product_failure("producer stage does not bind Protected Image v1", "protector")
        artifact_path = _product_file(root, "protected-image.bin", "protector", max_bytes=PRODUCT_MAX_ARTIFACT_BYTES)
        artifact_sha256 = sha256_file(artifact_path)
        artifact_size = artifact_path.stat().st_size
        for record, label in ((producer_stage, "producer stage"), (producer_role, "producer role")):
            _product_equal(record.get("artifactSha256"), artifact_sha256, f"{label}.artifactSha256", "protector")
            _product_equal(record.get("artifactSize"), artifact_size, f"{label}.artifactSize", "protector")
        image_metadata = _product_canonical_protected_image(
            artifact_path.read_bytes(),
            source_sha256=source_image_sha256,
            request_sha256=producer_stage["requestSha256"],
            unit_id=unit_id,
            profile=profile,
            producer_id=producer_stage["producerId"],
            producer_build_sha256=producer_stage["producerBuildSha256"],
            consumer_id=producer_stage["rehydratorConsumerId"],
            stage="protector",
        )
        if producer_stage.get("transformationStatus") != "passed":
            _product_failure("producer transformation status is not passed", "protector")
        for record, label in ((producer_stage, "producer stage"), (producer_role, "producer role")):
            selectors = record.get("selectors")
            passes = record.get("passes")
            if not isinstance(selectors, list) or any(not isinstance(item, str) for item in selectors):
                _product_failure(f"{label} selectors are malformed", "protector")
            if not isinstance(passes, list) or any(not isinstance(item, str) for item in passes):
                _product_failure(f"{label} passes are malformed", "protector")
            _product_equal(selectors, image_metadata["selectors"], f"{label}.selectors", "protector")
            _product_equal(passes, image_metadata["passes"], f"{label}.passes", "protector")
        partial["protector"] = {
            "status": "passed",
            "unitId": unit_id,
            "profile": profile,
            "sourceImageSha256": source_image_sha256,
            "outputSha256": artifact_sha256,
            "producerId": producer_role.get("producerId"),
            "producerBuildSha256": producer_role.get("producerBuildSha256"),
            "requestSha256": producer_role.get("requestSha256"),
        }

        partial["protected-image"] = {
            "status": "passed",
            "unitId": unit_id,
            "profile": profile,
            "sourceImageSha256": source_image_sha256,
            "artifactSha256": artifact_sha256,
            "abiId": producer_role.get("abiId"),
            "abiVersion": str(producer_role.get("abiVersion")),
            "producerId": producer_role.get("producerId"),
            "producerBuildSha256": producer_role.get("producerBuildSha256"),
            "requestSha256": producer_role.get("requestSha256"),
        }

        rehydration = _product_json(root, "rehydration.json", "rehydration")
        _product_status(rehydration, "rehydration", "rehydration")
        _product_digest(rehydration.get("consumerBuildSha256"), "rehydration.consumerBuildSha256", "rehydration")
        for field, expected in (
            ("unitId", unit_id),
            ("profile", profile),
            ("sourceSha256", source_image_sha256),
            ("requestSha256", producer_role.get("requestSha256")),
            ("protectedImageSha256", artifact_sha256),
            ("protectedImageSize", artifact_size),
            ("producerId", producer_role.get("producerId")),
            ("producerBuildSha256", producer_role.get("producerBuildSha256")),
            ("consumerId", producer_role.get("rehydratorConsumerId")),
        ):
            _product_equal(rehydration.get(field), expected, f"rehydration.{field}", "rehydration")
        if rehydration.get("abiId") != "urprotect.protected-image.v1" or rehydration.get("abiVersion") != 1 or rehydration.get("architecture") != "AArch64":
            _product_failure("rehydration ABI or architecture binding is unsupported", "rehydration")
        if rehydration.get("layoutStrategy") != "append-executable-pt-load-v1" or rehydration.get("materializationStatus") != "passed":
            _product_failure("rehydration materialization strategy/status is unsupported", "rehydration")
        native_image_sha256 = _product_digest(rehydration.get("nativeImageSha256"), "rehydration.nativeImageSha256", "rehydration")
        if rehydration.get("nativeImageSize") is None or not isinstance(rehydration.get("nativeImageSize"), int) or rehydration["nativeImageSize"] <= 0:
            _product_failure("rehydration Native Image size is invalid", "rehydration")
        _product_path_reference(rehydration.get("handoffRecordPath"), "rehydration.handoffRecordPath", "handoff.json", "rehydration")
        _product_path_reference(rehydration.get("rawEvidenceManifestPath"), "rehydration.rawEvidenceManifestPath", "SHA256SUMS", "rehydration")
        partial["rehydration"] = {
            "status": "passed",
            "unitId": unit_id,
            "profile": profile,
            "sourceImageSha256": source_image_sha256,
            "protectedImageSha256": artifact_sha256,
            "nativeImageSha256": native_image_sha256,
            "consumerId": rehydration.get("consumerId"),
            "producerId": rehydration.get("producerId"),
            "producerBuildSha256": rehydration.get("producerBuildSha256"),
            "consumerBuildSha256": rehydration.get("consumerBuildSha256"),
            "requestSha256": rehydration.get("requestSha256"),
        }
        _product_digest(rehydration.get("handoffRecordSha256"), "rehydration.handoffRecordSha256", "rehydration")
        _product_digest(rehydration.get("preHandoffRecordSha256"), "rehydration.preHandoffRecordSha256", "rehydration")
        native_path = _product_file(root, "native-image.bin", "native-image", max_bytes=PRODUCT_MAX_NATIVE_IMAGE_BYTES)
        native_bytes = native_path.read_bytes()
        _product_equal(sha256_bytes(native_bytes), native_image_sha256, "rehydration.nativeImageSha256", "native-image")
        _product_equal(len(native_bytes), rehydration.get("nativeImageSize"), "rehydration.nativeImageSize", "native-image")

        native_role = _product_json(root, "native-image.json", "native-image")
        if native_role.get("schemaVersion") != 1 or native_role.get("artifactRole") != "native-image":
            _product_failure("Native Image role identity is unsupported", "native-image")
        if native_role.get("abiId") != "urprotect.native-image.v1" or native_role.get("abiVersion") != 1 or native_role.get("architecture") != "AArch64":
            _product_failure("Native Image role ABI or architecture is unsupported", "native-image")
        for field, expected in (
            ("unitId", unit_id),
            ("profile", profile),
            ("sourceSha256", source_image_sha256),
            ("protectedImageSha256", artifact_sha256),
            ("producerId", producer_role.get("producerId")),
            ("producerBuildSha256", producer_role.get("producerBuildSha256")),
            ("consumerId", rehydration.get("consumerId")),
            ("consumerBuildSha256", rehydration.get("consumerBuildSha256")),
            ("nativeImageSha256", native_image_sha256),
            ("nativeImageSize", len(native_bytes)),
            ("rehydrationRecordSha256", sha256_file(root / "rehydration.json")),
        ):
            _product_equal(native_role.get(field), expected, f"native-image.{field}", "native-image")
        _product_native_image(native_bytes, source_image_sha256, artifact_sha256, "native-image")
        partial["native-image"] = {
            "status": "passed",
            "unitId": unit_id,
            "profile": profile,
            "sourceImageSha256": source_image_sha256,
            "sha256": native_image_sha256,
            "nativeImageSha256": native_image_sha256,
            "nativeImageSize": len(native_bytes),
            "consumerId": native_role.get("consumerId"),
            "consumerBuildSha256": native_role.get("consumerBuildSha256"),
        }

        handoff_path = _product_file(root, "handoff.json", "target-loader", max_bytes=PRODUCT_MAX_RECORD_BYTES)
        handoff = _product_json(root, "handoff.json", "target-loader")
        handoff_sha256 = sha256_file(handoff_path)
        _product_equal(rehydration.get("handoffRecordSha256"), handoff_sha256, "rehydration.handoffRecordSha256", "target-loader")
        _product_equal(rehydration.get("handoffStatus"), handoff.get("status"), "rehydration.handoffStatus", "target-loader")
        _product_status(handoff, "native-handoff", "target-loader")
        if handoff.get("loaderId") != row.get("targetLoader"):
            _product_failure("native handoff loader identity differs from the corpus target", "target-loader")
        _product_equal(handoff.get("nativeImageSha256"), native_image_sha256, "handoff.nativeImageSha256", "target-loader")
        _product_equal(handoff.get("rehydrationRecordSha256"), rehydration.get("preHandoffRecordSha256"), "handoff.rehydrationRecordSha256", "target-loader")
        for field in ("helperStatus", "fchmodStatus", "fsyncStatus", "execveatStatus"):
            if handoff.get(field) != "passed":
                _product_failure(f"native handoff {field} did not pass", "target-loader")
        for field in ("memfdCreated", "sealsSupported", "sealsApplied", "execveatInvoked"):
            if handoff.get(field) is not True:
                _product_failure(f"native handoff {field} was not proven", "target-loader")
        target_status = handoff.get("targetStatus")
        if (
            handoff.get("helperExitCode") != 0
            or isinstance(target_status, bool)
            or not isinstance(target_status, int)
            or not 0 <= target_status <= 255
            or handoff.get("targetSignal") is not None
        ):
            _product_failure("native handoff target result is malformed", "target-loader")
        stdout_path, stdout_sha256 = _product_stream(root, "target.stdout", "target-loader")
        stderr_path, stderr_sha256 = _product_stream(root, "target.stderr", "target-loader")
        if (
            handoff.get("stdoutBytes") != stdout_path.stat().st_size
            or handoff.get("stderrBytes") != stderr_path.stat().st_size
            or handoff.get("stdoutTruncated") is not False
            or handoff.get("stderrTruncated") is not False
        ):
            _product_failure("native handoff retained stream metadata is malformed", "target-loader")
        target_loader = _product_json(root, "target-loader.json", "target-loader")
        _product_status(target_loader, "target-loader", "target-loader")
        if target_loader.get("loaderId") != row.get("targetLoader"):
            _product_failure("target-loader identity differs from the corpus target", "target-loader")
        _product_equal(target_loader.get("nativeImageSha256"), native_image_sha256, "target-loader.nativeImageSha256", "target-loader")
        _product_equal(target_loader.get("evidenceSha256"), handoff_sha256, "target-loader.evidenceSha256", "target-loader")
        target_loader_status = target_loader.get("targetStatus")
        if isinstance(target_loader_status, bool) or not isinstance(target_loader_status, int) or not 0 <= target_loader_status <= 255:
            _product_failure("target-loader target status is malformed", "target-loader")
        _product_equal(target_loader_status, handoff.get("targetStatus"), "target-loader.targetStatus", "target-loader")
        _product_equal(target_loader.get("targetSignal"), handoff.get("targetSignal"), "target-loader.targetSignal", "target-loader")
        _product_equal(target_loader.get("stdoutSha256"), stdout_sha256, "target-loader.stdoutSha256", "target-loader")
        _product_equal(target_loader.get("stderrSha256"), stderr_sha256, "target-loader.stderrSha256", "target-loader")
        _product_equal(target_loader.get("stdoutBytes"), stdout_path.stat().st_size, "target-loader.stdoutBytes", "target-loader")
        _product_equal(target_loader.get("stderrBytes"), stderr_path.stat().st_size, "target-loader.stderrBytes", "target-loader")
        if target_loader.get("firstFailureStage") is not None:
            _product_failure("passed target-loader record contains a failure stage", "target-loader")
        partial["target-loader"] = {
            "status": "passed",
            "unitId": unit_id,
            "profile": profile,
            "sourceImageSha256": source_image_sha256,
            "nativeImageSha256": native_image_sha256,
            "evidenceSha256": handoff_sha256,
            "loaderId": target_loader.get("loaderId"),
            "targetStatus": target_loader.get("targetStatus"),
            "targetSignal": target_loader.get("targetSignal"),
        }

        oracle = _product_json(root, "behavioral-oracle.json", "behavioral-oracle")
        _product_status(oracle, "behavioral-oracle", "behavioral-oracle")
        if oracle.get("oracleId") != oracle_id:
            _product_failure("behavioral oracle identity differs from the corpus oracle", "behavioral-oracle")
        _product_equal(oracle.get("sourceSha256"), source_image_sha256, "behavioral-oracle.sourceSha256", "behavioral-oracle")
        _product_equal(oracle.get("nativeImageSha256"), native_image_sha256, "behavioral-oracle.nativeImageSha256", "behavioral-oracle")
        _product_equal(oracle.get("baselineStatus"), 0, "behavioral-oracle.baselineStatus", "behavioral-oracle")
        _product_equal(oracle.get("targetStatus"), 0, "behavioral-oracle.targetStatus", "behavioral-oracle")
        for field in ("stdoutEqual", "stderrEqual"):
            if oracle.get(field) is not True:
                _product_failure(f"behavioral oracle {field} did not pass", "behavioral-oracle")
        comparison_path = _product_file(root, "behavior-comparison.json", "behavioral-oracle", max_bytes=PRODUCT_MAX_RECORD_BYTES)
        comparison_sha256 = sha256_file(comparison_path)
        _product_equal(oracle.get("comparisonSha256"), comparison_sha256, "behavioral-oracle.comparisonSha256", "behavioral-oracle")
        comparison = _product_json(root, "behavior-comparison.json", "behavioral-oracle")
        for field, expected in (("unitId", unit_id), ("oracleId", oracle_id), ("sourceSha256", source_image_sha256), ("nativeImageSha256", native_image_sha256)):
            _product_equal(comparison.get(field), expected, f"behavior-comparison.{field}", "behavioral-oracle")
        for field in ("statusEqual", "stdoutEqual", "stderrEqual"):
            if comparison.get(field) is not True:
                _product_failure(f"behavior comparison {field} did not pass", "behavioral-oracle")
        for baseline_name, target_name, baseline_field, target_field in (
            ("baseline.stdout", "target.stdout", "baselineStdoutSha256", "targetStdoutSha256"),
            ("baseline.stderr", "target.stderr", "baselineStderrSha256", "targetStderrSha256"),
        ):
            baseline_path, baseline_sha256 = _product_stream(root, baseline_name, "behavioral-oracle")
            target_path, target_sha256 = _product_stream(root, target_name, "behavioral-oracle")
            if baseline_path.read_bytes() != target_path.read_bytes():
                _product_failure("behavioral oracle retained streams differ", "behavioral-oracle")
            _product_equal(comparison.get(baseline_field), baseline_sha256, f"behavior-comparison.{baseline_field}", "behavioral-oracle")
            _product_equal(comparison.get(target_field), target_sha256, f"behavior-comparison.{target_field}", "behavioral-oracle")
        partial["behavioral-oracle"] = {
            "status": "passed",
            "unitId": unit_id,
            "profile": profile,
            "sourceImageSha256": source_image_sha256,
            "comparisonSha256": comparison_sha256,
            "oracleId": oracle_id,
            "nativeImageSha256": native_image_sha256,
            "statusEqual": True,
            "stdoutEqual": True,
            "stderrEqual": True,
        }
    except ProductEvidenceError as error:
        fail_with_context(error)
    except (EvaluatorError, OSError, ValueError) as error:
        fail_with_context(ProductEvidenceError(str(error), stage="protector"))

    return {
        "root": root,
        "manifestEntries": entries,
        "productManifestSha256": product_manifest_sha256,
        "sourceImageSha256": source_image_sha256,
        "sourceSha256": row.get("sourceSha256"),
        "unitId": unit_id,
        "profile": profile,
        "runtime": runtime,
        "oracleId": oracle_id,
        "stages": partial,
    }


def copy_verified_product_evidence(source_root: Path, manifest_entries: Mapping[str, str], destination: Path) -> None:
    """Copy only files already covered by a verified product manifest."""
    source_root = Path(source_root)
    destination.mkdir(parents=True, exist_ok=True)
    for relative_name, expected_digest in sorted(manifest_entries.items()):
        relative = safe_relative_path(relative_name, "product evidence manifest path")
        source = source_root / relative
        if source.is_symlink() or not source.is_file():
            fail(f"product evidence changed after verification: {relative_name}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            fail(f"evaluator product evidence destination already exists: {relative_name}")
        with source.open("rb") as input_stream, target.open("xb") as output_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                output_stream.write(chunk)
        if sha256_file(target) != expected_digest:
            fail(f"product evidence changed while copying: {relative_name}")
    source_manifest = source_root / "SHA256SUMS"
    if source_manifest.is_symlink() or not source_manifest.is_file():
        fail("product evidence manifest disappeared while copying")
    target_manifest = destination / "SHA256SUMS"
    if target_manifest.exists() or target_manifest.is_symlink():
        fail("evaluator product evidence destination already contains SHA256SUMS")
    with source_manifest.open("rb") as input_stream, target_manifest.open("xb") as output_stream:
        for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
            output_stream.write(chunk)
    if sha256_file(target_manifest) != sha256_file(source_manifest):
        fail("product evidence manifest changed while copying")


def _reject_symlink_path(path: Path, root: Path, field: str) -> None:
    current = root
    for component in Path(path).relative_to(root).parts:
        current = current / component
        if current.is_symlink():
            fail(f"{field} may not traverse a symlink: {path}")


def resolve_repo_path(repo_root: Path, value: Any, field: str, *, require_file: bool = False) -> Path:
    relative = safe_relative_path(value, field)
    root = repo_root.resolve()
    unresolved = root / relative
    _reject_symlink_path(unresolved, root, field)
    path = unresolved.resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as error:
        fail(f"{field} escapes repository: {relative}")
    if require_file and not path.is_file():
        fail(f"{field} does not identify a file: {relative}")
    return path


def _require_root(value: Mapping[str, Any], kind: str) -> None:
    if value.get("schemaVersion") != SCHEMA_VERSION:
        fail(f"{kind} schemaVersion must be {SCHEMA_VERSION}")
    if value.get("kind") != kind:
        fail(f"manifest kind must be {kind}")


def validate_protocol(protocol: Mapping[str, Any]) -> None:
    _require_root(protocol, "urprotect-independent-evaluator-protocol")
    require_string(protocol.get("protocolVersion"), "protocolVersion")
    if protocol.get("readOnly") is not True:
        fail("evaluator protocol must be readOnly")
    digests = protocol.get("manifestDigests")
    if not isinstance(digests, dict):
        fail("protocol manifestDigests must be an object")
    for field in (
        "compatibilityCorpusSha256",
        "runtimeMatrixSha256",
        "schemeAManifestSha256",
        "oracleRegistrySha256",
        "toolchainManifestSha256",
    ):
        require_digest(digests.get(field), f"manifestDigests.{field}")
    if digests.get("baselineReferenceBinding") != "baseline-reference.json:baselineArtifactSha256":
        fail("protocol baseline reference binding is not content-addressed")
    compatibility = protocol.get("compatibility")
    if not isinstance(compatibility, dict):
        fail("protocol compatibility must be an object")
    if tuple(compatibility.get("stages", ())) != COMPATIBILITY_STAGES:
        fail("protocol compatibility stages are not the frozen six-stage chain")
    if set(compatibility.get("stageStatuses", ())) != STAGE_STATUSES:
        fail("protocol stage status vocabulary is incomplete or changed")
    if compatibility.get("growthMultiplier") != 100:
        fail("compatibility growth multiplier must be exactly 100")
    if compatibility.get("zeroDenominatorFactor") is not None:
        fail("zero-baseline compatibility factor must remain null")
    scheme = protocol.get("schemeA")
    if not isinstance(scheme, dict):
        fail("protocol schemeA must be an object")
    if tuple(scheme.get("requiredFamilyIds", ())) != REQUIRED_FAMILIES:
        fail("Scheme-A required family list is incomplete or reordered")
    if scheme.get("replicaCount") != 3 or scheme.get("minimumFactor") != 100.0:
        fail("Scheme-A replica count and factor are not frozen")
    budgets = protocol.get("budgets")
    if not isinstance(budgets, dict):
        fail("protocol budgets must be an object")
    for key in ("wallSeconds", "cpuSeconds", "rssBytes", "processLimit", "outputBytes", "rawArtifactBytes", "manualSteps"):
        require_int(budgets.get(key), f"budgets.{key}", minimum=0)
    if budgets.get("networkDisabled") is not True:
        fail("Scheme-A network must be disabled")


def validate_oracles(oracles: Mapping[str, Any]) -> set[str]:
    _require_root(oracles, "evaluator-oracle-registry")
    entries = oracles.get("oracles")
    if not isinstance(entries, list) or not entries:
        fail("oracle registry must contain at least one oracle")
    identifiers: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            fail(f"oracle {index} must be an object")
        oracle_id = require_id(entry.get("oracleId"), f"oracles[{index}].oracleId")
        if oracle_id in identifiers:
            fail(f"duplicate oracleId: {oracle_id}")
        identifiers.add(oracle_id)
        require_int(entry.get("version"), f"oracles[{index}].version", minimum=1)
        fields = entry.get("comparisonFields")
        if not isinstance(fields, list) or not fields or any(not isinstance(item, str) for item in fields):
            fail(f"oracles[{index}].comparisonFields must be a non-empty string list")
        require_int(entry.get("maxOutputBytes"), f"oracles[{index}].maxOutputBytes", minimum=1)
        require_digest(entry.get("oracleDefinitionSha256"), f"oracles[{index}].oracleDefinitionSha256")
        observation = entry.get("baselineObservation")
        if not isinstance(observation, dict):
            fail(f"oracles[{index}].baselineObservation must be an object")
    return identifiers


def validate_compatibility_corpus(corpus: Mapping[str, Any], repo_root: Path, oracle_ids: set[str]) -> tuple[dict[str, Any], ...]:
    _require_root(corpus, "compatibility-corpus")
    require_string(corpus.get("corpusVersion"), "corpusVersion")
    if corpus.get("appendOnly") is not True:
        fail("compatibility corpus must be append-only")
    fixed = corpus.get("fixedRowIds")
    rows = corpus.get("rows")
    if not isinstance(fixed, list) or any(not isinstance(item, str) for item in fixed):
        fail("fixedRowIds must be a string list")
    if not isinstance(rows, list) or not rows:
        fail("compatibility corpus rows must be non-empty")
    row_ids: set[str] = set()
    identity_keys: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            fail(f"compatibility row {index} must be an object")
        prefix = f"rows[{index}]"
        unit_id = require_id(row.get("unitId"), f"{prefix}.unitId")
        identity = require_id(row.get("identityKey"), f"{prefix}.identityKey")
        if unit_id in row_ids:
            fail(f"duplicate compatibility unitId: {unit_id}")
        if identity in identity_keys:
            fail(f"duplicate compatibility identityKey: {identity}")
        row_ids.add(unit_id)
        identity_keys.add(identity)
        source_path = resolve_repo_path(repo_root, row.get("sourceProvenance"), f"{prefix}.sourceProvenance", require_file=True)
        source_digest = require_digest(row.get("sourceSha256"), f"{prefix}.sourceSha256")
        actual_source_digest = sha256_file(source_path)
        if actual_source_digest != source_digest:
            fail(f"{prefix}.sourceSha256 does not match {source_path}")
        require_string(row.get("producerId"), f"{prefix}.producerId")
        require_digest(row.get("producerRecipeSha256"), f"{prefix}.producerRecipeSha256")
        tags = row.get("featureTags")
        if not isinstance(tags, list) or not tags or any(not isinstance(item, str) or not item for item in tags):
            fail(f"{prefix}.featureTags must be a non-empty string list")
        for field in ("profile", "runtimeCell", "targetLoader"):
            require_string(row.get(field), f"{prefix}.{field}")
        oracle_id = require_id(row.get("oracleId"), f"{prefix}.oracleId")
        if oracle_id not in oracle_ids:
            fail(f"{prefix}.oracleId is not registered: {oracle_id}")
        require_bool(row.get("applicable"), f"{prefix}.applicable")
        require_bool(row.get("required"), f"{prefix}.required")
        require_string(row.get("registrationStatus"), f"{prefix}.registrationStatus")
        auxiliary = row.get("auxiliaryEvidence", [])
        if not isinstance(auxiliary, list) or any(not isinstance(item, str) for item in auxiliary):
            fail(f"{prefix}.auxiliaryEvidence must be a string list")
        normalized.append(dict(row))
    if len(fixed) != len(set(fixed)):
        fail("fixedRowIds contains duplicates")
    if any(item not in row_ids for item in fixed):
        fail("fixedRowIds contains an unknown unitId")
    frozen_ids = {row["unitId"] for row in normalized if row.get("registrationStatus") == "frozen"}
    if set(fixed) != frozen_ids:
        fail("fixedRowIds must exactly identify frozen compatibility rows")
    for unit_id in fixed:
        frozen_row = next(row for row in normalized if row["unitId"] == unit_id)
        if frozen_row.get("required") is not True or frozen_row.get("applicable") is not True:
            fail("every frozen compatibility row must remain required and applicable")
    registries = corpus.get("retainedEvidenceRegistries", [])
    if not isinstance(registries, list) or not registries:
        fail("retainedEvidenceRegistries must preserve the existing auxiliary registries")
    registry_ids: set[str] = set()
    for index, registry in enumerate(registries):
        if not isinstance(registry, dict):
            fail(f"retainedEvidenceRegistries[{index}] must be an object")
        registry_id = require_id(registry.get("registryId"), f"retainedEvidenceRegistries[{index}].registryId")
        if registry_id in registry_ids:
            fail(f"duplicate retained registry: {registry_id}")
        registry_ids.add(registry_id)
        registry_path = resolve_repo_path(repo_root, registry.get("path"), f"retainedEvidenceRegistries[{index}].path", require_file=True)
        if sha256_file(registry_path) != require_digest(registry.get("sha256"), f"retainedEvidenceRegistries[{index}].sha256"):
            fail(f"retainedEvidenceRegistries[{index}] hash does not match {registry_path}")
        require_string(registry.get("role"), f"retainedEvidenceRegistries[{index}].role")
    negatives = corpus.get("negativeRows", [])
    if not isinstance(negatives, list):
        fail("negativeRows must be an array")
    negative_ids: set[str] = set()
    for index, row in enumerate(negatives):
        if not isinstance(row, dict):
            fail(f"negativeRows[{index}] must be an object")
        negative_id = require_id(row.get("id"), f"negativeRows[{index}].id")
        if negative_id in negative_ids or negative_id in row_ids:
            fail(f"duplicate corpus row identity: {negative_id}")
        negative_ids.add(negative_id)
        require_string(row.get("reason"), f"negativeRows[{index}].reason")
        require_bool(row.get("required"), f"negativeRows[{index}].required")
    return tuple(normalized)


def _validate_budget(budget: Mapping[str, Any], prefix: str) -> None:
    for key in ("wallSeconds", "cpuSeconds", "rssBytes", "processLimit", "outputBytes", "rawArtifactBytes", "manualSteps"):
        require_int(budget.get(key), f"{prefix}.{key}", minimum=0)
    if budget.get("networkDisabled") is not True:
        fail(f"{prefix}.networkDisabled must be true")


def validate_scheme_manifest(scheme: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    _require_root(scheme, "scheme-a-manifest")
    if scheme.get("protocolVersion") != "scheme-a-v1":
        fail("Scheme-A protocolVersion must be scheme-a-v1")
    if scheme.get("appendOnly") is not True:
        fail("Scheme-A manifest must be append-only")
    require_string(scheme.get("profile"), "scheme.profile")
    require_id(scheme.get("fixtureId"), "scheme.fixtureId")
    require_digest(scheme.get("sourceSha256"), "scheme.sourceSha256")
    require_digest(scheme.get("publishedArtifactSha256"), "scheme.publishedArtifactSha256", nullable=True)
    if scheme.get("publishedArtifactStatus") not in {"not-produced", "measured"}:
        fail("scheme.publishedArtifactStatus must explicitly describe artifact availability")
    require_string(scheme.get("baselineArtifactId"), "scheme.baselineArtifactId")
    if scheme.get("baselineStatus") not in {"baseline-not-calibrated", "measured"}:
        fail("scheme.baselineStatus is invalid")
    if scheme.get("replicaCount") != 3:
        fail("Scheme-A requires exactly three replicas")
    require_string(scheme.get("seed"), "scheme.seed")
    threat = scheme.get("threatModel")
    if not isinstance(threat, dict) or threat.get("version") != 1:
        fail("scheme.threatModel must be version 1")
    require_string(threat.get("statement"), "scheme.threatModel.statement")
    if threat.get("network") != "disabled" or threat.get("manualSteps") != 0:
        fail("scheme threat model must disable network and manual steps")
    budget = scheme.get("budget")
    if not isinstance(budget, dict):
        fail("scheme.budget must be an object")
    _validate_budget(budget, "scheme.budget")
    entries = scheme.get("requiredFamilies")
    if not isinstance(entries, list):
        fail("scheme.requiredFamilies must be an array")
    family_ids: list[str] = []
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            fail(f"scheme.requiredFamilies[{index}] must be an object")
        prefix = f"scheme.requiredFamilies[{index}]"
        family_id = require_id(entry.get("familyId"), f"{prefix}.familyId")
        if family_id in family_ids:
            fail(f"duplicate Scheme-A family: {family_id}")
        family_ids.append(family_id)
        require_bool(entry.get("required"), f"{prefix}.required")
        require_bool(entry.get("applicable"), f"{prefix}.applicable")
        require_digest(entry.get("attackRecipeSha256"), f"{prefix}.attackRecipeSha256")
        require_string(entry.get("objective"), f"{prefix}.objective")
        tool = entry.get("tool")
        if not isinstance(tool, dict):
            fail(f"{prefix}.tool must be an object")
        require_string(tool.get("name"), f"{prefix}.tool.name")
        if tool.get("availability") not in {"available", "not-calibrated", "environment-unavailable"}:
            fail(f"{prefix}.tool.availability is invalid")
        if tool.get("availability") == "available":
            require_string(tool.get("version"), f"{prefix}.tool.version")
            require_digest(tool.get("binarySha256"), f"{prefix}.tool.binarySha256")
        else:
            if tool.get("version") is not None or tool.get("binarySha256") is not None:
                fail(f"{prefix}. unavailable tool must not claim a version or binary hash")
        normalized.append(dict(entry))
    if tuple(family_ids) != REQUIRED_FAMILIES:
        fail("Scheme-A manifest must contain the frozen six families in order")
    if any(entry.get("required") is not True for entry in normalized):
        fail("a frozen Scheme-A family cannot be deleted or downgraded from required")
    if scheme.get("publishedArtifactStatus") == "not-produced" and scheme.get("publishedArtifactSha256") is not None:
        fail("a not-produced Scheme-A fixture must not claim a published artifact digest")
    if scheme.get("publishedArtifactStatus") == "measured" and scheme.get("publishedArtifactSha256") is None:
        fail("a measured Scheme-A fixture requires a published artifact digest")
    return tuple(normalized)


def validate_baseline_reference(
    reference: Mapping[str, Any],
    repo_root: Path,
    *,
    artifact_path_override: Path | None = None,
) -> dict[str, Any]:
    _require_root(reference, "evaluator-baseline-reference")
    expected = require_digest(reference.get("baselineArtifactSha256"), "baselineArtifactSha256")
    declared_artifact_path = resolve_repo_path(
        repo_root,
        reference.get("baselineArtifactPath"),
        "baselineArtifactPath",
        require_file=True,
    )
    if artifact_path_override is None:
        artifact_path = declared_artifact_path
    else:
        artifact_path = artifact_path_override
        if artifact_path.is_symlink() or not artifact_path.is_file():
            fail("baseline artifact copy must be a regular non-symlink file")
        if sha256_file(declared_artifact_path) != expected:
            fail("baseline artifact source digest does not match baseline reference")
    actual = sha256_file(artifact_path)
    if actual != expected:
        fail("baseline artifact digest does not match baseline-reference.json")
    artifact = read_json(artifact_path)
    _require_root(artifact, "compatibility-1x-baseline")
    if artifact.get("immutable") is not True or artifact.get("baselineStatus") not in {"baseline-zero", "measured"}:
        fail("baseline artifact is not immutable or has an invalid status")
    if artifact.get("commit") != reference.get("baselineCommit"):
        fail("baseline commit mismatch")
    artifact_id = artifact.get("baselineArtifactId", artifact.get("immutableArtifactId"))
    if artifact_id != reference.get("baselineArtifactId"):
        fail("baseline immutable artifact ID mismatch")
    artifact_complete_units = require_int(artifact.get("completeUnits"), "baseline.completeUnits", minimum=0)
    reference_complete_units = require_int(reference.get("completeUnits"), "baseline-reference.completeUnits", minimum=0)
    artifact_fixed_rows = require_int(artifact.get("fixedCorpusRows"), "baseline.fixedCorpusRows", minimum=0)
    reference_fixed_rows = require_int(reference.get("fixedCorpusRows"), "baseline-reference.fixedCorpusRows", minimum=0)
    if artifact_complete_units != reference_complete_units:
        fail("baseline complete-unit count mismatch")
    if artifact_fixed_rows != reference_fixed_rows:
        fail("baseline fixed-row count mismatch")
    complete_ids = artifact.get("completeUnitIds")
    if not isinstance(complete_ids, list) or any(not isinstance(item, str) for item in complete_ids):
        fail("baseline completeUnitIds must be a string list")
    for index, item in enumerate(complete_ids):
        require_id(item, f"baseline.completeUnitIds[{index}]")
    if len(complete_ids) != len(set(complete_ids)) or len(complete_ids) != artifact_complete_units:
        fail("baseline completeUnitIds do not match completeUnits")
    if reference.get("baselineStatus") != artifact.get("baselineStatus"):
        fail("baseline status mismatch")
    if reference.get("strengthStatus") != artifact.get("strengthStatus"):
        fail("baseline strength status mismatch")
    require_string(reference.get("baselineArtifactId"), "baselineArtifactId")
    require_string(reference.get("schemeProtocolVersion"), "schemeProtocolVersion")
    if reference.get("immutable") is not True or reference.get("contentAddressed") is not True or reference.get("neverOverwrite") is not True:
        fail("baseline reference must be immutable and content addressed")
    if artifact_complete_units > 0:
        if artifact.get("immutable") is not True or artifact.get("contentAddressed") is not True or artifact.get("neverOverwrite") is not True:
            fail("positive baseline payload must be immutable, content addressed, and never overwritten")
    return artifact


def validate_positive_baseline_v2(
    artifact: Mapping[str, Any],
    reference: Mapping[str, Any],
    *,
    repo_root: Path,
    corpus: Mapping[str, Any],
    protocol: Mapping[str, Any],
    scheme: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    corpus_path: Path,
    protocol_path: Path,
    scheme_path: Path,
    oracle_path: Path,
) -> None:
    """Validate the frozen v2 denominator's identity and six-stage summary."""
    if reference.get("baselineArtifactId") != "compatibility-1x-v2":
        return
    fixed_ids = corpus.get("fixedRowIds")
    if not isinstance(fixed_ids, list) or len(fixed_ids) != 1:
        fail("positive baseline v2 requires exactly one frozen fixed compatibility unit")
    unit_id = fixed_ids[0]
    row_by_id = {row.get("unitId"): row for row in rows}
    row = row_by_id.get(unit_id)
    if not isinstance(row, Mapping):
        fail("positive baseline v2 fixed unit is absent from the validated corpus")
    if artifact.get("baselineVersion") != "compatibility-1x-v2" or artifact.get("baselineArtifactId") != reference.get("baselineArtifactId"):
        fail("positive baseline v2 payload identity mismatch")
    if artifact.get("baselineStatus") != "measured" or artifact.get("completeUnits") != 1:
        fail("positive baseline v2 must record exactly one measured complete unit")
    if artifact.get("completeUnitIds") != [unit_id] or reference.get("completeUnits") != 1:
        fail("positive baseline v2 complete unit does not match the frozen fixed row")
    if artifact.get("claimable") is not False or artifact.get("rawEvidenceStatus") != "captured":
        fail("positive baseline v2 must remain non-claimable with captured raw evidence")

    identity = artifact.get("identity")
    if not isinstance(identity, Mapping):
        fail("positive baseline v2 identity record is missing")
    frozen_corpus_digest = identity.get("corpusManifestSha256")
    frozen_protocol_digest = identity.get("protocolSha256")
    require_digest(frozen_corpus_digest, "baseline.identity.corpusManifestSha256")
    require_digest(frozen_protocol_digest, "baseline.identity.protocolSha256")
    if sha256_bytes(canonical_json(dict(row))) != FROZEN_V2_FIXED_ROW_SHA256:
        fail("positive baseline v2 fixed row metadata changed")
    identity_expected = {
        "completeUnits": 1,
        "corpusManifestSha256": frozen_corpus_digest,
        "corpusVersion": corpus.get("corpusVersion"),
        "fixedCorpusRows": len(fixed_ids),
        "fixtureManifestSha256": sha256_file(repo_root / "fixtures/manifest.json"),
        "identityKey": row.get("identityKey"),
        "oracleManifestSha256": sha256_file(oracle_path),
        "protocolSha256": frozen_protocol_digest,
        "protocolVersion": protocol.get("protocolVersion"),
        "runtimeRegistrySha256": sha256_file(repo_root / "fixtures/runtime-matrix.json"),
        "schemeManifestSha256": sha256_file(scheme_path),
        "toolchainManifestSha256": sha256_file(repo_root / "global.json"),
        "unitId": unit_id,
    }
    for field, expected_value in identity_expected.items():
        if identity.get(field) != expected_value:
            fail(f"positive baseline v2 identity.{field} does not match the frozen evaluator inputs")
    if artifact.get("strengthStatus") != scheme.get("baselineStatus"):
        fail("positive baseline v2 Scheme-A status does not match the frozen manifest")

    chain = artifact.get("strictChain")
    if not isinstance(chain, Mapping):
        fail("positive baseline v2 strict-chain record is missing")
    if chain.get("allSixStagesPassed") is not True or chain.get("behaviorEqual") is not True:
        fail("positive baseline v2 requires all six linked strict-chain stages and oracle comparison")
    for field in (
        "behaviorComparisonSha256",
        "handoffSha256",
        "nativeImageSha256",
        "producerBuildSha256",
        "protectedImageSha256",
        "rehydrationRecordSha256",
        "rehydratorConsumerBuildSha256",
        "requestSha256",
        "sourceImageSha256",
    ):
        require_digest(chain.get(field), f"baseline.strictChain.{field}")
    if chain.get("protectedImageSha256") == chain.get("nativeImageSha256"):
        fail("positive baseline v2 Protected Image and Native Image hashes must remain distinct")
    if chain.get("producerId") != row.get("producerId") or chain.get("loaderId") != row.get("targetLoader") or chain.get("oracleId") != row.get("oracleId"):
        fail("positive baseline v2 producer, loader, or oracle link differs from the frozen row")
    require_string(chain.get("rehydratorConsumerId"), "baseline.strictChain.rehydratorConsumerId")
    require_int(chain.get("protectedImageSize"), "baseline.strictChain.protectedImageSize", minimum=1)
    require_int(chain.get("nativeImageSize"), "baseline.strictChain.nativeImageSize", minimum=1)
    require_int(chain.get("targetStatus"), "baseline.strictChain.targetStatus")
    if chain.get("targetSignal") is not None:
        require_string(chain.get("targetSignal"), "baseline.strictChain.targetSignal")

    scheme_record = artifact.get("schemeA")
    if not isinstance(scheme_record, Mapping):
        fail("positive baseline v2 Scheme-A record is missing")
    if (
        scheme_record.get("status") != "baseline-not-calibrated"
        or scheme_record.get("schemeAClaimable") is not False
        or scheme_record.get("protocolVersion") != scheme.get("protocolVersion")
        or scheme_record.get("requiredFamilies") != [family["familyId"] for family in scheme.get("requiredFamilies", [])]
        or scheme_record.get("familyFactors") != {family_id: None for family_id in REQUIRED_FAMILIES}
    ):
        fail("positive baseline v2 must preserve Scheme-A baseline-not-calibrated with null family factors")
    if scheme_record.get("manifestSha256") != sha256_file(scheme_path):
        fail("positive baseline v2 Scheme-A manifest digest mismatch")
    source = artifact.get("source")
    if not isinstance(source, Mapping):
        fail("positive baseline v2 source digest links are missing")
    for field in (
        "analysisInputSha256",
        "artifactManifestSha256",
        "environmentSha256",
        "evaluatorGateSha256",
        "negativeWitnessSha256",
        "productChainManifestSha256",
        "productEvidenceManifestSha256",
        "unitJsonSha256",
        "unitRawManifestSha256",
    ):
        require_digest(source.get(field), f"baseline.source.{field}")
    if source.get("productChainManifestSha256") != source.get("productEvidenceManifestSha256"):
        fail("positive baseline v2 product-chain manifest link mismatch")


def validate_scheme_baseline_reference(
    reference: Mapping[str, Any],
    artifact_path: Path,
    scheme: Mapping[str, Any],
    scheme_path: Path,
    repo_root: Path,
    *,
    declared_artifact_path: Path | None = None,
) -> dict[str, Any]:
    """Validate the immutable additive Scheme-A baseline binding.

    The compatibility baseline reference and the Scheme-A baseline reference are
    independent denominators.  Keeping this check separate prevents a
    compatibility baseline ID from being accidentally reused as the strength
    baseline identity, and makes every explicit v2 evaluator run consume the
    frozen per-family costs rather than a freshly measured denominator.
    """
    _require_root(reference, "scheme-a-baseline-reference")
    if reference.get("baselineArtifactId") != scheme.get("baselineArtifactId"):
        fail("Scheme-A baseline reference ID does not match the selected manifest")
    if reference.get("baselineStatus") != "measured":
        fail("Scheme-A baseline reference must be measured")
    if reference.get("protocolVersion") != scheme.get("protocolVersion"):
        fail("Scheme-A baseline reference protocol version does not match the manifest")
    if reference.get("baselineVersion") != "scheme-a-1x-v2":
        fail("Scheme-A baseline reference version is not the frozen v2 version")
    if reference.get("replicaCount") != scheme.get("replicaCount"):
        fail("Scheme-A baseline reference replica count does not match the manifest")
    expected_families = [family["familyId"] for family in scheme.get("requiredFamilies", ())]
    if reference.get("requiredFamilies") != expected_families:
        fail("Scheme-A baseline reference family order changed")
    if reference.get("schemeManifestSha256") != sha256_file(scheme_path):
        fail("Scheme-A baseline reference is not bound to the selected manifest")
    if any(reference.get(field) is not True for field in ("immutable", "contentAddressed", "neverOverwrite")):
        fail("Scheme-A baseline reference must be immutable and content addressed")

    declared_path = resolve_repo_path(
        repo_root,
        reference.get("baselineArtifactPath"),
        "scheme baselineArtifactPath",
        require_file=True,
    )
    if declared_artifact_path is not None:
        if declared_artifact_path.is_symlink() or not declared_artifact_path.is_file():
            fail("Scheme-A baseline artifact copy must be a regular non-symlink file")
        if sha256_file(declared_path) != reference.get("baselineArtifactSha256"):
            fail("Scheme-A baseline artifact source digest does not match its reference")
    actual_artifact_path = declared_artifact_path or artifact_path
    if sha256_file(actual_artifact_path) != reference.get("baselineArtifactSha256"):
        fail("Scheme-A baseline artifact digest does not match its reference")
    artifact = read_json(actual_artifact_path)
    _require_root(artifact, "scheme-a-baseline")
    if artifact.get("baselineArtifactId") != reference.get("baselineArtifactId"):
        fail("Scheme-A baseline artifact ID does not match its reference")
    if artifact.get("baselineVersion") != reference.get("baselineVersion"):
        fail("Scheme-A baseline artifact version does not match its reference")
    if artifact.get("status") != "measured" or artifact.get("claimable") is not False:
        fail("Scheme-A baseline artifact must be measured and non-claimable")
    if any(artifact.get(field) is not True for field in ("immutable", "contentAddressed", "neverOverwrite")):
        fail("Scheme-A baseline artifact must be immutable and content addressed")
    if artifact.get("protocolVersion") != scheme.get("protocolVersion"):
        fail("Scheme-A baseline artifact protocol version does not match the manifest")
    if artifact.get("replicaCount") != scheme.get("replicaCount"):
        fail("Scheme-A baseline artifact replica count does not match the manifest")
    if artifact.get("requiredFamilies") != expected_families:
        fail("Scheme-A baseline artifact family order changed")
    if artifact.get("schemeManifestSha256") != reference.get("schemeManifestSha256"):
        fail("Scheme-A baseline artifact is not bound to its manifest reference")
    if artifact.get("fixtureId") != scheme.get("fixtureId") or artifact.get("sourceSha256") != scheme.get("sourceSha256"):
        fail("Scheme-A baseline artifact fixture/source binding changed")
    families = artifact.get("families")
    if not isinstance(families, Mapping):
        fail("Scheme-A baseline artifact families are missing")
    for family in scheme.get("requiredFamilies", ()):
        family_id = family["familyId"]
        record = families.get(family_id)
        if not isinstance(record, Mapping):
            fail(f"Scheme-A baseline artifact is missing family {family_id}")
        replicas = record.get("baselineReplicas")
        if not isinstance(replicas, list) or len(replicas) != scheme.get("replicaCount"):
            fail(f"Scheme-A baseline artifact family {family_id} does not have three replicas")
        costs: list[int] = []
        seen_replicas: set[int] = set()
        for expected_replica, replica in enumerate(replicas, 1):
            if not isinstance(replica, Mapping) or replica.get("replica") != expected_replica:
                fail(f"Scheme-A baseline artifact family {family_id} replica order changed")
            cost = require_int(replica.get("successCpuNs"), f"scheme baseline {family_id} replica {expected_replica} cost", minimum=1)
            raw_manifest = replica.get("rawEvidenceManifest")
            safe_relative_path(raw_manifest, f"scheme baseline {family_id} replica {expected_replica} rawEvidenceManifest")
            costs.append(cost)
            seen_replicas.add(expected_replica)
        if seen_replicas != set(range(1, scheme.get("replicaCount") + 1)):
            fail(f"Scheme-A baseline artifact family {family_id} replicas are incomplete")
        if record.get("baselineCostCpuNs") != max(costs):
            fail(f"Scheme-A baseline artifact family {family_id} cost is not the max replica cost")
    return artifact


def validate_all_manifests(
    repo_root: Path,
    *,
    protocol_path: Path,
    corpus_path: Path,
    scheme_path: Path,
    oracle_path: Path,
    baseline_reference_path: Path,
    baseline_artifact_path: Path | None = None,
    scheme_baseline_reference_path: Path | None = None,
    scheme_baseline_artifact_path: Path | None = None,
) -> dict[str, Any]:
    default_scheme_path = (repo_root / "fixtures/evaluator/scheme-a-manifest.json").resolve()
    active_additive_scheme = scheme_path.resolve() != default_scheme_path
    scheme_baseline_reference: dict[str, Any] | None = None
    scheme_baseline: dict[str, Any] | None = None
    resolved_scheme_baseline_reference_path: Path | None = None
    resolved_scheme_baseline_artifact_path: Path | None = None
    protocol = read_json(protocol_path)
    validate_protocol(protocol)
    oracles = read_json(oracle_path)
    oracle_ids = validate_oracles(oracles)
    corpus = read_json(corpus_path)
    rows = validate_compatibility_corpus(corpus, repo_root, oracle_ids)
    scheme = read_json(scheme_path)
    families = validate_scheme_manifest(scheme)
    reference = read_json(baseline_reference_path)
    baseline = validate_baseline_reference(reference, repo_root, artifact_path_override=baseline_artifact_path)
    if protocol["budgets"] != scheme["budget"]:
        fail("compatibility and Scheme-A protocol budgets must be equal")
    if protocol["schemeA"].get("protocolVersion") != scheme.get("protocolVersion"):
        fail("protocol Scheme-A version does not match the Scheme-A manifest")
    if reference.get("corpusVersion") != corpus.get("corpusVersion"):
        fail("baseline reference corpusVersion does not match compatibility corpus")
    if reference.get("protocolVersion") != protocol.get("protocolVersion"):
        fail("baseline reference protocolVersion does not match protocol")
    if reference.get("schemeProtocolVersion") != scheme.get("protocolVersion"):
        fail("baseline reference Scheme-A version does not match the Scheme-A manifest")
    if reference.get("fixedCorpusRows") != len(corpus.get("fixedRowIds", ())):
        fail("baseline fixed-row count does not match the compatibility corpus")
    if not active_additive_scheme and baseline.get("strengthStatus") != scheme.get("baselineStatus"):
        fail("baseline strength status does not match the Scheme-A manifest")
    # The required default remains bound to the historical zero baseline.  An
    # explicitly selected additive reference is independently content-addressed
    # and may retain the commit at which that frozen positive artifact was made.
    if (
        reference.get("baselineArtifactId") == "compatibility-1x-baseline-zero"
        and protocol["baselineRules"].get("currentCommit") != baseline.get("commit")
    ):
        fail("protocol baseline commit does not match the immutable baseline")
    complete_ids = baseline.get("completeUnitIds")
    fixed_ids = set(corpus.get("fixedRowIds", ()))
    if not isinstance(complete_ids, list) or not set(complete_ids) <= fixed_ids:
        fail("baseline completeUnitIds must be frozen compatibility rows")
    digest_bindings = {
        "corpusManifestSha256": corpus_path,
        "protocolSha256": protocol_path,
        "schemeManifestSha256": scheme_path,
        "oracleManifestSha256": oracle_path,
    }
    protocol_digest_bindings = {
        "compatibilityCorpusSha256": corpus_path,
        "runtimeMatrixSha256": repo_root / "fixtures" / "runtime-matrix.json",
        "schemeAManifestSha256": scheme_path,
        "oracleRegistrySha256": oracle_path,
        "toolchainManifestSha256": repo_root / "global.json",
    }
    for field, path in protocol_digest_bindings.items():
        if active_additive_scheme and field == "schemeAManifestSha256":
            if scheme.get("parentManifestSha256") != sha256_file(default_scheme_path):
                fail("additive Scheme-A manifest is not bound to the frozen v1 manifest")
            continue
        if protocol["manifestDigests"].get(field) != sha256_file(path):
            fail(f"protocol manifestDigests.{field} does not match {path}")
    for field, path in digest_bindings.items():
        if active_additive_scheme and field == "schemeManifestSha256":
            continue
        # Corpus growth is append-only. The immutable baseline retains the
        # historical corpus/protocol snapshots; fixed-row immutability and the
        # current protocol manifest ledger are checked separately.
        if field in {"corpusManifestSha256", "protocolSha256"}:
            continue
        expected = baseline.get(field)
        if expected is not None and expected != sha256_file(path):
            fail(f"baseline snapshot {field} does not match {path}")
    fixture_manifest = repo_root / "fixtures" / "manifest.json"
    runtime_manifest = repo_root / "fixtures" / "runtime-matrix.json"
    if reference.get("baselineArtifactId") == "compatibility-1x-baseline-zero":
        if baseline.get("fixtureManifestSha256") != sha256_file(fixture_manifest):
            fail("baseline fixtureManifestSha256 does not match fixtures/manifest.json")
        if baseline.get("runtimeRegistrySha256") != sha256_file(runtime_manifest):
            fail("baseline runtimeRegistrySha256 does not match fixtures/runtime-matrix.json")
    if not active_additive_scheme:
        validate_positive_baseline_v2(
        baseline,
        reference,
        repo_root=repo_root,
        corpus=corpus,
        protocol=protocol,
        scheme=scheme,
        rows=rows,
        corpus_path=corpus_path,
        protocol_path=protocol_path,
        scheme_path=scheme_path,
        oracle_path=oracle_path,
    )
    else:
        scheme_reference_value = scheme.get("baselineReferencePath")
        require_string(scheme_reference_value, "scheme.baselineReferencePath")
        resolved_scheme_baseline_reference_path = (
            scheme_baseline_reference_path
            if scheme_baseline_reference_path is not None
            else resolve_repo_path(repo_root, scheme_reference_value, "scheme.baselineReferencePath", require_file=True)
        )
        scheme_baseline_reference = read_json(resolved_scheme_baseline_reference_path)
        declared_scheme_artifact_path = resolve_repo_path(
            repo_root,
            scheme_baseline_reference.get("baselineArtifactPath"),
            "scheme baselineArtifactPath",
            require_file=True,
        )
        resolved_scheme_baseline_artifact_path = (
            scheme_baseline_artifact_path or declared_scheme_artifact_path
        )
        scheme_baseline = validate_scheme_baseline_reference(
            scheme_baseline_reference,
            resolved_scheme_baseline_artifact_path,
            scheme,
            scheme_path,
            repo_root,
            declared_artifact_path=(
                declared_scheme_artifact_path
                if scheme_baseline_artifact_path is not None
                else None
            ),
        )
    return {
        "protocol": protocol,
        "corpus": corpus,
        "rows": rows,
        "scheme": scheme,
        "families": families,
        "oracles": oracles,
        "oracleIds": oracle_ids,
        "baselineReference": reference,
        "baseline": baseline,
        "schemeBaselineReference": scheme_baseline_reference,
        "schemeBaseline": scheme_baseline,
        "schemeBaselineReferencePath": resolved_scheme_baseline_reference_path,
        "schemeBaselineArtifactPath": resolved_scheme_baseline_artifact_path,
    }


def _stage_binding(stage_name: str, stage: Mapping[str, Any]) -> bool:
    digest_fields = STAGE_DIGEST_FIELDS[stage_name]
    if any(not isinstance(stage.get(field), str) or HEX64.fullmatch(stage[field]) is None for field in digest_fields):
        return False
    required_fields = STAGE_REQUIRED_FIELDS.get(stage_name, ())
    return all(isinstance(stage.get(field), str) and bool(stage[field]) for field in required_fields)


def validate_stage_record(stage_name: str, stage: Mapping[str, Any]) -> None:
    for field in STAGE_DIGEST_FIELDS[stage_name]:
        require_digest(stage.get(field), f"stage.{stage_name}.{field}")
    for field in STAGE_REQUIRED_FIELDS.get(stage_name, ()):
        require_string(stage.get(field), f"stage.{stage_name}.{field}")


def derive_unit_completion(unit: Mapping[str, Any], row: Mapping[str, Any] | None = None) -> tuple[bool, str | None]:
    stages = unit.get("stages")
    if not isinstance(stages, dict):
        return False, "protocol-failure"
    if row is not None:
        for field in ("unitId", "sourceSha256", "profile", "runtimeCell", "targetLoader", "oracleId"):
            if unit.get(field) != row.get(field):
                return False, "protocol-failure"
    for stage_name in COMPATIBILITY_STAGES:
        stage = stages.get(stage_name)
        if not isinstance(stage, dict):
            return False, stage_name
        if stage.get("status") not in STAGE_STATUSES:
            return False, stage_name
        if stage.get("status") != "passed":
            return False, stage_name
        if not _stage_binding(stage_name, stage):
            return False, stage_name
    return True, None


def validate_unit_record(unit: Mapping[str, Any], row: Mapping[str, Any]) -> tuple[bool, str | None]:
    _require_root(unit, "compatibility-unit")
    require_id(unit.get("unitId"), "unit.unitId")
    require_digest(unit.get("sourceSha256"), "unit.sourceSha256")
    strict_chain_measured = unit.get("strictChainMeasured") is True
    if strict_chain_measured:
        require_digest(unit.get("sourceImageSha256"), "unit.sourceImageSha256")
        product_binding = unit.get("productEvidence")
        if not isinstance(product_binding, dict):
            fail("strict compatibility unit must bind product evidence")
        safe_relative_path(product_binding.get("rawRoot"), "unit.productEvidence.rawRoot")
        require_digest(product_binding.get("manifestSha256"), "unit.productEvidence.manifestSha256")
    for field in ("corpusVersion", "profile", "runtimeCell", "targetLoader", "oracleId", "identityKey", "sourceProvenance"):
        require_string(unit.get(field), f"unit.{field}")
    require_digest(unit.get("producerRecipeSha256"), "unit.producerRecipeSha256")
    if (
        unit.get("identityKey") != row.get("identityKey")
        or unit.get("sourceProvenance") != row.get("sourceProvenance")
        or unit.get("producerRecipeSha256") != row.get("producerRecipeSha256")
    ):
        fail(f"unit corpus identity binding does not match the registered row for {unit.get('unitId')}")
    if unit.get("targetLoader") != row.get("targetLoader"):
        fail(f"unit.targetLoader does not match the frozen row for {unit.get('unitId')}")
    if unit.get("statusOwner") != STATUS_OWNER:
        fail(f"unit.statusOwner must be {STATUS_OWNER}")
    stages = unit.get("stages")
    if not isinstance(stages, dict):
        fail("unit.stages must be an object")
    if set(stages) != set(COMPATIBILITY_STAGES):
        fail("unit.stages must contain exactly the six compatibility stages")
    for stage_name in COMPATIBILITY_STAGES:
        stage = stages[stage_name]
        if not isinstance(stage, dict):
            fail(f"unit.stages.{stage_name} must be an object")
        if stage.get("status") not in STAGE_STATUSES:
            fail(f"unit.stages.{stage_name}.status is invalid")
        reason = stage.get("reason")
        if stage.get("status") != "passed" and (not isinstance(reason, str) or not reason):
            fail(f"unit.stages.{stage_name}.reason is required for non-passed status")
        if stage.get("status") == "passed":
            validate_stage_record(stage_name, stage)
            if strict_chain_measured:
                if stage.get("unitId") != unit.get("unitId") or stage.get("profile") != unit.get("profile"):
                    fail(f"strict stage {stage_name} does not bind the compatibility unit")
                if stage.get("sourceImageSha256") != unit.get("sourceImageSha256"):
                    fail(f"strict stage {stage_name} does not bind the Source Image")
    complete, first_failure = derive_unit_completion(unit, row)
    if unit.get("complete") is not complete:
        fail(f"unit.complete is not the derived value for {unit.get('unitId')}")
    if unit.get("firstFailureLayer") != first_failure:
        fail(f"unit.firstFailureLayer is not derived for {unit.get('unitId')}")
    raw_manifest = unit.get("rawEvidenceManifest")
    safe_relative_path(raw_manifest, "unit.rawEvidenceManifest")
    return complete, first_failure


def calculate_compatibility(corpus: Mapping[str, Any], baseline: Mapping[str, Any], units: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = {row["unitId"]: row for row in corpus["rows"]}
    if len(rows) != len(corpus["rows"]):
        fail("compatibility corpus contains duplicate unitId values")
    identity_keys = [row.get("identityKey") for row in corpus["rows"]]
    if any(not isinstance(identity, str) or not identity for identity in identity_keys) or len(set(identity_keys)) != len(identity_keys):
        fail("compatibility corpus contains duplicate or missing identityKey values")
    fixed_ids = set(corpus["fixedRowIds"])
    if not fixed_ids <= set(rows):
        fail("compatibility fixed view references an unknown unitId")
    seen: set[str] = set()
    complete_ids: set[str] = set()
    complete_identity_keys: set[str] = set()
    first_failures: dict[str, int] = {}
    for unit in units:
        unit_id = unit.get("unitId")
        if unit_id in seen:
            fail(f"duplicate compatibility unit evidence: {unit_id}")
        seen.add(unit_id)
        if unit_id not in rows:
            fail(f"compatibility unit is not registered: {unit_id}")
        if unit.get("corpusVersion") != corpus.get("corpusVersion"):
            fail(f"compatibility unit corpusVersion mismatch: {unit_id}")
        complete, first_failure = validate_unit_record(unit, rows[unit_id])
        if complete:
            complete_ids.add(unit_id)
            complete_identity_keys.add(rows[unit_id]["identityKey"])
        else:
            first_failures[first_failure or "protocol-failure"] = first_failures.get(first_failure or "protocol-failure", 0) + 1
    required_ids = {row["unitId"] for row in corpus["rows"] if row.get("required") and row.get("applicable")}
    if seen != required_ids:
        missing = sorted(required_ids - seen)
        extra = sorted(seen - required_ids)
        fail(f"compatibility evidence rows do not match required corpus (missing={missing}, extra={extra})")
    baseline_units = require_int(baseline.get("completeUnits"), "baseline.completeUnits", minimum=0)
    if baseline_units > len(fixed_ids):
        fail("baseline complete-unit count exceeds frozen fixed-row count")
    frozen_complete_ids_value = baseline.get("completeUnitIds")
    if frozen_complete_ids_value is None:
        # Keep the pure scoring helper useful for focused tests that provide only
        # the historical count, while checked-in baselines always carry IDs.
        frozen_complete_ids: set[str] | None = None
    else:
        if not isinstance(frozen_complete_ids_value, list) or any(not isinstance(item, str) for item in frozen_complete_ids_value):
            fail("baseline.completeUnitIds must be a string list")
        for index, item in enumerate(frozen_complete_ids_value):
            require_id(item, f"baseline.completeUnitIds[{index}]")
        frozen_complete_ids = set(frozen_complete_ids_value)
        if len(frozen_complete_ids) != len(frozen_complete_ids_value) or len(frozen_complete_ids) != baseline_units:
            fail("baseline.completeUnitIds do not match baseline.completeUnits")
        if not frozen_complete_ids <= fixed_ids:
            fail("baseline.completeUnitIds must belong to the frozen fixed view")
    fixed_identity_keys = {rows[unit_id]["identityKey"] for unit_id in fixed_ids}
    complete_fixed_identity_keys = {rows[unit_id]["identityKey"] for unit_id in complete_ids & fixed_ids}
    candidate_fixed = len(complete_fixed_identity_keys & fixed_identity_keys)
    candidate_growth = len(complete_identity_keys)
    if baseline_units == 0:
        factor: float | None = None
        status = "baseline-zero"
    else:
        factor = candidate_growth / baseline_units
        status = "measured"
    fixed_view_pass = candidate_fixed >= baseline_units
    if frozen_complete_ids is not None:
        fixed_view_pass = fixed_view_pass and frozen_complete_ids <= complete_ids
    return {
        "status": status,
        "fixedRows": len(fixed_ids),
        "growthRows": len(rows),
        "baselineCompleteUnits": baseline_units,
        "candidateFixedCompleteUnits": candidate_fixed,
        "candidateGrowthCompleteUnits": candidate_growth,
        "factor": factor,
        "growthTarget": 100 * baseline_units,
        "fixedViewPass": fixed_view_pass,
        "growthViewPass": baseline_units > 0 and candidate_growth >= 100 * baseline_units,
        "firstFailureCounts": dict(sorted(first_failures.items())),
        "completeUnitIds": sorted(complete_ids),
    }


def _attempt_success(attempt: Mapping[str, Any]) -> bool:
    return (
        attempt.get("classification") == "attack-success"
        and attempt.get("goalAchieved") is True
        and isinstance(attempt.get("successCpuNs"), int)
        and not isinstance(attempt.get("successCpuNs"), bool)
        and attempt["successCpuNs"] > 0
    )


def _attempt_exhausted(attempt: Mapping[str, Any], budget: Mapping[str, Any]) -> bool:
    return (
        attempt.get("classification") == "attack-failed"
        and attempt.get("goalAchieved") is False
        and attempt.get("censored") is True
        and attempt.get("successCpuNs") is None
        and attempt.get("resourceEvidence")
        and isinstance(attempt.get("blueOracle"), dict)
        and attempt["blueOracle"].get("status") == "passed"
        and isinstance(budget.get("cpuSeconds"), int)
        and not isinstance(budget.get("cpuSeconds"), bool)
    )


def validate_attempt_record(attempt: Mapping[str, Any], family: Mapping[str, Any], role: str, replica: int, scheme: Mapping[str, Any]) -> None:
    _require_root(attempt, "scheme-a-attempt")
    if attempt.get("familyId") != family.get("familyId"):
        fail(f"attempt family mismatch: {attempt.get('familyId')}")
    if attempt.get("role") != role:
        fail("attempt role mismatch")
    attempt_replica = require_int(attempt.get("replica"), "attempt.replica", minimum=1)
    if attempt_replica != replica:
        fail("attempt replica mismatch")
    require_string(attempt.get("profile"), "attempt.profile")
    require_id(attempt.get("unitId"), "attempt.unitId")
    require_digest(attempt.get("sourceSha256"), "attempt.sourceSha256")
    if attempt.get("profile") != scheme.get("profile"):
        fail("attempt profile changed from the frozen Scheme-A profile")
    if attempt.get("unitId") != scheme.get("fixtureId"):
        fail("attempt unitId changed from the frozen Scheme-A fixture")
    if attempt.get("sourceSha256") != scheme.get("sourceSha256"):
        fail("attempt source digest changed from the frozen Scheme-A fixture")
    require_digest(attempt.get("attackRecipeSha256"), "attempt.attackRecipeSha256")
    if attempt.get("attackRecipeSha256") != family.get("attackRecipeSha256"):
        fail("attempt attack recipe digest changed")
    if attempt.get("toolchain") != family.get("tool"):
        fail("attempt toolchain identity changed")
    expected_artifact_digest = scheme.get("publishedArtifactSha256")
    actual_artifact_digest = attempt.get("publishedArtifactSha256")
    if expected_artifact_digest is None:
        if actual_artifact_digest is not None:
            fail("attempt published artifact digest is present before the fixture is produced")
    else:
        require_digest(actual_artifact_digest, "attempt.publishedArtifactSha256")
        if actual_artifact_digest != expected_artifact_digest:
            fail("attempt published artifact digest changed")
    if attempt.get("statusOwner") != STATUS_OWNER:
        fail(f"attempt.statusOwner must be {STATUS_OWNER}")
    classification = attempt.get("classification")
    if classification not in ATTACK_CLASSIFICATIONS:
        fail(f"attempt classification is invalid: {classification}")
    if not isinstance(attempt.get("goalAchieved"), bool):
        fail("attempt.goalAchieved must be boolean")
    budget = attempt.get("budget")
    if not isinstance(budget, dict):
        fail("attempt.budget must be an object")
    _validate_budget(budget, "attempt.budget")
    if budget != scheme.get("budget"):
        fail("candidate and baseline attempt budgets must equal the frozen Scheme-A budget")
    if attempt.get("manualStepsObserved") != 0:
        fail("manual intervention is forbidden")
    safe_relative_path(attempt.get("rawEvidenceManifest"), "attempt.rawEvidenceManifest")
    for field in ("resourceEvidence", "stdout", "stderr", "commandLog"):
        safe_relative_path(attempt.get(field), f"attempt.{field}")
    blue_oracle = attempt.get("blueOracle")
    if not isinstance(blue_oracle, dict):
        fail("attempt.blueOracle must be an object")
    if blue_oracle.get("status") not in {"passed", "failed", "not-captured", "environment-unavailable"}:
        fail("attempt.blueOracle.status is invalid")
    if _attempt_success(attempt):
        if blue_oracle.get("status") != "passed":
            fail("successful attack requires an independently passed blue oracle")
        require_digest(blue_oracle.get("evidenceSha256"), "attempt.blueOracle.evidenceSha256")
        if attempt.get("censored") is not False:
            fail("successful attempt cannot be censored")
        success_cpu_ns = require_int(attempt.get("successCpuNs"), "attempt.successCpuNs", minimum=1)
        cpu_budget_ns = budget["cpuSeconds"] * 1_000_000_000
        if success_cpu_ns > cpu_budget_ns:
            fail("successful attack exceeds its frozen CPU budget")
        require_digest(attempt.get("recoveredArtifactSha256"), "attempt.recoveredArtifactSha256")
        require_int(attempt.get("recoveredArtifactSize"), "attempt.recoveredArtifactSize", minimum=1)
    elif attempt.get("successCpuNs") is not None:
        fail("unsuccessful attempt must not claim a success CPU cost")
    if not isinstance(attempt.get("censored"), bool):
        fail("attempt.censored must be boolean")
    if attempt.get("censored") and classification != "attack-failed":
        fail("only a fully attempted attack-failed result may be censored")
    if classification == "attack-success" and not _attempt_success(attempt):
        fail("attack-success must include a verified finite success")
    if classification != "attack-success" and attempt.get("goalAchieved") is not False:
        fail("non-successful attack classifications must set goalAchieved=false")


def calculate_scheme_gate(
    scheme: Mapping[str, Any],
    attempts: Mapping[tuple[str, str, int], Mapping[str, Any]],
    *,
    baseline_artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    families_by_id = {family["familyId"]: family for family in scheme["requiredFamilies"]}
    frozen_families = baseline_artifact.get("families") if isinstance(baseline_artifact, Mapping) else None
    if baseline_artifact is not None and not isinstance(frozen_families, Mapping):
        fail("Scheme-A baseline artifact families are missing")
    expected_keys = {
        (family_id, role, replica)
        for family_id in REQUIRED_FAMILIES
        for role in ("baseline", "candidate")
        for replica in range(1, scheme["replicaCount"] + 1)
    }
    if set(attempts) != expected_keys:
        fail(f"Scheme-A attempts do not exactly match required replicas: missing={sorted(expected_keys - set(attempts))}, extra={sorted(set(attempts) - expected_keys)}")
    family_results: dict[str, dict[str, Any]] = {}
    any_baseline_uncalibrated = False
    any_environment_unavailable = False
    for family_id in REQUIRED_FAMILIES:
        family = families_by_id[family_id]
        if not family.get("required") or not family.get("applicable"):
            family_results[family_id] = {"status": "not-applicable", "factorLowerBound": None, "baselineReplicas": 0, "candidateReplicas": 0}
            continue
        baseline_attempts: list[Mapping[str, Any]] = []
        candidate_attempts: list[Mapping[str, Any]] = []
        for role in ("baseline", "candidate"):
            for replica in range(1, scheme["replicaCount"] + 1):
                key = (family_id, role, replica)
                attempt = attempts.get(key)
                if attempt is None:
                    fail(f"missing required Scheme-A attempt: {key}")
                validate_attempt_record(attempt, family, role, replica, scheme)
                (baseline_attempts if role == "baseline" else candidate_attempts).append(attempt)
        baseline_successes = [attempt for attempt in baseline_attempts if _attempt_success(attempt)]
        candidate_successes = [attempt for attempt in candidate_attempts if _attempt_success(attempt)]
        baseline_env = any(attempt.get("classification") == "environment-unavailable" for attempt in baseline_attempts)
        candidate_env = any(attempt.get("classification") == "environment-unavailable" for attempt in candidate_attempts)
        if baseline_env or candidate_env:
            any_environment_unavailable = True
        if len(baseline_successes) != scheme["replicaCount"]:
            any_baseline_uncalibrated = True
            family_results[family_id] = {
                "status": "baseline-not-calibrated",
                "baselineReplicas": len(baseline_successes),
                "candidateReplicas": len(candidate_successes),
                "baselineCostCpuNs": None,
                "candidateCostLowerBoundCpuNs": None,
                "factorLowerBound": None,
                "censored": False,
                "environmentUnavailable": baseline_env,
            }
            continue
        measured_baseline_cost = max(attempt["successCpuNs"] for attempt in baseline_successes)
        if frozen_families is None:
            baseline_cost = measured_baseline_cost
        else:
            frozen_family = frozen_families.get(family_id)
            if not isinstance(frozen_family, Mapping):
                fail(f"Scheme-A baseline artifact is missing family {family_id}")
            baseline_cost = require_int(
                frozen_family.get("baselineCostCpuNs"),
                f"Scheme-A frozen baseline cost for {family_id}",
                minimum=1,
            )
        if candidate_env:
            family_results[family_id] = {
                "status": "environment-unavailable",
                "baselineReplicas": len(baseline_successes),
                "candidateReplicas": len(candidate_successes),
                "baselineCostCpuNs": baseline_cost,
                "candidateCostLowerBoundCpuNs": None,
                "factorLowerBound": None,
                "censored": False,
                "environmentUnavailable": True,
            }
            continue
        mixed_candidate = 0 < len(candidate_successes) < scheme["replicaCount"]
        candidate_exhausted = all(_attempt_exhausted(attempt, scheme["budget"]) for attempt in candidate_attempts)
        if mixed_candidate or (not candidate_exhausted and len(candidate_successes) != scheme["replicaCount"]):
            family_results[family_id] = {
                "status": "unknown",
                "baselineReplicas": len(baseline_successes),
                "candidateReplicas": len(candidate_successes),
                "baselineCostCpuNs": baseline_cost,
                "candidateCostLowerBoundCpuNs": None,
                "factorLowerBound": None,
                "censored": False,
                "environmentUnavailable": False,
            }
            continue
        if candidate_exhausted:
            candidate_cost = int(scheme["budget"]["cpuSeconds"] * 1_000_000_000)
            censored = True
        else:
            candidate_cost = min(attempt["successCpuNs"] for attempt in candidate_successes)
            censored = False
        factor = candidate_cost / max(baseline_cost, 1_000_000)
        family_results[family_id] = {
            "status": "pass" if factor >= 100.0 else "bounded-below-100",
            "baselineReplicas": len(baseline_successes),
            "candidateReplicas": len(candidate_successes),
            "baselineCostCpuNs": baseline_cost,
            "candidateCostLowerBoundCpuNs": candidate_cost,
            "factorLowerBound": factor,
            "censored": censored,
            "environmentUnavailable": candidate_env,
        }
    if any_baseline_uncalibrated:
        status = "baseline-not-calibrated"
    elif any_environment_unavailable:
        status = "environment-unavailable"
    elif all(result.get("status") == "pass" for result in family_results.values()):
        status = "pass"
    else:
        status = "measured"
    return {
        "status": status,
        "requiredFamilies": list(REQUIRED_FAMILIES),
        "families": family_results,
        "familyFactors": {family_id: result.get("factorLowerBound") for family_id, result in family_results.items()},
        "allRequiredPass": all(result.get("status") == "pass" and (result.get("factorLowerBound") or 0) >= 100.0 for result in family_results.values() if result.get("status") != "not-applicable") and not any_baseline_uncalibrated,
        "minimumFactorDiagnostic": min((result["factorLowerBound"] for result in family_results.values() if result.get("factorLowerBound") is not None), default=None),
    }


def inventory_digest(root: Path, *, exclude: Iterable[str] = ()) -> str:
    excluded = set(exclude)
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(root).as_posix()
        if relative in excluded or relative in EVIDENCE_HANDOFF_FILES:
            continue
        entries.append(f"{sha256_file(path)}  {relative}\n")
    return sha256_bytes("".join(entries).encode("utf-8"))


def validate_no_symlinks(root: Path, *, max_files: int = 10_000, max_bytes: int = 536_870_912) -> tuple[list[Path], int]:
    if not root.exists() or not root.is_dir() or root.is_symlink():
        fail(f"evaluator artifact root is not a real directory: {root}")
    files: list[Path] = []
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            fail(f"evaluator evidence contains a symlink: {path}")
        if path.is_file():
            files.append(path)
            size = path.stat().st_size
            total += size
            if len(files) > max_files:
                fail("evaluator evidence file count exceeds bound")
            if total > max_bytes:
                fail("evaluator evidence byte count exceeds bound")
    return files, total


def calculate_anti_gaming(
    repo_root: Path,
    manifests: Mapping[str, Any],
    compatibility: Mapping[str, Any],
    units: Iterable[Mapping[str, Any]],
    attempts: Mapping[tuple[str, str, int], Mapping[str, Any]],
    *,
    raw_evidence_bounded: bool,
    baseline_artifact_path: Path | None = None,
    scheme_path: Path | None = None,
) -> dict[str, bool]:
    """Recompute anti-gaming claims from independently checked records.

    The gate must not be able to turn a hard-coded ``True`` marker into an
    anti-gaming pass.  This function is deliberately fed the same records that
    the checker validates and is called by both producer and consumer.
    """
    reference = manifests["baselineReference"]
    baseline = manifests["baseline"]
    corpus_path = repo_root / "fixtures/evaluator/compatibility-corpus.json"
    oracle_path = repo_root / "fixtures/evaluator/oracles.json"
    scheme_path = scheme_path or (repo_root / "fixtures/evaluator/scheme-a-manifest.json")
    baseline_path = baseline_artifact_path or resolve_repo_path(repo_root, reference["baselineArtifactPath"], "baselineArtifactPath", require_file=True)
    baseline_identity = baseline.get("identity") if isinstance(baseline.get("identity"), Mapping) else {}
    unit_list = list(units)
    required_ids = {
        row["unitId"]
        for row in manifests["corpus"]["rows"]
        if row.get("required") and row.get("applicable")
    }
    observed_ids = [unit.get("unitId") for unit in unit_list]
    owner_markers = all(unit.get("statusOwner") == STATUS_OWNER for unit in unit_list)
    owner_markers = owner_markers and all(attempt.get("statusOwner") == STATUS_OWNER for attempt in attempts.values())
    identity_keys = [
        manifests["corpus"]["rows"][[row["unitId"] for row in manifests["corpus"]["rows"]].index(unit_id)]["identityKey"]
        for unit_id in compatibility.get("completeUnitIds", ())
    ]
    fixed_rows = [
        row for row in manifests["corpus"]["rows"]
        if row.get("unitId") in manifests["corpus"].get("fixedRowIds", ())
    ]
    frozen_baseline = baseline.get("baselineStatus") in {"baseline-zero", "measured"}
    corpus_unchanged = (
        len(fixed_rows) == 1
        and sha256_bytes(canonical_json(fixed_rows[0])) == FROZEN_V2_FIXED_ROW_SHA256
    ) if frozen_baseline else (
        (baseline.get("corpusManifestSha256") or baseline_identity.get("corpusManifestSha256")) == sha256_file(corpus_path)
    )
    return {
        "corpusUnchanged": corpus_unchanged,
        "oracleUnchanged": (baseline.get("oracleManifestSha256") or baseline_identity.get("oracleManifestSha256")) == sha256_file(oracle_path),
        "attackManifestUnchanged": (
            ((baseline.get("schemeManifestSha256") or baseline_identity.get("schemeManifestSha256")) == sha256_file(scheme_path))
            if scheme_path.resolve() == (repo_root / "fixtures/evaluator/scheme-a-manifest.json").resolve()
            else manifests["scheme"].get("parentManifestSha256") == sha256_file(repo_root / "fixtures/evaluator/scheme-a-manifest.json")
        ),
        "budgetsEqual": manifests["protocol"]["budgets"] == manifests["scheme"]["budget"],
        "baselineDigestMatches": sha256_file(baseline_path) == reference.get("baselineArtifactSha256"),
        "requiredRowsPresent": set(observed_ids) == required_ids and len(observed_ids) == len(set(observed_ids)),
        "noUnownedStatusMarkers": owner_markers,
        "noDuplicateIdentityCount": len(identity_keys) == len(set(identity_keys)),
        "rawEvidenceBounded": raw_evidence_bounded,
    }
