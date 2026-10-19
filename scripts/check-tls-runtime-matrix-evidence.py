#!/usr/bin/env python3
"""Validate the closed transformed TLS model/profile/runtime/lifecycle matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from tls_runtime_identity import verify_artifact_identity

DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_RECORD_BYTES = 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
MODELS = (
    "local-exec",
    "initial-exec",
    "local-dynamic",
    "general-dynamic",
    "tlsdesc",
)
PROFILES = ("outer-execveat", "host-context-entry")
RUNTIMES = ("glibc", "musl", "bionic")
LIFECYCLES = ("current-thread", "registered-worker")
EXPECTED_ROW_COUNT = 60
SOURCE_FIXTURES = {
    "local-exec": "native/urprotect-runtime/build/host-context-tlsle-fixture.so",
    "initial-exec": "native/urprotect-runtime/build/host-context-tls-fixture.so",
    "local-dynamic": "native/urprotect-runtime/build/host-context-tlsld-fixture.so",
    "general-dynamic": "native/urprotect-runtime/build/host-context-tlsgd-fixture.so",
    "tlsdesc": "native/urprotect-runtime/build/host-context-tlsdesc-fixture.so",
}
PROMOTED_ROWS = (
    "general-dynamic.host-context-entry.glibc.current-thread",
    "initial-exec.host-context-entry.glibc.current-thread",
    "local-dynamic.host-context-entry.glibc.current-thread",
    "tlsdesc.host-context-entry.glibc.current-thread",
)
RESULTS = (
    "accepted-and-runs",
    "environment-unavailable",
    "runtime-failure",
    "not-applicable",
)
ROW_FIELDS = {
    "schemaVersion",
    "rowId",
    "model",
    "sourceFixture",
    "profile",
    "runtime",
    "lifecycle",
    "result",
    "reason",
    "managedStatus",
    "loaderStatus",
    "toolchainIdentity",
    "loaderIdentity",
    "sourceSha256",
    "protectedSha256",
    "nativeSha256",
    "expectedEntryStatus",
    "runtimeVersion",
    "runtimeIdentitySha256",
    "libcPath",
    "libcSha256",
    "loaderPath",
    "loaderSha256",
    "behavioralOracleSha256",
    "behaviorComparisonSha256",
    "ptTls",
    "perThread",
    "zeroFill",
    "lifecycleOrder",
    "firstFailureStage",
    "publicationResult",
    "rollbackResult",
    "evidencePaths",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{label} is not a safe relative path")
    candidate = root / value
    if candidate.is_symlink():
        fail(f"{label} is not a retained regular file")
    path = candidate.resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes evidence root")
    if not path.is_file():
        fail(f"{label} is not a retained regular file")
    return path


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{label} is not a normalized SHA-256 digest")
    return value


def check_closed_manifest(root: Path) -> None:
    manifest = root / "SHA256SUMS"
    if not manifest.is_file() or manifest.is_symlink():
        fail("TLS runtime evidence SHA256SUMS is missing")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or not DIGEST.fullmatch(parts[0]):
            fail(f"invalid TLS SHA256SUMS entry at line {line_number}")
        relative = parts[1]
        path = Path(relative)
        if path.is_absolute() or "\\" in relative or ".." in path.parts:
            fail(f"TLS SHA256SUMS path escapes the evidence root: {relative}")
        target = root / path
        if target.is_symlink() or not target.is_file():
            fail(f"TLS SHA256SUMS path is missing or special: {relative}")
        if relative in entries or digest(target) != parts[0]:
            fail(f"TLS SHA256SUMS digest mismatch or duplicate: {relative}")
        entries[relative] = parts[0]
    files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest
    }
    if files != set(entries):
        fail(f"TLS SHA256SUMS is not closed (missing={sorted(files - set(entries))}, extra={sorted(set(entries) - files)})")


def expected_rows(registry: dict[str, Any]) -> dict[str, tuple[str, str, str, str]]:
    rows = {}
    for model in registry["models"]:
        for profile in registry["profiles"]:
            for runtime in registry["runtimes"]:
                for lifecycle in registry["lifecycles"]:
                    row_id = f"{model}.{profile}.{runtime}.{lifecycle}"
                    rows[row_id] = (model, profile, runtime, lifecycle)
    return rows


def read_json_bounded(path: Path, label: str) -> dict[str, Any]:
    if path.stat().st_size > MAX_RECORD_BYTES:
        fail(f"{label} exceeds its bounded JSON size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def _entry_process_status(entry_status: int) -> int:
    return 1 if entry_status < 0 else 255 if entry_status > 255 else entry_status


def check_behavioral_oracle(
    root: Path,
    row: dict[str, Any],
    by_name: dict[str, Path],
) -> None:
    row_id = row["rowId"]
    required = {
        "source-handoff.json",
        "handoff.json",
        "behavior-comparison.json",
        "behavioral-oracle.json",
        "baseline.stdout",
        "baseline.stderr",
        "target.stdout",
        "target.stderr",
    }
    missing = sorted(required - set(by_name))
    if missing:
        fail(f"{row_id}: behavioral oracle inputs are missing: {missing}")
    source_handoff_path = by_name["source-handoff.json"]
    target_handoff_path = by_name["handoff.json"]
    comparison_path = by_name["behavior-comparison.json"]
    oracle_path = by_name["behavioral-oracle.json"]
    source_handoff = read_json_bounded(source_handoff_path, f"{row_id}.source-handoff")
    target_handoff = read_json_bounded(target_handoff_path, f"{row_id}.target-handoff")
    comparison = read_json_bounded(comparison_path, f"{row_id}.behavior-comparison")
    oracle = read_json_bounded(oracle_path, f"{row_id}.behavioral-oracle")
    streams = {
        name: by_name[name].read_bytes()
        for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr")
    }
    if any(len(data) > MAX_STREAM_BYTES for data in streams.values()):
        fail(f"{row_id}: retained baseline/target stream exceeds its bound")

    for name, record, expected_hash in (
        ("source", source_handoff, row["sourceSha256"]),
        ("target", target_handoff, row["nativeSha256"]),
    ):
        if (
            record.get("schemaVersion") != 1
            or record.get("stage") != "host-context-handoff"
            or record.get("status") != "passed"
            or record.get("loaderId") != "host-context.sealed-memfd.dlopen"
            or record.get("nativeImageSha256") != expected_hash
            or record.get("entrySymbol") != "urp_entry"
            or not isinstance(record.get("entryStatus"), int)
            or isinstance(record.get("entryStatus"), bool)
            or record.get("releaseStatus") != "passed"
            or record.get("releaseOrder") != "entry-dispatch-before-release-image"
            or record.get("firstFailureStage") is not None
            or type(record.get("processStatus")) is not int
            or not 0 <= record["processStatus"] <= 255
            or record["processStatus"] != _entry_process_status(record["entryStatus"])
        ):
            fail(f"{row_id}: {name} handoff lacks measured process/entry/release evidence")

    source_handoff_sha = digest(source_handoff_path)
    target_handoff_sha = digest(target_handoff_path)
    baseline_stdout_sha = hashlib.sha256(streams["baseline.stdout"]).hexdigest()
    baseline_stderr_sha = hashlib.sha256(streams["baseline.stderr"]).hexdigest()
    target_stdout_sha = hashlib.sha256(streams["target.stdout"]).hexdigest()
    target_stderr_sha = hashlib.sha256(streams["target.stderr"]).hexdigest()
    source_process = source_handoff["processStatus"]
    target_process = target_handoff["processStatus"]
    source_entry = source_handoff["entryStatus"]
    target_entry = target_handoff["entryStatus"]
    expected_entry = row.get("expectedEntryStatus")
    if type(expected_entry) is not int or not 0 <= expected_entry <= 255 or source_entry != expected_entry or target_entry != expected_entry:
        fail(f"{row_id}: observed entry statuses do not match the row-specific expected nonzero semantics")
    status_equal = (
        source_handoff["status"] == target_handoff["status"]
        and source_process == target_process
        and source_entry == target_entry
        and source_handoff["releaseStatus"] == target_handoff["releaseStatus"]
    )
    stdout_equal = streams["baseline.stdout"] == streams["target.stdout"]
    stderr_equal = streams["baseline.stderr"] == streams["target.stderr"]
    observed = {
        "schemaVersion": 1,
        "unitId": row_id,
        "oracleId": "fixture.host-context-entry.v1",
        "sourceSha256": row["sourceSha256"],
        "protectedSha256": row["protectedSha256"],
        "nativeImageSha256": row["nativeSha256"],
        "sourceHandoffSha256": source_handoff_sha,
        "targetHandoffSha256": target_handoff_sha,
        "sourceProcessStatus": source_process,
        "targetProcessStatus": target_process,
        "sourceEntryStatus": source_entry,
        "targetEntryStatus": target_entry,
        "sourceReleaseStatus": source_handoff["releaseStatus"],
        "targetReleaseStatus": target_handoff["releaseStatus"],
        "baselineStdoutSha256": baseline_stdout_sha,
        "baselineStderrSha256": baseline_stderr_sha,
        "targetStdoutSha256": target_stdout_sha,
        "targetStderrSha256": target_stderr_sha,
        "statusEqual": status_equal,
        "stdoutEqual": stdout_equal,
        "stderrEqual": stderr_equal,
    }
    if comparison != observed:
        fail(f"{row_id}: behavioral comparison does not match recomputed retained observations")
    comparison_sha = digest(comparison_path)
    if row.get("behaviorComparisonSha256") != comparison_sha:
        fail(f"{row_id}: matrix behavior comparison digest mismatch")
    expected_oracle = {
        **observed,
        "stage": "behavioral-oracle",
        "status": "passed" if status_equal and stdout_equal and stderr_equal else "failed",
        "comparisonSha256": comparison_sha,
        "baselineStatus": source_process,
        "targetStatus": target_process,
        "entryStatus": target_entry,
        "expectedEntryStatus": expected_entry,
        "firstFailureStage": None if status_equal and stdout_equal and stderr_equal else "behavioral-oracle",
    }
    if oracle != expected_oracle:
        fail(f"{row_id}: behavioral oracle is not derived from measured handoff/stream evidence")
    if row.get("behavioralOracleSha256") != digest(oracle_path):
        fail(f"{row_id}: matrix behavioral oracle digest mismatch")
    if oracle["status"] != "passed":
        fail(f"{row_id}: accepted row has a failing source-vs-transformed oracle")


def check_stage_tls_binding(
    stage_record: dict[str, Any],
    row: dict[str, Any],
    runtime_identity: dict[str, Any],
) -> dict[str, Any]:
    row_id = row["rowId"]
    profile = row["profile"]
    stage_tls = stage_record.get("tlsEvidence")
    if not isinstance(stage_tls, dict):
        fail(f"{row_id}: accepted stage lacks bound tlsEvidence")
    if (
        stage_record.get("profile") != profile
        or stage_tls.get("model") != row["model"]
        or stage_tls.get("runtime") != row["runtime"]
        or stage_tls.get("profile") != profile
        or stage_tls.get("lifecycle") != row["lifecycle"]
        or stage_tls.get("sourceSha256") != row["sourceSha256"]
        or stage_tls.get("artifactSha256") != row["protectedSha256"]
        or stage_tls.get("transformedSha256") != row["protectedSha256"]
        or stage_tls.get("nativeImageSha256") != row["nativeSha256"]
        or stage_tls.get("runtimeIdentitySha256") != row["runtimeIdentitySha256"]
        or stage_tls.get("expectedEntryStatus") != row["expectedEntryStatus"]
        or stage_tls.get("runtimeIdentity") != runtime_identity
        or stage_tls.get("sourcePath") != "source-image.bin"
        or stage_tls.get("artifactPath") != "protected-image.bin"
        or stage_tls.get("nativeImagePath") != "native-image.bin"
        or stage_tls.get("zeroFill") != row["zeroFill"]
        or stage_tls.get("perThread") != row["perThread"]
    ):
        fail(f"{row_id}: nested stage TLS model/runtime/profile/lifecycle/hash binding differs from the row")
    return stage_tls


def check_pt_tls(root: Path, value: Any, row_id: str) -> None:
    if not isinstance(value, dict):
        fail(f"{row_id}: ptTls is not an object")
    required = {
        "templatePath",
        "templateSha256",
        "fileSize",
        "memorySize",
        "zeroFillSize",
        "alignment",
        "owningLoad",
    }
    if set(value) != required:
        fail(f"{row_id}: ptTls fields do not match the bounded contract")
    template = safe_path(root, value["templatePath"], f"{row_id}.ptTls.templatePath")
    if require_digest(value["templateSha256"], f"{row_id}.ptTls.templateSha256") != digest(template):
        fail(f"{row_id}: PT_TLS template hash mismatch")
    numbers = ("fileSize", "memorySize", "zeroFillSize", "alignment", "owningLoad")
    for field in numbers:
        if type(value[field]) is not int or value[field] < 0:
            fail(f"{row_id}: PT_TLS {field} is outside its bound")
    if template.stat().st_size != value["fileSize"]:
        fail(f"{row_id}: PT_TLS template size mismatch")
    if value["fileSize"] > value["memorySize"]:
        fail(f"{row_id}: PT_TLS file size exceeds memory size")
    if value["memorySize"] - value["fileSize"] != value["zeroFillSize"]:
        fail(f"{row_id}: PT_TLS zero-fill mismatch")
    if value["alignment"] == 0 or value["alignment"] & (value["alignment"] - 1):
        fail(f"{row_id}: PT_TLS alignment is not a positive power of two")


def check_row(
    root: Path,
    row: dict[str, Any],
    expected: tuple[str, str, str, str],
    runtime_identity: dict[str, Any],
) -> None:
    row_id = row.get("rowId")
    if not isinstance(row_id, str) or row_id not in expected_rows_cache:
        fail(f"unknown TLS matrix row: {row_id!r}")
    if set(row) != ROW_FIELDS:
        fail(f"{row_id}: row fields do not match the bounded contract")
    model, profile, runtime, lifecycle = expected
    if (row["model"], row["profile"], row["runtime"], row["lifecycle"]) != expected:
        fail(f"{row_id}: row identity does not match rowId")
    if row["sourceFixture"] != SOURCE_FIXTURES[model]:
        fail(f"{row_id}: source fixture is not the declared model-specific fixture")
    if row["schemaVersion"] != 1 or row["result"] not in RESULTS:
        fail(f"{row_id}: unsupported schema or result")
    for field in ("reason", "managedStatus", "loaderStatus", "toolchainIdentity", "loaderIdentity", "lifecycleOrder", "publicationResult", "rollbackResult"):
        if not isinstance(row[field], str) or not row[field] or len(row[field].encode()) > 512:
            fail(f"{row_id}: {field} is outside its bound")
    if runtime == "glibc":
        for field, expected_value in (
            ("runtimeVersion", runtime_identity["version"]),
            ("runtimeIdentitySha256", runtime_identity["identitySha256"]),
            ("libcPath", runtime_identity["libcPath"]),
            ("libcSha256", runtime_identity["libcSha256"]),
            ("loaderPath", runtime_identity["loaderPath"]),
            ("loaderSha256", runtime_identity["loaderSha256"]),
        ):
            if row[field] != expected_value:
                fail(f"{row_id}: {field} does not bind the retained native glibc identity")
    elif any(row[field] is not None for field in ("runtimeVersion", "runtimeIdentitySha256", "libcPath", "libcSha256", "loaderPath", "loaderSha256")):
        fail(f"{row_id}: non-glibc row may not borrow the host glibc identity")
    if not isinstance(row["evidencePaths"], list) or not row["evidencePaths"] or len(row["evidencePaths"]) > 32:
        fail(f"{row_id}: evidencePaths is outside its bound")
    evidence_paths: list[Path] = []
    for index, value in enumerate(row["evidencePaths"]):
        evidence_paths.append(safe_path(root, value, f"{row_id}.evidencePaths[{index}]"))
    if len({path.relative_to(root) for path in evidence_paths}) != len(evidence_paths):
        fail(f"{row_id}: evidencePaths contains duplicates")
    source_paths = [path for path in evidence_paths if path.name == "source-image.bin"]
    if len(source_paths) != 1:
        fail(f"{row_id}: evidencePaths must include exactly one source-image.bin")
    source_path = source_paths[0]
    native_paths = [path for path in evidence_paths if path.name == "native-preflight.json"]
    if len(native_paths) != 1:
        fail(f"{row_id}: evidencePaths must include exactly one native-preflight.json")
    semantic_paths = [path for path in evidence_paths if path.name == "managed-semantic-gate.txt"]
    if len(semantic_paths) != 1 or "Passed!" not in semantic_paths[0].read_text(encoding="utf-8"):
        fail(f"{row_id}: managed semantic gate evidence is missing or failed")
    native = json.loads(native_paths[0].read_text(encoding="utf-8"))
    require_digest(row["sourceSha256"], f"{row_id}.sourceSha256")
    if row["sourceSha256"] != digest(source_path):
        fail(f"{row_id}: source hash mismatch")
    if (
        native.get("processStatus") != 0
        or native.get("status") != 0
        or native.get("rowId") != row_id
        or native.get("sourceFixture") != row["sourceFixture"]
        or native.get("sourceSha256") != row["sourceSha256"]
    ):
        fail(f"{row_id}: native TLS preflight is not bound to this row's source fixture and hash")
    for field in ("protectedSha256", "nativeSha256"):
        if row[field] is not None and (not isinstance(row[field], str) or not DIGEST.fullmatch(row[field])):
            fail(f"{row_id}: {field} is not null or a digest")
    check_pt_tls(root, row["ptTls"], row_id)
    for field in ("perThread", "zeroFill"):
        if row[field] not in {"observed", "not-run", "not-applicable"}:
            fail(f"{row_id}: {field} observation is unsupported")
    if not isinstance(row["lifecycleOrder"], str) or not row["lifecycleOrder"] or len(row["lifecycleOrder"].encode()) > 512:
        fail(f"{row_id}: lifecycleOrder is outside its bounded text contract")
    if row["result"] == "accepted-and-runs":
        required_names = {
            "source-image.bin",
            "protected-image.bin",
            "native-image.bin",
            "pt-tls-template.bin",
            "tls-template.bin",
            "native-preflight.json",
            "managed-semantic-gate.txt",
            "stage.json",
            "rehydration.json",
            "handoff.json",
            "source-handoff.json",
            "baseline.stdout",
            "baseline.stderr",
            "target.stdout",
            "target.stderr",
            "behavior-comparison.json",
            "behavioral-oracle.json",
        }
        by_name = {path.name: path for path in evidence_paths}
        if any(sum(path.name == name for path in evidence_paths) != 1 for name in required_names):
            fail(f"{row_id}: accepted row must bind exactly one copy of each required evidence artifact")
        missing_names = sorted(required_names - set(by_name))
        if missing_names:
            fail(f"{row_id}: accepted row is missing retained lifecycle evidence: {missing_names}")
        stage_record = read_json_bounded(by_name["stage.json"], f"{row_id}.stage")
        rehydration_record = read_json_bounded(by_name["rehydration.json"], f"{row_id}.rehydration")
        handoff_record = read_json_bounded(by_name["handoff.json"], f"{row_id}.handoff")
        behavior_record = read_json_bounded(by_name["behavior-comparison.json"], f"{row_id}.behavior-comparison")
        stage_tls = check_stage_tls_binding(stage_record, row, runtime_identity)
        if (
            stage_record.get("status") != "passed"
            or stage_record.get("unitId") != row_id
            or stage_record.get("sourceSha256") != row["sourceSha256"]
            or stage_record.get("artifactSha256") != row["protectedSha256"]
            or rehydration_record.get("status") != "passed"
            or rehydration_record.get("unitId") != row_id
            or rehydration_record.get("nativeImageSha256") != row["nativeSha256"]
            or handoff_record.get("status") != "passed"
            or handoff_record.get("nativeImageSha256") != row["nativeSha256"]
            or behavior_record.get("unitId") != row_id
            or behavior_record.get("sourceSha256") != row["sourceSha256"]
            or behavior_record.get("nativeImageSha256") != row["nativeSha256"]
            or behavior_record.get("statusEqual") is not True
            or behavior_record.get("stdoutEqual") is not True
            or behavior_record.get("stderrEqual") is not True
            or row["expectedEntryStatus"] is None
        ):
            fail(f"{row_id}: accepted row lifecycle evidence is not hash/status bound")
        if row["protectedSha256"] != digest(by_name["protected-image.bin"]):
            fail(f"{row_id}: protected artifact hash does not match retained evidence")
        tls_template = by_name["tls-template.bin"]
        if (
            stage_tls.get("ptTls", {}).get("templatePath") != "tls-template.bin"
            or stage_tls.get("ptTls", {}).get("templateSha256") != digest(tls_template)
            or stage_tls.get("ptTls", {}).get("fileSize") != row["ptTls"].get("fileSize")
            or stage_tls.get("ptTls", {}).get("memorySize") != row["ptTls"].get("memorySize")
            or stage_tls.get("ptTls", {}).get("zeroFillSize") != row["ptTls"].get("zeroFillSize")
        ):
            fail(f"{row_id}: retained stage PT_TLS template facts differ from the row")
        if row["nativeSha256"] != digest(by_name["native-image.bin"]):
            fail(f"{row_id}: native artifact hash does not match retained evidence")
        if row["protectedSha256"] == row["sourceSha256"] or row["nativeSha256"] in {row["sourceSha256"], row["protectedSha256"]}:
            fail(f"{row_id}: accepted row aliases source/protected/native artifacts")
        if row["protectedSha256"] is None or row["nativeSha256"] is None:
            fail(f"{row_id}: accepted row lacks protected/native hashes")
        if row["runtime"] not in RUNTIMES:
            fail(f"{row_id}: accepted row has unsupported runtime")
        if row["perThread"] != "observed":
            fail(f"{row_id}: accepted row lacks a current-thread observation")
        expected_zero_fill = "not-run" if row["ptTls"]["zeroFillSize"] > 0 else "not-applicable"
        if row["zeroFill"] != expected_zero_fill:
            fail(f"{row_id}: zero-fill status overstates observations of uninitialized TLS storage")
        check_behavioral_oracle(root, row, by_name)
        if row["publicationResult"] != "published" or row["rollbackResult"] != "not-applicable":
            fail(f"{row_id}: accepted row has invalid publication/rollback")
        if row["firstFailureStage"] is not None:
            fail(f"{row_id}: accepted row has a failure stage")
    elif row["result"] == "environment-unavailable":
        if row["firstFailureStage"] != "environment":
            fail(f"{row_id}: environment row lacks environment first failure")
        if row["protectedSha256"] is not None or row["nativeSha256"] is not None:
            fail(f"{row_id}: environment row must not invent runtime artifact hashes")
        if row["perThread"] != "not-run" or row["zeroFill"] != "not-run":
            fail(f"{row_id}: environment row claims observations")
        if row["publicationResult"] != "not-published" or row["rollbackResult"] != "not-applicable":
            fail(f"{row_id}: environment row has invalid publication/rollback")
    elif row["result"] == "not-applicable":
        if row["firstFailureStage"] not in {"scope", "semantic"}:
            fail(f"{row_id}: not-applicable row lacks scope/semantic reason")
        if row["publicationResult"] != "not-published":
            fail(f"{row_id}: not-applicable row claims publication")
    else:
        if row["firstFailureStage"] in {None, "environment"}:
            fail(f"{row_id}: runtime-failure lacks a runtime failure stage")


expected_rows_cache: dict[str, tuple[str, str, str, str]] = {}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--registry", type=Path, default=Path("fixtures/tls-runtime-matrix.json"))
    args = parser.parse_args()
    root = args.artifact_root.resolve()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    if registry.get("schemaVersion") != 1:
        fail("TLS runtime registry schema is unsupported")
    if tuple(registry.get("models", ())) != MODELS or tuple(registry.get("profiles", ())) != PROFILES:
        fail("TLS runtime registry model/profile set drifted")
    if registry.get("sourceFixtures") != SOURCE_FIXTURES:
        fail("TLS runtime registry sourceFixtures drifted from the bounded model-to-fixture contract")
    if tuple(registry.get("runtimes", ())) != RUNTIMES or tuple(registry.get("lifecycles", ())) != LIFECYCLES:
        fail("TLS runtime registry runtime/lifecycle set drifted")
    global expected_rows_cache
    expected_rows_cache = expected_rows(registry)
    check_closed_manifest(root)
    manifest = root / "matrix.json"
    if not manifest.is_file() or manifest.is_symlink():
        fail("TLS runtime matrix manifest is missing")
    environment_path = root / "environment.json"
    if not environment_path.is_file() or environment_path.is_symlink():
        fail("TLS runtime environment identity is missing")
    environment = read_json_bounded(environment_path, "TLS runtime environment")
    runtime_identity = verify_artifact_identity(environment.get("runtimeIdentity"))
    if environment.get("architecture") not in {"aarch64", "arm64"} or runtime_identity["architecture"] != environment.get("architecture"):
        fail("TLS environment architecture does not match the measured glibc runtime")
    document = read_json_bounded(manifest, "TLS runtime matrix")
    if document.get("schemaVersion") != 1 or document.get("kind") != "tls-runtime-evidence":
        fail("TLS runtime evidence manifest schema is unsupported")
    rows = document.get("rows")
    if document.get("registry") != "fixtures/tls-runtime-matrix.json":
        fail("TLS runtime evidence is not bound to the checked-in registry")
    if not isinstance(rows, list) or len(rows) != EXPECTED_ROW_COUNT or len(rows) != len(expected_rows_cache):
        fail(f"TLS runtime matrix must contain exactly {EXPECTED_ROW_COUNT} rows")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            fail("TLS runtime row is not an object")
        row_id = row.get("rowId")
        if not isinstance(row_id, str) or row_id not in expected_rows_cache:
            fail(f"unknown TLS runtime row: {row_id!r}")
        if row_id in seen:
            fail(f"duplicate TLS runtime row: {row_id}")
        seen.add(row_id)
        check_row(root, row, expected_rows_cache[row_id], runtime_identity)
    missing = sorted(set(expected_rows_cache) - seen)
    if missing:
        fail(f"TLS runtime matrix is missing rows: {missing}")
    promoted_rows_value = registry.get("promotedRows")
    if (
        not isinstance(promoted_rows_value, list)
        or promoted_rows_value != list(PROMOTED_ROWS)
        or registry.get("controlRow") != "initial-exec.host-context-entry.glibc.current-thread"
    ):
        fail("TLS runtime registry must promote exactly the four glibc HostContext current-thread models")
    if (
        environment.get("architecture") not in {"aarch64", "arm64"}
        or environment.get("controlRow") != registry["controlRow"]
        or environment.get("promotedRows") != list(PROMOTED_ROWS)
    ):
        fail("TLS environment identity does not bind the required native-AArch64 promoted rows")
    accepted = {row["rowId"] for row in rows if row["result"] == "accepted-and-runs"}
    if accepted != set(PROMOTED_ROWS):
        fail(f"TLS runtime matrix promoted rows drifted: {sorted(accepted)}")
    print(f"TLS runtime evidence valid: {len(rows)} rows")


if __name__ == "__main__":
    main()
