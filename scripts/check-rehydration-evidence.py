#!/usr/bin/env python3
"""Validate hash-bound Protected Image -> Native Image -> execveat evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
sys.dont_write_bytecode = True
from pathlib import Path, PureWindowsPath
from typing import Any

DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_FILES = 1000
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_SOURCE_IMAGE_BYTES = 128 * 1024 * 1024
MAX_NATIVE_IMAGE_BYTES = 128 * 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
UNIT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_file(
    root: Path,
    name: str,
    *,
    allow_empty: bool = False,
    max_bytes: int | None = None,
) -> Path:
    path = root / name
    if not path.is_file() or path.is_symlink() or (not allow_empty and path.stat().st_size == 0):
        fail(f"missing or invalid rehydration evidence file: {name}")
    if max_bytes is not None and path.stat().st_size > max_bytes:
        fail(f"rehydration evidence file exceeds its bound: {name}")
    return path


def read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_RECORD_BYTES:
        fail(f"evidence JSON exceeds its bound: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid evidence JSON {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"evidence record is not an object: {path.name}")
    return value


def safe_relative(value: str, label: str) -> Path:
    candidate = Path(value)
    windows = PureWindowsPath(value)
    if (
        not value
        or "\\" in value
        or candidate.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(part in {"", ".", ".."} for part in windows.parts)
    ):
        fail(f"{label} is not a safe relative evidence path: {value!r}")
    return candidate


def check_closed_manifest(root: Path) -> dict[str, str]:
    manifest = require_file(root, "SHA256SUMS")
    if manifest.stat().st_size > 16 * 1024 * 1024:
        fail("SHA256SUMS exceeds its configured bound")
    entries: dict[str, str] = {}
    total_bytes = 0
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or not DIGEST.fullmatch(fields[0]):
            fail(f"invalid SHA256SUMS entry at line {line_number}")
        relative = safe_relative(fields[1], f"SHA256SUMS:{line_number}")
        if relative.as_posix() in entries:
            fail(f"duplicate SHA256SUMS path: {relative.as_posix()}")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            fail(f"SHA256SUMS references a missing, symlink, or non-file path: {relative.as_posix()}")
        resolved = path.resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            fail(f"SHA256SUMS entry escapes the evidence root: {relative.as_posix()}")
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_TREE_BYTES or total_bytes > MAX_TREE_BYTES:
            fail("rehydration evidence exceeds the bounded tree size")
        actual = digest(path)
        if actual != fields[0]:
            fail(f"SHA256SUMS digest mismatch: {relative.as_posix()}")
        entries[relative.as_posix()] = actual

    files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            fail(f"evidence tree contains a symlink: {path.relative_to(root).as_posix()}")
        if path.is_file() and path != manifest:
            relative = path.relative_to(root).as_posix()
            if relative.endswith(".tmp") or ".tmp." in relative:
                fail(f"evidence tree retains a temporary file: {relative}")
            files.add(relative)
    if len(files) > MAX_FILES:
        fail("rehydration evidence file count exceeds its configured bound")
    if files != set(entries):
        fail(f"SHA256SUMS is not closed (missing={sorted(files - set(entries))}, extra={sorted(set(entries) - files)})")
    return entries


def require_digest(value: Any, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{label} is not a normalized SHA-256 digest")


def check_diagnostics(record: dict[str, Any], status: str) -> None:
    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, list) or len(diagnostics) > 128:
        fail("rehydration diagnostics are outside the bounded schema")
    if status == "failed" and not diagnostics:
        fail("failed rehydration stage has no diagnostic")
    for item in diagnostics:
        if not isinstance(item, dict):
            fail("rehydration diagnostic is malformed")
        for field, maximum in (("severity", 16), ("code", 128), ("message", 4096)):
            value = item.get(field)
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
                fail(f"rehydration diagnostic {field} is outside its bound")


def check_producer(root: Path, unit: str) -> tuple[dict[str, Any], dict[str, Any], bytes | None, bytes | None]:
    stage = read_json(require_file(root, "stage.json"))
    if stage.get("schemaVersion") != 1 or stage.get("stage") != "protected-image-producer":
        fail("producer stage schema or identity is unsupported")
    if stage.get("status") not in {"passed", "failed"}:
        fail("producer stage has an unsupported status")
    if stage.get("unitId") != unit:
        fail("producer stage unit does not match the requested unit")
    if stage.get("status") == "failed":
        if (root / "protected-image.bin").exists() or (root / "protected-image.json").exists():
            fail("failed producer stage retained a Protected Image success artifact")
        return stage, {}, None, None

    role = read_json(require_file(root, "protected-image.json"))
    artifact = require_file(root, "protected-image.bin", max_bytes=16 * 1024 * 1024)
    source_path = require_file(root, "source-image.bin", max_bytes=MAX_SOURCE_IMAGE_BYTES)
    source_bytes = source_path.read_bytes()
    artifact_bytes = artifact.read_bytes()
    if role.get("schemaVersion") != 1 or role.get("artifactRole") != "protected-image":
        fail("producer role is not a Protected Image v1 role record")
    if role.get("abiId") != "urprotect.protected-image.v1" or role.get("abiVersion") != 1:
        fail("producer role ABI identity is unsupported")
    if role.get("unitId") != unit or stage.get("unitId") != role.get("unitId"):
        fail("producer stage/role unit binding mismatch")
    if role.get("profile") != "outer-execveat" or stage.get("profile") != role.get("profile"):
        fail("producer stage/role profile binding mismatch")
    for field in ("sourceSha256", "requestSha256", "producerBuildSha256", "artifactSha256"):
        require_digest(role.get(field), f"producer role {field}")
    for field in ("sourceSha256", "requestSha256", "producerBuildSha256", "artifactSha256"):
        if role.get(field) != stage.get(field):
            fail(f"producer role/stage {field} binding mismatch")
    if digest(source_path) != role["sourceSha256"]:
        fail("retained Source Image hash does not match the producer record")
    if digest(artifact) != role["artifactSha256"] or role.get("artifactSize") != len(artifact_bytes):
        fail("Protected Image bytes do not match the producer role")
    if role.get("rehydratorConsumerId") != stage.get("rehydratorConsumerId"):
        fail("producer consumer binding mismatch")
    if artifact_bytes[:4] != b"UPPI" or len(artifact_bytes) < 52:
        fail("Protected Image is not a bounded ABI v1 artifact")
    if int.from_bytes(artifact_bytes[12:16], "little") != len(artifact_bytes):
        fail("Protected Image declared size does not match the retained artifact")
    if hashlib.sha256(artifact_bytes[:-32]).digest() != artifact_bytes[-32:]:
        fail("Protected Image canonical integrity digest mismatch")
    return stage, role, source_bytes, artifact_bytes


def check_rehydration(
    root: Path,
    unit: str,
    producer_stage: dict[str, Any],
    role: dict[str, Any],
    source: bytes | None,
    protected: bytes | None,
) -> tuple[dict[str, Any], str | None]:
    record = read_json(require_file(root, "rehydration.json"))
    if record.get("schemaVersion") != 1 or record.get("stage") != "rehydration":
        fail("rehydration stage schema or identity is unsupported")
    if record.get("status") not in {"passed", "failed"}:
        fail("rehydration stage has an unsupported status")
    if record.get("unitId") != unit:
        fail("rehydration unit binding mismatch")
    if (
        record.get("abiId") != "urprotect.protected-image.v1"
        or record.get("abiVersion") != 1
        or record.get("architecture") != "AArch64"
        or record.get("layoutStrategy") != "append-executable-pt-load-v1"
    ):
        fail("rehydration ABI, architecture, or layout binding is unsupported")
    check_diagnostics(record, record["status"])
    if record["status"] == "passed":
        if producer_stage.get("status") != "passed" or role == {} or source is None or protected is None:
            fail("rehydration passed without a passed producer and retained inputs")
        if record.get("firstFailureStage") is not None or record.get("materializationStatus") != "passed":
            fail("passed rehydration stage contains failure state")
        if record.get("handoffRecordPath") != "handoff.json" or record.get("rawEvidenceManifestPath") != "SHA256SUMS":
            fail("rehydration stage does not bind the handoff record and closed evidence manifest")
        handoff = read_json(require_file(root, "handoff.json"))
        require_digest(record.get("handoffRecordSha256"), "rehydration handoff record")
        require_digest(record.get("preHandoffRecordSha256"), "rehydration pre-handoff record")
        if record.get("handoffRecordSha256") != digest(root / "handoff.json"):
            fail("rehydration record does not bind the retained handoff record")
        if record.get("handoffStatus") != handoff.get("status"):
            fail("rehydration record handoff status differs from the handoff record")
        if handoff.get("rehydrationRecordSha256") != record.get("preHandoffRecordSha256"):
            fail("handoff record does not bind the pre-handoff rehydration record")
        bindings = {
            "profile": role["profile"],
            "sourceSha256": role["sourceSha256"],
            "requestSha256": role["requestSha256"],
            "protectedImageSha256": role["artifactSha256"],
            "protectedImageSize": role["artifactSize"],
            "producerId": role["producerId"],
            "producerBuildSha256": role["producerBuildSha256"],
            "consumerId": role["rehydratorConsumerId"],
        }
        for field, expected in bindings.items():
            if record.get(field) != expected:
                fail(f"rehydration {field} binding does not match the producer")
        for field in ("sourceSha256", "requestSha256", "protectedImageSha256", "producerBuildSha256", "consumerBuildSha256", "nativeImageSha256"):
            require_digest(record.get(field), f"rehydration {field}")
        native_path = require_file(root, "native-image.bin", max_bytes=MAX_NATIVE_IMAGE_BYTES)
        native_bytes = native_path.read_bytes()
        if len(native_bytes) > MAX_NATIVE_IMAGE_BYTES or len(native_bytes) != record.get("nativeImageSize"):
            fail("Native Image size is outside the bound or differs from the rehydration record")
        if digest(native_path) != record["nativeImageSha256"]:
            fail("Native Image hash differs from the rehydration record")
        if record["nativeImageSha256"] in {role["sourceSha256"], role["artifactSha256"]}:
            fail("Native Image aliases the Source or Protected Image")
        if native_bytes[:6] != b"\x7fELF\x02\x01" or len(native_bytes) < 64:
            fail("Native Image is not ELF64 little-endian")
        if int.from_bytes(native_bytes[18:20], "little") != 183:
            fail("Native Image is not AArch64")
        if native_bytes[16:18] not in {b"\x02\x00", b"\x03\x00"}:
            fail("Native Image type is not ET_EXEC or ET_DYN")
        native_role = read_json(require_file(root, "native-image.json"))
        if native_role.get("schemaVersion") != 1 or native_role.get("artifactRole") != "native-image":
            fail("Native Image role record is unsupported")
        if native_role.get("abiId") != "urprotect.native-image.v1" or native_role.get("abiVersion") != 1:
            fail("Native Image ABI identity is unsupported")
        if native_role.get("nativeImageSha256") != record["nativeImageSha256"] or native_role.get("nativeImageSize") != len(native_bytes):
            fail("Native Image role bytes do not match its rehydration record")
        if native_role.get("rehydrationRecordSha256") != digest(root / "rehydration.json"):
            fail("Native Image role does not bind the retained rehydration record")
        for field, expected in {
            "unitId": record["unitId"],
            "profile": record["profile"],
            "sourceSha256": record["sourceSha256"],
            "protectedImageSha256": record["protectedImageSha256"],
            "producerId": record["producerId"],
            "producerBuildSha256": record["producerBuildSha256"],
            "consumerId": record["consumerId"],
            "consumerBuildSha256": record["consumerBuildSha256"],
        }.items():
            if native_role.get(field) != expected:
                fail(f"Native Image role {field} binding mismatch")
        return record, record["nativeImageSha256"]

    if (root / "native-image.bin").exists() or (root / "native-image.json").exists():
        fail("failed rehydration stage retained a successful Native Image or role record")
    if producer_stage.get("status") == "passed" and role:
        bindings = {
            "profile": role["profile"],
            "sourceSha256": role["sourceSha256"],
            "requestSha256": role["requestSha256"],
            "protectedImageSha256": role["artifactSha256"],
            "protectedImageSize": role["artifactSize"],
            "producerId": role["producerId"],
            "producerBuildSha256": role["producerBuildSha256"],
            "consumerId": role["rehydratorConsumerId"],
        }
        for field, expected in bindings.items():
            if record.get(field) != expected:
                fail(f"failed rehydration {field} does not retain the producer binding")
    if record.get("nativeImageSha256") is not None or record.get("nativeImageSize") is not None:
        fail("failed rehydration record claims Native Image bytes")
    return record, None


def check_handoff(root: Path, rehydration: dict[str, Any], native_hash: str | None) -> tuple[dict[str, Any], str | None]:
    record = read_json(require_file(root, "handoff.json"))
    if record.get("schemaVersion") != 1 or record.get("stage") != "native-handoff":
        fail("native handoff record schema or stage is unsupported")
    if record.get("status") not in {"passed", "failed", "not-run"}:
        fail("native handoff record status is unsupported")
    if record["status"] == "passed":
        if rehydration.get("status") != "passed" or native_hash is None:
            fail("native handoff passed without a passed Native Image stage")
        for field in ("helperStatus", "loaderId", "fchmodStatus", "fsyncStatus", "execveatStatus"):
            if not isinstance(record.get(field), str):
                fail(f"native handoff is missing {field}")
        if record.get("helperStatus") != "passed" or record.get("helperExitCode") != 0:
            fail("native handoff helper status is not a successful helper result")
        if record.get("loaderId") != "kernel.execveat-at-empty-path":
            fail("strict native handoff used an unsupported loader boundary")
        if record.get("nativeImageSha256") != native_hash:
            fail("native handoff image hash does not match the Native Image")
        expected_rehydration_hash = rehydration.get("preHandoffRecordSha256") or digest(root / "rehydration.json")
        if record.get("rehydrationRecordSha256") != expected_rehydration_hash:
            fail("native handoff does not bind the retained rehydration record")
        for field in ("memfdCreated", "sealsSupported", "sealsApplied", "execveatInvoked"):
            if record.get(field) is not True:
                fail(f"strict native handoff did not prove {field}")
        if record.get("fchmodStatus") != "passed" or record.get("fsyncStatus") != "passed" or record.get("execveatStatus") != "passed":
            fail("strict native handoff setup or execveat failed")
        target_status = record.get("targetStatus")
        if not isinstance(target_status, int) or not 0 <= target_status <= 255 or record.get("targetSignal") is not None:
            fail("native handoff target status is malformed")
        stdout = require_file(root, "target.stdout", allow_empty=True, max_bytes=MAX_STREAM_BYTES).read_bytes()
        stderr = require_file(root, "target.stderr", allow_empty=True, max_bytes=MAX_STREAM_BYTES).read_bytes()
        if len(stdout) > MAX_STREAM_BYTES or len(stderr) > MAX_STREAM_BYTES:
            fail("native handoff captured streams exceed their output bounds")
        if record.get("stdoutBytes") != len(stdout) or record.get("stderrBytes") != len(stderr):
            fail("native handoff stream byte counts do not match retained streams")
        if record.get("stdoutTruncated") is not False or record.get("stderrTruncated") is not False:
            fail("native handoff streams were truncated on a passing target")
        return record, native_hash

    if record.get("status") == "not-run" and rehydration.get("status") == "passed":
        if record.get("execveatInvoked") is True:
            fail("not-run handoff record claims an execveat invocation")
    elif record.get("status") == "failed" and rehydration.get("status") == "failed":
        if record.get("execveatStatus") == "passed":
            fail("handoff stage passed after failed rehydration")
    if native_hash is not None and record.get("nativeImageSha256") not in {None, native_hash}:
        fail("failed handoff record is bound to a different Native Image")
    if record.get("rehydrationRecordSha256") is not None:
        final_rehydration_hash = digest(root / "rehydration.json")
        pre_handoff_hash = rehydration.get("preHandoffRecordSha256")
        if pre_handoff_hash is not None:
            require_digest(pre_handoff_hash, "rehydration pre-handoff record")
        allowed_rehydration_hashes = {final_rehydration_hash}
        if pre_handoff_hash is not None:
            allowed_rehydration_hashes.add(pre_handoff_hash)
        if record.get("rehydrationRecordSha256") not in allowed_rehydration_hashes:
            fail("handoff record is bound to a different rehydration record")
    return record, None


def check_target_loader(root: Path, handoff: dict[str, Any], handoff_hash: str | None, native_hash: str | None) -> dict[str, Any]:
    record = read_json(require_file(root, "target-loader.json"))
    if record.get("schemaVersion") != 1 or record.get("stage") != "target-loader":
        fail("target loader record schema or identity is unsupported")
    if record.get("status") not in {"passed", "failed", "not-run"}:
        fail("target loader record status is unsupported")
    if record.get("status") == "passed":
        if handoff.get("status") != "passed" or native_hash is None or handoff_hash is None:
            fail("target loader passed without a successful handoff")
        if record.get("loaderId") != "kernel.execveat-at-empty-path":
            fail("target loader record names an unsupported loader")
        if record.get("nativeImageSha256") != native_hash or record.get("evidenceSha256") != handoff_hash:
            fail("target loader does not bind the exact Native Image and handoff record")
        if record.get("targetStatus") != handoff.get("targetStatus") or record.get("targetSignal") != handoff.get("targetSignal"):
            fail("target loader target status differs from the handoff record")
        for stream_name, field in (("target.stdout", "stdoutSha256"), ("target.stderr", "stderrSha256")):
            if record.get(field) != digest(require_file(root, stream_name, allow_empty=True, max_bytes=MAX_STREAM_BYTES)):
                fail(f"target loader {field} does not bind its retained stream")
        return record
    if record.get("status") == "not-run" and handoff.get("status") == "passed":
        fail("target loader was marked not-run after a successful handoff")
    if native_hash is not None and record.get("nativeImageSha256") not in {None, native_hash}:
        fail("target loader failure record binds a different Native Image")
    return record


def check_behavior(
    root: Path,
    record: dict[str, Any],
    target_loader: dict[str, Any],
    source_hash: str | None,
    native_hash: str | None,
) -> dict[str, Any]:
    oracle = read_json(require_file(root, "behavioral-oracle.json"))
    if oracle.get("schemaVersion") != 1 or oracle.get("stage") != "behavioral-oracle":
        fail("behavioral oracle record schema or identity is unsupported")
    if oracle.get("status") not in {"passed", "failed", "not-run"}:
        fail("behavioral oracle status is unsupported")
    if oracle.get("status") == "passed":
        if target_loader.get("status") != "passed" or native_hash is None:
            fail("behavior oracle passed without a target loader pass")
        if oracle.get("oracleId") != "fixture.process-oracle.v1":
            fail("behavior oracle identity differs from the frozen fixture oracle")
        if oracle.get("sourceSha256") != source_hash or oracle.get("nativeImageSha256") != native_hash:
            fail("behavior oracle source or Native Image binding mismatch")
        if oracle.get("statusEqual") is False or oracle.get("stdoutEqual") is False or oracle.get("stderrEqual") is False:
            fail("behavior oracle report records a mismatch despite passing")
        if oracle.get("baselineStatus") != 0 or oracle.get("targetStatus") != 0:
            fail("behavior oracle status must match the frozen zero-exit result")
        comparison_path = require_file(root, "behavior-comparison.json")
        comparison = read_json(comparison_path)
        if digest(comparison_path) != oracle.get("comparisonSha256"):
            fail("behavior comparison digest does not match the oracle record")
        for field, value in (("sourceSha256", source_hash), ("nativeImageSha256", native_hash), ("oracleId", oracle["oracleId"])):
            if comparison.get(field) != value:
                fail(f"behavior comparison {field} binding mismatch")
        for baseline, target in (("baseline.stdout", "target.stdout"), ("baseline.stderr", "target.stderr")):
            if require_file(root, baseline, allow_empty=True, max_bytes=MAX_STREAM_BYTES).read_bytes() != require_file(root, target, allow_empty=True, max_bytes=MAX_STREAM_BYTES).read_bytes():
                fail("retained baseline and target streams differ")
        if not all(comparison.get(field) is True for field in ("statusEqual", "stdoutEqual", "stderrEqual")):
            fail("behavior comparison failed equivalence")
    elif oracle.get("status") == "not-run" and target_loader.get("status") == "passed":
        fail("behavioral oracle was not run after target loader success")
    if native_hash is not None and oracle.get("nativeImageSha256") not in {None, native_hash}:
        fail("behavior oracle failure binds a different Native Image")
    return oracle

def check_negative_witness(root: Path, unit: str) -> None:
    witness = read_json(require_file(root, "negative-rollback.json"))
    if (
        witness.get("schemaVersion") != 1
        or witness.get("kind") != "strict-chain-negative-witness"
        or witness.get("status") != "passed"
        or witness.get("unitId") != unit
        or witness.get("rollbackStatus") != "passed"
        or witness.get("nativeImagePublished") is not False
        or witness.get("loaderInvoked") is not False
        or witness.get("loaderMarkerObserved") is not False
        or witness.get("stage") not in {"protected-image", "rehydration", "native-image", "target-loader"}
        or not isinstance(witness.get("failureClass"), str)
        or not witness.get("failureClass")
    ):
        fail("negative rollback witness does not prove blocked/no-publication behavior")
    for field in ("artifactPath", "nativeImagePath", "loaderMarkerPath"):
        value = witness.get(field)
        if value is not None:
            try:
                safe_relative(value, f"negative witness {field}")
            except SystemExit:
                raise

def check_benchmark(root: Path, first_failure: str | None, native_hash: str | None) -> None:
    record = read_json(require_file(root, "benchmark.json"))
    if record.get("schemaVersion") != 1:
        fail("rehydration benchmark record schema is unsupported")
    if record.get("firstFailureStage") != first_failure:
        fail("benchmark first-failure stage differs from the observed evidence")
    for field in (
        "rehydrationCpuMilliseconds",
        "rehydrationDurationMilliseconds",
        "producerEmissionDurationMilliseconds",
        "nativeImageSize",
        "handoffDurationNanoseconds",
        "maxRssBytes",
    ):
        value = record.get(field)
        if value is not None and (not isinstance(value, int) or value < 0):
            fail(f"benchmark {field} is not a non-negative integer")
    if native_hash is None and record.get("nativeImageSize") is not None:
        fail("benchmark records a Native Image size without a Native Image")


def check_first_failure(
    producer: dict[str, Any],
    rehydration: dict[str, Any],
    handoff: dict[str, Any],
    target_loader: dict[str, Any],
    oracle: dict[str, Any],
) -> str | None:
    statuses = (
        producer.get("status"),
        rehydration.get("status"),
        handoff.get("status"),
        target_loader.get("status"),
        oracle.get("status"),
    )
    stage_names = (
        "protected-image-producer",
        "rehydration",
        "native-handoff",
        "target-loader",
        "behavioral-oracle",
    )
    first_index = next((index for index, status in enumerate(statuses) if status != "passed"), None)
    first_failure = None if first_index is None else stage_names[first_index]
    if first_index is not None and any(status == "passed" for status in statuses[first_index + 1 :]):
        fail("a later rehydration stage passed after the first failed stage")

    records = (rehydration, handoff, target_loader, oracle)
    for index, record in enumerate(records, 1):
        expected = None
        if first_index is not None and index >= first_index:
            expected = first_failure
        if record.get("firstFailureStage") != expected:
            fail(f"{stage_names[index]} first-failure binding differs from the observed stage order")
    return first_failure


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    parser.add_argument("--runtime", choices=("glibc",), required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--expect-failure", action="store_true")
    args = parser.parse_args()
    if not UNIT_PATTERN.fullmatch(args.unit):
        fail("rehydration unit is not a safe bounded identifier")
    root = args.artifact_root
    if root.is_symlink() or not root.is_dir():
        fail("rehydration artifact root is missing or a symlink")
    root = root.resolve()
    if root.name != args.unit:
        fail("rehydration evidence root does not end in the selected unit")
    manifest_entries = check_closed_manifest(root)
    producer_stage, role, source, protected = check_producer(root, args.unit)
    if producer_stage.get("status") == "passed":
        for name in ("stdout.txt", "stderr.txt"):
            require_file(root, name, allow_empty=True)
        for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr"):
            require_file(root, name, allow_empty=True)
    else:
        for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr"):
            require_file(root, name, allow_empty=True)

    rehydration, native_hash = check_rehydration(root, args.unit, producer_stage, role, source, protected)
    handoff, passed_handoff_hash = check_handoff(root, rehydration, native_hash)
    handoff_hash = digest(root / "handoff.json") if handoff.get("status") == "passed" else None
    target_loader = check_target_loader(root, handoff, handoff_hash, native_hash if handoff.get("status") == "passed" else None)
    source_hash = role.get("sourceSha256") if role else rehydration.get("sourceSha256")
    oracle = check_behavior(root, rehydration, target_loader, source_hash, native_hash if target_loader.get("status") == "passed" else None)
    if producer_stage.get("status") == "passed" and rehydration.get("status") == "passed":
        check_negative_witness(root, args.unit)
    first_failure = check_first_failure(producer_stage, rehydration, handoff, target_loader, oracle)
    check_benchmark(root, first_failure, native_hash)

    all_passed = all(
        record.get("status") == "passed"
        for record in (producer_stage, rehydration, handoff, target_loader, oracle)
    )
    if args.expect_failure and all_passed:
        fail("evidence unexpectedly completed all rehydration and handoff stages")
    if all_passed:
        print(f"PASS rehydration evidence: root={root} unit={args.unit} stages=producer,protected-image,rehydration,native-image,target-loader,behavioral-oracle")
    else:
        print(f"PASS rehydration failure evidence: root={root} unit={args.unit} firstFailureStage={first_failure}")
    del manifest_entries, passed_handoff_hash


if __name__ == "__main__":
    main()
