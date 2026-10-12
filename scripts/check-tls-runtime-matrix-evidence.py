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

DIGEST = re.compile(r"^[0-9a-f]{64}$")
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
    path = (root / value).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes evidence root")
    if path.is_symlink() or not path.is_file():
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


def check_row(root: Path, row: dict[str, Any], expected: tuple[str, str, str, str]) -> None:
    row_id = row.get("rowId")
    if not isinstance(row_id, str) or row_id not in expected_rows_cache:
        fail(f"unknown TLS matrix row: {row_id!r}")
    if set(row) != ROW_FIELDS:
        fail(f"{row_id}: row fields do not match the bounded contract")
    model, profile, runtime, lifecycle = expected
    if (row["model"], row["profile"], row["runtime"], row["lifecycle"]) != expected:
        fail(f"{row_id}: row identity does not match rowId")
    if row["schemaVersion"] != 1 or row["result"] not in RESULTS:
        fail(f"{row_id}: unsupported schema or result")
    for field in ("reason", "managedStatus", "loaderStatus", "toolchainIdentity", "loaderIdentity", "lifecycleOrder", "publicationResult", "rollbackResult"):
        if not isinstance(row[field], str) or not row[field] or len(row[field].encode()) > 512:
            fail(f"{row_id}: {field} is outside its bound")
    if not isinstance(row["evidencePaths"], list) or not row["evidencePaths"] or len(row["evidencePaths"]) > 32:
        fail(f"{row_id}: evidencePaths is outside its bound")
    evidence_paths: list[Path] = []
    for index, value in enumerate(row["evidencePaths"]):
        evidence_paths.append(safe_path(root, value, f"{row_id}.evidencePaths[{index}]"))
    if len({path.relative_to(root) for path in evidence_paths}) != len(evidence_paths):
        fail(f"{row_id}: evidencePaths contains duplicates")
    source_path = evidence_paths[0]
    native_paths = [path for path in evidence_paths if path.name == "native-preflight.json"]
    if len(native_paths) != 1:
        fail(f"{row_id}: evidencePaths must include exactly one native-preflight.json")
    semantic_paths = [path for path in evidence_paths if path.name == "managed-semantic-gate.txt"]
    if len(semantic_paths) != 1 or "Passed!" not in semantic_paths[0].read_text(encoding="utf-8"):
        fail(f"{row_id}: managed semantic gate evidence is missing or failed")
    native = json.loads(native_paths[0].read_text(encoding="utf-8"))
    if native.get("processStatus") != 0 or native.get("status") != 0:
        fail(f"{row_id}: native PT_TLS preflight did not accept the common source fixture")
    require_digest(row["sourceSha256"], f"{row_id}.sourceSha256")
    if row["sourceSha256"] != digest(source_path):
        fail(f"{row_id}: source hash mismatch")
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
        if row["protectedSha256"] is None or row["nativeSha256"] is None:
            fail(f"{row_id}: accepted row lacks protected/native hashes")
        if row["runtime"] not in RUNTIMES:
            fail(f"{row_id}: accepted row has unsupported runtime")
        if any(row[field] != "observed" for field in ("perThread", "zeroFill")):
            fail(f"{row_id}: accepted row lacks TLS observations")
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
    if tuple(registry.get("runtimes", ())) != RUNTIMES or tuple(registry.get("lifecycles", ())) != LIFECYCLES:
        fail("TLS runtime registry runtime/lifecycle set drifted")
    global expected_rows_cache
    expected_rows_cache = expected_rows(registry)
    check_closed_manifest(root)
    manifest = root / "matrix.json"
    if not manifest.is_file():
        fail("TLS runtime matrix manifest is missing")
    document = json.loads(manifest.read_text(encoding="utf-8"))
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
        check_row(root, row, expected_rows_cache[row_id])
    missing = sorted(set(expected_rows_cache) - seen)
    if missing:
        fail(f"TLS runtime matrix is missing rows: {missing}")
    accepted = {row["rowId"] for row in rows if row["result"] == "accepted-and-runs"}
    if accepted != {registry["controlRow"]}:
        fail(f"TLS runtime matrix promoted rows drifted: {sorted(accepted)}")
    print(f"TLS runtime evidence valid: {len(rows)} rows")


if __name__ == "__main__":
    main()
