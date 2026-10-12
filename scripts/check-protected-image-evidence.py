#!/usr/bin/env python3
"""Validate the closed evidence tree emitted by protect-image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")
TLS_MODELS = frozenset({"local-exec", "initial-exec", "local-dynamic", "general-dynamic", "tlsdesc"})
TLS_PROFILES = frozenset({"outer-execveat", "host-context-entry"})
TLS_RESULTS = frozenset({"accepted-and-runs", "environment-unavailable", "runtime-failure"})
TLS_LIFECYCLES = frozenset({"current-thread", "registered-worker", "not-run"})
TLS_OBSERVATIONS = frozenset({"observed", "not-run", "not-applicable"})
TLS_MAX_SEGMENT_SIZE = 128 * 1024 * 1024
TLS_MAX_PROGRAM_HEADER_INDEX = (1 << 31) - 1
TLS_EVIDENCE_FIELDS = frozenset({
    "schemaVersion",
    "model",
    "profile",
    "runtime",
    "lifecycle",
    "result",
    "sourcePath",
    "sourceSha256",
    "transformedPath",
    "transformedSha256",
    "artifactPath",
    "artifactSha256",
    "toolchainIdentity",
    "loaderIdentity",
    "ptTls",
    "perThread",
    "zeroFill",
    "teardown",
    "firstFailureStage",
    "publicationResult",
    "rollbackResult",
})
TLS_PT_TLS_FIELDS = frozenset({
    "templatePath",
    "templateSha256",
    "fileSize",
    "memorySize",
    "zeroFillSize",
    "alignment",
    "owningLoad",
})


def fail(message: str) -> None:
    raise SystemExit(message)


def require_file(root: Path, name: str, allow_empty: bool = False) -> Path:
    path = root / name
    if path.is_symlink() or not path.is_file() or (not allow_empty and path.stat().st_size == 0):
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
        target_path = manifest_path.parent / relative
        if target_path.is_symlink():
            fail(f"SHA256SUMS entry references a symlink: {parts[1]}")
        target = target_path.resolve()
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

    files = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            fail(f"evidence tree contains a symlink: {path.relative_to(root)}")
        if path.is_file() and path.resolve() != manifest_path.resolve():
            files.add(path.resolve())
    if files != set(entries):
        missing = sorted(str(path.relative_to(root)) for path in files - set(entries))
        extra = sorted(str(path.relative_to(root)) for path in set(entries) - files)
        fail(f"SHA256SUMS is not closed (missing={missing}, extra={extra})")


def check_tls_evidence(root: Path, stage: dict, runtime: str | None) -> None:
    evidence = stage.get("tlsEvidence")
    if evidence is None:
        return
    if not isinstance(evidence, dict):
        fail("stage tlsEvidence must be an object")
    missing = sorted(TLS_EVIDENCE_FIELDS - evidence.keys())
    if missing:
        fail(f"tlsEvidence is missing fields: {missing}")
    unknown = sorted(set(evidence) - TLS_EVIDENCE_FIELDS)
    if unknown:
        fail(f"tlsEvidence contains unsupported fields: {unknown}")
    if evidence.get("schemaVersion") != 1:
        fail("tlsEvidence schemaVersion must be 1")

    def bounded_text(value: Any, label: str, maximum: int = 256) -> str:
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
            fail(f"tlsEvidence {label} is outside its bounded text contract")
        return value

    def bounded_digest(value: Any, label: str, optional: bool = False) -> str | None:
        if optional and value is None:
            return None
        if not isinstance(value, str) or not DIGEST.fullmatch(value):
            fail(f"tlsEvidence {label} is not a SHA-256 digest")
        return value.lower()

    def bounded_integer(
        value: Any,
        label: str,
        minimum: int = 0,
        maximum: int = TLS_MAX_SEGMENT_SIZE,
    ) -> int:
        if type(value) is not int or value < minimum or value > maximum:
            fail(f"tlsEvidence {label} is outside its bounded integer contract")
        return value

    model = bounded_text(evidence["model"], "model", 32)
    if model not in TLS_MODELS:
        fail(f"tlsEvidence model is unsupported: {model!r}")
    profile = bounded_text(evidence["profile"], "profile", 32)
    if profile not in TLS_PROFILES:
        fail(f"tlsEvidence profile is unsupported: {profile!r}")
    if profile != stage.get("profile"):
        fail("tlsEvidence profile does not match its enclosing stage")
    if runtime not in {"glibc", "musl", "bionic"}:
        fail("tlsEvidence requires an explicit glibc, musl, or bionic runtime argument")
    if bounded_text(evidence["runtime"], "runtime", 32) != runtime:
        fail("tlsEvidence runtime does not match the selected evidence lane")
    lifecycle = bounded_text(evidence["lifecycle"], "lifecycle", 32)
    if lifecycle not in TLS_LIFECYCLES:
        fail(f"tlsEvidence lifecycle is unsupported: {lifecycle!r}")
    result = bounded_text(evidence["result"], "result", 32)
    if result not in TLS_RESULTS:
        fail(f"tlsEvidence result is unsupported: {result!r}")

    source_path = resolve_under(
        root,
        bounded_text(evidence["sourcePath"], "sourcePath"),
        "tlsEvidence sourcePath",
    )
    if source_path.is_symlink() or not source_path.is_file():
        fail("tlsEvidence sourcePath must identify a retained regular file")
    source_sha = bounded_digest(evidence["sourceSha256"], "sourceSha256")
    if source_sha != digest(source_path):
        fail("tlsEvidence sourceSha256 does not match sourcePath")
    stage_source_sha = stage.get("sourceSha256")
    if not isinstance(stage_source_sha, str) or not DIGEST.fullmatch(stage_source_sha):
        fail("tlsEvidence enclosing stage has an invalid sourceSha256")
    if stage_source_sha.lower() != source_sha:
        fail("tlsEvidence sourceSha256 does not match its enclosing stage")

    if stage.get("status") != "passed" or stage.get("publicationComplete") is not True:
        fail("published TLS runtime evidence requires a completely published enclosing stage")
    transformed_sha = bounded_digest(evidence["transformedSha256"], "transformedSha256")
    artifact_sha = bounded_digest(evidence["artifactSha256"], "artifactSha256")
    transformed_path = resolve_under(
        root,
        bounded_text(evidence["transformedPath"], "transformedPath"),
        "tlsEvidence transformedPath",
    )
    artifact_path = resolve_under(
        root,
        bounded_text(evidence["artifactPath"], "artifactPath"),
        "tlsEvidence artifactPath",
    )
    stage_artifact_path = resolve_under(root, str(stage.get("artifactPath", "")), "stage artifactPath")
    if transformed_path != stage_artifact_path or artifact_path != stage_artifact_path:
        fail("tlsEvidence transformed/artifact paths must bind the enclosing Protected Image")
    if (transformed_path.is_symlink() or not transformed_path.is_file()
            or artifact_path.is_symlink() or not artifact_path.is_file()):
        fail("tlsEvidence transformed/artifact paths must identify retained regular files")
    actual_artifact_sha = digest(artifact_path)
    if transformed_sha != actual_artifact_sha or artifact_sha != actual_artifact_sha:
        fail("tlsEvidence transformed/artifact hashes do not match the retained Protected Image")
    stage_artifact_sha = stage.get("artifactSha256")
    if not isinstance(stage_artifact_sha, str) or not DIGEST.fullmatch(stage_artifact_sha):
        fail("tlsEvidence enclosing stage has an invalid artifactSha256")
    if artifact_sha != stage_artifact_sha.lower():
        fail("tlsEvidence artifactSha256 does not match its enclosing stage")

    bounded_text(evidence["toolchainIdentity"], "toolchainIdentity")
    bounded_text(evidence["loaderIdentity"], "loaderIdentity")

    pt_tls = evidence["ptTls"]
    if not isinstance(pt_tls, dict):
        fail("tlsEvidence ptTls must be an object")
    missing_pt_tls = sorted(TLS_PT_TLS_FIELDS - pt_tls.keys())
    if missing_pt_tls:
        fail(f"tlsEvidence ptTls is missing fields: {missing_pt_tls}")
    unknown_pt_tls = sorted(set(pt_tls) - TLS_PT_TLS_FIELDS)
    if unknown_pt_tls:
        fail(f"tlsEvidence ptTls contains unsupported fields: {unknown_pt_tls}")
    template_path = resolve_under(
        root,
        bounded_text(pt_tls["templatePath"], "ptTls.templatePath"),
        "tlsEvidence ptTls.templatePath",
    )
    if template_path.is_symlink() or not template_path.is_file():
        fail("tlsEvidence ptTls.templatePath must identify a retained regular file")
    template_sha = bounded_digest(pt_tls["templateSha256"], "ptTls.templateSha256")
    if template_sha != digest(template_path):
        fail("tlsEvidence ptTls.templateSha256 does not match templatePath")
    file_size = bounded_integer(pt_tls["fileSize"], "ptTls.fileSize")
    memory_size = bounded_integer(pt_tls["memorySize"], "ptTls.memorySize")
    zero_fill_size = bounded_integer(pt_tls["zeroFillSize"], "ptTls.zeroFillSize")
    if template_path.stat().st_size != file_size:
        fail("tlsEvidence PT_TLS template file size does not match fileSize")
    if file_size > memory_size or memory_size - file_size != zero_fill_size:
        fail("tlsEvidence PT_TLS file/memory/zero-fill facts are inconsistent")
    alignment = bounded_integer(pt_tls["alignment"], "ptTls.alignment", maximum=TLS_MAX_SEGMENT_SIZE)
    if alignment > 1 and alignment & (alignment - 1):
        fail("tlsEvidence PT_TLS alignment is not a power of two")
    bounded_integer(
        pt_tls["owningLoad"],
        "ptTls.owningLoad",
        maximum=TLS_MAX_PROGRAM_HEADER_INDEX,
    )

    for field in ("perThread", "zeroFill", "teardown"):
        observation = bounded_text(evidence[field], field, 32)
        if observation not in TLS_OBSERVATIONS:
            fail(f"tlsEvidence {field} observation is unsupported: {observation!r}")
    first_failure = evidence["firstFailureStage"]
    if first_failure is not None:
        first_failure = bounded_text(first_failure, "firstFailureStage", 128)
    publication = bounded_text(evidence["publicationResult"], "publicationResult", 32)
    rollback = bounded_text(evidence["rollbackResult"], "rollbackResult", 32)

    if result == "accepted-and-runs":
        if lifecycle == "not-run" or any(evidence[field] != "observed" for field in ("perThread", "zeroFill", "teardown")):
            fail("accepted-and-runs TLS evidence must retain per-thread, zero-fill, and teardown observations")
        if first_failure is not None or publication != "published" or rollback != "not-applicable":
            fail("accepted-and-runs TLS evidence has an invalid outcome or rollback projection")
    elif result == "environment-unavailable":
        if lifecycle != "not-run" or any(evidence[field] not in {"not-run", "not-applicable"} for field in ("perThread", "zeroFill", "teardown")):
            fail("environment-unavailable TLS evidence must not claim lifecycle observations")
        if first_failure != "environment" or publication != "published" or rollback != "not-applicable":
            fail("environment-unavailable TLS evidence must remain an explicit environment result")
    else:
        if first_failure is None or first_failure == "environment" or publication != "published" or rollback != "not-applicable":
            fail("runtime-failure TLS evidence must retain a runtime failure after complete publication")
        if lifecycle == "not-run" and any(evidence[field] == "observed" for field in ("perThread", "zeroFill", "teardown")):
            fail("runtime-failure TLS lifecycle cannot claim observations when lifecycle is not-run")
        if stage.get("firstFailureStage") not in {None, first_failure}:
            fail("TLS runtime-failure firstFailureStage does not match its enclosing stage")


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
    source_image = root / "source-image.bin"
    if source_image.exists() and digest(source_image) != role["sourceSha256"].lower():
        fail("retained Source Image hash differs from the Protected Image role binding")
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
    check_tls_evidence(root, stage, args.runtime)
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
