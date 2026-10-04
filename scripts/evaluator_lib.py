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


class EvaluatorError(ValueError):
    """A malformed manifest or evidence record."""


def fail(message: str) -> None:
    raise EvaluatorError(message)


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


def validate_baseline_reference(reference: Mapping[str, Any], repo_root: Path) -> dict[str, Any]:
    _require_root(reference, "evaluator-baseline-reference")
    artifact_path = resolve_repo_path(repo_root, reference.get("baselineArtifactPath"), "baselineArtifactPath", require_file=True)
    expected = require_digest(reference.get("baselineArtifactSha256"), "baselineArtifactSha256")
    actual = sha256_file(artifact_path)
    if actual != expected:
        fail("baseline artifact digest does not match baseline-reference.json")
    artifact = read_json(artifact_path)
    _require_root(artifact, "compatibility-1x-baseline")
    if artifact.get("immutable") is not True or artifact.get("baselineStatus") not in {"baseline-zero", "measured"}:
        fail("baseline artifact is not immutable or has an invalid status")
    if artifact.get("commit") != reference.get("baselineCommit"):
        fail("baseline commit mismatch")
    if artifact.get("immutableArtifactId") != reference.get("baselineArtifactId"):
        fail("baseline immutable artifact ID mismatch")
    if artifact.get("completeUnits") != reference.get("completeUnits"):
        fail("baseline complete-unit count mismatch")
    if artifact.get("fixedCorpusRows") != reference.get("fixedCorpusRows"):
        fail("baseline fixed-row count mismatch")
    complete_ids = artifact.get("completeUnitIds")
    if not isinstance(complete_ids, list) or any(not isinstance(item, str) for item in complete_ids):
        fail("baseline completeUnitIds must be a string list")
    for index, item in enumerate(complete_ids):
        require_id(item, f"baseline.completeUnitIds[{index}]")
    if len(complete_ids) != len(set(complete_ids)) or len(complete_ids) != artifact.get("completeUnits"):
        fail("baseline completeUnitIds do not match completeUnits")
    if reference.get("baselineStatus") != artifact.get("baselineStatus"):
        fail("baseline status mismatch")
    if reference.get("strengthStatus") != artifact.get("strengthStatus"):
        fail("baseline strength status mismatch")
    require_string(reference.get("baselineArtifactId"), "baselineArtifactId")
    require_string(reference.get("schemeProtocolVersion"), "schemeProtocolVersion")
    if not reference.get("contentAddressed") or not reference.get("neverOverwrite"):
        fail("baseline reference must be immutable and content addressed")
    return artifact


def validate_all_manifests(repo_root: Path, *, protocol_path: Path, corpus_path: Path, scheme_path: Path, oracle_path: Path, baseline_reference_path: Path) -> dict[str, Any]:
    protocol = read_json(protocol_path)
    validate_protocol(protocol)
    oracles = read_json(oracle_path)
    oracle_ids = validate_oracles(oracles)
    corpus = read_json(corpus_path)
    rows = validate_compatibility_corpus(corpus, repo_root, oracle_ids)
    scheme = read_json(scheme_path)
    families = validate_scheme_manifest(scheme)
    reference = read_json(baseline_reference_path)
    baseline = validate_baseline_reference(reference, repo_root)
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
    if baseline.get("strengthStatus") != scheme.get("baselineStatus"):
        fail("baseline strength status does not match the Scheme-A manifest")
    if protocol["baselineRules"].get("currentCommit") != baseline.get("commit"):
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
        if protocol["manifestDigests"].get(field) != sha256_file(path):
            fail(f"protocol manifestDigests.{field} does not match {path}")
    for field, path in digest_bindings.items():
        expected = baseline.get(field)
        if expected is not None and expected != sha256_file(path):
            fail(f"baseline snapshot {field} does not match {path}")
    fixture_manifest = repo_root / "fixtures" / "manifest.json"
    runtime_manifest = repo_root / "fixtures" / "runtime-matrix.json"
    if baseline.get("fixtureManifestSha256") != sha256_file(fixture_manifest):
        fail("baseline fixtureManifestSha256 does not match fixtures/manifest.json")
    if baseline.get("runtimeRegistrySha256") != sha256_file(runtime_manifest):
        fail("baseline runtimeRegistrySha256 does not match fixtures/runtime-matrix.json")
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
    for field in ("corpusVersion", "profile", "runtimeCell", "targetLoader", "oracleId"):
        require_string(unit.get(field), f"unit.{field}")
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


def calculate_scheme_gate(scheme: Mapping[str, Any], attempts: Mapping[tuple[str, str, int], Mapping[str, Any]]) -> dict[str, Any]:
    families_by_id = {family["familyId"]: family for family in scheme["requiredFamilies"]}
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
        baseline_cost = max(attempt["successCpuNs"] for attempt in baseline_successes)
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
        if relative in excluded:
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
    scheme_path = repo_root / "fixtures/evaluator/scheme-a-manifest.json"
    baseline_path = resolve_repo_path(repo_root, reference["baselineArtifactPath"], "baselineArtifactPath", require_file=True)
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
    return {
        "corpusUnchanged": baseline.get("corpusManifestSha256") == sha256_file(corpus_path),
        "oracleUnchanged": baseline.get("oracleManifestSha256") == sha256_file(oracle_path),
        "attackManifestUnchanged": baseline.get("schemeManifestSha256") == sha256_file(scheme_path),
        "budgetsEqual": manifests["protocol"]["budgets"] == manifests["scheme"]["budget"],
        "baselineDigestMatches": sha256_file(baseline_path) == reference.get("baselineArtifactSha256"),
        "requiredRowsPresent": set(observed_ids) == required_ids and len(observed_ids) == len(set(observed_ids)),
        "noUnownedStatusMarkers": owner_markers,
        "noDuplicateIdentityCount": len(identity_keys) == len(set(identity_keys)),
        "rawEvidenceBounded": raw_evidence_bounded,
    }
