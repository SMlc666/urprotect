#!/usr/bin/env python3
"""Fail closed when an independent-evaluator evidence tree is incomplete or altered."""

from __future__ import annotations

import argparse
import json
import sys
sys.dont_write_bytecode = True
from pathlib import Path, PureWindowsPath
from typing import Any

from evaluator_lib import (
    EvaluatorError,
    calculate_anti_gaming,
    calculate_compatibility,
    calculate_scheme_gate,
    inventory_digest,
    load_product_evidence,
    read_json,
    sha256_file,
    validate_all_manifests,
    validate_no_symlinks,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUIRED_OUTPUT_FILES = (
    "environment.json",
    "protocol.json",
    "corpus-manifest.json",
    "scheme-a-manifest.json",
    "oracles.json",
    "baseline-reference.json",
    "scheme-a-gate.json",
    "gate.json",
    "analysis-input.json",
    "SHA256SUMS",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--require-claimable", action="store_true", help="fail the process unless both independent dimensions are claimable")
    parser.add_argument(
        "--require-claimable-if-baseline-positive",
        action="store_true",
        help="enforce claimability once the frozen compatibility baseline has a positive denominator",
    )
    return parser.parse_args()


def fail(message: str) -> None:
    raise EvaluatorError(message)


def safe_artifact_path(root: Path, relative: str, field: str) -> Path:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        fail(f"{field} must be a non-empty relative path")
    path_value = Path(relative)
    windows = PureWindowsPath(relative)
    if "\\" in relative or path_value.is_absolute() or windows.is_absolute() or windows.drive or any(part in {"", ".", ".."} for part in path_value.parts) or any(part in {"", ".", ".."} for part in windows.parts):
        fail(f"{field} contains an unsafe path: {relative!r}")
    resolved = (root / path_value).resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise EvaluatorError(f"{field} escapes artifact root: {relative!r}") from error
    return resolved


def parse_checksum_manifest(root: Path, manifest_path: Path, *, label: str) -> None:
    try:
        if manifest_path.stat().st_size > 16 * 1024 * 1024:
            fail(f"{label} exceeds the bounded evidence size")
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    declared: dict[str, str] = {}
    for index, line in enumerate(lines, start=1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64 or any(character not in "0123456789abcdef" for character in parts[0]):
            fail(f"{label}:{index} is not a normalized SHA-256 line")
        digest, relative = parts
        if relative in declared:
            fail(f"{label} contains duplicate path: {relative}")
        path = safe_artifact_path(root, relative, f"{label}:{index}")
        if not path.is_file() or path.is_symlink():
            fail(f"{label}:{index} references missing/non-regular path: {relative}")
        if path.stat().st_size > 256 * 1024 * 1024:
            fail(f"{label}:{index} references an over-sized evidence file: {relative}")
        if sha256_file(path) != digest:
            fail(f"{label}:{index} hash mismatch: {relative}")
        declared[relative] = digest
    expected = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path != manifest_path
    }
    if set(declared) != expected:
        fail(f"{label} coverage mismatch: missing={sorted(expected - set(declared))}, extra={sorted(set(declared) - expected)}")


def check_raw_manifest(root: Path, relative_manifest: str, owner: str) -> None:
    manifest = safe_artifact_path(root, relative_manifest, f"{owner}.rawEvidenceManifest")
    if manifest.name != "SHA256SUMS":
        fail(f"{owner} raw manifest must be named SHA256SUMS")
    raw_root = manifest.parent
    parse_checksum_manifest(raw_root, manifest, label=f"{owner} raw SHA256SUMS")


def check_manifest_copies(root: Path, source_manifests: dict[str, Path]) -> None:
    copies = {
        "protocol.json": "protocol",
        "corpus-manifest.json": "corpus",
        "scheme-a-manifest.json": "scheme",
        "oracles.json": "oracles",
        "baseline-reference.json": "baseline-reference",
    }
    for destination, name in copies.items():
        path = root / destination
        if not path.is_file():
            fail(f"missing evaluator manifest copy: {destination}")
        source = source_manifests[name]
        if sha256_file(path) != sha256_file(source):
            fail(f"evaluator manifest copy changed: {destination}")


def compare_mapping(actual: dict[str, Any], expected: dict[str, Any], fields: tuple[str, ...], owner: str) -> None:
    for field in fields:
        if actual.get(field) != expected.get(field):
            fail(f"{owner}.{field} does not match recomputed value")


def check_evidence(root: Path) -> dict[str, Any]:
    artifacts_root = (REPO_ROOT / ".artifacts" / "evaluator").resolve()
    requested_root = root if root.is_absolute() else REPO_ROOT / root
    if requested_root.is_symlink():
        fail("evaluator artifact root may not be a symlink")
    current = artifacts_root
    try:
        relative_requested = requested_root.relative_to(artifacts_root)
    except ValueError as error:
        raise EvaluatorError("evaluator artifact root must remain under .artifacts/evaluator") from error
    for component in relative_requested.parts:
        current = current / component
        if current.is_symlink():
            fail(f"evaluator artifact root may not traverse a symlink: {current}")
    root = requested_root.resolve()
    artifacts_root = artifacts_root.resolve()
    try:
        root.relative_to(artifacts_root)
    except ValueError as error:
        raise EvaluatorError("evaluator artifact root must remain under .artifacts/evaluator") from error
    validate_no_symlinks(root)
    for name in REQUIRED_OUTPUT_FILES:
        if not (root / name).is_file():
            fail(f"missing evaluator output: {name}")
    parse_checksum_manifest(root, root / "SHA256SUMS", label="SHA256SUMS")
    source_paths = {
        "protocol": REPO_ROOT / "fixtures/evaluator/evaluator-protocol.json",
        "corpus": REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json",
        "scheme": REPO_ROOT / "fixtures/evaluator/scheme-a-manifest.json",
        "oracles": REPO_ROOT / "fixtures/evaluator/oracles.json",
        "baseline-reference": REPO_ROOT / "fixtures/evaluator/baseline-reference.json",
    }
    check_manifest_copies(root, source_paths)
    manifests = validate_all_manifests(
        REPO_ROOT,
        protocol_path=source_paths["protocol"],
        corpus_path=source_paths["corpus"],
        scheme_path=source_paths["scheme"],
        oracle_path=source_paths["oracles"],
        baseline_reference_path=source_paths["baseline-reference"],
    )
    environment = read_json(root / "environment.json")
    if environment.get("schemaVersion") != 1 or environment.get("kind") != "evaluator-environment":
        fail("environment.json schema/kind is invalid")
    if environment.get("commit") != git_commit_for_check():
        fail("environment commit does not match checked-out commit")
    gate = read_json(root / "gate.json")
    if gate.get("schemaVersion") != 1 or gate.get("kind") != "urprotect-independent-evaluator":
        fail("gate.json schema/kind is invalid")
    scheme_gate_document = read_json(root / "scheme-a-gate.json")
    if scheme_gate_document.get("schemaVersion") != 1 or scheme_gate_document.get("kind") != "scheme-a-gate":
        fail("scheme-a-gate.json schema/kind is invalid")
    analysis = read_json(root / "analysis-input.json")
    if analysis.get("schemaVersion") != 1 or analysis.get("kind") != "urprotect-independent-evaluator-analysis-input":
        fail("analysis-input.json schema/kind is invalid")
    if analysis.get("normativeGate") != "gate.json":
        fail("analysis-input.json must identify gate.json as its normative gate")
    if gate.get("baselineArtifactSha256") != manifests["baselineReference"]["baselineArtifactSha256"]:
        fail("gate baseline digest does not match baseline reference")
    if gate.get("baselineArtifactId") != manifests["baselineReference"]["baselineArtifactId"]:
        fail("gate baseline ID does not match baseline reference")
    if gate.get("commit") != environment.get("commit"):
        fail("gate commit does not match environment.json")
    if gate.get("corpusVersion") != manifests["corpus"]["corpusVersion"] or gate.get("protocolVersion") != manifests["protocol"]["protocolVersion"]:
        fail("gate protocol/corpus version mismatch")
    gate_environment = gate.get("environment")
    if not isinstance(gate_environment, dict):
        fail("gate.environment must be an object")
    compare_mapping(
        gate_environment,
        environment,
        ("status", "runtimeCell", "requiredCapabilities"),
        "gate.environment",
    )

    units: list[dict[str, Any]] = []
    for row in manifests["rows"]:
        if not row.get("required") or not row.get("applicable"):
            continue
        unit_path = root / "compatibility" / row["unitId"] / "unit.json"
        if not unit_path.is_file():
            fail(f"missing compatibility unit: {row['unitId']}")
        unit = read_json(unit_path)
        units.append(unit)
        check_raw_manifest(root, unit.get("rawEvidenceManifest"), f"compatibility {row['unitId']}")
        if unit.get("strictChainMeasured") is True:
            product_binding = unit.get("productEvidence")
            if not isinstance(product_binding, dict):
                fail(f"strict compatibility unit is missing product evidence binding: {row['unitId']}")
            product_root = safe_artifact_path(
                unit_path.parent,
                product_binding.get("rawRoot"),
                f"compatibility {row['unitId']}.productEvidence.rawRoot",
            )
            runtime = "glibc"
            if ".musl." in row["unitId"]:
                runtime = "musl"
            elif ".bionic." in row["unitId"]:
                runtime = "bionic"
            product_environment = read_json(product_root / "environment.json")
            product_tier = product_environment.get("tier")
            if root.name in {"pr", "nightly", "release"} and product_tier != root.name:
                fail(f"strict product evidence tier does not match evaluator tier: {row['unitId']}")
            try:
                recomputed_product = load_product_evidence(
                    product_root,
                    row,
                    tier=product_tier,
                    runtime=runtime,
                    require_unit_root_name=False,
                )
            except EvaluatorError as error:
                fail(f"strict product evidence could not be recomputed: {error}")
            if recomputed_product["stages"] != unit.get("stages"):
                fail(f"strict compatibility stages differ from recomputed product evidence: {row['unitId']}")
            if unit.get("sourceImageSha256") != recomputed_product.get("sourceImageSha256"):
                fail(f"strict compatibility source-image binding differs from product evidence: {row['unitId']}")
            if product_binding.get("manifestSha256") != recomputed_product.get("productManifestSha256"):
                fail(f"strict compatibility product manifest binding differs from product evidence: {row['unitId']}")
    compatibility = calculate_compatibility(manifests["corpus"], manifests["baseline"], units)
    compatibility_gate = gate.get("compatibility")
    if not isinstance(compatibility_gate, dict):
        fail("gate.compatibility must be an object")
    compare_mapping(
        compatibility_gate,
        compatibility,
        (
            "status",
            "fixedRows",
            "growthRows",
            "baselineCompleteUnits",
            "candidateFixedCompleteUnits",
            "candidateGrowthCompleteUnits",
            "factor",
            "growthTarget",
            "fixedViewPass",
            "growthViewPass",
            "firstFailureCounts",
        ),
        "gate.compatibility",
    )

    attempts: dict[tuple[str, str, int], dict[str, Any]] = {}
    for family in manifests["families"]:
        family_id = family["familyId"]
        for role in ("baseline", "candidate"):
            for replica in range(1, manifests["scheme"]["replicaCount"] + 1):
                attempt_path = root / "strength" / family_id / f"replica-{replica}" / role / "attempt.json"
                if not attempt_path.is_file():
                    fail(f"missing Scheme-A attempt: {family_id}/{role}/{replica}")
                attempt = read_json(attempt_path)
                attempts[(family_id, role, replica)] = attempt
                check_raw_manifest(root, attempt.get("rawEvidenceManifest"), f"Scheme-A {family_id}/{role}/{replica}")
    scheme_gate = calculate_scheme_gate(manifests["scheme"], attempts)
    scheme_result = gate.get("schemeA")
    if not isinstance(scheme_result, dict):
        fail("gate.schemeA must be an object")
    if scheme_gate_document.get("schemeAStatus") != scheme_gate["status"] or scheme_gate_document.get("families") != scheme_gate["families"]:
        fail("scheme-a-gate.json does not match recomputed family results")
    if scheme_gate_document.get("requiredFamilies") != scheme_gate["requiredFamilies"]:
        fail("scheme-a-gate required family list changed")
    if scheme_gate_document.get("familyFactors") != scheme_gate["familyFactors"]:
        fail("scheme-a-gate family factors changed")
    if scheme_gate_document.get("allRequiredPass") != scheme_gate["allRequiredPass"] or scheme_gate_document.get("minimumFactorDiagnostic") != scheme_gate["minimumFactorDiagnostic"]:
        fail("scheme-a-gate aggregate result changed")
    if scheme_gate_document.get("baselineArtifactId") != manifests["baselineReference"]["baselineArtifactId"]:
        fail("scheme-a-gate baseline ID does not match baseline reference")
    if scheme_gate_document.get("baselineArtifactSha256") != manifests["baselineReference"]["baselineArtifactSha256"]:
        fail("scheme-a-gate baseline digest does not match baseline reference")
    if scheme_gate_document.get("protocolVersion") != manifests["scheme"]["protocolVersion"]:
        fail("scheme-a-gate protocol version mismatch")
    compare_mapping(
        scheme_result,
        scheme_gate,
        ("status", "requiredFamilies", "familyFactors", "families", "allRequiredPass", "minimumFactorDiagnostic"),
        "gate.schemeA",
    )

    anti_gaming = gate.get("antiGaming")
    if not isinstance(anti_gaming, dict) or not anti_gaming:
        fail("gate.antiGaming must be a non-empty object")
    expected_anti_gaming = calculate_anti_gaming(
        REPO_ROOT,
        manifests,
        compatibility,
        units,
        attempts,
        raw_evidence_bounded=True,
    )
    if anti_gaming != expected_anti_gaming:
        fail("gate anti-gaming checks do not match independently recomputed checks")
    if any(value is not True for value in anti_gaming.values()):
        fail("anti-gaming checks did not all pass")
    expected_artifact_digest = inventory_digest(root, exclude=("gate.json", "analysis-input.json"))
    if gate.get("artifactManifestSha256") != expected_artifact_digest or gate.get("rawEvidenceManifestSha256") != expected_artifact_digest:
        fail("gate artifact/evidence inventory digest mismatch")
    compatibility_claimable = compatibility["status"] == "measured" and compatibility["fixedViewPass"] and compatibility["growthViewPass"]
    scheme_claimable = scheme_gate["status"] == "pass" and scheme_gate["allRequiredPass"]
    expected_claimable = all(anti_gaming.values()) and compatibility_claimable and scheme_claimable
    if gate.get("claimable") is not expected_claimable:
        fail("gate.claimable is not derived from independent dimensions and anti-gaming checks")
    if manifests["baseline"]["completeUnits"] == 0:
        if compatibility["status"] != "baseline-zero" or compatibility["factor"] is not None:
            fail("zero compatibility baseline must remain baseline-zero with null factor")
        if gate["schemeA"]["status"] != "baseline-not-calibrated":
            fail("uncalibrated Scheme-A baseline must remain explicit")
        if gate["claimable"]:
            fail("baseline-zero/not-calibrated evaluator cannot be claimable")
    for field in ("commit", "baselineArtifactId", "baselineArtifactSha256", "corpusVersion", "protocolVersion"):
        if analysis.get(field) != gate.get(field):
            fail(f"analysis-input.{field} does not match gate.json")
    if analysis.get("antiGaming") != anti_gaming:
        fail("analysis-input anti-gaming projection differs from gate")
    return gate


def git_commit_for_check() -> str:
    import subprocess

    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip()


def main() -> int:
    args = parse_args()
    try:
        gate = check_evidence(args.artifact_root)
    except (EvaluatorError, OSError, json.JSONDecodeError) as error:
        print(f"FAIL independent evaluator evidence: {error}", file=sys.stderr)
        return 1
    print(
        "PASS independent evaluator evidence: "
        f"compatibility={gate['compatibility']['status']} "
        f"schemeA={gate['schemeA']['status']} claimable={gate['claimable']}"
    )
    if args.require_claimable and gate.get("claimable") is not True:
        print("FAIL independent evaluator claim gate: result is not claimable", file=sys.stderr)
        return 1
    if (
        args.require_claimable_if_baseline_positive
        and gate["compatibility"].get("baselineCompleteUnits", 0) > 0
        and gate.get("claimable") is not True
    ):
        print("FAIL independent evaluator claim gate: positive baseline is not claimable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
