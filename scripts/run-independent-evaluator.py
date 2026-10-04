#!/usr/bin/env python3
"""Run the read-only compatibility/Scheme-A evaluator into its own evidence tree.

The current checkout intentionally has no Protected Image or rehydrator product
stage and no pinned Scheme-A attack tools. The runner records those facts as
machine-readable unavailable/not-calibrated evidence; it never promotes auxiliary
wrapper/protection output to a strict compatibility or strength result.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from typing import Any

from evaluator_lib import (
    COMPATIBILITY_STAGES,
    EvaluatorError,
    calculate_anti_gaming,
    calculate_compatibility,
    calculate_scheme_gate,
    canonical_json,
    inventory_digest,
    sha256_file,
    validate_all_manifests,
    validate_no_symlinks,
    validate_unit_record,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVALUATOR_ROOT = REPO_ROOT / ".artifacts" / "evaluator"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), default="pr")
    parser.add_argument("--output-root", type=Path, help="evaluator evidence directory (default: .artifacts/evaluator/<tier>)")
    parser.add_argument("--keep-existing", action="store_true", help="fail instead of replacing only the evaluator's previous output directory")
    return parser.parse_args()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def write_raw_manifest(raw_root: Path) -> Path:
    entries: list[str] = []
    for path in sorted(raw_root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        entries.append(f"{sha256_file(path)}  {path.relative_to(raw_root).as_posix()}\n")
    manifest = raw_root / "SHA256SUMS"
    manifest.write_text("".join(entries), encoding="utf-8")
    return manifest


def write_top_level_manifest(root: Path) -> Path:
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path == root / "SHA256SUMS":
            continue
        entries.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n")
    manifest = root / "SHA256SUMS"
    manifest.write_text("".join(entries), encoding="utf-8")
    return manifest


def command_identity(command: str) -> dict[str, Any]:
    executable = shutil.which(command)
    if executable is None:
        return {"available": False, "version": None, "binarySha256": None}
    try:
        result = subprocess.run([executable, "--version"], check=False, capture_output=True, text=True, timeout=5)
        text = (result.stdout or result.stderr).splitlines()
        version = text[0][:240] if text else None
        digest = sha256_file(Path(executable))
    except (OSError, subprocess.SubprocessError, EvaluatorError):
        return {"available": False, "version": None, "binarySha256": None}
    return {"available": True, "version": version, "binarySha256": digest}


def git_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip()


def build_environment(root: Path, protocol: dict[str, Any], scheme: dict[str, Any]) -> dict[str, Any]:
    architecture = platform.machine()
    native_arm64 = architecture in {"aarch64", "arm64"}
    tools = {name: command_identity(name) for name in ("python3", "dotnet", "readelf", "bwrap")}
    dotnet_available = tools["dotnet"]["available"]
    network_disabled = os.environ.get("EVALUATOR_NETWORK_DISABLED") == "1"
    required_capabilities = {
        "nativeAarch64": native_arm64,
        "pinnedRuntimeCell": False,
        "dotnetSdk": dotnet_available,
        "protectedImageProducer": False,
        "rehydrator": False,
        "schemeAttackToolset": False,
        "networkDisabled": network_disabled,
    }
    status = "available" if all(required_capabilities.values()) else "environment-unavailable"
    reason = None
    if status != "available":
        missing = sorted(key for key, value in required_capabilities.items() if not value)
        reason = "required evaluator capabilities are unavailable: " + ", ".join(missing)
    environment = {
        "schemaVersion": 1,
        "kind": "evaluator-environment",
        "commit": git_commit(),
        "status": status,
        "os": platform.system(),
        "architecture": architecture,
        "nativeAarch64": native_arm64,
        "emulated": False,
        "kernel": platform.release(),
        "pageSize": os.sysconf("SC_PAGESIZE") if hasattr(os, "sysconf") else None,
        "runtimeCell": "glibc.current.native-arm64",
        "loaderIdentity": "not-captured",
        "isolation": {
            "networkDisabled": network_disabled,
            "readOnlyInputs": False,
            "noNewPrivileges": False,
            "droppedCapabilities": False,
            "boundedProcesses": protocol["budgets"]["processLimit"],
            "boundedMemoryBytes": protocol["budgets"]["rssBytes"],
            "boundedWallSeconds": protocol["budgets"]["wallSeconds"],
        },
        "tools": tools,
        "requiredCapabilities": required_capabilities,
        "reason": reason,
        "evaluator": {
            "runnerSha256": sha256_file(Path(__file__)),
            "librarySha256": sha256_file(Path(__file__).with_name("evaluator_lib.py")),
            "command": "scripts/run-independent-evaluator.sh --tier <tier>",
        },
        "budget": protocol["budgets"],
    }
    write_json(root / "environment.json", environment)
    return environment


def make_compatibility_unit(root: Path, row: dict[str, Any], corpus: dict[str, Any]) -> dict[str, Any]:
    unit_root = root / "compatibility" / row["unitId"]
    raw_root = unit_root / "raw"
    write_json(
        raw_root / "strict-chain-status.json",
        {
            "schemaVersion": 1,
                "status": "baseline-zero",
            "statusOwner": "independent-evaluator",
            "strictChainMeasured": False,
            "reason": "The current product declares no Protected Image ABI or rehydration consumer; auxiliary direct ELF/wrapper evidence is not a strict-chain result.",
            "auxiliaryEvidence": row.get("auxiliaryEvidence", []),
            "nativeResultsCaptured": False,
        },
    )
    raw_manifest = write_raw_manifest(raw_root)
    stages = {
        stage: {
            "status": "not-applicable",
            "reason": "strict Protected Image chain is not declared by the current product",
        }
        for stage in COMPATIBILITY_STAGES
    }
    unit = {
        "schemaVersion": 1,
        "kind": "compatibility-unit",
        "unitId": row["unitId"],
        "corpusVersion": corpus["corpusVersion"],
        "sourceSha256": row["sourceSha256"],
        "profile": row["profile"],
        "runtimeCell": row["runtimeCell"],
        "targetLoader": row["targetLoader"],
        "oracleId": row["oracleId"],
        "statusOwner": "independent-evaluator",
        "stages": stages,
        "complete": False,
        "firstFailureLayer": "protector",
        "rawEvidenceManifest": str(raw_manifest.relative_to(root)),
        "evidenceStatus": "baseline-zero",
        "auxiliaryEvidence": row.get("auxiliaryEvidence", []),
    }
    write_json(unit_root / "unit.json", unit)
    # Validate before returning so the runner cannot emit an internally inconsistent row.
    validate_unit_record(unit, row)
    return unit


def make_scheme_attempt(
    root: Path,
    scheme: dict[str, Any],
    family: dict[str, Any],
    role: str,
    replica: int,
) -> dict[str, Any]:
    family_id = family["familyId"]
    attempt_root = root / "strength" / family_id / f"replica-{replica}" / role
    raw_root = attempt_root / "raw"
    write_json(
        raw_root / "resource.json",
        {
            "schemaVersion": 1,
            "classification": "environment-unavailable",
            "statusOwner": "independent-evaluator",
            "role": role,
            "replica": replica,
            "requiredCapability": "pinned Scheme-A attack toolset",
            "available": False,
            "reason": "No pinned attack runner/tool binary exists in the current checkout; no attack result is inferred.",
            "budget": scheme["budget"],
        },
    )
    (raw_root / "command.log").write_text(
        "attack-not-started: required pinned Scheme-A toolset is unavailable\n",
        encoding="utf-8",
    )
    (raw_root / "stdout.txt").write_text("not-run: environment-unavailable\n", encoding="utf-8")
    (raw_root / "stderr.txt").write_text("environment-unavailable\n", encoding="utf-8")
    raw_manifest = write_raw_manifest(raw_root)
    attempt = {
        "schemaVersion": 1,
        "kind": "scheme-a-attempt",
        "familyId": family_id,
        "profile": scheme["profile"],
        "replica": replica,
        "role": role,
        "unitId": scheme["fixtureId"],
        "sourceSha256": scheme["sourceSha256"],
        "publishedArtifactSha256": scheme.get("publishedArtifactSha256"),
        "attackRecipeSha256": family["attackRecipeSha256"],
        "toolchain": family["tool"],
        "budget": scheme["budget"],
        "classification": "environment-unavailable",
        "statusOwner": "independent-evaluator",
        "goalAchieved": False,
        "successCpuNs": None,
        "censored": False,
        "blueOracle": {
            "status": "not-captured",
            "reason": "No strict Native Image was produced for this checkout.",
        },
        "recoveredArtifactSha256": None,
        "recoveredArtifactSize": 0,
        "resourceEvidence": str((raw_root / "resource.json").relative_to(root)),
        "stdout": str((raw_root / "stdout.txt").relative_to(root)),
        "stderr": str((raw_root / "stderr.txt").relative_to(root)),
        "commandLog": str((raw_root / "command.log").relative_to(root)),
        "manualStepsObserved": 0,
        "rawEvidenceManifest": str(raw_manifest.relative_to(root)),
    }
    write_json(attempt_root / "attempt.json", attempt)
    return attempt


def copy_manifests(root: Path) -> None:
    sources = {
        "protocol.json": REPO_ROOT / "fixtures/evaluator/evaluator-protocol.json",
        "corpus-manifest.json": REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json",
        "scheme-a-manifest.json": REPO_ROOT / "fixtures/evaluator/scheme-a-manifest.json",
        "oracles.json": REPO_ROOT / "fixtures/evaluator/oracles.json",
        "baseline-reference.json": REPO_ROOT / "fixtures/evaluator/baseline-reference.json",
    }
    for destination, source in sources.items():
        copy_file(source, root / destination)


def build_gate(
    root: Path,
    environment: dict[str, Any],
    manifests: dict[str, Any],
    compatibility: dict[str, Any],
    scheme_gate: dict[str, Any],
    units: list[dict[str, Any]],
    attempts: dict[tuple[str, str, int], dict[str, Any]],
) -> dict[str, Any]:
    reference = manifests["baselineReference"]
    baseline = manifests["baseline"]
    anti_gaming = calculate_anti_gaming(
        REPO_ROOT,
        manifests,
        compatibility,
        units,
        attempts,
        raw_evidence_bounded=True,
    )
    compatibility_claimable = (
        compatibility["status"] == "measured"
        and compatibility["fixedViewPass"]
        and compatibility["growthViewPass"]
    )
    scheme_claimable = scheme_gate["status"] == "pass" and scheme_gate["allRequiredPass"]
    gate = {
        "schemaVersion": 1,
        "kind": "urprotect-independent-evaluator",
        "commit": environment["commit"],
        "baselineArtifactId": reference["baselineArtifactId"],
        "baselineArtifactSha256": reference["baselineArtifactSha256"],
        "corpusVersion": manifests["corpus"]["corpusVersion"],
        "protocolVersion": manifests["protocol"]["protocolVersion"],
        "compatibility": {
            key: value
            for key, value in compatibility.items()
            if key not in {"completeUnitIds"}
        },
        "schemeA": {
            "status": scheme_gate["status"],
            "requiredFamilies": scheme_gate["requiredFamilies"],
            "familyFactors": scheme_gate["familyFactors"],
            "families": scheme_gate["families"],
            "allRequiredPass": scheme_gate["allRequiredPass"],
            "minimumFactorDiagnostic": scheme_gate["minimumFactorDiagnostic"],
        },
        "environment": {
            "status": environment["status"],
            "runtimeCell": environment["runtimeCell"],
            "requiredCapabilities": environment["requiredCapabilities"],
        },
        "antiGaming": anti_gaming,
        "rawEvidenceManifestSha256": inventory_digest(root, exclude=("gate.json", "analysis-input.json")),
        "artifactManifestSha256": inventory_digest(root, exclude=("gate.json", "analysis-input.json")),
        "claimable": all(anti_gaming.values()) and compatibility_claimable and scheme_claimable,
        "residualRisks": [
            "strict compatibility is baseline-zero because Protected Image and rehydration stages are not product-declared",
            "Scheme-A is baseline-not-calibrated because no required family has three finite reproducible baseline successes",
            "native product and attack results are environment-unavailable and are not fabricated",
        ],
    }
    return gate


def build_analysis_input(root: Path, gate: dict[str, Any], units: list[dict[str, Any]], attempts: dict[tuple[str, str, int], dict[str, Any]]) -> dict[str, Any]:
    family_summary: dict[str, list[dict[str, Any]]] = {}
    for (family, role, replica), attempt in sorted(attempts.items()):
        family_summary.setdefault(family, []).append(
            {
                "role": role,
                "replica": replica,
                "classification": attempt["classification"],
                "rawEvidenceManifest": attempt["rawEvidenceManifest"],
                "manualStepsObserved": attempt["manualStepsObserved"],
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "urprotect-independent-evaluator-analysis-input",
        "normativeGate": "gate.json",
        "commit": gate["commit"],
        "baselineArtifactId": gate["baselineArtifactId"],
        "baselineArtifactSha256": gate["baselineArtifactSha256"],
        "corpusVersion": gate["corpusVersion"],
        "protocolVersion": gate["protocolVersion"],
        "compatibility": {
            "status": gate["compatibility"]["status"],
            "fixedViewPass": gate["compatibility"]["fixedViewPass"],
            "growthViewPass": gate["compatibility"]["growthViewPass"],
            "baselineCompleteUnits": gate["compatibility"]["baselineCompleteUnits"],
            "candidateFixedCompleteUnits": gate["compatibility"]["candidateFixedCompleteUnits"],
            "candidateGrowthCompleteUnits": gate["compatibility"]["candidateGrowthCompleteUnits"],
            "firstFailureCounts": gate["compatibility"]["firstFailureCounts"],
            "units": [
                {
                    "unitId": unit["unitId"],
                    "complete": unit["complete"],
                    "firstFailureLayer": unit["firstFailureLayer"],
                    "rawEvidenceManifest": unit["rawEvidenceManifest"],
                }
                for unit in units
            ],
        },
        "schemeA": {
            "status": gate["schemeA"]["status"],
            "requiredFamilies": gate["schemeA"]["requiredFamilies"],
            "familyFactors": gate["schemeA"]["familyFactors"],
            "families": family_summary,
        },
        "antiGaming": gate["antiGaming"],
        "benchmarkDiagnostics": {
            "existingEvidence": [
                "fixtures/manifest.json",
                "fixtures/runtime-matrix.json",
                "scripts/run-protection-e2e.sh",
                "scripts/run-coverage-fuzz.sh",
                "benchmarks/UrProtect.Benchmarks/Program.cs",
            ],
            "strictChainCounted": False,
            "schemeAFactorCounted": False,
        },
        "residualRisks": gate["residualRisks"],
        "nextLocalGates": [
            "protected-image-emission-v1",
            "rehydration-native-handoff-v1",
            "scheme-a-baseline-calibration-v1",
        ],
    }


def _reject_output_symlink_components(path: Path, root: Path) -> None:
    candidate = path if path.is_absolute() else (REPO_ROOT / path)
    root = root.resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise EvaluatorError("output must remain under .artifacts/evaluator") from error
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise EvaluatorError(f"output path may not traverse a symlink: {current}")


def main() -> int:
    args = parse_args()
    evaluator_root = DEFAULT_EVALUATOR_ROOT.resolve()
    requested_output = args.output_root or (evaluator_root / args.tier)
    try:
        _reject_output_symlink_components(requested_output, evaluator_root)
    except EvaluatorError as error:
        print(f"FAIL evaluator: {error}", file=sys.stderr)
        return 1
    output_root = requested_output.resolve()
    try:
        output_root.relative_to(evaluator_root)
    except ValueError:
        print("FAIL evaluator: output must remain under .artifacts/evaluator", file=sys.stderr)
        return 1
    if output_root == evaluator_root:
        print("FAIL evaluator: output must name a tier directory", file=sys.stderr)
        return 1
    if output_root.exists():
        if args.keep_existing:
            print(f"FAIL evaluator: output already exists: {output_root}", file=sys.stderr)
            return 1
        if not output_root.is_dir() or output_root.is_symlink():
            print(f"FAIL evaluator: output is not a real directory: {output_root}", file=sys.stderr)
            return 1
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)
    try:
        manifests = validate_all_manifests(
            REPO_ROOT,
            protocol_path=REPO_ROOT / "fixtures/evaluator/evaluator-protocol.json",
            corpus_path=REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json",
            scheme_path=REPO_ROOT / "fixtures/evaluator/scheme-a-manifest.json",
            oracle_path=REPO_ROOT / "fixtures/evaluator/oracles.json",
            baseline_reference_path=REPO_ROOT / "fixtures/evaluator/baseline-reference.json",
        )
        copy_manifests(output_root)
        environment = build_environment(output_root, manifests["protocol"], manifests["scheme"])
        units = [make_compatibility_unit(output_root, row, manifests["corpus"]) for row in manifests["rows"] if row.get("required") and row.get("applicable")]
        compatibility = calculate_compatibility(manifests["corpus"], manifests["baseline"], units)
        attempts: dict[tuple[str, str, int], dict[str, Any]] = {}
        for family in manifests["families"]:
            for role in ("baseline", "candidate"):
                for replica in range(1, manifests["scheme"]["replicaCount"] + 1):
                    attempt = make_scheme_attempt(output_root, manifests["scheme"], family, role, replica)
                    attempts[(family["familyId"], role, replica)] = attempt
        scheme_gate = calculate_scheme_gate(manifests["scheme"], attempts)
        write_json(
            output_root / "scheme-a-gate.json",
            {
                "schemaVersion": 1,
                "kind": "scheme-a-gate",
                "scheme": "A",
                "protocolVersion": manifests["scheme"]["protocolVersion"],
                "baselineArtifactId": manifests["baselineReference"]["baselineArtifactId"],
                "baselineArtifactSha256": manifests["baselineReference"]["baselineArtifactSha256"],
                "requiredFamilies": scheme_gate["requiredFamilies"],
                "families": scheme_gate["families"],
                "familyFactors": scheme_gate["familyFactors"],
                "schemeAStatus": scheme_gate["status"],
                "allRequiredPass": scheme_gate["allRequiredPass"],
                "minimumFactorDiagnostic": scheme_gate["minimumFactorDiagnostic"],
            },
        )
        # Close the generated tree's structural boundary before deriving any
        # anti-gaming marker or gate digest.
        validate_no_symlinks(output_root)
        gate = build_gate(output_root, environment, manifests, compatibility, scheme_gate, units, attempts)
        write_json(output_root / "gate.json", gate)
        analysis_input = build_analysis_input(output_root, gate, units, attempts)
        write_json(output_root / "analysis-input.json", analysis_input)
        # Recompute the closed inventory after all generated evidence exists. The
        # digest intentionally excludes the two self-describing handoff files.
        gate["rawEvidenceManifestSha256"] = inventory_digest(output_root, exclude=("gate.json", "analysis-input.json"))
        gate["artifactManifestSha256"] = gate["rawEvidenceManifestSha256"]
        write_json(output_root / "gate.json", gate)
        write_json(output_root / "analysis-input.json", build_analysis_input(output_root, gate, units, attempts))
        write_top_level_manifest(output_root)
        validate_no_symlinks(output_root)
    except (EvaluatorError, OSError, ValueError) as error:
        print(f"FAIL evaluator: {error}", file=sys.stderr)
        return 1
    print(
        f"PASS evaluator evidence: root={output_root} "
        f"compatibility={gate['compatibility']['status']} "
        f"schemeA={gate['schemeA']['status']} claimable={gate['claimable']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
