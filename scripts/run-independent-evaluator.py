#!/usr/bin/env python3
"""Run the read-only compatibility/Scheme-A evaluator into its own evidence tree.

The current checkout intentionally has no Protected Image or rehydrator product
stage and no pinned Scheme-A attack tools. The runner records those facts as
machine-readable unavailable/not-calibrated evidence; it never promotes auxiliary
wrapper/protection output to a strict compatibility or strength result.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from typing import Any

from evaluator_lib import (
    COMPATIBILITY_STAGES,
    EvaluatorError,
    ProductEvidenceError,
    calculate_anti_gaming,
    calculate_compatibility,
    calculate_scheme_gate,
    canonical_json,
    calculate_claimable,
    derive_evaluator_environment_capabilities,
    evaluator_product_unit_bindings,
    copy_verified_product_evidence,
    inventory_digest,
    load_product_evidence,
    project_product_failure,
    sha256_file,
    resolve_repo_path,
    validate_all_manifests,
    validate_no_symlinks,
    validate_unit_record,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVALUATOR_ROOT = REPO_ROOT / ".artifacts" / "evaluator"
DEFAULT_BASELINE_REFERENCE = REPO_ROOT / "fixtures/evaluator/baseline-reference.json"
STRICT_UNIT_ID = "compat.protection-symbolized-fixture.glibc.outer-execveat"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), default="pr")
    parser.add_argument("--output-root", type=Path, help="evaluator evidence directory (default: .artifacts/evaluator/<tier>)")
    parser.add_argument(
        "--product-evidence-root",
        type=Path,
        help="read-only Protected Image evidence unit (default: EVALUATOR_PRODUCT_EVIDENCE_ROOT or .artifacts/protected-image/<tier>/glibc/<unit>)",
    )
    parser.add_argument(
        "--baseline-reference",
        type=Path,
        default=DEFAULT_BASELINE_REFERENCE,
        help="content-addressed baseline reference (default: fixtures/evaluator/baseline-reference.json)",
    )
    parser.add_argument("--keep-existing", action="store_true", help="fail instead of replacing only the evaluator's previous output directory")
    return parser.parse_args()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.anchor else Path.cwd()
    components = path.parts[1:] if path.anchor else path.parts
    for component in components:
        if component in {"", "."}:
            continue
        if component == "..":
            current = current.parent
            continue
        current /= component
        if current.is_symlink():
            raise EvaluatorError(f"baseline reference may not traverse a symlink: {current}")


def write_raw_manifest(raw_root: Path) -> Path:
    entries: list[str] = []
    for path in sorted(raw_root.rglob("*")):
        if not path.is_file() or path == raw_root / "SHA256SUMS":
            continue
        entries.append(f"{sha256_file(path)}  {path.relative_to(raw_root).as_posix()}\n")
    manifest = raw_root / "SHA256SUMS"
    manifest.write_text("".join(entries), encoding="utf-8")
    return manifest


def write_top_level_manifest(root: Path) -> Path:
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(root).as_posix()
        # gate.json and analysis-input.json are written after the inventory is
        # derived.  The positive-baseline handoff is likewise written by the
        # local v2 gate after this runner exits.  Keep all three out of the
        # content-addressed root manifest to avoid a circular digest.
        if relative in {"gate.json", "analysis-input.json", "positive-baseline-v2-gate.json"}:
            continue
        entries.append(f"{sha256_file(path)}  {relative}\n")
    manifest = root / "SHA256SUMS"
    manifest.write_text("".join(entries), encoding="utf-8")
    return manifest


def command_identity(command: str) -> dict[str, Any]:
    executable = shutil.which(command)
    if executable is None:
        return {"available": False, "version": None, "binarySha256": None}
    try:
        result = subprocess.run([executable, "--version"], check=False, capture_output=True, text=True, timeout=5, env=os.environ.copy())
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


def _read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def _read_proc_status() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                values[key] = value.strip()
    except OSError:
        pass
    return values


def _read_limit(resource_id: int | None) -> dict[str, int | None]:
    if resource_id is None or resource_id < 0:
        return {"soft": None, "hard": None}
    try:
        soft, hard = resource.getrlimit(resource_id)
    except (OSError, ValueError):
        return {"soft": None, "hard": None}
    infinity = resource.RLIM_INFINITY
    return {
        "soft": None if soft == infinity else int(soft),
        "hard": None if hard == infinity else int(hard),
    }


def _probe_network_syscalls() -> tuple[bool, int | None]:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        return error.errno == errno.EPERM, error.errno
    else:
        probe.close()
        return False, None


def _is_read_only(path: Path) -> bool:
    try:
        if bool(os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1)):
            return True
        if os.environ.get("EVALUATOR_STAGED_READONLY") == "1":
            resolved = path.resolve()
            try:
                resolved.relative_to(REPO_ROOT.resolve())
                resolved.relative_to((REPO_ROOT / ".artifacts/evaluator").resolve())
            except ValueError:
                return True
        mode = path.stat().st_mode
        return (mode & 0o222) == 0
    except OSError:
        return False


def _file_digest(path: Path) -> str | None:
    try:
        return sha256_file(path) if path.is_file() else None
    except (OSError, EvaluatorError):
        return None


def build_environment(
    root: Path,
    protocol: dict[str, Any],
    scheme: dict[str, Any],
    *,
    product_evidence_root: Path,
    units: list[dict[str, Any]],
) -> dict[str, Any]:
    del scheme
    architecture = platform.machine().lower()
    os_release = _read_os_release()
    tools = {name: command_identity(name) for name in ("python3", "dotnet", "readelf", "bwrap", "ldd")}
    ldd_version = tools["ldd"].get("version") or ""
    glibc_match = re.search(r"\b(\d+\.\d+)\b", ldd_version)
    glibc_version = glibc_match.group(1) if glibc_match else None
    runner = {
        "provider": "github-actions" if os.environ.get("GITHUB_ACTIONS", "").lower() == "true" else "local-or-unknown",
        "githubActions": os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
        "runnerOS": os.environ.get("RUNNER_OS"),
        "runnerArch": os.environ.get("RUNNER_ARCH"),
        "runnerName": os.environ.get("RUNNER_NAME"),
        "runId": os.environ.get("GITHUB_RUN_ID"),
        "imageOS": os.environ.get("ImageOS"),
        "imageVersion": os.environ.get("ImageVersion"),
    }
    host = {
        "system": platform.system(),
        "architecture": architecture,
        "distributionId": os_release.get("ID"),
        "distributionVersion": os_release.get("VERSION_ID"),
        "glibcVersion": glibc_version,
        "kernel": platform.release(),
        "pageSize": os.sysconf("SC_PAGESIZE") if hasattr(os, "sysconf") else None,
    }
    namespaces = {
        "currentNetwork": _read_namespace("/proc/self/ns/net"),
        "initialNetwork": _read_namespace("/proc/1/ns/net"),
    }
    proc_status = _read_proc_status()
    network_syscalls_denied, network_probe_errno = _probe_network_syscalls()
    security = {
        "noNewPrivileges": _parse_integer(proc_status.get("NoNewPrivs")),
        "effectiveCapabilities": proc_status.get("CapEff"),
        "networkSyscallsDenied": network_syscalls_denied,
        "networkProbeErrno": network_probe_errno,
    }
    mounts = {
        "repositoryReadOnly": _is_read_only(REPO_ROOT),
        "fixturesReadOnly": _is_read_only(REPO_ROOT / "fixtures"),
        "productEvidenceReadOnly": _is_read_only(product_evidence_root),
        "evaluatorOutputWritable": root.is_dir() and not _is_read_only(root) and os.access(root, os.W_OK),
    }
    budgets = dict(protocol["budgets"])
    resource_limits = {
        "cpuSeconds": _read_limit(getattr(resource, "RLIMIT_CPU", None)),
        "addressSpaceBytes": _read_limit(getattr(resource, "RLIMIT_AS", None)),
        "processes": _read_limit(getattr(resource, "RLIMIT_NPROC", None)),
        "fileSizeBytes": _read_limit(getattr(resource, "RLIMIT_FSIZE", None)),
    }
    try:
        alarm_remaining = float(signal.getitimer(signal.ITIMER_REAL)[0])
    except (OSError, ValueError):
        alarm_remaining = 0.0
    isolation = {
        "networkDisabled": False,
        "readOnlyInputs": False,
        "noNewPrivileges": False,
        "droppedCapabilities": False,
        "wallLimit": {
            "seconds": budgets.get("wallSeconds"),
            "alarmRemainingSeconds": alarm_remaining,
        },
    }
    producer_script = REPO_ROOT / "scripts/run-protected-image-e2e.sh"
    producer_source = REPO_ROOT / "src/UrProtect.Core/Protect/ProtectionPlan.cs"
    rehydrator_source = REPO_ROOT / "src/UrProtect.Core/Rehydrate/GenericRehydrationEngine.cs"
    product_capabilities = {
        "producerScriptSha256": _file_digest(producer_script),
        "producerSourceSha256": _file_digest(producer_source),
        "rehydratorSourceSha256": _file_digest(rehydrator_source),
        "strictUnits": evaluator_product_unit_bindings(units),
    }
    github_runner = (
        runner["githubActions"] is True
        and runner["runnerOS"] == "Linux"
        and runner["runnerArch"] == "ARM64"
        and bool(runner["runnerName"])
        and isinstance(runner["runId"], str)
        and runner["runId"].isdigit()
    )
    pinned_cell = (
        github_runner
        and host["distributionId"] == "ubuntu"
        and host["distributionVersion"] == "24.04"
        and host["glibcVersion"] == "2.39"
        and architecture in {"aarch64", "arm64"}
    )
    runtime_cell = "glibc.current.native-arm64" if pinned_cell else (
        f"{host['distributionId'] or 'unknown'}-{host['distributionVersion'] or 'unknown'}."
        f"glibc-{glibc_version or 'unknown'}.{architecture or 'unknown'}"
    )
    loader_identity = "not-captured"
    for unit in units:
        target_loader = unit.get("stages", {}).get("target-loader", {})
        if target_loader.get("status") == "passed" and isinstance(target_loader.get("loaderId"), str):
            loader_identity = target_loader["loaderId"]
            break
    environment = {
        "schemaVersion": 2,
        "kind": "evaluator-environment",
        "commit": git_commit(),
        "status": "environment-unavailable",
        "runner": runner,
        "host": host,
        "architecture": architecture,
        "nativeAarch64": architecture in {"aarch64", "arm64"},
        "emulated": not github_runner or architecture not in {"aarch64", "arm64"},
        "kernel": host["kernel"],
        "pageSize": host["pageSize"],
        "runtimeCell": runtime_cell,
        "loaderIdentity": loader_identity,
        "namespaces": namespaces,
        "mountFacts": mounts,
        "security": security,
        "resourceLimits": resource_limits,
        "isolation": isolation,
        "tools": tools,
        "productCapabilities": product_capabilities,
        "requiredCapabilities": {},
        "budget": budgets,
        "reason": None,
        "evaluator": {
            "runnerSha256": sha256_file(Path(__file__)),
            "librarySha256": sha256_file(Path(__file__).with_name("evaluator_lib.py")),
            "launcherSha256": sha256_file(Path(__file__).with_name("run-independent-evaluator.sh")),
            "command": "scripts/run-independent-evaluator.sh --tier <tier>",
        },
    }
    capabilities = derive_evaluator_environment_capabilities(environment)
    environment["requiredCapabilities"] = capabilities
    for field, capability in (
        ("networkDisabled", "networkDisabled"),
        ("readOnlyInputs", "readOnlyInputs"),
        ("noNewPrivileges", "noNewPrivileges"),
        ("droppedCapabilities", "droppedCapabilities"),
    ):
        isolation[field] = capabilities.get(capability) is True
    missing = [name for name, available in capabilities.items() if name != "schemeAttackToolset" and available is not True]
    environment["status"] = "environment-unavailable" if missing else "available"
    if missing:
        environment["reason"] = "required compatibility evaluator capabilities are not established: " + ", ".join(missing)
    write_json(root / "environment.json", environment)
    return environment


def _read_namespace(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _parse_integer(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None

def default_product_evidence_root(tier: str, unit_id: str) -> Path:
    configured = os.environ.get("EVALUATOR_PRODUCT_EVIDENCE_ROOT")
    if configured:
        return Path(configured)
    return REPO_ROOT / ".artifacts" / "protected-image" / tier / "glibc" / unit_id


def _compatibility_fallback_stages(
    row: dict[str, Any],
    error: ProductEvidenceError | None,
) -> tuple[dict[str, dict[str, Any]], str]:
    del row
    absent_reason = "strict Protected Image product evidence is absent; auxiliary direct ELF/wrapper evidence is not a strict-chain result"
    if error is None:
        return (
            {
                stage: {"status": "not-applicable", "reason": absent_reason}
                for stage in COMPATIBILITY_STAGES
            },
            absent_reason,
        )
    return project_product_failure(error)


def make_compatibility_unit(
    root: Path,
    row: dict[str, Any],
    corpus: dict[str, Any],
    *,
    tier: str = "pr",
    product_evidence_root: Path | None = None,
) -> dict[str, Any]:
    unit_root = root / "compatibility" / row["unitId"]
    raw_root = unit_root / "raw"
    if product_evidence_root is None:
        product_root = default_product_evidence_root(tier, row["unitId"])
    elif row["unitId"] == STRICT_UNIT_ID:
        product_root = product_evidence_root
    else:
        # An explicit root is a test/fixture projection for the frozen unit;
        # never let unrelated checkout artifacts leak into that projection.
        product_root = product_evidence_root.parent / f".absent-{row['unitId']}"
    product: dict[str, Any] | None = None
    product_error: ProductEvidenceError | None = None
    try:
        product = load_product_evidence(product_root, row, tier=tier, runtime="glibc")
    except ProductEvidenceError as error:
        # Absence retains the historical baseline-zero/not-applicable projection;
        # a present but malformed tree is retained as an explicit failure row.
        if not product_root.exists() and not product_root.is_symlink():
            product_error = None
        else:
            product_error = error

    raw_root.mkdir(parents=True, exist_ok=True)
    copied_product = False
    product_manifest_sha256: str | None = None
    source_image_sha256: str | None = None
    if product is not None:
        copy_verified_product_evidence(product["root"], product["manifestEntries"], raw_root / "product-chain")
        copied_product = True
        product_manifest_sha256 = product["productManifestSha256"]
        source_image_sha256 = product["sourceImageSha256"]
    elif product_error is not None and product_error.source_root is not None and product_error.manifest_entries:
        copy_verified_product_evidence(product_error.source_root, product_error.manifest_entries, raw_root / "product-chain")
        copied_product = True
        product_manifest_sha256 = product_error.product_manifest_sha256
        source_image_sha256 = product_error.source_image_sha256

    if product is not None:
        stages = {stage: dict(record) for stage, record in product["stages"].items()}
        reason = "all retained product Protected Image, rehydration, Native Image, loader, and behavioral-oracle records passed"
        strict_status = "measured"
        strict_chain_measured = True
        first_failure = None
        complete = True
    else:
        stages, reason = _compatibility_fallback_stages(row, product_error)
        strict_status = "baseline-zero" if product_error is None else "product-evidence-invalid"
        strict_chain_measured = False
        first_failure = None
        complete = False
        for stage in COMPATIBILITY_STAGES:
            if stages[stage]["status"] != "passed":
                first_failure = stage
                break
        if first_failure is None:
            first_failure = "protector"

    write_json(
        raw_root / "strict-chain-status.json",
        {
            "schemaVersion": 1,
            "status": strict_status,
            "statusOwner": "independent-evaluator",
            "strictChainMeasured": strict_chain_measured,
            "reason": reason,
            "auxiliaryEvidence": row.get("auxiliaryEvidence", []),
            "nativeResultsCaptured": "native-image" in stages and stages["native-image"].get("status") == "passed",
            "sourceSha256": row.get("sourceSha256"),
            "sourceImageSha256": source_image_sha256,
            "productEvidenceManifestSha256": product_manifest_sha256,
            "firstFailureLayer": first_failure,
        },
    )
    raw_manifest = write_raw_manifest(raw_root)
    unit = {
        "schemaVersion": 1,
        "kind": "compatibility-unit",
        "unitId": row["unitId"],
        "identityKey": row["identityKey"],
        "sourceProvenance": row["sourceProvenance"],
        "producerRecipeSha256": row["producerRecipeSha256"],
        "corpusVersion": corpus["corpusVersion"],
        "sourceSha256": row["sourceSha256"],
        "sourceImageSha256": source_image_sha256,
        "profile": row["profile"],
        "runtimeCell": row["runtimeCell"],
        "targetLoader": row["targetLoader"],
        "oracleId": row["oracleId"],
        "statusOwner": "independent-evaluator",
        "stages": stages,
        "complete": complete,
        "firstFailureLayer": None if complete else first_failure,
        "rawEvidenceManifest": str(raw_manifest.relative_to(root)),
        "evidenceStatus": strict_status,
        "strictChainMeasured": strict_chain_measured,
        "productEvidence": {
            "rawRoot": "raw/product-chain",
            "manifestSha256": product_manifest_sha256,
        }
        if copied_product
        else None,
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


def copy_manifests(root: Path, baseline_reference_path: Path, baseline_artifact_path: Path) -> None:
    sources = {
        "protocol.json": REPO_ROOT / "fixtures/evaluator/evaluator-protocol.json",
        "corpus-manifest.json": REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json",
        "scheme-a-manifest.json": REPO_ROOT / "fixtures/evaluator/scheme-a-manifest.json",
        "oracles.json": REPO_ROOT / "fixtures/evaluator/oracles.json",
        "baseline-reference.json": baseline_reference_path,
        "baseline-artifact.json": baseline_artifact_path,
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
    baseline_artifact_path: Path,
) -> dict[str, Any]:
    reference = manifests["baselineReference"]
    anti_gaming = calculate_anti_gaming(
        REPO_ROOT,
        manifests,
        compatibility,
        units,
        attempts,
        raw_evidence_bounded=True,
        baseline_artifact_path=baseline_artifact_path,
    )
    # An independently measured row is not claimable when the evaluator's
    # declared native/isolation environment is unavailable.  Keep the
    # environment gate independent from stage projections so a stale or
    # partially provisioned runner cannot turn a complete-looking evidence
    # tree into a parent claim.
    residual_risks: list[str] = []
    if compatibility["status"] == "baseline-zero":
        residual_risks.append("strict compatibility is baseline-zero because Protected Image and rehydration stages are not product-declared")
    elif not compatibility["growthViewPass"]:
        residual_risks.append("strict compatibility fixed evidence is measured, but the exact growth target is not met")
    if scheme_gate["status"] == "baseline-not-calibrated":
        residual_risks.append("Scheme-A is baseline-not-calibrated because no required family has three finite reproducible baseline successes")
    if environment["status"] != "available":
        residual_risks.append("required evaluator environment capabilities are unavailable and are not fabricated")
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
        "claimable": calculate_claimable(environment, compatibility, scheme_gate, anti_gaming, units),
        "residualRisks": residual_risks,
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
        baseline_reference_path = args.baseline_reference
        if not baseline_reference_path.is_absolute():
            baseline_reference_path = REPO_ROOT / baseline_reference_path
        reject_symlink_components(baseline_reference_path)
        if baseline_reference_path.is_symlink():
            raise EvaluatorError("baseline reference must be a regular non-symlink file")
        baseline_reference_path = baseline_reference_path.resolve(strict=True)
        if not baseline_reference_path.is_file():
            raise EvaluatorError("baseline reference must be a regular non-symlink file")
        manifests = validate_all_manifests(
            REPO_ROOT,
            protocol_path=REPO_ROOT / "fixtures/evaluator/evaluator-protocol.json",
            corpus_path=REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json",
            scheme_path=REPO_ROOT / "fixtures/evaluator/scheme-a-manifest.json",
            oracle_path=REPO_ROOT / "fixtures/evaluator/oracles.json",
            baseline_reference_path=baseline_reference_path,
        )
        baseline_artifact_path = resolve_repo_path(
            REPO_ROOT,
            manifests["baselineReference"]["baselineArtifactPath"],
            "baselineArtifactPath",
            require_file=True,
        )
        copy_manifests(output_root, baseline_reference_path, baseline_artifact_path)
        product_evidence_root = args.product_evidence_root
        if product_evidence_root is None:
            product_evidence_root = default_product_evidence_root(args.tier, STRICT_UNIT_ID)
        units = [
            make_compatibility_unit(
                output_root,
                row,
                manifests["corpus"],
                tier=args.tier,
                product_evidence_root=product_evidence_root,
            )
            for row in manifests["rows"]
            if row.get("required") and row.get("applicable")
        ]
        signal.setitimer(signal.ITIMER_REAL, float(manifests["protocol"]["budgets"]["wallSeconds"]))
        environment = build_environment(
            output_root,
            manifests["protocol"],
            manifests["scheme"],
            product_evidence_root=product_evidence_root,
            units=units,
        )
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
        gate = build_gate(
            output_root,
            environment,
            manifests,
            compatibility,
            scheme_gate,
            units,
            attempts,
            output_root / "baseline-artifact.json",
        )
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
