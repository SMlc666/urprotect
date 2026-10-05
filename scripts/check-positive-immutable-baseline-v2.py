#!/usr/bin/env python3
"""Freeze and validate the positive immutable strict-chain baseline-v2.

The command is deliberately a control-plane operation.  It only reads the
producer, rehydration, evaluator, and frozen-manifest evidence trees.  When
all checks pass it may create the additive baseline and its external reference
exactly once; a failed check writes only a bounded blocked gate record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from evaluator_lib import (  # noqa: E402
    COMPATIBILITY_STAGES,
    EVIDENCE_HANDOFF_FILES,
    REQUIRED_FAMILIES,
    EvaluatorError,
    canonical_json,
    load_product_evidence,
    read_json,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
)

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TREE_FILES = 10_000
MAX_TREE_BYTES = 536_870_912
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
UNIT_ID = "compat.protection-symbolized-fixture.glibc.outer-execveat"

# These are the reviewed v1 corpus/protocol identities and the strict-chain
# hashes observed by the analysis task.  They are intentionally explicit: a
# positive denominator must not be assembled from a merely self-consistent,
# rewritten ledger.
EXPECTED = {
    "corpusVersion": "compat-corpus-v1",
    "protocolVersion": "evaluator-v1",
    "schemeProtocolVersion": "scheme-a-v1",
    "corpusManifestSha256": "8f48bed4fe66a2fde8ad968972fec2654890956d777a54d6394687d5e503efa4",
    "protocolSha256": "b3aa29a728cb4e98d4704ab7fa9cd7bf6e4afefaa6e646fde92a211557e8c6bd",
    "schemeManifestSha256": "bece932bd38e8c3e1def844023e19306acd37583862f17c6e3943c4ecf57eacc",
    "oracleManifestSha256": "91e8a867157808f839edbabaf6c766c00d86e10f10729130debab0ce640175a4",
    "runtimeRegistrySha256": "8d778d22926ba5e2791f46821623700e0baccad3fce26201e10ba6cf0ea0dac5",
    "fixtureManifestSha256": "c354380e84234e6dd94a9d848956010a2d92ad4014dcec24bf5e466eb9a3ddab",
    "toolchainManifestSha256": "613d8088b6ee7dc9df930863d12b2434ce927363431d863b1bef09a726f8833d",
    "unitId": UNIT_ID,
    "identityKey": "protection-symbolized-fixture",
    "sourceSha256": "4f26b59a88c9ccfac1edee65dddb5f3bef2db4d7e7cfad99ec1d032fd8864088",
    "sourceImageSha256": "d676d7180958ea55fe3344c02ebb213d3b40c75f5fccdbeebd4b16aa82e26ac9",
    "protectedImageSha256": "2e59a4472f11626a0a9465d049c8be0363c95189525b22cf66229114b276ba62",
    "nativeImageSha256": "ede64f3fcc2c9651c8c92e3686bcd206f04ad783b72afdb415ef836de4505fff",
    "handoffSha256": "cb8475c4e8fe834555e03317adf27cb52f6f21193d717e3418a97f1b4b643850",
    "behaviorComparisonSha256": "179a03ec7a6e41f513ce74f7602434c238b52604c5d8f1d30371ef982672bcbf",
    "producerId": "gcc-c-protection-fixture",
    "producerBuildSha256": "b1dd5735d33bba36d53421e33bb237e8baaee882c2e124dce2e5b21b56bbb360",
    "requestSha256": "4c759b0d839d8f3e6452271981031a423210df7759fe069600f1622458e1a575",
    "consumerId": "urprotect.rehydrator.v1",
    "consumerBuildSha256": "57589fa193df5bd7a35dd9efad0bf0d56d5a28b0a127e9d1f247f2403fcdf66d",
    "loaderId": "kernel.execveat-at-empty-path",
    "oracleId": "fixture.process-oracle.v1",
    "protectedImageSize": 393,
    "nativeImageSize": 73764,
    "targetStatus": 0,
    "targetSignal": None,
    "oldBaselineId": "compatibility-1x-baseline-zero",
    "oldBaselineSha256": "3e34370ec7db4095fdbc9465f25df13370dda6372efff395cd707d15c84806c2",
    "oldReferenceSha256": "3290389f3c28778131b6a633143f17432cc3ffc807d3e38907e941495636b44c",
}


class GateError(ValueError):
    """A local baseline precondition failed."""


class State:
    """Bounded values retained while projecting the immutable ledger."""

    def __init__(self) -> None:
        self.evaluator_root: Path
        self.product_root: Path
        self.gate: dict[str, Any]
        self.environment: dict[str, Any]
        self.unit: dict[str, Any]
        self.row: dict[str, Any]
        self.product: dict[str, Any]
        self.product_manifest: dict[str, str]
        self.raw_manifest: dict[str, str]
        self.product_chain_manifest: dict[str, str]
        self.negative_path: Path
        self.negative_sha256: str
        self.commit: str
        self.root_manifest_sha256: str
        self.unit_sha256: str
        self.unit_raw_manifest_sha256: str
        self.product_manifest_sha256: str
        self.evaluator_gate_sha256: str
        self.analysis_input_sha256: str
        self.environment_sha256: str
        self.scheme_manifest_sha256: str


def fail(message: str) -> None:
    raise GateError(message)


def _assert_regular(path: Path, label: str, *, directory: bool = False) -> None:
    try:
        if path.is_symlink():
            fail(f"{label} is a symlink")
        if directory:
            if not path.is_dir():
                fail(f"{label} is not a directory")
        elif not path.is_file():
            fail(f"{label} is not a regular file")
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject a symlink in every existing component before resolving a path."""
    if "\x00" in str(path) or "\\" in str(path):
        fail(f"{label} contains an unsafe path")
    current = Path(path.anchor) if path.anchor else Path.cwd()
    parts = path.parts[1:] if path.anchor else path.parts
    for component in parts:
        if component in {"", ".", ".."}:
            fail(f"{label} contains an unsafe path component")
        current /= component
        try:
            if current.is_symlink():
                fail(f"{label} traverses a symlink")
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")


def _repo_path(value: str | Path, label: str, *, allow_fixtures: bool = True) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = REPO_ROOT / path
    _reject_symlink_components(path, label)
    resolved = path.resolve(strict=False)
    allowed_roots = [REPO_ROOT / ".artifacts"]
    if allow_fixtures:
        allowed_roots.append(REPO_ROOT / "fixtures")
    allowed = False
    for root in allowed_roots:
        try:
            resolved.relative_to(root.resolve())
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        fail(f"{label} must remain in repository fixtures or .artifacts")
    return resolved


def _under(root: Path, relative: Any, label: str) -> Path:
    try:
        safe = safe_relative_path(relative, label)
    except EvaluatorError as error:
        fail(str(error))
    path = root / safe
    _reject_symlink_components(path, label)
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise GateError(f"{label} escapes its root") from error
    return resolved


def _bounded_tree(root: Path, label: str) -> None:
    _assert_regular(root, label, directory=True)
    count = 0
    total = 0
    try:
        for path in root.rglob("*"):
            if path.is_symlink():
                fail(f"{label} contains a symlink")
            if path.is_file():
                count += 1
                total += path.stat().st_size
                if count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                    fail(f"{label} exceeds the bounded evidence limit")
            elif not path.is_dir():
                fail(f"{label} contains a non-regular path")
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = read_json(path, max_bytes=1_048_576)
    except (EvaluatorError, OSError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid: {error}")
    return value


def _hash(path: Path, label: str) -> str:
    _assert_regular(path, label)
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            fail(f"{label} exceeds the bounded file size")
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    return sha256_file(path)


def _verify_manifest(
    root: Path,
    relative_manifest: str,
    label: str,
    *,
    excluded: Iterable[str] = (),
    exclude_nested_manifests: bool = False,
) -> tuple[dict[str, str], str]:
    """Verify a normalized, closed SHA256SUMS tree without following links."""
    manifest = _under(root, relative_manifest, f"{label} manifest")
    _assert_regular(manifest, f"{label} manifest")
    if manifest.name != "SHA256SUMS":
        fail(f"{label} manifest must be named SHA256SUMS")
    if manifest.stat().st_size > MAX_MANIFEST_BYTES:
        fail(f"{label} manifest exceeds the bounded size")
    excluded_set = set(excluded)
    declared: dict[str, str] = {}
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {label} manifest: {error}")
    for line_number, line in enumerate(lines, 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or len(fields[0]) != 64 or any(char not in "0123456789abcdef" for char in fields[0]):
            fail(f"{label} manifest line {line_number} is not normalized")
        digest, relative_value = fields
        try:
            relative = safe_relative_path(relative_value, f"{label} manifest line {line_number}")
        except EvaluatorError as error:
            fail(str(error))
        if relative in declared or relative == "SHA256SUMS":
            fail(f"{label} manifest contains a duplicate/self path")
        path = _under(root, relative, f"{label} manifest line {line_number}")
        _assert_regular(path, f"{label} manifest entry {relative}")
        if _hash(path, f"{label} manifest entry {relative}") != digest:
            fail(f"{label} manifest hash mismatch: {relative}")
        declared[relative] = digest
    expected = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and (not exclude_nested_manifests or path.name != "SHA256SUMS")
        and path != manifest
        and path.relative_to(root).as_posix() not in excluded_set
    }
    if set(declared) != expected:
        fail(
            f"{label} manifest is not closed: "
            f"missing={sorted(expected - set(declared))[:8]}, "
            f"extra={sorted(set(declared) - expected)[:8]}"
        )
    return declared, _hash(manifest, f"{label} manifest")


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"cannot resolve checkout commit: {error}")
    commit = result.stdout.strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        fail("checkout commit is not a normalized SHA-1")
    return commit


def _run_independent_checker(root: Path) -> None:
    checker = REPO_ROOT / "scripts" / "check-independent-evaluator.py"
    result = subprocess.run(
        [sys.executable, str(checker), str(root)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:512]
        fail(f"independent evaluator checker failed: {detail}")


def _verify_old_baseline(previous: Path, previous_reference: Path) -> dict[str, Any]:
    actual = _hash(previous, "historical baseline")
    if actual != EXPECTED["oldBaselineSha256"]:
        fail("historical baseline bytes changed")
    reference_actual = _hash(previous_reference, "historical baseline reference")
    if reference_actual != EXPECTED["oldReferenceSha256"]:
        fail("historical baseline reference bytes changed")
    artifact = _read_json(previous, "historical baseline")
    reference = _read_json(previous_reference, "historical baseline reference")
    if (
        artifact.get("immutableArtifactId") != EXPECTED["oldBaselineId"]
        or artifact.get("baselineStatus") != "baseline-zero"
        or artifact.get("completeUnits") != 0
        or artifact.get("completeUnitIds") != []
        or artifact.get("immutable") is not True
    ):
        fail("historical baseline is not the frozen baseline-zero object")
    if (
        reference.get("baselineArtifactId") != EXPECTED["oldBaselineId"]
        or reference.get("baselineArtifactSha256") != EXPECTED["oldBaselineSha256"]
        or reference.get("completeUnits") != 0
        or reference.get("immutable") is not True
        or reference.get("contentAddressed") is not True
        or reference.get("neverOverwrite") is not True
    ):
        fail("historical baseline reference binding changed")
    return {"artifact": artifact, "reference": reference}


def _verify_environment(state: State) -> None:
    gate = state.gate
    environment = state.environment
    if environment.get("schemaVersion") != 1 or environment.get("kind") != "evaluator-environment":
        fail("evaluator environment schema is invalid")
    if gate.get("schemaVersion") != 1 or gate.get("kind") != "urprotect-independent-evaluator":
        fail("evaluator gate schema is invalid")
    if gate.get("commit") != environment.get("commit") or gate.get("commit") != state.commit:
        fail("checkout, evaluator gate, and environment commits do not match")
    if environment.get("status") != "available":
        fail("compatibility evaluator environment is unavailable")
    if environment.get("architecture") not in {"aarch64", "arm64"} or environment.get("nativeAarch64") is not True:
        fail("compatibility evidence is not native AArch64")
    if environment.get("emulated") is not False:
        fail("compatibility evidence is emulated")
    if environment.get("runtimeCell") != "glibc.current.native-arm64":
        fail("compatibility runtime cell is not the frozen native glibc cell")
    if environment.get("loaderIdentity") != EXPECTED["loaderId"]:
        fail("environment loader identity is not the declared native loader")
    capabilities = environment.get("requiredCapabilities")
    if not isinstance(capabilities, dict):
        fail("environment requiredCapabilities is missing")
    required_true = (
        "nativeAarch64",
        "pinnedRuntimeCell",
        "dotnetSdk",
        "protectedImageProducer",
        "rehydrator",
        "networkDisabled",
    )
    for name in required_true:
        if capabilities.get(name) is not True:
            fail(f"required compatibility capability is unavailable: {name}")
    # Scheme-A tooling is independent of a compatibility denominator and may
    # remain absent, but it must be represented as a boolean fact.
    if not isinstance(capabilities.get("schemeAttackToolset"), bool):
        fail("Scheme-A capability fact is malformed")
    isolation = environment.get("isolation")
    if not isinstance(isolation, dict):
        fail("evaluator isolation facts are missing")
    for name in ("networkDisabled", "readOnlyInputs", "noNewPrivileges", "droppedCapabilities"):
        if isolation.get(name) is not True:
            fail(f"declared evaluator isolation capability is unavailable: {name}")
    gate_environment = gate.get("environment")
    if not isinstance(gate_environment, dict):
        fail("evaluator gate environment projection is missing")
    if (
        gate_environment.get("status") != environment.get("status")
        or gate_environment.get("runtimeCell") != environment.get("runtimeCell")
        or gate_environment.get("requiredCapabilities") != capabilities
    ):
        fail("evaluator gate/environment capability projections differ")
    if gate.get("claimable") is not False:
        fail("strict positive baseline input must not be claimable")
    compatibility = gate.get("compatibility")
    if not isinstance(compatibility, dict):
        fail("evaluator compatibility projection is missing")
    if (
        compatibility.get("status") != "baseline-zero"
        or compatibility.get("baselineCompleteUnits") != 0
        or compatibility.get("candidateFixedCompleteUnits") != 1
        or compatibility.get("candidateGrowthCompleteUnits") != 1
        or compatibility.get("factor") is not None
        or compatibility.get("growthTarget") != 0
        or compatibility.get("growthViewPass") is not False
    ):
        fail("positive candidate must preserve the historical baseline-zero evaluator result")


def _verify_identities(state: State) -> None:
    root = state.evaluator_root
    expected_files = {
        "protocol.json": EXPECTED["protocolSha256"],
        "corpus-manifest.json": EXPECTED["corpusManifestSha256"],
        "scheme-a-manifest.json": EXPECTED["schemeManifestSha256"],
        "oracles.json": EXPECTED["oracleManifestSha256"],
    }
    for name, expected in expected_files.items():
        path = _under(root, name, f"evaluator {name}")
        if _hash(path, f"evaluator {name}") != expected:
            fail(f"evaluator identity changed: {name}")
    protocol = _read_json(_under(root, "protocol.json", "protocol"), "protocol")
    corpus = _read_json(_under(root, "corpus-manifest.json", "corpus"), "corpus")
    scheme = _read_json(_under(root, "scheme-a-manifest.json", "Scheme-A manifest"), "Scheme-A manifest")
    oracles = _read_json(_under(root, "oracles.json", "oracle registry"), "oracle registry")
    if protocol.get("protocolVersion") != EXPECTED["protocolVersion"] or corpus.get("corpusVersion") != EXPECTED["corpusVersion"]:
        fail("protocol/corpus version changed")
    digests = protocol.get("manifestDigests")
    if not isinstance(digests, dict):
        fail("protocol manifest digest ledger is missing")
    digest_expectations = {
        "compatibilityCorpusSha256": EXPECTED["corpusManifestSha256"],
        "runtimeMatrixSha256": EXPECTED["runtimeRegistrySha256"],
        "schemeAManifestSha256": EXPECTED["schemeManifestSha256"],
        "oracleRegistrySha256": EXPECTED["oracleManifestSha256"],
        "toolchainManifestSha256": EXPECTED["toolchainManifestSha256"],
    }
    for name, expected in digest_expectations.items():
        if digests.get(name) != expected:
            fail(f"protocol manifest identity changed: {name}")
    rows = corpus.get("rows")
    fixed = corpus.get("fixedRowIds")
    if not isinstance(rows, list) or not isinstance(fixed, list) or len(rows) != 1 or fixed != [UNIT_ID]:
        fail("strict positive baseline requires exactly one frozen corpus row")
    row = rows[0]
    source_corpus = _read_json(REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json", "source corpus")
    if row != source_corpus.get("rows", [None])[0]:
        fail("fixed corpus row metadata changed")
    if (
        row.get("unitId") != UNIT_ID
        or row.get("identityKey") != EXPECTED["identityKey"]
        or row.get("sourceSha256") != EXPECTED["sourceSha256"]
        or row.get("profile") != "outer-execveat"
        or row.get("runtimeCell") != "glibc.current.native-arm64"
        or row.get("targetLoader") != EXPECTED["loaderId"]
        or row.get("oracleId") != EXPECTED["oracleId"]
        or row.get("required") is not True
        or row.get("applicable") is not True
        or row.get("registrationStatus") != "frozen"
    ):
        fail("fixed corpus row identity is not the reviewed row")
    state.row = row
    if scheme.get("protocolVersion") != EXPECTED["schemeProtocolVersion"]:
        fail("Scheme-A protocol version changed")
    if not isinstance(oracles.get("oracles"), list) or not any(entry.get("oracleId") == EXPECTED["oracleId"] for entry in oracles["oracles"]):
        fail("frozen behavior oracle is not registered")
    state.scheme_manifest_sha256 = EXPECTED["schemeManifestSha256"]


def _verify_scheme_a(state: State) -> None:
    root = state.evaluator_root
    scheme = _read_json(_under(root, "scheme-a-manifest.json", "Scheme-A manifest"), "Scheme-A manifest")
    scheme_gate = _read_json(_under(root, "scheme-a-gate.json", "Scheme-A gate"), "Scheme-A gate")
    gate_scheme = state.gate.get("schemeA")
    if not isinstance(gate_scheme, dict):
        fail("evaluator Scheme-A projection is missing")
    if scheme.get("protocolVersion") != "scheme-a-v1" or scheme.get("baselineStatus") != "baseline-not-calibrated":
        fail("Scheme-A baseline policy drifted")
    if scheme.get("publishedArtifactSha256") is not None or scheme.get("publishedArtifactStatus") != "not-produced":
        fail("Scheme-A publication state is unexpectedly calibrated")
    entries = scheme.get("requiredFamilies")
    if not isinstance(entries, list) or [entry.get("familyId") for entry in entries] != list(REQUIRED_FAMILIES):
        fail("Scheme-A required family list changed")
    if any(entry.get("required") is not True or entry.get("applicable") is not True for entry in entries):
        fail("Scheme-A family was removed or downgraded")
    if (
        scheme_gate.get("schemeAStatus") != "baseline-not-calibrated"
        or scheme_gate.get("requiredFamilies") != list(REQUIRED_FAMILIES)
        or scheme_gate.get("allRequiredPass") is not False
        or scheme_gate.get("familyFactors") != {family: None for family in REQUIRED_FAMILIES}
    ):
        fail("Scheme-A gate is not the six-family uncalibrated result")
    families = scheme_gate.get("families")
    if not isinstance(families, dict) or set(families) != set(REQUIRED_FAMILIES):
        fail("Scheme-A gate family projection is incomplete")
    for family in REQUIRED_FAMILIES:
        result = families[family]
        if (
            result.get("status") != "baseline-not-calibrated"
            or result.get("baselineReplicas") != 0
            or result.get("baselineCostCpuNs") is not None
            or result.get("factorLowerBound") is not None
        ):
            fail(f"Scheme-A family was assigned a fabricated baseline: {family}")
    if (
        gate_scheme.get("status") != "baseline-not-calibrated"
        or gate_scheme.get("requiredFamilies") != list(REQUIRED_FAMILIES)
        or gate_scheme.get("familyFactors") != {family: None for family in REQUIRED_FAMILIES}
        or gate_scheme.get("allRequiredPass") is not False
    ):
        fail("evaluator gate promoted Scheme-A")


def _verify_negative_witness(state: State) -> None:
    candidates = (
        state.product_root / "negative-rollback.json",
        state.product_root / "negative" / "rollback.json",
        state.product_root / "negative-rehydration-rollback.json",
    )
    path = next((candidate for candidate in candidates if candidate.is_file() and not candidate.is_symlink()), None)
    if path is None:
        fail("nearest-negative rollback witness is missing")
    _reject_symlink_components(path, "negative rollback witness")
    relative = path.relative_to(state.product_root).as_posix()
    if relative not in state.product_manifest:
        fail("negative rollback witness is not covered by the product manifest")
    witness = _read_json(path, "negative rollback witness")
    if (
        witness.get("schemaVersion") != 1
        or witness.get("kind") != "strict-chain-negative-witness"
        or witness.get("status") != "passed"
        or witness.get("unitId") != UNIT_ID
        or witness.get("rollbackStatus") != "passed"
        or witness.get("nativeImagePublished") is not False
        or witness.get("loaderInvoked") is not False
        or witness.get("loaderMarkerObserved") is not False
    ):
        fail("negative rollback witness does not prove blocked/no-publication behavior")
    if witness.get("stage") not in {"protected-image", "rehydration", "native-image", "target-loader"}:
        fail("negative rollback witness names an unsupported stage")
    if not isinstance(witness.get("failureClass"), str) or not witness["failureClass"]:
        fail("negative rollback witness has no bounded failure class")
    for field in ("artifactPath", "nativeImagePath", "loaderMarkerPath"):
        if field in witness and witness[field] is not None:
            try:
                safe_relative_path(witness[field], f"negative witness {field}")
            except EvaluatorError as error:
                fail(str(error))
    state.negative_path = path
    state.negative_sha256 = _hash(path, "negative rollback witness")


def _verify_unit(state: State) -> None:
    root = state.evaluator_root
    compatibility_root = _under(root, "compatibility", "compatibility root")
    _assert_regular(compatibility_root, "compatibility root", directory=True)
    unit_paths = sorted(path / "unit.json" for path in compatibility_root.iterdir() if path.is_dir() and not path.is_symlink() and (path / "unit.json").is_file())
    if len(unit_paths) != 1 or unit_paths[0].parent.name != UNIT_ID:
        fail("fixed compatibility view must contain exactly one unit record")
    unit_path = unit_paths[0]
    unit = _read_json(unit_path, "strict unit")
    state.unit = unit
    if (
        unit.get("unitId") != UNIT_ID
        or unit.get("corpusVersion") != EXPECTED["corpusVersion"]
        or unit.get("sourceSha256") != EXPECTED["sourceSha256"]
        or not isinstance(unit.get("sourceImageSha256"), str)
        or len(unit.get("sourceImageSha256", "")) != 64
        or unit.get("profile") != "outer-execveat"
        or unit.get("runtimeCell") != "glibc.current.native-arm64"
        or unit.get("targetLoader") != EXPECTED["loaderId"]
        or unit.get("oracleId") != EXPECTED["oracleId"]
        or unit.get("complete") is not True
        or unit.get("strictChainMeasured") is not True
        or unit.get("evidenceStatus") != "measured"
        or unit.get("firstFailureLayer") is not None
        or unit.get("statusOwner") != "independent-evaluator"
    ):
        fail("strict unit identity or completion projection is invalid")
    stages = unit.get("stages")
    if not isinstance(stages, dict) or tuple(stages) != COMPATIBILITY_STAGES:
        # JSON key order is not a semantic identity, but accepting an omitted
        # or extra stage would permit a partial strict chain to count.
        if not isinstance(stages, dict) or set(stages) != set(COMPATIBILITY_STAGES):
            fail("strict unit does not contain exactly the six stages")
    if set(stages) != set(COMPATIBILITY_STAGES) or any(record.get("status") != "passed" for record in stages.values()):
        fail("strict unit has a non-passed or missing stage")
    unit_root = unit_path.parent
    raw_relative = unit.get("rawEvidenceManifest")
    raw_manifest_path = _under(root, raw_relative, "unit raw evidence manifest")
    state.raw_manifest, state.unit_raw_manifest_sha256 = _verify_manifest(
        raw_manifest_path.parent,
        "SHA256SUMS",
        "unit raw evidence",
    )
    state.unit_sha256 = _hash(unit_path, "unit record")
    strict_status_path = _under(raw_manifest_path.parent, "strict-chain-status.json", "strict status")
    strict_status = _read_json(strict_status_path, "strict status")
    if (
        strict_status.get("status") != "measured"
        or strict_status.get("strictChainMeasured") is not True
        or strict_status.get("nativeResultsCaptured") is not True
        or strict_status.get("firstFailureLayer") is not None
        or not isinstance(strict_status.get("sourceImageSha256"), str)
        or len(strict_status.get("sourceImageSha256", "")) != 64
    ):
        fail("strict status does not prove native six-stage measurement")
    product_relative = unit.get("productEvidence", {}).get("rawRoot") if isinstance(unit.get("productEvidence"), dict) else None
    product_chain_root = _under(unit_root, product_relative, "unit product-chain root")
    state.product_chain_manifest, product_chain_sha = _verify_manifest(product_chain_root, "SHA256SUMS", "unit product-chain evidence")
    if unit.get("productEvidence", {}).get("manifestSha256") != product_chain_sha:
        fail("unit product evidence manifest binding is stale")
    state.product_root = _repo_path(args_product_root, "product evidence root")
    _bounded_tree(state.product_root, "product evidence")
    state.product_manifest, state.product_manifest_sha256 = _verify_manifest(state.product_root, "SHA256SUMS", "product evidence")
    if product_chain_sha != state.product_manifest_sha256:
        fail("retained product-chain manifest differs from product evidence manifest")
    for relative, digest in state.product_manifest.items():
        if state.product_chain_manifest.get(relative) != digest:
            fail(f"retained product-chain evidence differs from product evidence: {relative}")
    product = load_product_evidence(state.product_root, state.row, tier="pr", runtime="glibc", require_unit_root_name=False)
    state.product = product
    if product.get("stages") != stages or product.get("sourceImageSha256") != unit.get("sourceImageSha256"):
        fail("strict unit stages differ from independently recomputed product evidence")
    retained_source_sha256 = _hash(product_chain_root / "source-image.bin", "retained Source Image")
    if retained_source_sha256 != unit.get("sourceImageSha256") or strict_status.get("sourceImageSha256") != retained_source_sha256:
        fail("strict Source Image hash is not continuous across the unit evidence")
    _verify_negative_witness(state)
    _verify_stage_ledger(state, product_chain_root)


def _verify_stage_ledger(state: State, product_chain_root: Path) -> None:
    stage_files = {
        "source": "source-image.bin",
        "protected": "protected-image.bin",
        "native": "native-image.bin",
        "handoff": "handoff.json",
        "comparison": "behavior-comparison.json",
    }
    hashes = {name: _hash(product_chain_root / filename, filename) for name, filename in stage_files.items()}
    # The bytes are content-addressed by the fresh run.  Verify their exact
    # continuity and distinctness rather than pinning a compiler-dependent
    # build output to the older retained observation.
    if len(set(hashes.values())) != len(hashes):
        fail("strict source, image, handoff, and oracle evidence hashes are not distinct")
    producer = _read_json(product_chain_root / "stage.json", "producer stage")
    protected = _read_json(product_chain_root / "protected-image.json", "Protected Image role")
    rehydration = _read_json(product_chain_root / "rehydration.json", "rehydration record")
    native = _read_json(product_chain_root / "native-image.json", "Native Image role")
    handoff = _read_json(product_chain_root / "handoff.json", "native handoff")
    loader = _read_json(product_chain_root / "target-loader.json", "target loader")
    oracle = _read_json(product_chain_root / "behavioral-oracle.json", "behavioral oracle")
    source_sha256 = hashes["source"]
    protected_sha256 = hashes["protected"]
    native_sha256 = hashes["native"]
    handoff_sha256 = hashes["handoff"]
    comparison_sha256 = hashes["comparison"]
    for label, value in (
        ("producer build", producer.get("producerBuildSha256")),
        ("request", producer.get("requestSha256")),
        ("consumer build", rehydration.get("consumerBuildSha256")),
    ):
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            fail(f"{label} identity is not a normalized digest")
    if (
        producer.get("producerId") != EXPECTED["producerId"]
        or protected.get("producerId") != producer.get("producerId")
        or rehydration.get("producerId") != producer.get("producerId")
        or producer.get("requestSha256") != protected.get("requestSha256")
        or rehydration.get("requestSha256") != producer.get("requestSha256")
        or protected.get("abiId") != "urprotect.protected-image.v1"
        or protected.get("abiVersion") != 1
        or protected.get("artifactSha256") != protected_sha256
        or protected.get("artifactSize") != (product_chain_root / "protected-image.bin").stat().st_size
    ):
        fail("Protected Image producer/role ledger is not continuous")
    if (
        rehydration.get("consumerId") != EXPECTED["consumerId"]
        or rehydration.get("consumerBuildSha256") != native.get("consumerBuildSha256")
        or rehydration.get("protectedImageSha256") != protected_sha256
        or rehydration.get("nativeImageSha256") != native_sha256
        or rehydration.get("nativeImageSize") != (product_chain_root / "native-image.bin").stat().st_size
        or rehydration.get("handoffRecordSha256") != handoff_sha256
    ):
        fail("rehydration ledger is not continuous")
    if (
        native.get("abiId") != "urprotect.native-image.v1"
        or native.get("abiVersion") != 1
        or native.get("nativeImageSha256") != native_sha256
        or native.get("nativeImageSize") != (product_chain_root / "native-image.bin").stat().st_size
        or native.get("rehydrationRecordSha256") != _hash(product_chain_root / "rehydration.json", "rehydration record")
    ):
        fail("Native Image role ledger is not continuous")
    if (
        handoff.get("loaderId") != EXPECTED["loaderId"]
        or handoff.get("nativeImageSha256") != native_sha256
        or handoff.get("targetStatus") != EXPECTED["targetStatus"]
        or handoff.get("targetSignal") is not EXPECTED["targetSignal"]
        or handoff.get("execveatInvoked") is not True
        or handoff.get("sealsApplied") is not True
    ):
        fail("native handoff ledger is not continuous")
    if (
        loader.get("loaderId") != EXPECTED["loaderId"]
        or loader.get("nativeImageSha256") != native_sha256
        or loader.get("evidenceSha256") != handoff_sha256
        or loader.get("targetStatus") != EXPECTED["targetStatus"]
        or loader.get("targetSignal") is not EXPECTED["targetSignal"]
        or loader.get("status") != "passed"
    ):
        fail("target-loader ledger is not continuous")
    if (
        oracle.get("oracleId") != EXPECTED["oracleId"]
        or oracle.get("sourceSha256") != source_sha256
        or oracle.get("nativeImageSha256") != native_sha256
        or oracle.get("comparisonSha256") != comparison_sha256
        or oracle.get("baselineStatus") != 0
        or oracle.get("targetStatus") != 0
        or oracle.get("stdoutEqual") is not True
        or oracle.get("stderrEqual") is not True
        or oracle.get("status") != "passed"
    ):
        fail("behavioral oracle did not prove equality")
    comparison = _read_json(product_chain_root / "behavior-comparison.json", "behavior comparison")
    if (
        comparison.get("sourceSha256") != source_sha256
        or comparison.get("nativeImageSha256") != native_sha256
        or comparison.get("statusEqual") is not True
        or comparison.get("stdoutEqual") is not True
        or comparison.get("stderrEqual") is not True
        or comparison.get("baselineStatus") != 0
        or comparison.get("targetStatus") != 0
    ):
        fail("behavior comparison is not equal")


def _relative_repo(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def _project_payload(state: State) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    root = state.evaluator_root
    state.evaluator_gate_sha256 = _hash(root / "gate.json", "evaluator gate")
    state.analysis_input_sha256 = _hash(root / "analysis-input.json", "analysis input")
    state.environment_sha256 = _hash(root / "environment.json", "evaluator environment")
    producer = _read_json(state.product_root / "stage.json", "producer stage")
    rehydration = _read_json(state.product_root / "rehydration.json", "rehydration record")
    native = _read_json(state.product_root / "native-image.json", "Native Image role")
    loader = _read_json(state.product_root / "target-loader.json", "target loader")
    oracle = _read_json(state.product_root / "behavioral-oracle.json", "behavioral oracle")
    scheme_gate = _read_json(root / "scheme-a-gate.json", "Scheme-A gate")
    source = {
        "evaluatorGateSha256": state.evaluator_gate_sha256,
        "analysisInputSha256": state.analysis_input_sha256,
        "environmentSha256": state.environment_sha256,
        "artifactManifestSha256": state.root_manifest_sha256,
        "unitJsonSha256": state.unit_sha256,
        "unitRawManifestSha256": state.unit_raw_manifest_sha256,
        "productEvidenceManifestSha256": state.product_manifest_sha256,
        "productChainManifestSha256": state.unit.get("productEvidence", {}).get("manifestSha256"),
        "negativeWitnessSha256": state.negative_sha256,
    }
    identity = {
        "corpusVersion": EXPECTED["corpusVersion"],
        "protocolVersion": EXPECTED["protocolVersion"],
        "corpusManifestSha256": EXPECTED["corpusManifestSha256"],
        "protocolSha256": EXPECTED["protocolSha256"],
        "schemeManifestSha256": EXPECTED["schemeManifestSha256"],
        "oracleManifestSha256": EXPECTED["oracleManifestSha256"],
        "runtimeRegistrySha256": EXPECTED["runtimeRegistrySha256"],
        "fixtureManifestSha256": EXPECTED["fixtureManifestSha256"],
        "toolchainManifestSha256": EXPECTED["toolchainManifestSha256"],
        "unitId": UNIT_ID,
        "identityKey": EXPECTED["identityKey"],
        "fixedCorpusRows": 1,
        "completeUnits": 1,
    }
    strict_chain = {
        "allSixStagesPassed": True,
        "sourceImageSha256": _hash(state.product_root / "source-image.bin", "Source Image"),
        "protectedImageSha256": _hash(state.product_root / "protected-image.bin", "Protected Image"),
        "protectedImageSize": (state.product_root / "protected-image.bin").stat().st_size,
        "nativeImageSha256": _hash(state.product_root / "native-image.bin", "Native Image"),
        "nativeImageSize": (state.product_root / "native-image.bin").stat().st_size,
        "producerId": producer.get("producerId"),
        "producerBuildSha256": producer.get("producerBuildSha256"),
        "requestSha256": producer.get("requestSha256"),
        "rehydratorConsumerId": rehydration.get("consumerId"),
        "rehydratorConsumerBuildSha256": rehydration.get("consumerBuildSha256"),
        "rehydrationRecordSha256": _hash(state.product_root / "rehydration.json", "rehydration record"),
        "loaderId": loader.get("loaderId"),
        "handoffSha256": _hash(state.product_root / "handoff.json", "native handoff"),
        "oracleId": oracle.get("oracleId"),
        "behaviorComparisonSha256": _hash(state.product_root / "behavior-comparison.json", "behavior comparison"),
        "targetStatus": loader.get("targetStatus"),
        "targetSignal": loader.get("targetSignal"),
        "behaviorEqual": True,
    }
    scheme = {
        "protocolVersion": "scheme-a-v1",
        "manifestSha256": EXPECTED["schemeManifestSha256"],
        "status": "baseline-not-calibrated",
        "requiredFamilies": list(REQUIRED_FAMILIES),
        "familyFactors": {family: None for family in REQUIRED_FAMILIES},
        "schemeAClaimable": False,
    }
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "compatibility-1x-baseline",
        "baselineVersion": "compatibility-1x-v2",
        "baselineArtifactId": "compatibility-1x-v2",
        "commit": state.commit,
        "environment": {
            "commit": state.environment.get("commit"),
            "architecture": state.environment.get("architecture"),
            "runtimeCell": state.environment.get("runtimeCell"),
            "loaderIdentity": state.environment.get("loaderIdentity"),
            "nativeResultsCaptured": True,
        },
        "source": source,
        "identity": identity,
        "strictChain": strict_chain,
        "schemeA": scheme,
        "fixedCorpusRows": 1,
        "completeUnits": 1,
        "completeUnitIds": [UNIT_ID],
        "baselineStatus": "measured",
        "strengthStatus": "baseline-not-calibrated",
        "rawEvidenceStatus": "captured",
        "claimable": False,
        "immutable": True,
        "contentAddressed": True,
        "neverOverwrite": True,
        "generatedBy": "scripts/check-positive-immutable-baseline-v2.py",
    }
    payload_bytes = canonical_json(payload)
    payload_sha256 = sha256_bytes(payload_bytes)
    reference = {
        "schemaVersion": 1,
        "kind": "evaluator-baseline-reference",
        "baselineArtifactId": "compatibility-1x-v2",
        "baselineArtifactPath": _relative_repo(args_baseline_path),
        "baselineArtifactSha256": payload_sha256,
        "baselineCommit": state.commit,
        "corpusVersion": EXPECTED["corpusVersion"],
        "protocolVersion": EXPECTED["protocolVersion"],
        "schemeProtocolVersion": "scheme-a-v1",
        "fixedCorpusRows": 1,
        "completeUnits": 1,
        "baselineStatus": "measured",
        "strengthStatus": "baseline-not-calibrated",
        "immutable": True,
        "contentAddressed": True,
        "neverOverwrite": True,
    }
    return payload, payload_bytes, reference


def _verify_existing_or_publish(path: Path, expected: bytes, label: str, *, check_only: bool) -> bool:
    """Verify an existing immutable file or create it exclusively."""
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            fail(f"{label} is not a regular immutable file")
        try:
            actual = path.read_bytes()
        except OSError as error:
            fail(f"cannot read existing {label}: {error}")
        if actual != expected:
            fail(f"existing {label} does not match the deterministic projection")
        return False
    if check_only:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(expected)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != expected:
            fail(f"concurrent {label} publication changed its content")
        return False
    except OSError as error:
        fail(f"cannot publish {label}: {error}")
    return True


def _gate_output(state: State, payload: dict[str, Any], payload_sha256: str, *, status: str, reason: str | None = None) -> dict[str, Any]:
    rollback = {
        "previousBaselineArtifactId": EXPECTED["oldBaselineId"],
        "previousBaselineArtifactSha256": EXPECTED["oldBaselineSha256"],
        "fallbackProfile": "strict-chain-not-ready",
        "futureGrowthTarget": 100,
        "publishOnFailure": False,
    }
    if status == "blocked":
        return {
            "schemaVersion": 1,
            "kind": "compatibility-positive-baseline-local-gate",
            "gateId": "compatibility-positive-immutable-baseline-v2",
            "status": "blocked",
            "baselineArtifactId": "compatibility-1x-v2",
            "baselineArtifactSha256": None,
            "reason": (reason or "precondition failed")[:512],
            "schemeAStatus": "baseline-not-calibrated",
            "schemeAClaimable": False,
            "rollback": rollback,
        }
    return {
        "schemaVersion": 1,
        "kind": "compatibility-positive-baseline-local-gate",
        "gateId": "compatibility-positive-immutable-baseline-v2",
        "status": "pass",
        "baselineArtifactId": "compatibility-1x-v2",
        "baselineArtifactSha256": payload_sha256,
        "source": payload["source"],
        "identity": payload["identity"],
        "strictChain": payload["strictChain"],
        "schemeA": payload["schemeA"],
        "schemeAStatus": "baseline-not-calibrated",
        "schemeAClaimable": False,
        "completeUnits": 1,
        "claimable": False,
        "rollback": rollback,
    }


def _write_output(path: Path, document: dict[str, Any]) -> None:
    _reject_symlink_components(path, "local gate output")
    if path.exists() and path.is_symlink():
        fail("local gate output is a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json(document)
    if len(data) > MAX_OUTPUT_BYTES:
        fail("local gate output exceeds the bounded size")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        fail("local gate output temporary path already exists")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        fail(f"cannot write local gate output: {error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluator-root", type=Path, default=REPO_ROOT / ".artifacts/evaluator/pr")
    parser.add_argument("--product-root", type=Path, required=True)
    parser.add_argument("--previous-baseline", type=Path, default=REPO_ROOT / "fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json")
    parser.add_argument("--previous-baseline-reference", type=Path, default=REPO_ROOT / "fixtures/evaluator/baseline-reference.json")
    parser.add_argument("--baseline", type=Path, default=REPO_ROOT / "fixtures/evaluator/baselines/compatibility-1x-v2.json")
    parser.add_argument("--baseline-reference", type=Path, default=REPO_ROOT / "fixtures/evaluator/baselines/compatibility-1x-v2-reference.json")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / ".artifacts/evaluator/pr/positive-baseline-v2-gate.json")
    parser.add_argument("--check-only", action="store_true", help="validate the deterministic projection without publishing v2 files")
    return parser.parse_args()


# The validation helpers need these paths while keeping their signatures small;
# they are assigned only for one invocation and never read from the environment.
args_product_root: Path
args_baseline_path: Path


def run(arguments: argparse.Namespace) -> tuple[dict[str, Any], list[Path]]:
    global args_product_root, args_baseline_path
    args_product_root = _repo_path(arguments.product_root, "product evidence root")
    args_baseline_path = _repo_path(arguments.baseline, "baseline-v2 payload")
    evaluator_root = _repo_path(arguments.evaluator_root, "evaluator root")
    previous = _repo_path(arguments.previous_baseline, "historical baseline")
    previous_reference = _repo_path(arguments.previous_baseline_reference, "historical baseline reference")
    baseline_reference_path = _repo_path(arguments.baseline_reference, "baseline-v2 reference")
    output_path = _repo_path(arguments.output, "local gate output")
    if evaluator_root == args_product_root or evaluator_root == args_baseline_path:
        fail("evidence and publication paths must be distinct")
    _bounded_tree(evaluator_root, "evaluator evidence")
    state = State()
    state.evaluator_root = evaluator_root
    state.product_root = args_product_root
    state.commit = _git_commit()
    state.gate = _read_json(evaluator_root / "gate.json", "evaluator gate")
    state.environment = _read_json(evaluator_root / "environment.json", "evaluator environment")
    state.root_manifest_sha256 = _hash(evaluator_root / "SHA256SUMS", "evaluator root manifest")
    _verify_manifest(
        evaluator_root,
        "SHA256SUMS",
        "evaluator root",
        excluded=EVIDENCE_HANDOFF_FILES,
        exclude_nested_manifests=True,
    )
    if state.gate.get("artifactManifestSha256") != state.root_manifest_sha256 or state.gate.get("rawEvidenceManifestSha256") != state.root_manifest_sha256:
        fail("observed evaluator root manifest digest does not match both gate fields")
    _verify_old_baseline(previous, previous_reference)
    _verify_environment(state)
    _verify_identities(state)
    _verify_scheme_a(state)
    _verify_unit(state)
    _run_independent_checker(evaluator_root)
    payload, payload_bytes, reference = _project_payload(state)
    reference_bytes = canonical_json(reference)
    created: list[Path] = []
    if not arguments.check_only:
        # A pre-existing one-sided publication is not repaired implicitly; it
        # is retained as evidence of an interrupted publication and blocks.
        if baseline_reference_path.exists() and not args_baseline_path.exists():
            fail("baseline reference exists without its immutable payload")
        if args_baseline_path.exists() and not baseline_reference_path.exists():
            existing = args_baseline_path.read_bytes()
            if existing != payload_bytes:
                fail("existing baseline-v2 payload differs from the deterministic projection")
        made_payload = _verify_existing_or_publish(args_baseline_path, payload_bytes, "baseline-v2 payload", check_only=False)
        if made_payload:
            created.append(args_baseline_path)
        made_reference = _verify_existing_or_publish(baseline_reference_path, reference_bytes, "baseline-v2 reference", check_only=False)
        if made_reference:
            created.append(baseline_reference_path)
    else:
        _verify_existing_or_publish(args_baseline_path, payload_bytes, "baseline-v2 payload", check_only=True)
        _verify_existing_or_publish(baseline_reference_path, reference_bytes, "baseline-v2 reference", check_only=True)
    gate_document = _gate_output(state, payload, sha256_bytes(payload_bytes), status="pass")
    _write_output(output_path, gate_document)
    return gate_document, created


def main() -> int:
    arguments = parse_args()
    created: list[Path] = []
    output_path = arguments.output if arguments.output.is_absolute() else REPO_ROOT / arguments.output
    try:
        gate, created = run(arguments)
    except (GateError, EvaluatorError, OSError, ValueError, subprocess.SubprocessError) as error:
        for path in reversed(created):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            safe_output = _repo_path(output_path, "local gate output")
            blocked = {
                "schemaVersion": 1,
                "kind": "compatibility-positive-baseline-local-gate",
                "gateId": "compatibility-positive-immutable-baseline-v2",
                "status": "blocked",
                "baselineArtifactId": "compatibility-1x-v2",
                "baselineArtifactSha256": None,
                "reason": str(error)[:512],
                "schemeAStatus": "baseline-not-calibrated",
                "schemeAClaimable": False,
                "rollback": {
                    "previousBaselineArtifactId": EXPECTED["oldBaselineId"],
                    "previousBaselineArtifactSha256": EXPECTED["oldBaselineSha256"],
                    "fallbackProfile": "strict-chain-not-ready",
                    "futureGrowthTarget": 100,
                    "publishOnFailure": False,
                },
            }
            _write_output(safe_output, blocked)
        except (GateError, OSError, ValueError):
            pass
        print(f"BLOCKED positive immutable baseline-v2: {str(error)[:512]}", file=sys.stderr)
        return 1
    print(
        "PASS positive immutable baseline-v2: "
        f"completeUnits={gate['completeUnits']} schemeA={gate['schemeAStatus']} claimable={gate['claimable']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
