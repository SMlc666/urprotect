#!/usr/bin/env python3
"""Focused tests for the positive immutable compatibility baseline-v2 gate."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
UNIT = "compat.protection-symbolized-fixture.glibc.outer-execveat"
PRODUCT_SOURCE = ROOT / ".artifacts/protected-image/pr/glibc" / UNIT
RUNNER = ROOT / "scripts/run-independent-evaluator.py"
GATE = ROOT / "scripts/check-positive-immutable-baseline-v2.py"


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def close_manifest(root: Path, *, evaluator: bool = False) -> None:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(root).as_posix()
        if evaluator and relative in {"gate.json", "analysis-input.json", "positive-baseline-v2-gate.json"}:
            continue
        lines.append(f"{digest(path)}  {relative}\n")
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


class PositiveBaselineV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not PRODUCT_SOURCE.is_dir():
            raise unittest.SkipTest("retained strict product evidence is not present")
        (ROOT / ".artifacts/evaluator").mkdir(parents=True, exist_ok=True)
        (ROOT / ".artifacts/protected-image").mkdir(parents=True, exist_ok=True)

        dotnet_root = Path.home() / ".dotnet"
        if dotnet_root.is_dir():
            import os
            os.environ["PATH"] = str(dotnet_root) + os.pathsep + os.environ.get("PATH", "")
    def make_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path, Path, Path]:
        workspace = tempfile.TemporaryDirectory(dir=ROOT / ".artifacts/evaluator")
        workspace_root = Path(workspace.name)
        product_parent = Path(tempfile.mkdtemp(prefix="positive-baseline-product-", dir=ROOT / ".artifacts/protected-image"))
        product_root = product_parent / UNIT
        shutil.copytree(PRODUCT_SOURCE, product_root)
        negative = {
            "schemaVersion": 1,
            "kind": "strict-chain-negative-witness",
            "status": "passed",
            "unitId": UNIT,
            "stage": "rehydration",
            "failureClass": "tampered-protected-image",
            "rollbackStatus": "passed",
            "nativeImagePublished": False,
            "loaderInvoked": False,
            "loaderMarkerObserved": False,
            "artifactPath": "protected-image.bin",
            "nativeImagePath": "native-image.bin",
            "loaderMarkerPath": "target.stdout",
        }
        (product_root / "negative-rollback.json").write_bytes(canonical(negative))
        close_manifest(product_root)
        evaluator_root = workspace_root / "pr"
        run = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--tier",
                "pr",
                "--output-root",
                str(evaluator_root),
                "--product-evidence-root",
                str(product_root),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.make_available_environment(evaluator_root)
        baseline = workspace_root / "compatibility-1x-v2.json"
        reference = workspace_root / "compatibility-1x-v2-reference.json"
        output = evaluator_root / "positive-baseline-v2-gate.json"
        return workspace, evaluator_root, product_root, baseline, reference, output

    def make_available_environment(self, evaluator_root: Path) -> None:
        environment_path = evaluator_root / "environment.json"
        environment = json.loads(environment_path.read_text(encoding="utf-8"))
        environment["runner"].update({
            "githubActions": True,
            "runnerOS": "Linux",
            "runnerArch": "ARM64",
            "runnerName": "test-runner",
            "runId": "1",
        })
        environment["host"].update({
            "architecture": "aarch64",
            "distributionId": "ubuntu",
            "distributionVersion": "24.04",
            "glibcVersion": "2.39",
        })
        environment["architecture"] = "aarch64"
        environment["nativeAarch64"] = True
        environment["emulated"] = False
        environment["runtimeCell"] = "glibc.current.native-arm64"
        environment["loaderIdentity"] = "kernel.execveat-at-empty-path"
        environment["namespaces"] = {"currentNetwork": "net:[2]", "initialNetwork": "net:[1]"}
        environment["mountFacts"] = {
            "repositoryReadOnly": True,
            "fixturesReadOnly": True,
            "productEvidenceReadOnly": True,
            "evaluatorOutputWritable": True,
        }
        environment["security"] = {"noNewPrivileges": 1, "effectiveCapabilities": "0000000000000000"}
        environment["resourceLimits"] = {
            "cpuSeconds": {"soft": 45, "hard": 45},
            "addressSpaceBytes": {"soft": 1073741824, "hard": 1073741824},
            "processes": {"soft": 32, "hard": 32},
            "fileSizeBytes": {"soft": 268435456, "hard": 268435456},
        }
        environment["isolation"].update({
            "networkDisabled": True,
            "readOnlyInputs": True,
            "noNewPrivileges": True,
            "droppedCapabilities": True,
            "wallLimit": {"seconds": 60, "alarmRemainingSeconds": 30.0},
        })
        environment["requiredCapabilities"] = {
            name: True if name != "schemeAttackToolset" else False
            for name in environment["requiredCapabilities"]
        }
        environment["status"] = "available"
        environment["reason"] = None
        environment_path.write_bytes(canonical(environment))
        close_manifest(evaluator_root, evaluator=True)
        gate_path = evaluator_root / "gate.json"
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        root_manifest_sha256 = digest(evaluator_root / "SHA256SUMS")
        gate["artifactManifestSha256"] = root_manifest_sha256
        gate["rawEvidenceManifestSha256"] = root_manifest_sha256
        gate["environment"] = {
            "status": environment["status"],
            "runtimeCell": environment["runtimeCell"],
            "requiredCapabilities": environment["requiredCapabilities"],
        }
        gate_path.write_bytes(canonical(gate))

    def run_gate(
        self,
        evaluator_root: Path,
        product_root: Path,
        baseline: Path,
        reference: Path,
        output: Path,
        *,
        previous_baseline: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(GATE),
            "--evaluator-root",
            str(evaluator_root),
            "--product-root",
            str(product_root),
            "--baseline",
            str(baseline),
            "--baseline-reference",
            str(reference),
            "--output",
            str(output),
        ]
        if previous_baseline is not None:
            command.extend(["--previous-baseline", str(previous_baseline)])
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_passes_with_copy_fixture_and_rechecks_immutable_publication(self) -> None:
        workspace, evaluator, product, baseline, reference, output = self.make_fixture()
        try:
            result = self.run_gate(evaluator, product, baseline, reference, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            gate = json.loads(output.read_text(encoding="utf-8"))
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            reference_document = json.loads(reference.read_text(encoding="utf-8"))
            self.assertEqual(gate["status"], "pass")
            self.assertEqual(gate["completeUnits"], 1)
            self.assertFalse(gate["claimable"])
            self.assertEqual(gate["schemeAStatus"], "baseline-not-calibrated")
            self.assertEqual(payload["completeUnits"], 1)
            self.assertEqual(payload["completeUnitIds"], [UNIT])
            self.assertEqual(payload["schemeA"]["requiredFamilies"], [
                "runtime_dump_reassembly",
                "patch_repack",
                "function_logic_recovery",
                "static_decomposition",
                "dynamic_instrumentation",
                "integrity_handoff",
            ])
            self.assertEqual(reference_document["baselineArtifactSha256"], digest(baseline))
            baseline_bytes = baseline.read_bytes()
            reference_bytes = reference.read_bytes()
            second = self.run_gate(evaluator, product, baseline, reference, output)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(baseline.read_bytes(), baseline_bytes)
            self.assertEqual(reference.read_bytes(), reference_bytes)
        finally:
            workspace.cleanup()

    def test_stale_commit_blocks_without_publication(self) -> None:
        workspace, evaluator, product, baseline, reference, output = self.make_fixture()
        try:
            gate_path = evaluator / "gate.json"
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            gate["commit"] = "0" * 40
            gate_path.write_bytes(canonical(gate))
            result = self.run_gate(evaluator, product, baseline, reference, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "blocked")
            self.assertFalse(baseline.exists())
            self.assertFalse(reference.exists())
        finally:
            workspace.cleanup()

    def test_root_manifest_mismatch_blocks(self) -> None:
        workspace, evaluator, product, baseline, reference, output = self.make_fixture()
        try:
            (evaluator / "SHA256SUMS").write_text((evaluator / "SHA256SUMS").read_text(encoding="utf-8") + "\n", encoding="utf-8")
            result = self.run_gate(evaluator, product, baseline, reference, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("blocked", output.read_text(encoding="utf-8"))
            self.assertFalse(baseline.exists())
            self.assertFalse(reference.exists())
        finally:
            workspace.cleanup()

    def test_tampered_stage_or_hash_blocks(self) -> None:
        workspace, evaluator, product, baseline, reference, output = self.make_fixture()
        try:
            stage_path = product / "target-loader.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["nativeImageSha256"] = "0" * 64
            stage_path.write_bytes(canonical(stage))
            close_manifest(product)
            result = self.run_gate(evaluator, product, baseline, reference, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(baseline.exists())
            self.assertFalse(reference.exists())
        finally:
            workspace.cleanup()

    def test_missing_negative_or_unsafe_witness_blocks(self) -> None:
        for unsafe in (False, True):
            workspace, evaluator, product, baseline, reference, output = self.make_fixture()
            try:
                witness_path = product / "negative-rollback.json"
                if unsafe:
                    witness = json.loads(witness_path.read_text(encoding="utf-8"))
                    witness["artifactPath"] = "../outside"
                    witness_path.write_bytes(canonical(witness))
                    close_manifest(product)
                else:
                    witness_path.unlink()
                    close_manifest(product)
                result = self.run_gate(evaluator, product, baseline, reference, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(baseline.exists())
                self.assertFalse(reference.exists())
            finally:
                workspace.cleanup()

    def test_scheme_a_drift_blocks(self) -> None:
        workspace, evaluator, product, baseline, reference, output = self.make_fixture()
        try:
            scheme_gate_path = evaluator / "scheme-a-gate.json"
            scheme_gate = json.loads(scheme_gate_path.read_text(encoding="utf-8"))
            scheme_gate["allRequiredPass"] = True
            scheme_gate_path.write_bytes(canonical(scheme_gate))
            close_manifest(evaluator, evaluator=True)
            gate_path = evaluator / "gate.json"
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            root_manifest_sha256 = digest(evaluator / "SHA256SUMS")
            gate["artifactManifestSha256"] = root_manifest_sha256
            gate["rawEvidenceManifestSha256"] = root_manifest_sha256
            gate_path.write_bytes(canonical(gate))
            result = self.run_gate(evaluator, product, baseline, reference, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(baseline.exists())
            self.assertFalse(reference.exists())
        finally:
            workspace.cleanup()

    def test_old_baseline_mutation_blocks_and_rolls_back(self) -> None:
        workspace, evaluator, product, baseline, reference, output = self.make_fixture()
        try:
            mutated_old = Path(workspace.name) / "old-baseline.json"
            shutil.copyfile(ROOT / "fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json", mutated_old)
            mutated_old.write_bytes(mutated_old.read_bytes() + b"\n")
            command = self.run_gate(
                evaluator,
                product,
                baseline,
                reference,
                output,
                previous_baseline=mutated_old,
            )
            # The copied historical object is intentionally not accepted as a
            # substitute for the tracked immutable zero baseline.
            self.assertNotEqual(command.returncode, 0)
            self.assertFalse(baseline.exists())
            self.assertFalse(reference.exists())
        finally:
            workspace.cleanup()


if __name__ == "__main__":
    unittest.main()
