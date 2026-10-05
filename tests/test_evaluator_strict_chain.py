#!/usr/bin/env python3
"""Read-only strict Protected Image chain binding tests."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run-independent-evaluator.py"
CHECKER = ROOT / "scripts/check-independent-evaluator.py"
UNIT = "compat.protection-symbolized-fixture.glibc.outer-execveat"
PRODUCT = ROOT / ".artifacts/protected-image/pr/glibc" / UNIT


def rewrite_product_manifest(root: Path) -> None:
    lines = []
    for path in sorted(root.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def read_unit(output: Path) -> dict:
    return json.loads((output / "compatibility" / UNIT / "unit.json").read_text(encoding="utf-8"))


class StrictChainEvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (ROOT / ".artifacts" / "evaluator").mkdir(parents=True, exist_ok=True)

    def run_evaluator(self, output: Path, product_root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--tier",
                "pr",
                "--output-root",
                str(output),
                "--product-evidence-root",
                str(product_root),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def run_with_product(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        self.assertTrue(PRODUCT.is_dir(), "the retained local vertical slice is required for this test")
        workspace = tempfile.TemporaryDirectory(dir=ROOT / ".artifacts" / "evaluator")
        workspace_path = Path(workspace.name)
        product_root = workspace_path / UNIT
        shutil.copytree(PRODUCT, product_root)
        output = workspace_path / "evaluator" / "pr"
        return workspace, product_root, output

    def test_complete_projection_and_zero_baseline(self) -> None:
        if not PRODUCT.is_dir():
            self.skipTest("retained local product evidence is not present")
        workspace, product_root, output = self.run_with_product()
        try:
            result = self.run_evaluator(output, product_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            unit = read_unit(output)
            self.assertTrue(unit["complete"])
            self.assertNotEqual(unit["sourceImageSha256"], unit["sourceSha256"])
            self.assertEqual({stage["status"] for stage in unit["stages"].values()}, {"passed"})
            self.assertTrue((output / "compatibility" / UNIT / "raw/product-chain/SHA256SUMS").is_file())
            check = subprocess.run([sys.executable, str(CHECKER), str(output)], cwd=ROOT, check=False, capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            gate = json.loads((output / "gate.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["compatibility"]["status"], "baseline-zero")
            self.assertIsNone(gate["compatibility"]["factor"])
            self.assertFalse(gate["claimable"])
            self.assertEqual(gate["schemeA"]["status"], "baseline-not-calibrated")
        finally:
            workspace.cleanup()

    def test_absent_product_evidence_keeps_baseline_zero_fallback(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts" / "evaluator") as directory:
            output = Path(directory) / "pr"
            absent = Path(directory) / UNIT
            result = self.run_evaluator(output, absent)
            self.assertEqual(result.returncode, 0, result.stderr)
            unit = read_unit(output)
            self.assertFalse(unit["complete"])
            self.assertFalse(unit["strictChainMeasured"])
            self.assertEqual(unit["evidenceStatus"], "baseline-zero")
            self.assertEqual(unit["firstFailureLayer"], "protector")
            self.assertTrue(all(stage["status"] == "not-applicable" for stage in unit["stages"].values()))

    def test_missing_rehydration_is_an_explicit_stage_failure(self) -> None:
        if not PRODUCT.is_dir():
            self.skipTest("retained local product evidence is not present")
        workspace, product_root, output = self.run_with_product()
        try:
            (product_root / "rehydration.json").unlink()
            rewrite_product_manifest(product_root)
            result = self.run_evaluator(output, product_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            unit = read_unit(output)
            self.assertEqual(unit["firstFailureLayer"], "rehydration")
            self.assertEqual(unit["stages"]["rehydration"]["status"], "failed")
            self.assertFalse(unit["complete"])
        finally:
            workspace.cleanup()

    def test_role_and_source_image_mismatch_is_rejected(self) -> None:
        if not PRODUCT.is_dir():
            self.skipTest("retained local product evidence is not present")
        workspace, product_root, output = self.run_with_product()
        try:
            role_path = product_root / "protected-image.json"
            role = json.loads(role_path.read_text(encoding="utf-8"))
            role["sourceSha256"] = "0" * 64
            role_path.write_text(json.dumps(role, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            rewrite_product_manifest(product_root)
            result = self.run_evaluator(output, product_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            unit = read_unit(output)
            self.assertEqual(unit["firstFailureLayer"], "protector")
            self.assertEqual(unit["stages"]["protector"]["status"], "failed")
        finally:
            workspace.cleanup()

    def test_tampered_stage_and_closed_manifest_drift_are_rejected(self) -> None:
        if not PRODUCT.is_dir():
            self.skipTest("retained local product evidence is not present")
        workspace, product_root, output = self.run_with_product()
        try:
            loader_path = product_root / "target-loader.json"
            loader = json.loads(loader_path.read_text(encoding="utf-8"))
            loader["loaderId"] = "wrong-loader"
            loader_path.write_text(json.dumps(loader, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            rewrite_product_manifest(product_root)
            result = self.run_evaluator(output, product_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(read_unit(output)["firstFailureLayer"], "target-loader")
        finally:
            workspace.cleanup()

        workspace, product_root, output = self.run_with_product()
        try:
            with (product_root / "protected-image.bin").open("ab") as stream:
                stream.write(b"drift")
            result = self.run_evaluator(output, product_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(read_unit(output)["firstFailureLayer"], "protector")
        finally:
            workspace.cleanup()

    def test_symlink_root_and_producer_only_evidence_do_not_count(self) -> None:
        if not PRODUCT.is_dir():
            self.skipTest("retained local product evidence is not present")
        workspace, product_root, output = self.run_with_product()
        try:
            symlink = product_root.parent / "symlink-root"
            symlink.symlink_to(product_root, target_is_directory=True)
            result = self.run_evaluator(output, symlink)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(read_unit(output)["firstFailureLayer"], "protector")
        finally:
            workspace.cleanup()

        workspace, product_root, output = self.run_with_product()
        try:
            for name in ("rehydration.json", "native-image.bin", "native-image.json", "handoff.json", "target-loader.json", "behavioral-oracle.json", "behavior-comparison.json"):
                (product_root / name).unlink()
            rewrite_product_manifest(product_root)
            result = self.run_evaluator(output, product_root)
            self.assertEqual(result.returncode, 0, result.stderr)
            unit = read_unit(output)
            self.assertEqual(unit["firstFailureLayer"], "rehydration")
            self.assertFalse(unit["complete"])
        finally:
            workspace.cleanup()


if __name__ == "__main__":
    unittest.main()
