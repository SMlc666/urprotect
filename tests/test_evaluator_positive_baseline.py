#!/usr/bin/env python3
"""Focused evaluator baseline-selection and historical-fallback checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run-independent-evaluator.py"
CHECKER = ROOT / "scripts/check-independent-evaluator.py"
UNIT = "compat.protection-symbolized-fixture.glibc.outer-execveat"
PRODUCT = ROOT / ".artifacts/protected-image/pr/glibc" / UNIT
HISTORICAL_REFERENCE = ROOT / "fixtures/evaluator/baseline-reference.json"
HISTORICAL_PAYLOAD = ROOT / "fixtures/evaluator/baselines/compatibility-1x-baseline-zero.json"
V2_REFERENCE = ROOT / "fixtures/evaluator/baselines/compatibility-1x-v2-reference.json"
V2_PAYLOAD = ROOT / "fixtures/evaluator/baselines/compatibility-1x-v2.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class EvaluatorPositiveBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (ROOT / ".artifacts/evaluator").mkdir(parents=True, exist_ok=True)

    def run_evaluator(
        self,
        output: Path,
        *,
        baseline_reference: Path | None = None,
        product_root: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(RUNNER),
            "--tier",
            "pr",
            "--output-root",
            str(output),
            "--product-evidence-root",
            str(product_root or output.parent / "absent-product"),
        ]
        if baseline_reference is not None:
            command.extend(["--baseline-reference", str(baseline_reference)])
        environment = dict(os.environ)
        environment["EVALUATOR_COMPATIBILITY_MODE"] = "1"
        environment["EVALUATOR_NETWORK_DISABLED"] = "1"
        return subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True, env=environment)

    def check_evidence(self, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(output)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_explicit_v2_reports_measured_one_x_without_claim(self) -> None:
        if not PRODUCT.is_dir():
            self.skipTest("fresh strict product evidence is not present")
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts/evaluator") as temporary:
            output = Path(temporary) / "v2"
            run = self.run_evaluator(output, baseline_reference=V2_REFERENCE, product_root=PRODUCT)
            self.assertEqual(run.returncode, 0, run.stderr)
            check = self.check_evidence(output)
            self.assertEqual(check.returncode, 0, check.stderr)
            gate = read_json(output / "gate.json")
            compatibility = gate["compatibility"]
            self.assertEqual(gate["baselineArtifactId"], "compatibility-1x-v2")
            self.assertEqual(gate["baselineArtifactSha256"], digest(V2_PAYLOAD))
            self.assertEqual(compatibility["status"], "measured")
            self.assertEqual(compatibility["baselineCompleteUnits"], 1)
            self.assertEqual(compatibility["candidateFixedCompleteUnits"], 1)
            self.assertEqual(compatibility["candidateGrowthCompleteUnits"], 1)
            self.assertEqual(compatibility["factor"], 1.0)
            self.assertEqual(compatibility["growthTarget"], 100)
            self.assertTrue(compatibility["fixedViewPass"])
            self.assertFalse(compatibility["growthViewPass"])
            self.assertFalse(gate["claimable"])
            self.assertFalse(any("baseline-zero" in risk for risk in gate["residualRisks"]))
            self.assertEqual(gate["schemeA"]["status"], "baseline-not-calibrated")
            self.assertTrue(all(value is None for value in gate["schemeA"]["familyFactors"].values()))
            analysis = read_json(output / "analysis-input.json")
            self.assertEqual(analysis["baselineArtifactId"], gate["baselineArtifactId"])
            self.assertEqual(analysis["baselineArtifactSha256"], gate["baselineArtifactSha256"])
            self.assertEqual((output / "baseline-artifact.json").read_bytes(), V2_PAYLOAD.read_bytes())

    def test_omitted_reference_keeps_historical_zero_fallback(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts/evaluator") as temporary:
            output = Path(temporary) / "historical"
            run = self.run_evaluator(output)
            self.assertEqual(run.returncode, 0, run.stderr)
            check = self.check_evidence(output)
            self.assertEqual(check.returncode, 0, check.stderr)
            gate = read_json(output / "gate.json")
            self.assertEqual(gate["baselineArtifactId"], "compatibility-1x-baseline-zero")
            self.assertEqual(gate["baselineArtifactSha256"], digest(HISTORICAL_PAYLOAD))
            self.assertEqual(gate["compatibility"]["status"], "baseline-zero")
            self.assertIsNone(gate["compatibility"]["factor"])
            self.assertEqual(gate["compatibility"]["growthTarget"], 0)
            self.assertFalse(gate["claimable"])
            self.assertEqual((output / "baseline-artifact.json").read_bytes(), HISTORICAL_PAYLOAD.read_bytes())

    def test_stale_or_mismatched_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts/evaluator") as temporary:
            reference = Path(temporary) / "stale-reference.json"
            stale = read_json(V2_REFERENCE)
            stale["baselineArtifactSha256"] = "0" * 64
            reference.write_text(json.dumps(stale), encoding="utf-8")
            output = Path(temporary) / "stale"
            run = self.run_evaluator(output, baseline_reference=reference)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("baseline artifact digest", run.stderr)

            stale["baselineArtifactSha256"] = digest(V2_PAYLOAD)
            stale["baselineCommit"] = "0" * 40
            reference.write_text(json.dumps(stale), encoding="utf-8")
            output = Path(temporary) / "stale-commit"
            run = self.run_evaluator(output, baseline_reference=reference)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("baseline commit mismatch", run.stderr)

    def test_historical_reference_and_payload_are_not_mutated(self) -> None:
        reference_bytes = HISTORICAL_REFERENCE.read_bytes()
        payload_bytes = HISTORICAL_PAYLOAD.read_bytes()
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts/evaluator") as temporary:
            output = Path(temporary) / "immutability"
            run = self.run_evaluator(output)
            self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(HISTORICAL_REFERENCE.read_bytes(), reference_bytes)
        self.assertEqual(HISTORICAL_PAYLOAD.read_bytes(), payload_bytes)
        self.assertEqual(digest(HISTORICAL_PAYLOAD), read_json(HISTORICAL_REFERENCE)["baselineArtifactSha256"])


if __name__ == "__main__":
    unittest.main()
