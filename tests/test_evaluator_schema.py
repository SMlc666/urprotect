#!/usr/bin/env python3
"""Focused schema and baseline checks for the independent evaluator."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluator_lib import calculate_claimable, EvaluatorError, read_json, validate_all_manifests  # noqa: E402


class EvaluatorSchemaTests(unittest.TestCase):
    def test_claimability_rejects_unverified_environment(self) -> None:
        compatibility = {
            "status": "measured",
            "fixedViewPass": True,
            "growthViewPass": True,
        }
        scheme_gate = {"status": "pass", "allRequiredPass": True}
        anti_gaming = {"corpusUnchanged": True}
        with self.assertRaises(EvaluatorError):
            calculate_claimable({"status": "available"}, compatibility, scheme_gate, anti_gaming)
        with self.assertRaises(EvaluatorError):
            calculate_claimable({"status": "environment-unavailable"}, compatibility, scheme_gate, anti_gaming)

    def test_checked_in_manifests_and_immutable_baseline_validate(self) -> None:
        manifests = validate_all_manifests(
            ROOT,
            protocol_path=ROOT / "fixtures/evaluator/evaluator-protocol.json",
            corpus_path=ROOT / "fixtures/evaluator/compatibility-corpus.json",
            scheme_path=ROOT / "fixtures/evaluator/scheme-a-manifest.json",
            oracle_path=ROOT / "fixtures/evaluator/oracles.json",
            baseline_reference_path=ROOT / "fixtures/evaluator/baseline-reference.json",
        )
        self.assertEqual(manifests["baseline"]["baselineStatus"], "baseline-zero")
        self.assertEqual(manifests["baseline"]["completeUnits"], 0)
        self.assertEqual(len(manifests["families"]), 6)

    def test_manifest_cli_is_machine_checkable(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate-evaluator-manifests.py")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("baseline-zero", result.stdout)
        self.assertIn("baseline-not-calibrated", result.stdout)

    def test_baseline_digest_tamper_is_rejected(self) -> None:
        reference_path = ROOT / "fixtures/evaluator/baseline-reference.json"
        original = reference_path.read_text(encoding="utf-8")
        try:
            data = json.loads(original)
            data["baselineArtifactSha256"] = "0" * 64
            reference_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(EvaluatorError):
                validate_all_manifests(
                    ROOT,
                    protocol_path=ROOT / "fixtures/evaluator/evaluator-protocol.json",
                    corpus_path=ROOT / "fixtures/evaluator/compatibility-corpus.json",
                    scheme_path=ROOT / "fixtures/evaluator/scheme-a-manifest.json",
                    oracle_path=ROOT / "fixtures/evaluator/oracles.json",
                    baseline_reference_path=reference_path,
                )
        finally:
            reference_path.write_text(original, encoding="utf-8")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.NamedTemporaryFile(dir=ROOT / ".artifacts", suffix=".json", mode="w", encoding="utf-8") as temporary:
            temporary.write('{"schemaVersion": 1, "schemaVersion": 2}')
            temporary.flush()
            with self.assertRaises(EvaluatorError):
                read_json(Path(temporary.name))

    def test_runner_and_post_run_checker_emit_closed_zero_not_ready_gate(self) -> None:
        (ROOT / ".artifacts" / "evaluator").mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts" / "evaluator") as temporary:
            output = Path(temporary) / "evaluator" / "pr"
            run = subprocess.run(
                [sys.executable, str(ROOT / "scripts/run-independent-evaluator.py"), "--tier", "pr", "--output-root", str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            check = subprocess.run(
                [sys.executable, str(ROOT / "scripts/check-independent-evaluator.py"), str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(check.returncode, 0, check.stderr)
            claim = subprocess.run(
                [sys.executable, str(ROOT / "scripts/check-independent-evaluator.py"), str(output), "--require-claimable"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(claim.returncode, 0)
            prebaseline = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/check-independent-evaluator.py"),
                    str(output),
                    "--require-claimable-if-baseline-positive",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(prebaseline.returncode, 0, prebaseline.stderr)
            gate = read_json(output / "gate.json")
            self.assertFalse(gate["claimable"])
            self.assertEqual(gate["compatibility"]["status"], "baseline-zero")
            self.assertIsNone(gate["compatibility"]["factor"])
            self.assertEqual(gate["schemeA"]["status"], "baseline-not-calibrated")
            self.assertEqual(read_json(output / "scheme-a-gate.json")["schemeAStatus"], "baseline-not-calibrated")
            self.assertTrue((output / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
