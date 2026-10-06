#!/usr/bin/env python3
"""Focused anti-gaming and evidence-integrity checks."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluator_lib import EvaluatorError, read_json, validate_compatibility_corpus, validate_oracles  # noqa: E402


class EvaluatorAntiGamingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (ROOT / ".artifacts" / "evaluator").mkdir(parents=True, exist_ok=True)

    def test_duplicate_identity_key_is_rejected(self) -> None:
        corpus = read_json(ROOT / "fixtures/evaluator/compatibility-corpus.json")
        duplicate = copy.deepcopy(corpus["rows"][0])
        duplicate["unitId"] = "compat.second-identity"
        corpus["rows"].append(duplicate)
        oracles = read_json(ROOT / "fixtures/evaluator/oracles.json")
        with self.assertRaises(EvaluatorError):
            validate_compatibility_corpus(corpus, ROOT, validate_oracles(oracles))

    def test_changed_required_family_or_budget_cannot_be_hidden(self) -> None:
        scheme = read_json(ROOT / "fixtures/evaluator/scheme-a-manifest.json")
        families = scheme["requiredFamilies"]
        families[0]["required"] = False
        # The frozen family order/required vector is validated independently of
        # any attack result, so deleting a family is a protocol failure.
        from evaluator_lib import validate_scheme_manifest

        with self.assertRaises(EvaluatorError):
            validate_scheme_manifest(scheme)

    def test_checker_rejects_tampered_gate_even_when_json_remains_valid(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts" / "evaluator") as temporary:
            output = Path(temporary) / "pr"
            run = subprocess.run(
                [sys.executable, str(ROOT / "scripts/run-independent-evaluator.py"), "--tier", "pr", "--output-root", str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            gate_path = output / "gate.json"
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            gate["claimable"] = True
            gate_path.write_text(json.dumps(gate), encoding="utf-8")
            check = subprocess.run(
                [sys.executable, str(ROOT / "scripts/check-independent-evaluator.py"), str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(check.returncode, 0)
            self.assertIn("hash mismatch", check.stderr)

    def test_checker_rejects_raw_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".artifacts" / "evaluator") as temporary:
            output = Path(temporary) / "pr"
            run = subprocess.run(
                [sys.executable, str(ROOT / "scripts/run-independent-evaluator.py"), "--tier", "pr", "--output-root", str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            unit_path = next((output / "compatibility").glob("*/unit.json"))
            unit = json.loads(unit_path.read_text(encoding="utf-8"))
            unit["rawEvidenceManifest"] = "../../outside/SHA256SUMS"
            unit_path.write_text(json.dumps(unit), encoding="utf-8")
            check = subprocess.run(
                [sys.executable, str(ROOT / "scripts/check-independent-evaluator.py"), str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(check.returncode, 0)
            self.assertTrue("hash mismatch" in check.stderr or "unsafe path" in check.stderr)


if __name__ == "__main__":
    unittest.main()
