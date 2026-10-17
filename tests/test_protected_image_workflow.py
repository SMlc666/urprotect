from __future__ import annotations
import json

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/run-protected-image-e2e.sh"
CHECKER = ROOT / "scripts/check-protected-image-evidence.py"

CORPUS_RUNNER = ROOT / "scripts/run-strict-compatibility-corpus.sh"

class ProtectedImageWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_producer_and_evidence_checker_remain_required(self) -> None:
        start = self.workflow.index("  protection-and-tls:")
        end = self.workflow.index("  fixture-and-pack:", start)
        block = self.workflow[start:end]
        self.assertIn("Run Protected Image producer evidence", block)
        self.assertIn("run-protected-image-e2e.sh", block)
        self.assertIn("check-protected-image-evidence.py", block)
        self.assertIn(".artifacts/protected-image/", block)
        self.assertIn("include-hidden-files: true", block)

    def test_shard_verifier_requires_actual_product_units(self) -> None:
        start = self.workflow.index("  independent-evaluator:")
        end = self.workflow.index("  ci-quality-gate:", start)
        block = self.workflow[start:end]
        self.assertIn("Download strict compatibility shard evidence", block)
        self.assertIn("strict-compatibility-shard-*-", block)
        self.assertIn("Merge strict shard evidence", block)
        self.assertIn("check-strict-product-corpus.py", block)
        self.assertIn("--shard-count 4", block)
        self.assertIn("ci-event-gate", block)
        self.assertIn("strict-compatibility-shard", block)
        self.assertNotIn("scheme-a", block.lower())
        self.assertNotIn("require-claimable", block)

    def test_original_quality_gates_are_still_required(self) -> None:
        block = self.workflow.split("  ci-quality-gate:\n", 1)[1]
        for job in (
            "build-and-test", "managed-tests", "protection-and-tls",
            "fixture-and-pack", "native-host-context", "coverage-fuzz",
            "strict-compatibility-shard", "independent-evaluator",
            "real-sample-matrix", "runtime-matrix-native-arm64",
            "bionic-native-arm64", "musl-container-smoke",
        ):
            self.assertIn(f"      - {job}", block)
        self.assertIn("Require every mandatory validation result", block)

    def test_runner_and_checker_are_checked_in(self) -> None:
        self.assertTrue(RUNNER.is_file())
        self.assertTrue(CHECKER.is_file())
        self.assertTrue(RUNNER.stat().st_mode & 0o111)
        self.assertTrue(CHECKER.stat().st_mode & 0o111)
        self.assertRegex(RUNNER.read_text(encoding="utf-8"), r"protect-image")

    def test_all_four_strict_shards_are_preserved(self) -> None:
        start = self.workflow.index("  strict-compatibility-shard:")
        end = self.workflow.index("  real-sample-matrix:", start)
        block = self.workflow[start:end]
        self.assertIn("shard: [0, 1, 2, 3]", block)
        self.assertIn("--workers 2", block)
        self.assertIn("scripts/run-strict-compatibility-corpus.sh", block)
        self.assertIn("if: always()", block)
        self.assertTrue(CORPUS_RUNNER.is_file())
        self.assertTrue(CORPUS_RUNNER.stat().st_mode & 0o111)
        self.assertEqual(len(json.loads((ROOT / "fixtures/evaluator/compatibility-corpus.json").read_text())["rows"]), 100)
        self.assertRegex(CHECKER.read_text(), r"SHA256SUMS")


if __name__ == "__main__":
    unittest.main()
