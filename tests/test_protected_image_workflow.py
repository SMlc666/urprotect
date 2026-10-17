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

    def test_producer_evidence_is_after_build_and_before_tests(self) -> None:
        build = self.workflow.index("- name: Build\n")
        producer = self.workflow.index("Run Protected Image producer evidence")
        tests = self.workflow.index("- name: Test\n")
        self.assertLess(build, producer)
        self.assertLess(producer, tests)
        self.assertIn("additive, not strict compatibility", self.workflow[producer - 120 : producer + 120])

    def test_producer_evidence_is_checked_and_retained_on_failure(self) -> None:
        producer = self.workflow.index("Run Protected Image producer evidence")
        checker = self.workflow.index("Check retained Protected Image producer evidence", producer)
        upload = self.workflow.index("- name: Upload test evidence", checker)
        self.assertIn("run-protected-image-e2e.sh", self.workflow[producer:checker])
        self.assertIn("check-protected-image-evidence.py", self.workflow[checker:upload])
        self.assertIn("if: always()", self.workflow[checker:upload])
        upload_block = self.workflow[upload : upload + 900]
        self.assertIn(".artifacts/protected-image/", upload_block)
        self.assertIn("include-hidden-files: true", upload_block)

    def test_independent_compatibility_check_consumes_actual_product_evidence(self) -> None:
        evaluator = self.workflow.index("independent-evaluator:")
        download = self.workflow.index("Download actual Protected Image product evidence", evaluator)
        select = self.workflow.index("Select compatibility evidence tier", download)
        block = self.workflow[download:select]
        self.assertIn("actions/download-artifact@v4", block)
        self.assertIn("test-evidence-${{ github.run_id }}", block)
        self.assertIn("Normalize downloaded product evidence directory", block)
        self.assertIn('destination="${GITHUB_WORKSPACE}/.artifacts/protected-image"', block)

    def test_no_synthetic_attack_metric_in_independent_gate(self) -> None:
        evaluator = self.workflow.index("independent-evaluator:")
        block = self.workflow[evaluator:]
        self.assertIn("check-strict-product-corpus.py", block)
        self.assertIn("Independently verify 100 strict product chains", block)
        self.assertNotIn("scheme-a", block.lower())
        self.assertNotIn("require-claimable", block)
        self.assertIn("Preserve all existing required verification lanes", block)

    def test_runner_and_checker_are_checked_in(self) -> None:
        self.assertTrue(RUNNER.is_file())
        self.assertTrue(CHECKER.is_file())
        self.assertTrue(RUNNER.stat().st_mode & 0o111)
        self.assertTrue(CHECKER.stat().st_mode & 0o111)
        self.assertRegex(RUNNER.read_text(encoding="utf-8"), r"protect-image")

    def test_strict_corpus_growth_runs_before_evidence_upload(self) -> None:
        corpus = self.workflow.index("Run strict compatibility corpus growth evidence")
        upload = self.workflow.index("- name: Upload test evidence", corpus)
        self.assertIn("run-strict-compatibility-corpus.sh", self.workflow[corpus:upload])
        self.assertIn("if: always()", self.workflow[corpus:upload])
        self.assertTrue(CORPUS_RUNNER.is_file())
        self.assertTrue(CORPUS_RUNNER.stat().st_mode & 0o111)
        self.assertEqual(len(json.loads((ROOT / 'fixtures/evaluator/compatibility-corpus.json').read_text())['rows']), 100)
        self.assertRegex(CHECKER.read_text(encoding="utf-8"), r"SHA256SUMS")


if __name__ == "__main__":
    unittest.main()
