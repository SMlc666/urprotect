from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/run-protected-image-e2e.sh"
CHECKER = ROOT / "scripts/check-protected-image-evidence.py"


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
        self.assertIn(".artifacts/protected-image/", self.workflow[upload : upload + 700])

    def test_independent_evaluator_downloads_product_chain_evidence(self) -> None:
        evaluator = self.workflow.index("independent-evaluator:")
        download = self.workflow.index("Download build-and-test Protected Image evidence", evaluator)
        select = self.workflow.index("Select evaluator tier", download)
        block = self.workflow[download:select]
        self.assertIn("if: always()", block)
        self.assertIn("continue-on-error: true", block)
        self.assertIn("actions/download-artifact@v4", block)
        self.assertIn("test-evidence-${{ github.run_id }}", block)
        self.assertIn("path: .", block)

    def test_runner_and_checker_are_checked_in(self) -> None:
        self.assertTrue(RUNNER.is_file())
        self.assertTrue(CHECKER.is_file())
        self.assertTrue(RUNNER.stat().st_mode & 0o111)
        self.assertTrue(CHECKER.stat().st_mode & 0o111)
        self.assertRegex(RUNNER.read_text(encoding="utf-8"), r"protect-image")
        self.assertRegex(CHECKER.read_text(encoding="utf-8"), r"SHA256SUMS")


if __name__ == "__main__":
    unittest.main()
