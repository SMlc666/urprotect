from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/run-rehydration-e2e.sh"
CHECKER = ROOT / "scripts/check-rehydration-evidence.py"
HANDOFF = ROOT / "native/urprotect-runtime/native_image_handoff.c"


class RehydrationEvidenceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.checker = CHECKER.read_text(encoding="utf-8")

    def test_workflow_runs_and_checks_rehydration_after_build(self) -> None:
        build = self.workflow.index("- name: Build\n")
        run = self.workflow.index("Run Generic Rehydration and Native Image handoff")
        check = self.workflow.index("Check retained Generic Rehydration and Native Image evidence", run)
        upload = self.workflow.index("- name: Upload test evidence", check)
        self.assertLess(build, run)
        self.assertLess(run, check)
        self.assertLess(check, upload)
        self.assertIn("if: always()", self.workflow[run:check])
        self.assertIn("if: always()", self.workflow[check:upload])
        self.assertIn(".artifacts/protected-image/", self.workflow[upload : upload + 800])

    def test_runner_retains_all_stage_records_and_closes_manifest(self) -> None:
        for marker in (
            "protected-image.bin",
            "rehydration.json",
            "native-image.bin",
            "handoff.json",
            "target-loader.json",
            "behavioral-oracle.json",
            "SHA256SUMS",
            "close_manifest",
        ):
            self.assertIn(marker, self.runner)
        self.assertIn("run-protected-image-e2e.sh", self.runner)
        self.assertIn("execveat", self.runner)

    def test_checker_requires_stage_specific_bindings_and_closed_evidence(self) -> None:
        for marker in (
            "SHA256SUMS is not closed",
            "preHandoffRecordSha256",
            "handoffRecordSha256",
            "native-image.json",
            "target-loader",
            "behavioral-oracle",
            "execveat-at-empty-path",
        ):
            self.assertIn(marker, self.checker)

    def test_native_helper_uses_sealed_memfd_and_execveat(self) -> None:
        handoff = HANDOFF.read_text(encoding="utf-8")
        for marker in ("memfd_create", "F_ADD_SEALS", "fsync", "execveat", "AT_EMPTY_PATH"):
            self.assertIn(marker, handoff)


if __name__ == "__main__":
    unittest.main()
