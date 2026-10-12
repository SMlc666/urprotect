from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "fixtures/tls-runtime-matrix.json"
MATRIX_RUNNER = ROOT / "scripts/run-tls-runtime-matrix.py"
MATRIX_CHECKER = ROOT / "scripts/check-tls-runtime-matrix-evidence.py"
PREREQ_RUNNER = ROOT / "scripts/run-tls-prerequisite-probes.py"
PREREQ_CHECKER = ROOT / "scripts/check-tls-prerequisite-evidence.py"


class TlsRuntimeMatrixContractTests(unittest.TestCase):
    def test_registry_is_a_closed_four_dimensional_contract(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(registry["schemaVersion"], 1)
        self.assertEqual(
            registry["models"],
            ["local-exec", "initial-exec", "local-dynamic", "general-dynamic", "tlsdesc"],
        )
        self.assertEqual(registry["profiles"], ["outer-execveat", "host-context-entry"])
        self.assertEqual(registry["runtimes"], ["glibc", "musl", "bionic"])
        self.assertEqual(registry["lifecycles"], ["current-thread", "registered-worker"])
        self.assertEqual(
            len(registry["models"])
            * len(registry["profiles"])
            * len(registry["runtimes"])
            * len(registry["lifecycles"]),
            60,
        )
        self.assertEqual(
            registry["controlRow"],
            "initial-exec.host-context-entry.glibc.current-thread",
        )

    def test_matrix_runner_and_checker_bind_independent_rows(self) -> None:
        runner = MATRIX_RUNNER.read_text(encoding="utf-8")
        checker = MATRIX_CHECKER.read_text(encoding="utf-8")
        for marker in (
            "model",
            "profile",
            "runtime",
            "lifecycle",
            "environment-unavailable",
            "not-applicable",
            "accepted-and-runs",
            "native-preflight.json",
            "SHA256SUMS",
            "controlRow",
        ):
            self.assertIn(marker, runner if marker != "controlRow" else runner + checker)
        self.assertIn("EXPECTED_ROW_COUNT = 60", checker)
        self.assertIn("promoted rows drifted", checker)
        self.assertIn("is not closed", checker)

    def test_prerequisite_probe_covers_all_android_tags_and_pt_tls_cases(self) -> None:
        runner = PREREQ_RUNNER.read_text(encoding="utf-8")
        checker = PREREQ_CHECKER.read_text(encoding="utf-8")
        for marker in (
            "DT_ANDROID_REL",
            "DT_ANDROID_RELSZ",
            "DT_ANDROID_RELA",
            "DT_ANDROID_RELASZ",
            "DT_ANDROID_RELR",
            "DT_ANDROID_RELRCOUNT",
            "DT_ANDROID_RELRSZ",
            "DT_ANDROID_RELRENT",
            "tls-executable",
            "owner-read-only",
            "tls-empty-memory",
            "filesz-exceeds-memsz",
            "non-power-two-alignment",
            "SHA256SUMS",
        ):
            self.assertIn(marker, runner)
        self.assertIn("exactly eight rows", checker)
        self.assertIn("six bounded cases", checker)

    def test_ci_and_regression_matrix_reference_tls_producers(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        regression = (ROOT / "tests/regression-matrix.json").read_text(encoding="utf-8")
        for marker in (
            "run-tls-prerequisite-probes.py",
            "check-tls-prerequisite-evidence.py",
            "run-tls-runtime-matrix.py",
            "check-tls-runtime-matrix-evidence.py",
            ".artifacts/tls-runtime/",
            ".artifacts/tls-prerequisites/",
        ):
            self.assertIn(marker, workflow)
            self.assertIn(marker, regression)


if __name__ == "__main__":
    unittest.main()
