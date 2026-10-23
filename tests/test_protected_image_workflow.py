from __future__ import annotations
import json
import subprocess
import textwrap
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

    def test_shared_musl_run_block_uses_posix_dynsym_index_validation(self) -> None:
        start = self.workflow.index("      - name: Run shared musl indirect jump-table evidence")
        end = self.workflow.index("      - name: Upload musl container and indirect-control evidence", start)
        block = self.workflow[start:end]
        run_script = textwrap.dedent(block.split("run: |\n", 1)[1])

        for bash_only_token in ("[[", "]]", "=~"):
            with self.subTest(bash_only_token=bash_only_token):
                self.assertNotIn(bash_only_token, run_script)

        syntax_check = subprocess.run(
            ["/bin/sh", "-n"], input=run_script, capture_output=True, text=True, check=False,
        )
        self.assertEqual(syntax_check.returncode, 0, syntax_check.stderr)

        function_start = run_script.index("is_dynsym_index() {")
        function_end = run_script.index("\n}", function_start) + len("\n}")
        validation_line = next(
            line for line in run_script[function_end:].splitlines()
            if line.startswith("is_dynsym_index ")
        )
        validator = (
            run_script[function_start:function_end]
            + '\nselected_function="$1"\n'
            + validation_line
        )
        for index in ("dynsym:0", "dynsym:7", "dynsym:12345"):
            with self.subTest(index=index):
                result = subprocess.run(
                    ["/bin/sh", "-c", validator, "dynsym-index-test", index],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

        for index in ("dynsym:", "dynsym:x", "dynsym:12x", "dynsym:-1", "12"):
            with self.subTest(index=index):
                result = subprocess.run(
                    ["/bin/sh", "-c", validator, "dynsym-index-test", index],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_shared_musl_jump_table_row_runs_with_exact_identity_and_checker(self) -> None:
        start = self.workflow.index("      - name: Run shared musl indirect jump-table evidence")
        end = self.workflow.index("      - name: Upload musl container and indirect-control evidence", start)
        block = self.workflow[start:end]
        self.assertIn("run-shared-jump-table-copy-e2e.sh", block)
        self.assertIn("--runtime musl", block)
        self.assertIn("runtime.indirect-control.shared-table.musl.host-context-entry", block)
        self.assertIn("check-rehydration-evidence.py", block)
        self.assertIn("--require-runtime-identity", block)
        self.assertIn("build/musl-shared-jump-table/host-context-shared-jump-table-fixture.so", block)
        self.assertIn("check-shared-jump-table-evidence.py", block)

        upload_start = self.workflow.index("      - name: Upload musl container and indirect-control evidence")
        upload_end = self.workflow.index("  benchmark:\n", upload_start)
        upload = self.workflow[upload_start:upload_end]
        self.assertIn("if: always()", upload)
        self.assertIn("include-hidden-files: true", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn(".artifacts/indirect-control/musl-${{ github.run_id }}-${{ github.run_attempt }}/", upload)

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
