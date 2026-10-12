import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-aarch64-encoding-boundary.py"
FIXTURE = ROOT / "tests" / "ArchitectureFixtures" / "ForbiddenAarch64WordWriter.cs"


class Aarch64EncodingBoundaryTests(unittest.TestCase):
    def run_checker(self, *arguments):
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_production_tree_passes(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("production tree passed", result.stdout)

    def test_forbidden_fixture_is_detected(self):
        result = self.run_checker("--fixture", str(FIXTURE))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden fixture detected", result.stdout)
        self.assertIn("manual AArch64 final-word writer", result.stdout)

    def test_self_test_accepts_expected_fixture_failure(self):
        result = self.run_checker(
            "--fixture",
            str(FIXTURE),
            "--self-test",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("forbidden fixture detected", result.stdout)


if __name__ == "__main__":
    unittest.main()
