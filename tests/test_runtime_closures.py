#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RuntimeClosureContractTests(unittest.TestCase):
    def test_locked_closure_covers_all_three_runtimes_and_registry(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/validate-runtime-closures.py"),
                str(ROOT / "fixtures/real-samples/runtime-closures.json"),
                str(ROOT / "fixtures/real-samples/manifest.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_default_policy_requires_baseline_and_outer_execution(self) -> None:
        closure = json.loads(
            (ROOT / "fixtures/real-samples/runtime-closures.json").read_text()
        )
        default = closure["projects"]["*"]
        self.assertEqual(default["baseline"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(default["outerWrapper"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(default["outerWrapper"]["mode"], "outer-execveat")


if __name__ == "__main__":
    unittest.main()
