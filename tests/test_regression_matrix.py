from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "tests" / "regression-matrix.json"
VALIDATOR = ROOT / "scripts" / "validate-regression-matrix.py"


class RegressionMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(MATRIX.read_text(encoding="utf-8"))

    def validate(self, data: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", dir=ROOT, delete=False) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)

    def test_current_matrix_is_valid_and_covers_required_classes(self) -> None:
        result = self.validate(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("managed.coverage-guided-fuzz", {case["id"] for case in self.data["cases"]})
        self.assertIn("native.host-context-e2e", {case["id"] for case in self.data["cases"]})

    def test_duplicate_case_id_is_rejected(self) -> None:
        data = copy.deepcopy(self.data)
        data["cases"].append(copy.deepcopy(data["cases"][0]))
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr)

    def test_empty_artifact_witness_is_rejected(self) -> None:
        data = copy.deepcopy(self.data)
        data["cases"][0]["artifacts"] = []
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifacts", result.stderr)

    def test_missing_artifact_path_is_rejected_when_witness_check_is_requested(self) -> None:
        data = copy.deepcopy(self.data)
        data["cases"][0]["artifacts"] = [".artifacts/does-not-exist/"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", dir=ROOT, delete=False) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    str(path),
                    "--tier",
                    "pr",
                    "--check-artifacts",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact witnesses", result.stderr)

    def test_optional_android_row_is_not_required(self) -> None:
        android = next(case for case in self.data["cases"] if case["class"] == "android-native-bridge")
        self.assertFalse(android["required"])
        self.assertEqual(android["expected"], "pass-or-unavailable")


if __name__ == "__main__":
    unittest.main()
