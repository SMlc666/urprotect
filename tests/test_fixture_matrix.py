#!/usr/bin/env python3
"""Regression tests for the repository-owned compatibility matrix contract."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "fixtures" / "manifest.json"
VALIDATOR = REPO_ROOT / "scripts" / "validate-fixtures.py"
RENDERER = REPO_ROOT / "scripts" / "render-compatibility-matrix.py"


class FixtureMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(MANIFEST.read_text())

    def run_validator(self, data: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=REPO_ROOT / "fixtures",
            prefix=".matrix-validation-",
            suffix=".json",
            delete=False,
        ) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path), "--tier", "pr"],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)

    def test_current_manifest_contains_unknown_bionic_handoff_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.bionic-handoff"
        )
        self.assertEqual(feature["status"], "unknown")
        self.assertTrue(feature["nextEvidence"])

    def test_pt_tls_is_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.pt-tls"
        )
        self.assertEqual(feature["status"], "rejected")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn("dlopen", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn(
            "native/urprotect-runtime/host_context_self_test.c",
            feature["evidence"],
        )
        self.assertIn(
            ".artifacts/host-context/pr/self-test.log",
            feature["evidence"],
        )
        self.assertTrue(any("p_filesz" in item for item in feature["constraints"]))

    def test_unknown_feature_requires_next_evidence(self) -> None:
        data = copy.deepcopy(self.data)
        feature = next(
            item
            for item in data["features"]
            if item["id"] == "runtime.host-context.bionic-handoff"
        )
        del feature["nextEvidence"]

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nextEvidence", result.stderr or result.stdout)

    def test_gnu_property_is_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.gnu-property"
        )
        self.assertEqual(feature["status"], "rejected")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn("property negotiation", feature["reason"])
        self.assertIn("BTI/PAC", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn(
            ".artifacts/host-context/pr/self-test.log",
            feature["evidence"],
        )
        self.assertTrue(any("zero image handle" in item for item in feature["constraints"]))

    def test_unsupported_image_boundary_covers_only_dependencies(self) -> None:
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.unsupported-image-boundaries"
        )
        self.assertIn("DT_NEEDED", feature["obligation"])
        self.assertNotIn("PT_GNU_PROPERTY", feature["obligation"])
        self.assertIn("dependency-resolution", feature["reason"])
        self.assertNotIn("GNU property", feature["reason"])

    def test_feature_covering_strategy_is_required(self) -> None:
        data = copy.deepcopy(self.data)
        data["coverage"]["strategy"] = "cartesian"

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage.strategy", result.stderr or result.stdout)

    def test_case_cannot_repeat_a_feature_identifier(self) -> None:
        data = copy.deepcopy(self.data)
        case = next(item for item in data["cases"] if item["id"] == "c-gcc-glibc-pie")
        case["features"].append(case["features"][0])

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate feature identifiers", result.stderr or result.stdout)

    def test_required_case_cannot_claim_unknown_feature(self) -> None:
        data = copy.deepcopy(self.data)
        case = next(item for item in data["cases"] if item["id"] == "c-termux-bionic-pie")
        case["required"] = True

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-supporting features", result.stderr or result.stdout)

    def test_bionic_case_requires_kernel_and_architecture_facts(self) -> None:
        data = copy.deepcopy(self.data)
        host = next(item for item in data["cases"] if item["id"] == "c-termux-bionic-pie")["host"]
        del host["kernel"]

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host.kernel", result.stderr or result.stdout)

    def test_rejected_feature_requires_a_valid_negative_oracle(self) -> None:
        data = copy.deepcopy(self.data)
        feature = next(
            item
            for item in data["features"]
            if item["id"] == "runtime.host-context.unsupported-image-boundaries"
        )
        feature["negativeOracle"] = "fixtures/missing-negative-oracle"

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("negativeOracle", result.stderr or result.stdout)

    def test_rendered_matrix_explains_unknown_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "matrix.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(RENDERER),
                    str(MANIFEST),
                    "--output",
                    str(output),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text()
            self.assertIn("unknown` rows never count as support", rendered)
            self.assertIn("runtime.host-context.bionic-handoff | unknown", rendered)
            self.assertIn("runtime.host-context.gnu-property | rejected", rendered)
            self.assertIn("runtime.host-context.pt-tls | rejected", rendered)


if __name__ == "__main__":
    unittest.main()
