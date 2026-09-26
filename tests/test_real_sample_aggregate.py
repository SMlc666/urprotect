#!/usr/bin/env python3
"""Contract tests for normalized fingerprints and identity aggregates."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
INSPECTOR = ROOT / "scripts/inspect-real-sample.py"
BASELINE = ROOT / "fixtures/real-samples/baseline-aggregate.json"
RENDERER = ROOT / "scripts/render-real-sample-report.py"
SCHEMA = ROOT / "scripts/real_sample_schema.py"


def load_schema():
    spec = importlib.util.spec_from_file_location("real_sample_schema", SCHEMA)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealSampleAggregateTests(unittest.TestCase):
    def test_checked_in_baseline_is_distinct_identity_schema_two(self) -> None:
        aggregate = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(aggregate["schemaVersion"], 2)
        self.assertEqual(aggregate["evidenceMode"], "registry-baseline")
        self.assertEqual(aggregate["identityCount"], 20)
        self.assertEqual(aggregate["coverage"]["approvedTargetProjectCount"], 100)
        self.assertEqual(aggregate["coverage"]["shortfall"], 80)
        self.assertEqual(len(aggregate["projectIds"]), 20)
        self.assertTrue(aggregate["featureHistogram"])
        self.assertTrue(
            all(
                item["disposition"]["status"]
                and item["disposition"]["reason"]
                and len(item["identityKeys"]) == item["identityCount"]
                for item in aggregate["featureHistogram"]
                if item["thresholdTriggered"]
            )
        )

    def test_first_failure_mapping_keeps_environment_separate(self) -> None:
        schema = load_schema()
        layers = {
            "static": {
                "expected": "accepted-and-runs",
                "actual": "accepted-and-runs",
            },
            "baseline": {
                "expected": "accepted-and-runs",
                "actual": "environment-unavailable",
            },
            "outerWrapper": {
                "expected": "not-applicable",
                "actual": "not-applicable",
            },
            "hostContext": {
                "expected": "not-applicable",
                "actual": "not-applicable",
            },
        }
        self.assertEqual(schema.first_failure_layer(layers), "environment")
        self.assertEqual(schema.first_failure_layer(layers, "fingerprint"), "fingerprint")

    def test_observed_feature_projection_is_bounded_and_typed(self) -> None:
        schema = load_schema()
        features = schema.observed_features(
            {
                "featureTags": ["rela", "rela", "gnu-relro"],
                "type": "DYN (Position-Independent Executable file)",
                "interpreter": "/lib/ld-linux-aarch64.so.1",
                "relocations": {
                    "rela": True,
                    "plt": True,
                    "families": {"relative": 4, "plt": 2, "unknown": 0},
                },
                "dependencies": {"needed": ["libc.so.6"], "rpath": []},
            }
        )
        self.assertIn("rela", features)
        self.assertIn("relocations.family.relative", features)
        self.assertIn("dependencies.needed", features)
        self.assertIn("elf.type.ET_DYN", features)
        self.assertLessEqual(len(features), 512)

    def test_inspector_emits_concrete_feature_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "fingerprint.json"
            readelf = root / "readelf.txt"
            result = subprocess.run(
                [
                    sys.executable,
                    str(INSPECTOR),
                    "--input",
                    "/usr/bin/ls",
                    "--output",
                    str(output),
                    "--readelf-output",
                    str(readelf),
                    "--project-id",
                    "aggregate-test",
                    "--producer",
                    "test-producer",
                    "--runtime",
                    "glibc",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            fingerprint = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(fingerprint["schemaVersion"], 2)
            self.assertEqual(fingerprint["projectId"], "aggregate-test")
            for key in (
                "dependencies",
                "relocations",
                "symbolVersions",
                "tls",
                "gnuProperty",
                "hardening",
                "loader",
                "pageSize",
                "producer",
            ):
                self.assertIn(key, fingerprint)
            self.assertLessEqual(len(fingerprint["relocations"].get("types", [])), 128)
            self.assertLessEqual(fingerprint["inspection"]["readelfBytes"], 16 * 1024 * 1024)

    def test_renderer_requires_evidence_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    str(RENDERER),
                    "fixtures/real-samples/manifest.json",
                    "--tier",
                    "pr",
                    "--artifact-root",
                    str(root),
                    "--require-evidence",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("result.json", result.stderr)


if __name__ == "__main__":
    unittest.main()
