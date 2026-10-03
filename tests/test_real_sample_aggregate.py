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


def load_renderer():
    spec = importlib.util.spec_from_file_location("real_sample_report", RENDERER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealSampleAggregateTests(unittest.TestCase):
    def test_checked_in_baseline_is_distinct_identity_schema_two(self) -> None:
        aggregate = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(aggregate["schemaVersion"], 2)
        self.assertEqual(aggregate["evidenceMode"], "registry-baseline")
        target = aggregate["coverage"]["approvedTargetProjectCount"]
        self.assertEqual(aggregate["identityCount"], target)
        self.assertEqual(aggregate["requiredProjectCount"], target)
        self.assertEqual(aggregate["observedProjectCount"], target)
        self.assertEqual(aggregate["coverage"]["shortfall"], 0)
        self.assertEqual(len(aggregate["projectIds"]), target)
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
        records = {record["projectId"]: record for record in aggregate["records"]}
        for project_id in ("busybox", "gnu-coreutils", "nodejs"):
            for layer in ("baseline", "outerWrapper"):
                self.assertEqual(records[project_id]["layers"][layer]["actual"], "not-applicable")
                self.assertEqual(records[project_id]["layers"][layer]["actualSource"], "registry-baseline")
        for layer in ("baseline", "outerWrapper"):
            self.assertEqual(aggregate["layerCounts"][layer], {"not-applicable": 100})
            self.assertNotIn("accepted-and-runs", aggregate["layerCounts"][layer])
        markdown = BASELINE.with_suffix(".md").read_text(encoding="utf-8")
        self.assertNotIn("| `busybox` | `musl` | `outerWrapper` | `accepted-and-runs` |", markdown)
        self.assertIn("Registry-only baseline facts are labeled metadata", markdown)

    def test_renderer_prefers_project_closure_and_preserves_node_boundary(self) -> None:
        renderer = load_renderer()
        manifest = json.loads((ROOT / "fixtures/real-samples/manifest.json").read_text(encoding="utf-8"))
        closures = json.loads((ROOT / "fixtures/real-samples/runtime-closures.json").read_text(encoding="utf-8"))
        projects = {project["projectId"]: project for project in manifest["corpus"]["projects"]}
        node = projects["nodejs"]
        self.assertEqual(renderer.expected_layers(node, closures)["baseline"]["expected"], "accepted-and-runs")
        self.assertEqual(renderer.expected_layers(node, closures)["outerWrapper"]["expected"], "accepted-and-runs")
        self.assertEqual(renderer.expected_layers(node, closures)["baseline"]["actual"], "not-applicable")
        self.assertEqual(renderer.expected_layers(node, closures)["outerWrapper"]["actual"], "not-applicable")

        # A per-project closure entry takes precedence over the wildcard even
        # when both entries describe the same runtime layer.
        closures["projects"]["gnu-coreutils"] = {
            "baseline": {"expectedResult": "accepted-and-runs"}
        }
        closures["projects"]["*"]["baseline"]["expectedResult"] = "environment-unavailable"
        self.assertEqual(
            renderer.expected_layers(projects["gnu-coreutils"], closures)["baseline"]["expected"],
            "accepted-and-runs",
        )

    def test_renderer_preserves_not_applicable_registry_boundary(self) -> None:
        renderer = load_renderer()
        manifest = json.loads((ROOT / "fixtures/real-samples/manifest.json").read_text(encoding="utf-8"))
        closures = json.loads((ROOT / "fixtures/real-samples/runtime-closures.json").read_text(encoding="utf-8"))
        project = next(project for project in manifest["corpus"]["projects"] if project["projectId"] == "gnu-coreutils")
        closures["projects"]["*"]["hostContext"] = {"expectedResult": "accepted-and-runs"}
        layers = renderer.expected_layers(project, closures)
        self.assertEqual(layers["hostContext"]["expected"], "not-applicable")
        self.assertEqual(layers["hostContext"]["actual"], "not-applicable")

    def test_first_failure_mapping_keeps_environment_separate(self) -> None:
        schema = load_schema()
        layers = {
            "static": {
                "expected": "validated",
                "actual": "validated",
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
