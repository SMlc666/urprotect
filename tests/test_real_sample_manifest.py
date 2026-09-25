#!/usr/bin/env python3
"""Contract tests for the metadata-only public real-sample corpus."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures/real-samples/manifest.json"
CANDIDATES = ROOT / "fixtures/real-samples/candidates.json"
VALIDATOR = ROOT / "scripts/validate-real-samples.py"


class RealSampleManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.candidates = json.loads(CANDIDATES.read_text(encoding="utf-8"))

    def validate(self, manifest=None, candidates=None, *extra: str) -> subprocess.CompletedProcess[str]:
        manifest = self.manifest if manifest is None else manifest
        candidates = self.candidates if candidates is None else candidates
        with tempfile.TemporaryDirectory(dir=ROOT / "fixtures") as directory:
            directory_path = Path(directory)
            manifest_path = directory_path / "manifest.json"
            candidates_path = directory_path / "candidates.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            candidates_path.write_text(json.dumps(candidates), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(manifest_path), "--candidates", str(candidates_path), *extra],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_locked_registry_has_exactly_twenty_distinct_projects(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        projects = self.manifest["corpus"]["projects"]
        self.assertEqual(len(projects), 20)
        self.assertEqual(self.manifest["corpus"]["targetProjectCount"], 100)
        self.assertEqual(self.manifest["corpus"]["expansion"]["currentApproved"], 20)
        self.assertEqual(self.manifest["corpus"]["expansion"]["approvedTarget"], 100)
        self.assertEqual(len({project["projectId"] for project in projects}), 20)
        self.assertEqual(len({project["identityKey"] for project in projects}), 20)
        self.assertEqual(
            {project["target"]["runtime"] for project in projects},
            {"glibc", "musl", "bionic"},
        )

    def test_candidate_ledger_is_broader_than_locked_selection(self) -> None:
        self.assertGreaterEqual(len(self.candidates["candidates"]), 40)
        self.assertTrue(all(len(candidate["provenance"]["archiveSha256"]) == 64 for candidate in self.candidates["candidates"]))
        selected = {
            candidate["projectId"]
            for candidate in self.candidates["candidates"]
            if candidate["disposition"] == "selected"
        }
        self.assertEqual(selected, {project["projectId"] for project in self.manifest["corpus"]["projects"]})
        self.assertTrue(any(candidate["disposition"] in {"rejected", "deferred"} for candidate in self.candidates["candidates"]))

    def test_duplicate_candidate_identity_is_rejected(self) -> None:
        candidates = copy.deepcopy(self.candidates)
        candidates["candidates"][20]["identityKey"] = candidates["candidates"][0]["identityKey"]
        result = self.validate(candidates=candidates)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct upstream project", result.stderr or result.stdout)

    def test_malformed_archive_hash_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][0]["provenance"]["archiveSha256"] = "not-a-hash"
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archiveSha256", result.stderr or result.stdout)

    def test_duplicate_project_identity_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][1]["identityKey"] = data["corpus"]["projects"][0]["identityKey"]
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct upstream project", result.stderr or result.stdout)

    def test_variant_does_not_increase_project_count(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][0]["variants"] = [
            {
                "variantId": "musl-build-reference",
                "kind": "runtime-comparison",
                "runtime": "musl",
                "reason": "A comparison attribute for the same Bash identity; never another project.",
            }
        ]
        result = self.validate(data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(len(data["corpus"]["projects"]), 20)

    def test_missing_provenance_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        del data["corpus"]["projects"][0]["provenance"]
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provenance", result.stderr or result.stdout)

    def test_unsupported_layer_result_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][0]["executionPolicy"]["static"]["expectedResult"] = "skipped"
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expectedResult", result.stderr or result.stdout)

    def test_not_applicable_layer_requires_reason(self) -> None:
        data = copy.deepcopy(self.manifest)
        del data["corpus"]["projects"][0]["executionPolicy"]["hostContext"]["reason"]
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hostContext.reason", result.stderr or result.stdout)

    def test_expected_result_projection_must_match_policy(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][0]["expectedResults"]["static"] = "expected-rejected"
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expectedResults.static", result.stderr or result.stdout)

    def test_candidate_and_selected_hashes_are_cross_checked(self) -> None:
        candidates = copy.deepcopy(self.candidates)
        candidates["candidates"][0]["provenance"]["archiveSha256"] = "0" * 64
        result = self.validate(candidates=candidates)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match candidate ledger", result.stderr or result.stdout)

    def test_tier_selection_emits_all_twenty_without_network(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        # The production command's validation output explicitly records that it
        # did not perform network access; acquisition belongs to the CI runner.
        self.assertIn("network=not-used", result.stdout)


if __name__ == "__main__":
    unittest.main()
