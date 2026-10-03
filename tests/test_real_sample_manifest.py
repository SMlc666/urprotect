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
RUNTIME_CLOSURES = ROOT / "fixtures/real-samples/runtime-closures.json"


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

    def test_locked_registry_has_exactly_one_hundred_distinct_projects(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        projects = self.manifest["corpus"]["projects"]
        target = self.manifest["corpus"]["targetProjectCount"]
        self.assertEqual(len(projects), target)
        self.assertEqual(self.manifest["corpus"]["requiredProjectCount"], target)
        self.assertEqual(self.manifest["corpus"]["expansion"]["currentApproved"], target)
        self.assertEqual(self.manifest["corpus"]["expansion"]["approvedTarget"], target)
        self.assertEqual(len({project["projectId"] for project in projects}), target)
        self.assertEqual(len({project["identityKey"] for project in projects}), target)
        apk_increment = self.manifest["corpus"]["expansion"]["increment"]["alpineV322Arm64ApkAdded"]
        self.assertEqual(sum(project["provenance"]["archiveFormat"] == "apk" for project in projects), apk_increment)
        increment_projects = [
            project for project in projects
            if project["provenance"].get("sourceIndexSha256") is not None
        ]
        self.assertEqual(len(increment_projects), 80)
        self.assertTrue(
            all(
                "boundedExtraction" in project["provenance"]
                and project["provenance"]["archiveSizeBytes"]
                == project["provenance"]["boundedExtraction"]["localArchiveBytes"]
                for project in projects
            )
        )
        self.assertTrue(
            all(
                project["acquisition"]["maxArchiveBytes"] == 64 * 1024 * 1024
                and project["acquisition"]["maxExtractedBytes"] == 2 * 1024 * 1024 * 1024
                for project in projects
            )
        )
        self.assertEqual(
            {project["target"]["runtime"] for project in projects},
            {"glibc", "musl", "bionic"},
        )
        self.assertEqual(
            {project["executionPolicy"]["static"]["expectedResult"] for project in projects},
            {"validated"},
        )

    def test_candidate_ledger_is_broader_than_locked_selection(self) -> None:
        self.assertGreaterEqual(len(self.candidates["candidates"]), self.manifest["corpus"]["targetProjectCount"])
        self.assertTrue(all(len(candidate["provenance"]["archiveSha256"]) == 64 for candidate in self.candidates["candidates"]))
        selected = {
            candidate["projectId"]
            for candidate in self.candidates["candidates"]
            if candidate["disposition"] == "selected"
        }
        self.assertEqual(selected, {project["projectId"] for project in self.manifest["corpus"]["projects"]})
        self.assertTrue(any(candidate["disposition"] in {"rejected", "deferred"} for candidate in self.candidates["candidates"]))

    def test_pr_runtime_witness_policies_are_explicit_and_bionic_is_locked(self) -> None:
        projects = {project["projectId"]: project for project in self.manifest["corpus"]["projects"]}
        busybox = projects["busybox"]["executionPolicy"]
        coreutils = projects["gnu-coreutils"]["executionPolicy"]
        node = projects["nodejs"]["executionPolicy"]
        for policy in (busybox, coreutils):
            self.assertTrue(policy["baseline"]["applicable"])
            self.assertTrue(policy["outerWrapper"]["applicable"])
            self.assertEqual(policy["baseline"]["expectedResult"], "accepted-and-runs")
            self.assertEqual(policy["outerWrapper"]["expectedResult"], "accepted-and-runs")
        self.assertTrue(node["baseline"]["applicable"])
        self.assertTrue(node["outerWrapper"]["applicable"])
        self.assertEqual(node["baseline"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(node["outerWrapper"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(node["outerWrapper"]["mode"], "outer-path-preserving")
        self.assertIn("five-archive", node["baseline"]["reason"])

    def test_dynamic_et_exec_samples_retain_explicit_runtime_boundary(self) -> None:
        projects = {project["projectId"]: project for project in self.manifest["corpus"]["projects"]}
        for project_id in ("caddy", "python"):
            project = projects[project_id]
            self.assertEqual(project["featureFingerprint"]["type"], "ET_EXEC")
            self.assertEqual(
                project["featureFingerprint"]["interpreter"],
                "/lib/ld-linux-aarch64.so.1",
            )
            self.assertEqual(project["executionPolicy"]["static"]["expectedResult"], "validated")
            self.assertTrue(project["executionPolicy"]["outerWrapper"]["applicable"])
            self.assertEqual(project["executionPolicy"]["outerWrapper"]["expectedResult"], "accepted-and-runs")
            self.assertEqual(project["executionPolicy"]["hostContext"]["expectedResult"], "not-applicable")

    def test_nightly_and_release_runtime_policies_cover_all_one_hundred_identities(self) -> None:
        projects = self.manifest["corpus"]["projects"]
        self.assertEqual(len(projects), 100)
        for project in projects:
            for layer in ("baseline", "outerWrapper"):
                declaration = project["executionPolicy"][layer]
                self.assertTrue(declaration["applicable"], f"{project['projectId']}/{layer}")
                self.assertEqual(declaration["expectedResult"], "accepted-and-runs")
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/validate-runtime-closures.py"),
                str(RUNTIME_CLOSURES),
                str(MANIFEST),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("100 identities", result.stdout)
        self.assertTrue(
            all(
                project["executionPolicy"][layer]["expectedResult"] == "accepted-and-runs"
                for project in projects
                for layer in ("baseline", "outerWrapper")
            )
        )

    def test_pr_tier_override_is_explicit_and_does_not_weaken_nightly_policy(self) -> None:
        projects = {project["projectId"]: project for project in self.manifest["corpus"]["projects"]}
        for project_id in set(projects) - {"busybox", "gnu-coreutils", "nodejs"}:
            override = projects[project_id]["executionPolicy"]["tierOverrides"]["pr"]
            self.assertFalse(override["baseline"]["applicable"])
            self.assertEqual(override["baseline"]["expectedResult"], "not-applicable")
            self.assertFalse(override["outerWrapper"]["applicable"])
            self.assertEqual(override["outerWrapper"]["expectedResult"], "not-applicable")
        self.assertNotIn("tierOverrides", projects["nodejs"]["executionPolicy"])

    def test_tier_override_execution_fields_use_strict_runtime_contracts(self) -> None:
        mutations = (
            ("expectedStatus", "0"),
            ("mode", {"name": "runtime-closure"}),
            ("command", "/bin/bash"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                data = copy.deepcopy(self.manifest)
                project = next(item for item in data["corpus"]["projects"] if item["projectId"] == "gnu-bash")
                project["executionPolicy"]["tierOverrides"]["pr"]["baseline"][field] = value
                result = self.validate(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr or result.stdout)

    def test_canonical_dynamic_policy_cannot_predeclare_environment_unavailable(self) -> None:
        data = copy.deepcopy(self.manifest)
        project = next(item for item in data["corpus"]["projects"] if item["projectId"] == "gnu-bash")
        project["executionPolicy"]["baseline"]["expectedResult"] = "environment-unavailable"
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("environment-unavailable is observed evidence", result.stderr or result.stdout)

    def test_static_policy_cannot_claim_execution_success(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][0]["executionPolicy"]["static"]["expectedResult"] = "accepted-and-runs"
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("static", result.stderr or result.stdout)

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
        self.assertEqual(len(data["corpus"]["projects"]), data["corpus"]["targetProjectCount"])

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

    def test_every_selected_provenance_field_is_cross_checked(self) -> None:
        candidates = copy.deepcopy(self.candidates)
        candidate = next(
            item for item in candidates["candidates"]
            if item["projectId"] == "ruby"
        )
        candidate["provenance"]["sourceKind"] = "other-public-source"
        result = self.validate(candidates=candidates)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match candidate ledger", result.stderr or result.stdout)

    def test_pinned_alpine_index_digest_is_cross_checked(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["expansion"]["increment"]["alpineIndexSha256"] = "0" * 64
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pinned Alpine package index digest", result.stderr or result.stdout)

    def test_documented_runtime_mix_matches_selected_targets(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["expansion"]["runtimeMix"]["glibc"] += 1
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected project target runtime fields", result.stderr or result.stdout)

    def test_selected_acquisition_limits_match_shared_extractor_bounds(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["corpus"]["projects"][0]["acquisition"]["maxArchiveBytes"] -= 1
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("match the extractor bound", result.stderr or result.stdout)

    def test_selected_bounded_extraction_facts_match_shared_limits(self) -> None:
        data = copy.deepcopy(self.manifest)
        apk = next(
            project for project in data["corpus"]["projects"]
            if project["provenance"]["archiveFormat"] == "apk"
        )
        apk["provenance"]["boundedExtraction"]["memberLimit"] += 1
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match the extractor bound", result.stderr or result.stdout)

    def test_tier_selection_emits_complete_registry_without_network(self) -> None:
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        # The production command's validation output explicitly records that it
        # did not perform network access; acquisition belongs to the CI runner.
        self.assertIn("network=not-used", result.stdout)


if __name__ == "__main__":
    unittest.main()
