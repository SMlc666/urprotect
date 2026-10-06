#!/usr/bin/env python3
"""Focused Scheme-A replica, cost, censoring, and conjunction tests."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluator_lib import (  # noqa: E402
    EvaluatorError,
    REQUIRED_FAMILIES,
    calculate_scheme_gate,
    read_json,
    validate_scheme_manifest,
)

SCORER_SPEC = importlib.util.spec_from_file_location("run_scheme_a_fixture", ROOT / "scripts/run-scheme-a-fixture.py")
assert SCORER_SPEC is not None and SCORER_SPEC.loader is not None
SCORER = importlib.util.module_from_spec(SCORER_SPEC)
SCORER_SPEC.loader.exec_module(SCORER)

DIGEST = "b" * 64


def attempts_for(scheme: dict, *, candidate_cpu_ns: int = 100_000_000, mixed_family: str | None = None) -> dict[tuple[str, str, int], dict]:
    families = {entry["familyId"]: entry for entry in scheme["requiredFamilies"]}
    attempts: dict[tuple[str, str, int], dict] = {}
    for family_id in REQUIRED_FAMILIES:
        family = families[family_id]
        for role in ("baseline", "candidate"):
            for replica in range(1, scheme["replicaCount"] + 1):
                is_mixed_failure = role == "candidate" and family_id == mixed_family and replica == 3
                classification = "attack-failed" if is_mixed_failure else "attack-success"
                attempts[(family_id, role, replica)] = {
                    "schemaVersion": 1,
                    "kind": "scheme-a-attempt",
                    "familyId": family_id,
                    "profile": scheme["profile"],
                    "replica": replica,
                    "role": role,
                    "statusOwner": "independent-evaluator",
                    "unitId": scheme["fixtureId"],
                    "sourceSha256": scheme["sourceSha256"],
                    "attackRecipeSha256": family["attackRecipeSha256"],
                    "budget": copy.deepcopy(scheme["budget"]),
                    "classification": classification,
                    "goalAchieved": not is_mixed_failure,
                    "blueOracle": {
                        "status": "failed" if is_mixed_failure else "passed",
                        "evidenceSha256": None if is_mixed_failure else DIGEST,
                    },
                    "successCpuNs": None if is_mixed_failure else (1_000_000 if role == "baseline" else candidate_cpu_ns),
                    "censored": False,
                    "manualStepsObserved": 0,
                    "rawEvidenceManifest": "raw/SHA256SUMS",
                    "resourceEvidence": "raw/resource.json",
                    "stdout": "raw/stdout.txt",
                    "stderr": "raw/stderr.txt",
                    "commandLog": "raw/command.log",
                    "publishedArtifactSha256": scheme.get("publishedArtifactSha256"),
                    "toolchain": copy.deepcopy(family["tool"]),
                    "recoveredArtifactSha256": DIGEST if not is_mixed_failure else None,
                    "recoveredArtifactSize": 1 if not is_mixed_failure else 0,
                }
    return attempts


class SchemeAGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scheme = read_json(ROOT / "fixtures/evaluator/scheme-a-manifest.json")
        validate_scheme_manifest(cls.scheme)

    def test_three_finite_baselines_and_exact_100x_conjunction(self) -> None:
        result = calculate_scheme_gate(self.scheme, attempts_for(self.scheme))
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["allRequiredPass"])
        self.assertEqual(result["familyFactors"]["patch_repack"], 100.0)
        self.assertEqual(result["minimumFactorDiagnostic"], 100.0)

    def test_one_family_below_100_blocks_conjunction(self) -> None:
        result = calculate_scheme_gate(self.scheme, attempts_for(self.scheme, candidate_cpu_ns=99_000_000))
        self.assertEqual(result["status"], "measured")
        self.assertFalse(result["allRequiredPass"])
        self.assertEqual(result["families"]["static_decomposition"]["status"], "bounded-below-100")

    def test_mixed_replica_outcome_is_unknown_not_average(self) -> None:
        result = calculate_scheme_gate(self.scheme, attempts_for(self.scheme, mixed_family="dynamic_instrumentation"))
        self.assertEqual(result["status"], "measured")
        self.assertEqual(result["families"]["dynamic_instrumentation"]["status"], "unknown")
        self.assertFalse(result["allRequiredPass"])

    def test_fully_exhausted_candidate_is_a_censored_lower_bound(self) -> None:
        attempts = attempts_for(self.scheme)
        for key, attempt in attempts.items():
            if key[1] != "candidate":
                continue
            attempt["classification"] = "attack-failed"
            attempt["goalAchieved"] = False
            attempt["blueOracle"] = {"status": "passed", "evidenceSha256": DIGEST}
            attempt["successCpuNs"] = None
            attempt["censored"] = True
        result = calculate_scheme_gate(self.scheme, attempts)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["families"]["patch_repack"]["censored"])
        self.assertGreaterEqual(result["families"]["patch_repack"]["factorLowerBound"], 100.0)

    def test_missing_finite_baseline_is_not_calibrated(self) -> None:
        attempts = attempts_for(self.scheme)
        attempts[("integrity_handoff", "baseline", 2)]["classification"] = "environment-unavailable"
        attempts[("integrity_handoff", "baseline", 2)]["goalAchieved"] = False
        attempts[("integrity_handoff", "baseline", 2)]["successCpuNs"] = None
        result = calculate_scheme_gate(self.scheme, attempts)
        self.assertEqual(result["status"], "baseline-not-calibrated")
        self.assertEqual(result["families"]["integrity_handoff"]["baselineReplicas"], 2)
        self.assertIsNone(result["families"]["integrity_handoff"]["factorLowerBound"])

    def test_candidate_environment_unavailable_is_not_unknown(self) -> None:
        attempts = attempts_for(self.scheme)
        for replica in range(1, self.scheme["replicaCount"] + 1):
            attempt = attempts[("dynamic_instrumentation", "candidate", replica)]
            attempt["classification"] = "environment-unavailable"
            attempt["goalAchieved"] = False
            attempt["blueOracle"] = {"status": "environment-unavailable"}
            attempt["successCpuNs"] = None
        result = calculate_scheme_gate(self.scheme, attempts)
        self.assertEqual(result["families"]["dynamic_instrumentation"]["status"], "environment-unavailable")
        self.assertEqual(result["status"], "environment-unavailable")
        self.assertFalse(result["allRequiredPass"])

    def test_success_cost_cannot_exceed_frozen_cpu_budget(self) -> None:
        attempts = attempts_for(self.scheme)
        attempts[("patch_repack", "candidate", 1)]["successCpuNs"] = self.scheme["budget"]["cpuSeconds"] * 1_000_000_001
        with self.assertRaises(EvaluatorError):
            calculate_scheme_gate(self.scheme, attempts)


class SchemeAFixtureScorerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scheme = read_json(ROOT / "fixtures/evaluator/scheme-a-manifest.json")
        validate_scheme_manifest(cls.scheme)

    @staticmethod
    def _product_fixture(root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "protected-image.bin").write_bytes(b"protected-image-fixture")
        native = b"native-image-fixture"
        (root / "native-image.bin").write_bytes(native)
        native_digest = hashlib.sha256(native).hexdigest()
        (root / "target-loader.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "stage": "target-loader",
                    "status": "passed",
                    "targetStatus": 0,
                    "nativeImageSha256": native_digest,
                    "loaderId": "fixture-loader",
                }
            ),
            encoding="utf-8",
        )
        (root / "behavioral-oracle.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "stage": "behavioral-oracle",
                    "status": "passed",
                    "baselineStatus": 0,
                    "targetStatus": 0,
                    "stdoutEqual": True,
                    "stderrEqual": True,
                    "nativeImageSha256": native_digest,
                    "oracleId": "fixture-oracle",
                }
            ),
            encoding="utf-8",
        )

    def test_all_six_families_remain_frozen_and_unavailable_without_tools(self) -> None:
        _, families = SCORER._load_scheme()
        self.assertEqual(tuple(families), REQUIRED_FAMILIES)
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory) / "product"
            self._product_fixture(product)
            for index, family_id in enumerate(REQUIRED_FAMILIES):
                with self.subTest(family=family_id):
                    with self.assertRaises(SCORER.ScorerError) as context:
                        SCORER.run_fixture(family_id, "baseline", 1, product, Path(directory) / f"out-{index}")
                    self.assertIn("not calibrated", str(context.exception))

    def test_missing_blue_oracle_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory) / "product"
            self._product_fixture(product)
            (product / "behavioral-oracle.json").unlink()
            with self.assertRaises(SCORER.ScorerError) as context:
                SCORER.run_fixture(REQUIRED_FAMILIES[0], "baseline", 1, product, Path(directory) / "out")
            self.assertIn("behavioral-oracle.json", str(context.exception))

    def test_factor_math_is_exact_for_each_frozen_family(self) -> None:
        result = calculate_scheme_gate(self.scheme, attempts_for(self.scheme))
        self.assertEqual(result["requiredFamilies"], list(REQUIRED_FAMILIES))
        for family_id in REQUIRED_FAMILIES:
            with self.subTest(family=family_id):
                self.assertEqual(result["families"][family_id]["factorLowerBound"], 100.0)


if __name__ == "__main__":
    unittest.main()
