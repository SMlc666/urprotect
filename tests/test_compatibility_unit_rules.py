#!/usr/bin/env python3
"""Compatibility complete-unit, fixed-view, growth, and zero-baseline tests."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluator_lib import (  # noqa: E402
    COMPATIBILITY_STAGES,
    EvaluatorError,
    calculate_compatibility,
    derive_unit_completion,
    validate_unit_record,
)


DIGEST = "a" * 64


def row(unit_id: str, identity: str) -> dict:
    return {
        "unitId": unit_id,
        "identityKey": identity,
        "sourceSha256": DIGEST,
        "profile": "test-profile",
        "runtimeCell": "test-runtime",
        "targetLoader": "test-loader",
        "oracleId": "test-oracle",
        "required": True,
        "applicable": True,
    }


def unit(registration: dict, *, passed: bool = True) -> dict:
    stages = {}
    passed_bindings = {
        "protector": {"outputSha256": DIGEST},
        "protected-image": {"artifactSha256": DIGEST, "abiId": "test-abi", "abiVersion": "1"},
        "rehydration": {"protectedImageSha256": DIGEST, "nativeImageSha256": DIGEST, "consumerId": "test-consumer"},
        "native-image": {"sha256": DIGEST},
        "target-loader": {"nativeImageSha256": DIGEST, "evidenceSha256": DIGEST, "loaderId": "test-loader"},
        "behavioral-oracle": {"comparisonSha256": DIGEST},
    }
    for stage in COMPATIBILITY_STAGES:
        if passed:
            stages[stage] = {"status": "passed", **passed_bindings[stage]}
        else:
            stages[stage] = {"status": "failed", "reason": "test failure"}
    complete, first_failure = derive_unit_completion(
        {
            "unitId": registration["unitId"],
            "sourceSha256": registration["sourceSha256"],
            "profile": registration["profile"],
            "runtimeCell": registration["runtimeCell"],
            "targetLoader": registration["targetLoader"],
            "oracleId": registration["oracleId"],
            "statusOwner": "independent-evaluator",
            "stages": stages,
        },
        registration,
    )
    return {
        "schemaVersion": 1,
        "kind": "compatibility-unit",
        "unitId": registration["unitId"],
        "corpusVersion": "test-corpus",
        "sourceSha256": registration["sourceSha256"],
        "profile": registration["profile"],
        "runtimeCell": registration["runtimeCell"],
        "targetLoader": registration["targetLoader"],
        "oracleId": registration["oracleId"],
        "statusOwner": "independent-evaluator",
        "stages": stages,
        "complete": complete,
        "firstFailureLayer": first_failure,
        "rawEvidenceManifest": "raw/SHA256SUMS",
    }


class CompatibilityUnitRuleTests(unittest.TestCase):
    def test_non_passed_stage_never_counts_and_retains_first_failure(self) -> None:
        registration = row("unit-1", "identity-1")
        record = unit(registration, passed=False)
        complete, first_failure = derive_unit_completion(record, registration)
        self.assertFalse(complete)
        self.assertEqual(first_failure, "protector")

    def test_zero_baseline_does_not_create_numeric_factor(self) -> None:
        registration = row("unit-1", "identity-1")
        corpus = {
            "corpusVersion": "test-corpus",
            "rows": [registration],
            "fixedRowIds": [registration["unitId"]],
        }
        result = calculate_compatibility(corpus, {"completeUnits": 0}, [unit(registration)])
        self.assertEqual(result["status"], "baseline-zero")
        self.assertIsNone(result["factor"])
        self.assertFalse(result["growthViewPass"])

    def test_exact_integer_growth_requires_one_hundred_distinct_units(self) -> None:
        rows = [row(f"unit-{index}", f"identity-{index}") for index in range(100)]
        corpus = {"corpusVersion": "test-corpus", "rows": rows, "fixedRowIds": [rows[0]["unitId"]]}
        records = [unit(item) for item in rows]
        result = calculate_compatibility(corpus, {"completeUnits": 1}, records)
        self.assertEqual(result["candidateGrowthCompleteUnits"], 100)
        self.assertEqual(result["growthTarget"], 100)
        self.assertTrue(result["growthViewPass"])
        self.assertEqual(result["factor"], 100.0)

    def test_fixed_view_regression_is_visible(self) -> None:
        registration = row("unit-1", "identity-1")
        corpus = {"corpusVersion": "test-corpus", "rows": [registration], "fixedRowIds": [registration["unitId"]]}
        result = calculate_compatibility(corpus, {"completeUnits": 1}, [unit(registration, passed=False)])
        self.assertFalse(result["fixedViewPass"])
        self.assertFalse(result["growthViewPass"])

    def test_generic_evidence_digest_cannot_complete_all_stages(self) -> None:
        registration = row("unit-1", "identity-1")
        record = unit(registration)
        record["stages"]["protected-image"] = {"status": "passed", "evidenceSha256": DIGEST}
        record["complete"] = False
        record["firstFailureLayer"] = "protected-image"
        with self.assertRaises(EvaluatorError):
            validate_unit_record(record, registration)

    def test_fixed_view_cannot_replace_a_completed_baseline_identity(self) -> None:
        first = row("unit-1", "identity-1")
        second = row("unit-2", "identity-2")
        corpus = {
            "corpusVersion": "test-corpus",
            "rows": [first, second],
            "fixedRowIds": [first["unitId"], second["unitId"]],
        }
        result = calculate_compatibility(
            corpus,
            {"completeUnits": 1, "completeUnitIds": [first["unitId"]]},
            [unit(second, passed=True), unit(first, passed=False)],
        )
        self.assertFalse(result["fixedViewPass"])

    def test_duplicate_evidence_unit_is_protocol_failure(self) -> None:
        registration = row("unit-1", "identity-1")
        record = unit(registration)
        corpus = {"corpusVersion": "test-corpus", "rows": [registration], "fixedRowIds": [registration["unitId"]]}
        with self.assertRaises(EvaluatorError):
            calculate_compatibility(corpus, {"completeUnits": 1}, [record, copy.deepcopy(record)])


if __name__ == "__main__":
    unittest.main()
