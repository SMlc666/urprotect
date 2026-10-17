#!/usr/bin/env python3
"""Regression contracts for compatibility-only, no-claim independent verification."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "compatibility_checker", ROOT / "scripts/check-strict-product-corpus.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CompatibilityOnlyGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.evidence = root / "product"
        self.evidence.mkdir()
        self.manifest = root / "registry.json"
        self.rows = [
            {
                "unitId": f"compat.fixture-{i:03d}",
                "identityKey": f"fixture-id-{i:03d}",
                "sourceProvenance": f"fixtures/samples/{i:03d}.c",
                "required": True, "applicable": True,
            }
            for i in range(100)
        ]
        self.rows[0]["unitId"] = "compat.protection-symbolized-fixture.glibc.outer-execveat"
        self.manifest.write_text(json.dumps({
            "rows": self.rows, "fixedRowIds": [self.rows[0]["unitId"]],
        }))
        self.summaries = []
        for index in range(4):
            selected = self.rows[index::4]
            path = self.evidence / f"strict-corpus-summary-shard-{index}-of-4.json"
            path.write_text(json.dumps({
                "schemaVersion": 1,
                "kind": "strict-compatibility-corpus-run",
                "tier": "pr",
                "runtime": "glibc",
                "shardIndex": index,
                "shardCount": 4,
                "totalRows": len(selected),
                "completedRows": len(selected),
                "failedRows": 0,
                "status": "passed",
                "unitIds": [row["unitId"] for row in selected],
            }))
            self.summaries.append(path)
        for row in self.rows:
            p = self.evidence / row["unitId"]
            p.mkdir()
            (p / "SHA256SUMS").write_text("a" * 64 + "  proof.json\n")

    @patch.object(module.subprocess, "run")
    def test_all_100_raw_product_chains_must_validate(self, run):
        run.return_value.returncode = 0
        result = module.check(self.manifest, self.evidence, "pr", "glibc")
        self.assertEqual(result["passedUnits"], 100)
        self.assertIsNone(result["securityStrengthClaim"])
        self.assertEqual(run.call_count, 100)

    @patch.object(module.subprocess, "run")
    def test_missing_unit_fails_not_silently_skipped(self, run):
        directory = self.evidence / self.rows[10]["unitId"]
        (directory / "SHA256SUMS").unlink()
        directory.rmdir()
        run.return_value.returncode = 0
        with self.assertRaisesRegex(ValueError, "missing or symlinked"):
            module.check(self.manifest, self.evidence, "pr", "glibc")

    @patch.object(module.subprocess, "run")
    def test_invalid_product_manifest_cannot_be_claimed(self, run):
        run.return_value.returncode = 1
        run.return_value.stderr = "hash mismatch"
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            module.check(self.manifest, self.evidence, "pr", "glibc")

    @patch.object(module.subprocess, "run")
    def test_summary_is_not_a_substitute_for_product_validation(self, run):
        record = json.loads(self.summaries[0].read_text())
        record["failedRows"] = 1
        self.summaries[0].write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "invalid/incomplete strict shard"):
            module.check(self.manifest, self.evidence, "pr", "glibc")
        run.assert_not_called()

    @patch.object(module.subprocess, "run")
    def test_missing_shard_summary_is_rejected(self, run):
        self.summaries[2].unlink()
        with self.assertRaisesRegex(ValueError, "shard summary inventory"):
            module.check(self.manifest, self.evidence, "pr", "glibc")
        run.assert_not_called()

    @patch.object(module.subprocess, "run")
    def test_reordered_shard_units_are_rejected(self, run):
        record = json.loads(self.summaries[1].read_text())
        record["unitIds"].reverse()
        self.summaries[1].write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "invalid/incomplete strict shard"):
            module.check(self.manifest, self.evidence, "pr", "glibc")
        run.assert_not_called()

    @patch.object(module.subprocess, "run")
    def test_unexpected_unit_directory_is_rejected(self, run):
        (self.evidence / "unexpected-unit-101").mkdir()
        with self.assertRaisesRegex(ValueError, "strict corpus inventory mismatch"):
            module.check(self.manifest, self.evidence, "pr", "glibc")
        run.assert_not_called()

    def test_registry_identity_is_unique(self):
        self.rows[1]["identityKey"] = self.rows[0]["identityKey"]
        self.manifest.write_text(json.dumps({
            "rows": self.rows, "fixedRowIds": [self.rows[0]["unitId"]],
        }))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            module.required_units(self.manifest)

    def test_registry_requires_all_100(self):
        self.manifest.write_text(json.dumps({
            "rows": self.rows[:99], "fixedRowIds": [self.rows[0]["unitId"]],
        }))
        with self.assertRaisesRegex(ValueError, "exactly 100"):
            module.required_units(self.manifest)


if __name__ == "__main__":
    unittest.main()
