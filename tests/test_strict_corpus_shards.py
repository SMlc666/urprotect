#!/usr/bin/env python3
"""Regression tests for deterministic, fail-closed strict compatibility sharding."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "strict_corpus_shards", ROOT / "scripts/strict_corpus_shards.py"
)
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)


class StrictCorpusShardsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "corpus.json"
        self.rows = [
            {"unitId": f"compat.unit-{index:03d}", "sourceProvenance": f"src/{index}.c",
             "required": True, "applicable": True}
            for index in range(100)
        ]
        self.manifest.write_text(json.dumps({"rows": self.rows}), encoding="utf-8")

    def make_evidence(self, count=4):
        root = self.root / "evidence"
        root.mkdir(exist_ok=True)
        for index in range(count):
            selected = shards.selected_rows(shards.required_rows(self.manifest), index, count)
            for unit, _ in selected:
                (root / unit).mkdir(exist_ok=True)
            document = {
                "schemaVersion": 1,
                "kind": "strict-compatibility-corpus-run",
                "tier": "pr",
                "runtime": "glibc",
                "shardIndex": index,
                "shardCount": count,
                "totalRows": len(selected),
                "completedRows": len(selected),
                "failedRows": 0,
                "status": "passed",
                "unitIds": [unit for unit, _ in selected],
            }
            (root / shards.summary_name(index, count)).write_text(
                json.dumps(document), encoding="utf-8"
            )
        return root

    def test_exact_partition_and_stable_order(self):
        rows = shards.required_rows(self.manifest)
        assignments = [shards.selected_rows(rows, i, 4) for i in range(4)]
        self.assertEqual([len(shard) for shard in assignments], [25] * 4)
        self.assertEqual({unit for shard in assignments for unit, _ in shard},
                         {unit for unit, _ in rows})
        self.assertEqual(assignments[0][1][0], "compat.unit-004")
        with self.assertRaises(ValueError):
            shards.selected_rows(rows, 4, 4)

    @patch.object(shards.subprocess, "run")
    def test_valid_merge_checks_every_unit(self, run):
        run.return_value.returncode = 0
        root = self.make_evidence()
        shards.verify(self.manifest, root, "pr", "glibc", 4)
        self.assertEqual(run.call_count, 100)

    @patch.object(shards.subprocess, "run")
    def test_missing_shard_fails_closed(self, run):
        root = self.make_evidence()
        (root / shards.summary_name(2, 4)).unlink()
        with self.assertRaisesRegex(ValueError, "summary inventory differs"):
            shards.verify(self.manifest, root, "pr", "glibc", 4)
        run.assert_not_called()

    @patch.object(shards.subprocess, "run")
    def test_missing_unit_fails_closed(self, run):
        root = self.make_evidence()
        (root / "compat.unit-005").rmdir()
        with self.assertRaisesRegex(ValueError, "unit inventory differs"):
            shards.verify(self.manifest, root, "pr", "glibc", 4)
        run.assert_not_called()

    @patch.object(shards.subprocess, "run")
    def test_duplicated_or_unexpected_shard_members_fail(self, run):
        root = self.make_evidence()
        path = root / shards.summary_name(0, 4)
        document = json.loads(path.read_text(encoding="utf-8"))
        document["unitIds"][0] = document["unitIds"][1]
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "incomplete summary"):
            shards.verify(self.manifest, root, "pr", "glibc", 4)
        run.assert_not_called()

    @patch.object(shards.subprocess, "run")
    def test_evidence_checker_failure_fails_closed(self, run):
        root = self.make_evidence()
        run.return_value.returncode = 1
        run.return_value.stderr = "invalid hash"
        with self.assertRaisesRegex(ValueError, "invalid strict evidence"):
            shards.verify(self.manifest, root, "pr", "glibc", 4)

    def test_duplicate_registry_identity_fails(self):
        self.rows[10]["unitId"] = self.rows[0]["unitId"]
        self.manifest.write_text(json.dumps({"rows": self.rows}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            shards.required_rows(self.manifest)


if __name__ == "__main__":
    unittest.main()
