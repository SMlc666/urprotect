#!/usr/bin/env python3
"""Offline contracts for strict corpus within-shard concurrency and evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "run_strict_compatibility_corpus",
    ROOT / "scripts/run_strict_compatibility_corpus.py",
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class StrictCorpusRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.manifest = root / "manifest.json"
        self.artifacts = root / "artifacts"
        self.rows = [
            {
                "unitId": f"compat.fixture-{index:03d}",
                "sourceProvenance": f"fixtures/samples/compatibility-100x/unit-{index:03d}.c",
                "required": True,
                "applicable": True,
            }
            for index in range(6)
        ]
        self.manifest.write_text(json.dumps({"rows": self.rows}), encoding="utf-8")
        self.options = {
            "tier": "pr",
            "runtime": "glibc",
            "shard_index": 0,
            "shard_count": 2,
            "workers": 2,
            "skip_existing": False,
            "manifest": self.manifest,
            "artifact_root": self.artifacts,
            "env": {"PATH": "/usr/bin", "DOTNET_ROOT": "/opt/dotnet"},
        }

    @patch.object(runner, "prepare_parallel_runtime")
    @patch.object(runner, "run_unit")
    def test_parallel_shard_covers_only_owned_units(self, run_unit, prepare):
        run_unit.side_effect = lambda row, **kwargs: (row[0], True, "")
        self.assertEqual(runner.execute(**self.options), 0)
        summary = json.loads(
            (self.artifacts / "strict-corpus-summary-shard-0-of-2.json").read_text()
        )
        self.assertEqual(summary["unitIds"], [
            "compat.fixture-000", "compat.fixture-002", "compat.fixture-004"
        ])
        self.assertEqual(summary["completedRows"], 3)
        self.assertEqual(summary["failedRows"], 0)
        self.assertEqual(run_unit.call_count, 3)
        prepare.assert_called_once()

    @patch.object(runner, "prepare_parallel_runtime")
    @patch.object(runner, "run_unit")
    def test_worker_failure_does_not_drop_remaining_samples(self, run_unit, prepare):
        run_unit.side_effect = lambda row, **kwargs: (
            row[0], row[0] != "compat.fixture-002", ""
        )
        self.assertEqual(runner.execute(**self.options), 1)
        summary = json.loads(
            (self.artifacts / "strict-corpus-summary-shard-0-of-2.json").read_text()
        )
        self.assertEqual(summary["completedRows"], 2)
        self.assertEqual(summary["failedRows"], 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(run_unit.call_count, 3)

    @patch.object(runner, "prepare_parallel_runtime")
    @patch.object(runner, "run_unit")
    def test_worker_exception_is_recorded_not_ignored(self, run_unit, prepare):
        def simulate(row, **kwargs):
            if row[0] == "compat.fixture-000":
                raise RuntimeError("simulated child failure")
            return row[0], True, ""
        run_unit.side_effect = simulate
        self.assertEqual(runner.execute(**self.options), 1)
        summary = json.loads(
            (self.artifacts / "strict-corpus-summary-shard-0-of-2.json").read_text()
        )
        self.assertEqual(summary["failedRows"], 1)

    @patch.object(runner, "prepare_parallel_runtime")
    @patch.object(runner, "run_unit")
    def test_two_workers_actually_overlap(self, run_unit, prepare):
        barrier = threading.Barrier(2, timeout=3)
        visits = []
        lock = threading.Lock()

        def simulate(row, **kwargs):
            with lock:
                visits.append(row[0])
            if len(visits) < 3:
                barrier.wait()
            return row[0], True, ""

        # Both first two tasks must overlap to cross the barrier.
        run_unit.side_effect = simulate
        self.assertEqual(runner.execute(**self.options), 0)
        self.assertEqual(len(visits), 3)

    @patch.object(runner, "prepare_parallel_runtime")
    @patch.object(runner, "run_unit")
    def test_serial_mode_does_not_prebuild(self, run_unit, prepare):
        options = dict(self.options, workers=1, shard_index=None, shard_count=None)
        run_unit.side_effect = lambda row, **kwargs: (row[0], True, "")
        self.assertEqual(runner.execute(**options), 0)
        self.assertEqual(run_unit.call_count, 6)
        prepare.assert_not_called()
        self.assertTrue((self.artifacts / "strict-corpus-summary.json").is_file())

    @patch.object(runner.subprocess, "run")
    def test_run_unit_uses_isolated_artifact_root(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "PASS"
        run.return_value.stderr = ""
        row = ("compat.fixture-000", "fixtures/samples/compatibility-100x/unit-000.c")
        unit, passed, detail = runner.run_unit(
            row, tier="pr", runtime="glibc", artifact_root=self.artifacts,
            env={"PATH": "/usr/bin", "URPROTECT_PREBUILT_CLI": "1"},
            skip_existing=False,
        )
        self.assertTrue(passed)
        self.assertEqual(unit, row[0])
        self.assertEqual(detail, "PASS")
        self.assertEqual(
            run.call_args.kwargs["env"]["PROTECTED_IMAGE_ARTIFACT_ROOT"],
            str(self.artifacts / row[0]),
        )

    def test_partial_shard_args_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "both shard"):
            runner.execute(**dict(self.options, shard_count=None))

    def test_worker_limit_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 8"):
            runner.execute(**dict(self.options, workers=9))


if __name__ == "__main__":
    unittest.main()
