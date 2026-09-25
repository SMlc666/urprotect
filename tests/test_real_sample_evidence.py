#!/usr/bin/env python3
"""Evidence-gate regressions without acquiring real samples."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures/real-samples/manifest.json"
CANDIDATES = ROOT / "fixtures/real-samples/candidates.json"
GATE = ROOT / "scripts/check-real-sample-evidence.py"


class RealSampleEvidenceTests(unittest.TestCase):
    def run_gate(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(GATE), str(MANIFEST), "--candidates", str(CANDIDATES), "--tier", "pr", "--artifact-root", str(root)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def write_complete_text_evidence(self, root: Path) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for project in manifest["corpus"]["projects"]:
            project_root = root / project["projectId"]
            (project_root / "logs").mkdir(parents=True)
            expected = {
                layer: project["executionPolicy"][layer]["expectedResult"]
                for layer in ("static", "baseline", "outerWrapper", "hostContext")
            }
            result = {
                "schemaVersion": 2,
                "tier": "pr",
                "projectId": project["projectId"],
                "artifactSha256": "",
                "firstFailureLayer": None,
                "layers": {
                    layer: {
                        "expected": status,
                        "actual": status,
                        "status": "passed",
                        "reason": "contract test evidence",
                    }
                    for layer, status in expected.items()
                },
            }
            (project_root / "source.txt").write_text("source metadata\n", encoding="utf-8")
            (project_root / "hashes.txt").write_text("hash metadata\n", encoding="utf-8")
            (project_root / "environment.txt").write_text("network=none\n", encoding="utf-8")
            (project_root / "elf-fingerprint.json").write_text(
                json.dumps({
                    "schemaVersion": 2,
                    "projectId": project["projectId"],
                    "error": "metadata-only contract fixture",
                    "unknownFields": ["all"],
                }) + "\n",
                encoding="utf-8",
            )
            (project_root / "fingerprint-comparison.json").write_text(
                json.dumps({
                    "schemaVersion": 2,
                    "projectId": project["projectId"],
                    "status": "not-applicable",
                }) + "\n",
                encoding="utf-8",
            )
            (project_root / "readelf.txt").write_text("readelf evidence\n", encoding="utf-8")
            (project_root / "urprotect-report.json").write_text("{}\n", encoding="utf-8")
            (project_root / "result.json").write_text(json.dumps(result) + "\n", encoding="utf-8")
            (project_root / "raw-inputs-removed.txt").write_text(
                "raw-inputs-removed=true\n", encoding="utf-8"
            )
            (project_root / "logs" / "run.log").write_text("run evidence\n", encoding="utf-8")
        ids = [project["projectId"] for project in manifest["corpus"]["projects"]]
        aggregate = {
            "schemaVersion": 2,
            "tier": "pr",
            "requiredProjectCount": 20,
            "observedProjectCount": 20,
            "identityCount": 20,
            "projectIds": ids,
            "coverage": {
                "approvedTargetProjectCount": 100,
                "currentIdentityCount": 20,
                "shortfall": 80,
            },
            "featureHistogram": [],
            "firstFailureLayers": {},
        }
        (root / "aggregate.json").write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
        (root / "aggregate.md").write_text("# aggregate\n", encoding="utf-8")

    def test_missing_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_gate(Path(directory) / "missing")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact root", result.stderr)

    def test_complete_metadata_only_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checked 20 projects", result.stdout)

    def test_raw_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            (root / "gnu-bash" / "source.deb").write_text("not a real archive", encoding="utf-8")
            result = self.run_gate(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw sample/archive-like", result.stderr)


if __name__ == "__main__":
    unittest.main()
