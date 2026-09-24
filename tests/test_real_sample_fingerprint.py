#!/usr/bin/env python3
"""Regression tests for the locked-vs-observed real-sample fingerprint."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures/real-samples/manifest.json"
COMPARE = ROOT / "scripts/compare-real-sample-fingerprint.py"


class RealSampleFingerprintTests(unittest.TestCase):
    def run_compare(self, fingerprint: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "fingerprint.json"
            output_path = root / "comparison.json"
            input_path.write_text(json.dumps(fingerprint), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(COMPARE),
                    "--manifest",
                    str(MANIFEST),
                    "--project-id",
                    "gnu-bash",
                    "--fingerprint",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_readelf_dyn_alias_matches_locked_et_dyn(self) -> None:
        result = self.run_compare(
            {
                "elfClass": "ELF64",
                "data": "2's complement, little endian",
                "machine": "AArch64",
                "type": "DYN",
                "interpreter": "/lib/ld-linux-aarch64.so.1",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_interpreter_mismatch_fails_closed(self) -> None:
        result = self.run_compare(
            {
                "elfClass": "ELF64",
                "data": "2's complement, little endian",
                "machine": "AArch64",
                "type": "DYN",
                "interpreter": "/TARGET/loader",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interpreter", result.stderr)


if __name__ == "__main__":
    unittest.main()
