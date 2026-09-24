#!/usr/bin/env python3
"""Archive extraction regressions for the CI-only real-sample boundary."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
EXTRACTOR = ROOT / "scripts/extract-real-sample.py"


class RealSampleExtractionTests(unittest.TestCase):
    def run_extractor(self, archive: Path, fmt: str, destination: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(EXTRACTOR), "--archive", str(archive), "--format", fmt, "--destination", str(destination)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_safe_in_root_symlink_is_preserved_without_resolution_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            (source / "bin").mkdir(parents=True)
            (source / "bin" / "sample").write_text("sample", encoding="utf-8")
            (source / "bin" / "link").symlink_to("/bin/sample")
            archive = root / "sample.tar"
            with tarfile.open(archive, "w") as handle:
                handle.add(source, arcname=".")
            output = root / "output"
            result = self.run_extractor(archive, "tar", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output / "bin" / "sample").is_file())
            self.assertTrue((output / "bin" / "link").is_symlink())
            self.assertEqual((output / "bin" / "link").readlink(), Path("/bin/sample"))

    def test_parent_traversal_is_rejected_before_writing_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "escape"
            archive = root / "traversal.tar"
            with tarfile.open(archive, "w") as handle:
                info = tarfile.TarInfo("../escape")
                payload = b"escape"
                info.size = len(payload)
                import io
                handle.addfile(info, io.BytesIO(payload))
            result = self.run_extractor(archive, "tar", root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(outside.exists())

    def test_symlink_parent_cannot_be_used_for_archive_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "outside").mkdir()
            (source / "outside" / "sample").write_text("sample", encoding="utf-8")
            (source / "pivot").symlink_to("outside")
            archive = root / "pivot.tar"
            with tarfile.open(archive, "w") as handle:
                handle.add(source, arcname=".", recursive=False)
                link = tarfile.TarInfo("pivot")
                link.type = tarfile.SYMTYPE
                link.linkname = "outside"
                handle.addfile(link)
                info = tarfile.TarInfo("pivot/sample")
                payload = b"sample"
                info.size = len(payload)
                import io
                handle.addfile(info, io.BytesIO(payload))
            result = self.run_extractor(archive, "tar", root / "output")
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
