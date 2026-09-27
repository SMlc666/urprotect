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
    def run_extractor(
        self,
        archive: Path,
        fmt: str,
        destination: Path,
        *,
        apk_package: str = "sample",
        apk_version: str = "1.0-r0",
        apk_origin: str = "sample",
        apk_license: str = "MIT",
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(EXTRACTOR),
            "--archive",
            str(archive),
            "--format",
            fmt,
            "--destination",
            str(destination),
        ]
        if fmt == "apk":
            command.extend(
                [
                    "--expected-apk-package",
                    apk_package,
                    "--expected-apk-version",
                    apk_version,
                    "--expected-apk-architecture",
                    "aarch64",
                    "--expected-apk-origin",
                    apk_origin,
                    "--expected-apk-license",
                    apk_license,
                ]
            )
        return subprocess.run(
            command,
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

    def test_apk_signed_tar_extracts_direct_payload_and_matches_pkginfo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.apk"
            with tarfile.open(archive, "w") as handle:
                signature = tarfile.TarInfo(".SIGN.RSA.test.pub")
                signature_payload = b"locked package signature bytes"
                signature.size = len(signature_payload)
                import io
                handle.addfile(signature, io.BytesIO(signature_payload))

                pkginfo = tarfile.TarInfo(".PKGINFO")
                metadata = (
                    "pkgname = sample\n"
                    "pkgver = 1.0-r0\n"
                    "arch = aarch64\n"
                    "origin = sample\n"
                    "license = MIT\n"
                ).encode()
                pkginfo.size = len(metadata)
                handle.addfile(pkginfo, io.BytesIO(metadata))

                payload = b"apk executable fixture"
                info = tarfile.TarInfo("usr/bin/sample")
                info.mode = 0o755
                info.size = len(payload)
                handle.addfile(info, io.BytesIO(payload))
                link = tarfile.TarInfo("usr/local/bin/sample")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../bin/sample"
                handle.addfile(link)
            output = root / "output"
            result = self.run_extractor(archive, "apk", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / "usr/bin/sample").read_bytes(), b"apk executable fixture")
            self.assertTrue((output / "usr/local/bin/sample").is_symlink())
            self.assertTrue((output / ".PKGINFO").is_file())
            self.assertFalse((output / "data.tar.gz").exists())

    def test_apk_pkginfo_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "mismatch.apk"
            with tarfile.open(archive, "w") as handle:
                metadata = (
                    "pkgname = sample\n"
                    "pkgver = 1.0-r0\n"
                    "arch = x86_64\n"
                    "origin = sample\n"
                    "license = MIT\n"
                ).encode()
                info = tarfile.TarInfo(".PKGINFO")
                info.size = len(metadata)
                import io
                handle.addfile(info, io.BytesIO(metadata))
            result = self.run_extractor(archive, "apk", root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("APK metadata arch mismatch", result.stderr)

    def test_apk_archive_traversal_is_rejected_before_writing_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "traversal.apk"
            with tarfile.open(archive, "w") as handle:
                payload = b"escape"
                info = tarfile.TarInfo("../../escape")
                info.size = len(payload)
                import io
                handle.addfile(info, io.BytesIO(payload))
            result = self.run_extractor(archive, "apk", root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "escape").exists())

    def test_apk_special_file_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "special.apk"
            with tarfile.open(archive, "w") as handle:
                info = tarfile.TarInfo("dev/device")
                info.type = tarfile.CHRTYPE
                info.devmajor = 1
                info.devminor = 3
                handle.addfile(info)
            result = self.run_extractor(archive, "apk", root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "output/dev/device").exists())

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
