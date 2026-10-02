#!/usr/bin/env python3
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


BUILDER_SPEC = importlib.util.spec_from_file_location(
    "build_runtime_closure", ROOT / "scripts/build-runtime-closure.py"
)
assert BUILDER_SPEC is not None and BUILDER_SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(BUILDER_SPEC)
BUILDER_SPEC.loader.exec_module(BUILDER)


class RuntimeClosureContractTests(unittest.TestCase):
    def test_locked_closure_covers_all_three_runtimes_and_registry(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/validate-runtime-closures.py"),
                str(ROOT / "fixtures/real-samples/runtime-closures.json"),
                str(ROOT / "fixtures/real-samples/manifest.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_default_policy_requires_baseline_and_outer_execution(self) -> None:
        closure = json.loads(
            (ROOT / "fixtures/real-samples/runtime-closures.json").read_text()
        )
        default = closure["projects"]["*"]
        self.assertEqual(default["baseline"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(default["outerWrapper"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(default["outerWrapper"]["mode"], "outer-execveat")


    def test_project_policy_inclusions_are_resolved_and_retained(self) -> None:
        closure = {
            "projects": {
                "*": {"includePackages": [{"package": "base", "reason": "default"}]},
                "sample": {
                    "includePackages": [
                        {"package": "locales-all", "reason": "UTF-8 oracle"}
                    ]
                },
            }
        }
        project = {"projectId": "sample"}
        policy = BUILDER.closure_project_policy(closure, project)
        self.assertEqual(
            BUILDER.policy_package_entries(policy, "includePackages"),
            [{"package": "locales-all", "reason": "UTF-8 oracle"}],
        )
        self.assertEqual(
            BUILDER.policy_package_entries(
                BUILDER.closure_project_policy(closure, {"projectId": "other"}),
                "includePackages",
            ),
            [{"package": "base", "reason": "default"}],
        )
        with self.assertRaises(SystemExit):
            BUILDER.policy_package_entries(
                {"includePackages": [{"package": "bad name"}]}, "includePackages"
            )

    def test_tmux_policy_locks_utf8_locale_and_zero_status_witness(self) -> None:
        closure = json.loads(
            (ROOT / "fixtures/real-samples/runtime-closures.json").read_text()
        )
        tmux = closure["projects"]["tmux"]
        self.assertEqual(tmux["baseline"]["command"], ["/usr/bin/tmux", "-V"])
        self.assertEqual(
            [entry["package"] for entry in tmux["includePackages"]], ["locales-all"]
        )

    def test_debian_include_package_enters_selected_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = {
                name: {
                    "Package": name,
                    "Filename": f"pool/main/{name}.deb",
                    "SHA256": "0" * 64,
                    "Size": "1",
                    "Architecture": "arm64",
                    "Depends": "",
                }
                for name in ("tmux", "libc6", "locales-all")
            }
            args = SimpleNamespace(
                closure={
                    "projects": {
                        "tmux": {
                            "includePackages": [
                                {"package": "locales-all", "reason": "UTF-8 oracle"}
                            ]
                        }
                    }
                },
                index_dir=root / "index",
                work_root=root / "work",
                rootfs=root / "rootfs",
                package_cache=None,
            )
            runtime = {
                "packageIndexUrl": "https://example.invalid/Packages.xz",
                "packageIndexSha256": "0" * 64,
                "repositoryRoot": "https://example.invalid/",
            }
            project = {
                "projectId": "tmux",
                "provenance": {"archivePath": "pool/main/tmux.deb"},
            }

            def fake_acquire(*_arguments: object, **_keywords: object) -> Path:
                destination = _arguments[1]
                assert isinstance(destination, Path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"x")
                return destination

            with (
                patch.object(BUILDER, "download"),
                patch.object(
                    BUILDER,
                    "parse_debian_index",
                    return_value=(records, {records["tmux"]["Filename"]: records["tmux"]}, {}),
                ),
                patch.object(BUILDER, "acquire_package", side_effect=fake_acquire),
                patch.object(BUILDER.subprocess, "run"),
            ):
                lock = BUILDER.build_debian(args, runtime, project)

            self.assertEqual(
                {package["name"] for package in lock["packages"]},
                {"tmux", "libc6", "locales-all"},
            )
            self.assertEqual(
                lock["policyIncludes"],
                [{"package": "locales-all", "reason": "UTF-8 oracle"}],
            )


class RuntimePackageCacheTests(unittest.TestCase):
    def test_apk_index_parser_handles_signed_concatenated_gzip_members(self) -> None:
        def tar_bytes(entries: dict[str, bytes]) -> bytes:
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:") as tar:
                for name, value in entries.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(value)
                    tar.addfile(info, io.BytesIO(value))
            return output.getvalue()

        index_record = (
            b"P:demo\nV:1-r0\nA:aarch64\nS:7\nC:Q1"
            + base64.b64encode(bytes(range(20)))
            + b"\n\n"
        )
        signed_tar = tar_bytes({".SIGN": b"signature"})[:1024]
        package = gzip.compress(signed_tar) + gzip.compress(
            tar_bytes({"DESCRIPTION": b"index", "APKINDEX": index_record})
        )
        with tempfile.TemporaryDirectory() as temporary:
            index = Path(temporary) / "APKINDEX.tar.gz"
            index.write_bytes(package)
            by_name, providers = BUILDER.parse_apk_index(index)
            self.assertEqual(by_name["demo"]["S"], "7")
            self.assertIs(providers["demo"], by_name["demo"])

    def test_apk_c_checksum_uses_the_control_gzip_member(self) -> None:
        signature = gzip.compress(b"signature tar bytes")
        control = gzip.compress(b"control tar bytes")
        package = signature + control + gzip.compress(b"data tar bytes")
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "sample.apk"
            archive.write_bytes(package)
            expected = hashlib.sha1(control).hexdigest()
            self.assertEqual(BUILDER.apk_identity_digest(archive, "sha1"), expected)
            BUILDER.verify_package(archive, "sample", "apk-sha1", expected, len(package))
            tampered = bytearray(package)
            tampered[len(signature) + 10] ^= 1
            archive.write_bytes(tampered)
            with self.assertRaises(SystemExit):
                BUILDER.verify_package(archive, "sample", "apk-sha1", expected, len(package))

    def test_apk_c_checksum_accepts_apk_tools_encodings_only(self) -> None:
        digest = bytes(range(20))
        q1 = "Q1" + base64.b64encode(digest).decode()
        self.assertEqual(
            BUILDER.normalize_apk_checksum(q1, "sample"),
            ("sha1", digest.hex()),
        )
        self.assertEqual(
            BUILDER.normalize_apk_checksum("X1" + digest.hex(), "sample"),
            ("sha1", digest.hex()),
        )
        self.assertEqual(
            BUILDER.normalize_apk_checksum(
                "0123456789abcdef0123456789abcdef", "sample"
            ),
            ("md5", "0123456789abcdef0123456789abcdef"),
        )
        for value in (
            "Q2" + base64.b64encode(bytes(range(32))).decode(),
            "0123456789abcdef0123456789abcdef0123456789",
            "Q1not-a-checksum",
        ):
            with self.assertRaises(SystemExit):
                BUILDER.normalize_apk_checksum(value, "sample")

    def test_archive_absolute_links_are_root_relative_and_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "links.tar.gz"
            output = root / "extract"
            outside = root / "outside"
            outside.mkdir()
            with tarfile.open(archive, mode="w:gz") as tar:
                link = tarfile.TarInfo("link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/inside"
                tar.addfile(link)
            BUILDER.safe_extract_tar(archive, output, apk=True)
            self.assertEqual(os.readlink(output / "link"), "inside")

            unsafe_archive = root / "unsafe-links.tar.gz"
            with tarfile.open(unsafe_archive, mode="w:gz") as tar:
                link = tarfile.TarInfo("link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/inside"
                tar.addfile(link)
                payload = b"inside only"
                member = tarfile.TarInfo("link/payload")
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
            with self.assertRaises(SystemExit):
                BUILDER.safe_extract_tar(unsafe_archive, root / "unsafe-output", apk=True)
            self.assertFalse((outside / "payload").exists())

    def test_package_expectation_requires_locked_sizes(self) -> None:
        digest = "Q1" + base64.b64encode(bytes(range(20))).decode()
        self.assertEqual(
            BUILDER.package_expectation(
                "musl", {"C": digest, "S": "123"}, "sample"
            ),
            ("apk-sha1", bytes(range(20)).hex(), 123),
        )
        with self.assertRaises(SystemExit):
            BUILDER.package_expectation("musl", {"C": digest, "S": "0"}, "sample")
        with self.assertRaises(SystemExit):
            BUILDER.package_expectation(
                "glibc", {"SHA256": "0" * 64, "Size": "not-a-size"}, "sample"
            )

    def test_download_streams_and_repairs_a_digest_mismatch(self) -> None:
        payload = b"streamed package archive" * 1024
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(payload)
            destination = root / "indexes" / "index"
            BUILDER.download(source.as_uri(), destination, digest, max_bytes=len(payload))
            self.assertEqual(destination.read_bytes(), payload)
            destination.write_bytes(b"tampered")
            BUILDER.download(source.as_uri(), destination, digest, max_bytes=len(payload))
            self.assertEqual(destination.read_bytes(), payload)
            with self.assertRaises(SystemExit):
                BUILDER.download(source.as_uri(), root / "too-small", digest, max_bytes=1)

    def test_package_cache_rejects_symlink_entries(self) -> None:
        payload = b"locked package archive\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.deb"
            source.write_bytes(payload)
            cache = root / "cache"
            _, cached = BUILDER.package_cache_path(
                cache, "demo-package", "demo.deb", "sha256", digest
            )
            cached.parent.mkdir(parents=True)
            cached.symlink_to(source)
            with self.assertRaises(SystemExit):
                BUILDER.acquire_package(
                    source.as_uri(),
                    root / "sample" / "work.deb",
                    cache,
                    "demo-package",
                    "demo.deb",
                    "sha256",
                    digest,
                    len(payload),
                )

    def test_cache_reuses_verified_archive_and_repairs_tampering(self) -> None:
        payload = b"locked package archive\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.deb"
            source.write_bytes(payload)
            cache = root / "cache"
            destination = root / "sample" / "work.deb"
            cached = BUILDER.acquire_package(
                source.as_uri(),
                destination,
                cache,
                "demo-package",
                "../demo-package.deb",
                "sha256",
                digest,
                len(payload),
            )
            self.assertTrue(cached.is_file())
            self.assertTrue(cache in cached.parents)
            cached.write_bytes(b"tampered")
            repaired = BUILDER.acquire_package(
                source.as_uri(),
                destination,
                cache,
                "demo-package",
                "../demo-package.deb",
                "sha256",
                digest,
                len(payload),
            )
            self.assertEqual(repaired, cached)
            self.assertEqual(repaired.read_bytes(), payload)
            source.unlink()
            self.assertEqual(
                BUILDER.acquire_package(
                    source.as_uri(),
                    destination,
                    cache,
                    "demo-package",
                    "../demo-package.deb",
                    "sha256",
                    digest,
                    len(payload),
                ).read_bytes(),
                payload,
            )


if __name__ == "__main__":
    unittest.main()
