#!/usr/bin/env python3
"""Contract tests for the manual-only bionic Node.js closure capture."""

from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture-bionic-node-closure.py"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


SPEC = importlib.util.spec_from_file_location("capture_bionic_node_closure", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load bionic closure capture helper")
CAPTURE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CAPTURE
SPEC.loader.exec_module(CAPTURE)


class BionicNodeClosureTests(unittest.TestCase):
    def test_pinned_inputs_are_read_from_the_two_authoritative_manifests(self) -> None:
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        self.assertEqual(
            inputs["image"],
            "termux/termux-docker@sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4",
        )
        self.assertEqual(inputs["nodeVersion"], "26.4.0-1")
        self.assertEqual(
            inputs["nodeArchiveSha256"],
            "eaf3ed8a6e4b72ebaa8c2cb3bad778c577cdf9ea87ca91761213d8a3940fc090",
        )
        self.assertEqual(inputs["nodeArchiveSizeBytes"], 10349280)
        self.assertEqual(inputs["nodeArchivePath"], "pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb")

    def candidate_document(self) -> dict[str, Any]:
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        package = {
            "name": "nodejs",
            "version": inputs["nodeVersion"],
            "architecture": "aarch64",
            "filename": inputs["nodeArchivePath"],
            "localFilename": "nodejs_26.4.0-1_aarch64.deb",
            "url": "https://packages-cf.termux.dev/apt/termux-main/"
            + inputs["nodeArchivePath"],
            "sizeBytes": inputs["nodeArchiveSizeBytes"],
            "sha256": inputs["nodeArchiveSha256"],
            "dependencies": {"Depends": "libc++"},
        }
        return CAPTURE.build_candidate_document(
            inputs=inputs,
            image_identity={
                "requestedRef": inputs["image"],
                "id": "sha256:" + "0" * 64,
                "os": "linux",
                "architecture": "arm64",
                "repoDigests": [inputs["image"]],
                "created": "2026-01-01T00:00:00Z",
            },
            host_architecture="aarch64",
            docker_server_platform="linux/arm64",
            package_inventory=[
                {
                    "name": "base-package",
                    "version": "1",
                    "architecture": "aarch64",
                    "status": "install ok installed",
                }
            ],
            package_records=[package],
            captured_at="2026-01-01T00:00:00Z",
        )

    def test_candidate_schema_is_metadata_only_and_complete(self) -> None:
        document = self.candidate_document()
        self.assertEqual(CAPTURE.validate_candidate_document(document), [])
        self.assertEqual(document["status"], "candidate-lock")
        self.assertFalse(document["runtimeEvidence"])
        self.assertEqual(document["compatibilityStatus"], "not-established")
        self.assertNotIn("accepted-and-runs", json.dumps(document))
        self.assertFalse(document["resolution"]["archivesIncludedInCandidateJson"])
        self.assertFalse(document["resolution"]["rawNodeBinaryIncluded"])
        self.assertIn("dependencies", document["packages"][0])
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        self.assertEqual(CAPTURE.validate_candidate_against_pins(document, inputs), [])

    def test_candidate_schema_rejects_compatibility_claims_and_missing_dependency_metadata(self) -> None:
        document = self.candidate_document()
        document["runtimeEvidence"] = True
        document["packages"][0].pop("dependencies")
        errors = CAPTURE.validate_candidate_document(document)
        self.assertTrue(any("runtime evidence" in error for error in errors))
        self.assertTrue(any("dependency metadata" in error for error in errors))

    def test_downloaded_package_record_checks_index_size_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "nodejs.deb"
            payload = b"bounded package fixture"
            archive.write_bytes(payload)
            digest = CAPTURE.hashlib.sha256(payload).hexdigest()
            fields = {
                "Package": "nodejs",
                "Version": "26.4.0-1",
                "Architecture": "aarch64",
                "Depends": "libc++",
            }
            index = {
                **fields,
                "Filename": "pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb",
                "Size": str(len(payload)),
                "SHA256": digest,
            }
            record = CAPTURE.build_package_record(
                archive, fields, index, "https://packages-cf.termux.dev/apt/termux-main"
            )
        self.assertEqual(record["name"], "nodejs")
        self.assertEqual(record["dependencies"], {"Depends": "libc++"})
        self.assertEqual(record["url"], "https://packages-cf.termux.dev/apt/termux-main/" + index["Filename"])

        index["SHA256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "nodejs.deb"
            archive.write_bytes(payload)
            with self.assertRaises(CAPTURE.CaptureError):
                CAPTURE.build_package_record(
                    archive, fields, index, "https://packages-cf.termux.dev/apt/termux-main"
                )

    def test_capture_tree_entry_bound_and_deadline_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capture_tree = Path(temporary) / "capture"
            (capture_tree / "debs").mkdir(parents=True)
            for index in range(3):
                (capture_tree / "debs" / f"package-{index}.deb").write_bytes(b"x")
            with patch.object(CAPTURE, "MAX_CAPTURE_ENTRIES", 2):
                with self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE._capture_directory_bytes(capture_tree)

            clock = [0.0]

            def advancing_clock() -> float:
                clock[0] += 1.0
                return clock[0]

            with patch.object(CAPTURE.time, "monotonic", side_effect=advancing_clock):
                with self.assertRaises(CAPTURE.CaptureDeadlineExceeded):
                    CAPTURE._capture_directory_bytes(capture_tree, deadline=2.0)

    def test_package_hash_checks_deadline_between_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "nodejs.deb"
            payload = b"x" * (CAPTURE.SHA256_CHUNK_BYTES * 2 + 1)
            archive.write_bytes(payload)
            real_sha256 = CAPTURE.hashlib.sha256
            expected_sha256 = real_sha256(payload).hexdigest()
            fields = {
                "Package": "nodejs",
                "Version": "26.4.0-1",
                "Architecture": "aarch64",
            }
            index = {
                **fields,
                "Filename": "pool/main/n/nodejs/nodejs_26.4.0-1_aarch64.deb",
                "Size": str(len(payload)),
                "SHA256": expected_sha256,
            }
            clock = [0.0]

            class AdvancingDigest:
                def __init__(self) -> None:
                    self.inner = real_sha256()

                def update(self, block: bytes) -> None:
                    self.inner.update(block)
                    clock[0] = 11.0

                def hexdigest(self) -> str:
                    return self.inner.hexdigest()

            with (
                patch.object(CAPTURE.time, "monotonic", side_effect=lambda: clock[0]),
                patch.object(CAPTURE.hashlib, "sha256", return_value=AdvancingDigest()),
            ):
                with self.assertRaises(CAPTURE.CaptureDeadlineExceeded):
                    CAPTURE.build_package_record(
                        archive,
                        fields,
                        index,
                        "https://packages-cf.termux.dev/apt/termux-main",
                        deadline=10.0,
                    )

    def test_post_capture_expiration_leaves_no_candidate_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_output = Path(temporary) / "candidate.json.tmp"
            output = Path(temporary) / "candidate.json"
            with patch.object(CAPTURE.time, "monotonic", return_value=11.0):
                with self.assertRaises(CAPTURE.CaptureDeadlineExceeded):
                    CAPTURE._publish_candidate_document(
                        temporary_output,
                        output,
                        self.candidate_document(),
                        deadline=10.0,
                    )
            self.assertFalse(output.exists())
            self.assertFalse(temporary_output.exists())

    def test_capture_rejects_expiry_after_container_cleanup_before_publication(self) -> None:
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        image_inspect = {
            "Id": "sha256:" + "0" * 64,
            "Os": "linux",
            "Architecture": "arm64",
            "RepoDigests": [inputs["image"]],
        }
        clock = [0.0]

        def controlled_clock() -> float:
            return clock[0]

        def fake_run(command: list[str], **kwargs: Any) -> tuple[bytes, bytes]:
            if command[1] == "version":
                return b"linux/arm64\n", b""
            if command[1] == "pull":
                return b"", b""
            raise AssertionError(f"unexpected command: {command}")

        def fake_capture(command: list[str], **kwargs: Any) -> None:
            del command, kwargs
            clock[0] = 41.0

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "candidate.json"
            with (
                patch.object(CAPTURE.time, "monotonic", side_effect=controlled_clock),
                patch.object(CAPTURE.shutil, "which", return_value="/usr/bin/tool"),
                patch.object(CAPTURE.platform, "machine", return_value="aarch64"),
                patch.object(CAPTURE, "host_android_context", return_value=False),
                patch.object(CAPTURE, "run_bounded", side_effect=fake_run),
                patch.object(CAPTURE, "_load_image_identity", return_value=image_inspect),
                patch.object(CAPTURE, "_run_capture_with_cleanup", side_effect=fake_capture),
            ):
                with self.assertRaises(CAPTURE.CaptureDeadlineExceeded):
                    CAPTURE.capture(
                        fixture_manifest_path=ROOT / "fixtures/manifest.json",
                        real_sample_manifest_path=ROOT / "fixtures/real-samples/manifest.json",
                        output_path=output,
                        docker_command="docker",
                        timeout_seconds=40,
                    )
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + ".tmp").exists())

    def test_package_inventory_parser_accepts_delimiters_and_rejects_other_controls(self) -> None:
        inventory = CAPTURE.parse_package_inventory(
            "base-package\t1\taarch64\tinstall ok installed\n", "base package inventory"
        )
        self.assertEqual(inventory[0]["name"], "base-package")
        with self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.parse_package_inventory("base-package\t1\taarch64\tbad\x01status\n", "inventory")

    def test_candidate_pin_validation_rejects_a_changed_image_or_node_hash(self) -> None:
        document = self.candidate_document()
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        document["baseImage"]["requestedRef"] = "termux/termux-docker@sha256:" + "f" * 64
        document["packages"][0]["sha256"] = "0" * 64
        errors = CAPTURE.validate_candidate_against_pins(document, inputs)
        self.assertTrue(any("baseImage requestedRef" in error for error in errors))
        self.assertTrue(any("Node.js package sha256" in error for error in errors))

    def test_candidate_document_and_pinned_validation_require_exactly_one_node_package(self) -> None:
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        missing = self.candidate_document()
        missing["packages"] = []
        missing_errors = CAPTURE.validate_candidate_document(missing)
        self.assertTrue(any("exactly one Node.js package record" in error for error in missing_errors))
        self.assertTrue(
            any(
                "exactly one pinned Node.js package record" in error
                for error in CAPTURE.validate_candidate_against_pins(missing, inputs)
            )
        )

        duplicate = self.candidate_document()
        duplicate["packages"].append(dict(duplicate["packages"][0]))
        duplicate_errors = CAPTURE.validate_candidate_document(duplicate)
        self.assertTrue(any("exactly one Node.js package record" in error for error in duplicate_errors))
        self.assertTrue(
            any(
                "exactly one pinned Node.js package record" in error
                for error in CAPTURE.validate_candidate_against_pins(duplicate, inputs)
            )
        )

        wrong_architecture = self.candidate_document()
        wrong_architecture["packages"][0]["architecture"] = "all"
        architecture_errors = CAPTURE.validate_candidate_document(wrong_architecture)
        self.assertTrue(any("Node.js package architecture" in error for error in architecture_errors))
        pinned_architecture_errors = CAPTURE.validate_candidate_against_pins(wrong_architecture, inputs)
        self.assertTrue(any("Node.js package architecture" in error for error in pinned_architecture_errors))

    def test_candidate_package_url_and_filename_metadata_must_agree(self) -> None:
        document = self.candidate_document()
        document["packages"][0]["url"] = "https://packages-cf.termux.dev/apt/termux-main/pool/main/n/nodejs/other.deb"
        errors = CAPTURE.validate_candidate_document(document)
        self.assertTrue(any("URL path must end with its indexed filename" in error for error in errors))
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        pinned_errors = CAPTURE.validate_candidate_against_pins(document, inputs)
        self.assertTrue(any("package url" in error.lower() for error in pinned_errors))

    def test_candidate_image_identity_requires_pinned_digest_id_linux_and_arm64(self) -> None:
        mutations = (
            ("requestedRef", "termux/termux-docker:latest", "requestedRef"),
            ("repoDigests", ["termux/termux-docker@sha256:" + "f" * 64], "repoDigests"),
            ("id", "sha256:" + "0" * 63, "id"),
            ("os", "android", "os"),
            ("architecture", "amd64", "architecture"),
        )
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        for field, value, marker in mutations:
            with self.subTest(field=field):
                document = self.candidate_document()
                document["baseImage"][field] = value
                errors = CAPTURE.validate_candidate_document(document)
                self.assertTrue(any(marker in error for error in errors), errors)
                pinned_errors = CAPTURE.validate_candidate_against_pins(document, inputs)
                self.assertTrue(any(marker in error for error in pinned_errors), pinned_errors)

    def test_bind_mount_capture_repairs_permissions_before_host_cleanup(self) -> None:
        cleanup = CAPTURE._capture_cleanup_script()
        self.assertIn("set -eu", cleanup)
        self.assertNotIn("chown", cleanup)
        self.assertNotIn("|| true", cleanup)
        self.assertIn(
            "find /capture/debs /capture/apt-lists -type d -exec chmod 0777 {} +",
            cleanup,
        )
        self.assertIn("entry-count limit", cleanup)
        capture_script = CAPTURE._container_capture_script()
        self.assertIn("MAX_CAPTURE_ENTRIES", capture_script)
        self.assertIn("trap cleanup_capture_mount 0", capture_script)
        self.assertIn(
            "find /capture/debs /capture/apt-lists -type d -exec chmod 0777 {} +",
            capture_script,
        )
        self.assertNotIn("|| true", capture_script)

    def test_cleanup_mode_validation_preserves_archive_contents_without_chown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capture_tree = Path(temporary) / "capture"
            debs = capture_tree / "debs"
            partial = debs / "partial"
            apt_lists = capture_tree / "apt-lists"
            partial.mkdir(parents=True)
            apt_lists.mkdir()
            archive = debs / "nodejs.deb"
            payload = b"foreign-owned package archive"
            archive.write_bytes(payload)
            expected_hash = CAPTURE.hashlib.sha256(payload).hexdigest()
            for directory in (capture_tree, debs, partial, apt_lists):
                directory.chmod(0o700)

            with self.assertRaises(CAPTURE.CaptureError):
                CAPTURE._capture_directory_bytes(capture_tree, require_removable=True)

            for directory in (capture_tree, debs, partial, apt_lists):
                directory.chmod(0o777)

            self.assertEqual(
                CAPTURE._capture_directory_bytes(capture_tree, require_removable=True),
                len(payload),
            )
            self.assertEqual(CAPTURE.hashlib.sha256(archive.read_bytes()).hexdigest(), expected_hash)
            for directory in (capture_tree, debs, partial, apt_lists):
                self.assertEqual(CAPTURE.stat.S_IMODE(directory.stat().st_mode), 0o777)

    def _run_capture_failure_with_mocked_docker(
        self,
        failure_message: str,
        *,
        repair_failure: bool = False,
        cleanup_validation_failure: bool = False,
        main_failure: bool = True,
    ) -> tuple[list[list[str]], list[bool], Path]:
        if os.geteuid() != 0:
            self.skipTest("foreign-owned bind-mount behavior requires a root-capable test host")
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        calls: list[list[str]] = []
        repair_saw_foreign_owned_directory: list[bool] = []
        repaired_directory: Path | None = None

        def fake_run(command: list[str], **kwargs: Any) -> tuple[bytes, bytes]:
            nonlocal repaired_directory
            command = list(command)
            calls.append(command)
            if command[1] == "version":
                return b"linux/arm64\n", b""
            if command[1] == "pull":
                return b"", b""
            if command[1] == "image":
                return (
                    json.dumps(
                        {
                            "Id": "sha256:" + "0" * 64,
                            "Os": "linux",
                            "Architecture": "arm64",
                            "RepoDigests": [inputs["image"]],
                        }
                    ).encode(),
                    b"",
                )
            if command[1] == "run":
                network = command[command.index("--network") + 1]
                if network == "bridge":
                    capture_directory = Path(
                        next(value.removeprefix("type=bind,src=") for value in command if value.startswith("type=bind,src="))
                    )
                    partial = capture_directory / "debs" / "partial"
                    partial.mkdir(parents=True)
                    if hasattr(os, "chown") and os.geteuid() == 0:
                        os.chown(capture_directory / "debs", 1000, 1000)
                        os.chown(partial, 1000, 1000)
                    partial.chmod(0o700)
                    if main_failure:
                        raise CAPTURE.CaptureError(failure_message)
                    inventory = "base-package\t1\taarch64\tinstall ok installed\n"
                    (capture_directory / "packages-before.tsv").write_text(inventory, encoding="utf-8")
                    (capture_directory / "packages-after.tsv").write_text(inventory, encoding="utf-8")
                    (capture_directory / "apt-update.log").write_text("update\n", encoding="utf-8")
                    (capture_directory / "apt-download.log").write_text("download\n", encoding="utf-8")
                    return b"", b""
                if command[command.index("--user") + 1] != "0:0":
                    raise AssertionError("unexpected non-root cleanup helper")
                repaired_directory = Path(
                    next(value.removeprefix("type=bind,src=") for value in command if value.startswith("type=bind,src="))
                )
                partial = repaired_directory / "debs" / "partial"
                repair_saw_foreign_owned_directory.append(
                    os.geteuid() == 0 and partial.stat().st_uid == 1000
                )
                if repair_failure:
                    raise CAPTURE.CaptureError("permission repair failed")
                if not cleanup_validation_failure:
                    for directory in (repaired_directory, repaired_directory / "debs", partial):
                        directory.chmod(0o777)
                return b"", b""
            if command[1] == "inspect":
                # The package container is still considered running after the
                # mocked Docker client timeout; the cleanup helper has exited.
                return (b"true\n" if "package-capture" in command[-1] else b"false\n"), b""
            if command[1] in {"stop", "wait", "rm"}:
                return b"", b""
            raise AssertionError(f"unexpected mocked command: {command}")

        collector_context = (
            patch.object(CAPTURE, "_collect_package_records", return_value=self.candidate_document()["packages"])
            if not main_failure
            else nullcontext()
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "candidate.json"
            with (
                patch.object(CAPTURE.shutil, "which", return_value="/usr/bin/tool"),
                patch.object(CAPTURE.platform, "machine", return_value="aarch64"),
                patch.object(CAPTURE, "host_android_context", return_value=False),
                patch.object(CAPTURE, "run_bounded", side_effect=fake_run),
                collector_context,
            ):
                with self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE.capture(
                        fixture_manifest_path=ROOT / "fixtures/manifest.json",
                        real_sample_manifest_path=ROOT / "fixtures/real-samples/manifest.json",
                        output_path=output,
                        docker_command="docker",
                        timeout_seconds=40,
                    )
            self.assertFalse(output.exists())
            self.assertFalse((Path(temporary) / "candidate.json.tmp").exists())
            self.assertTrue(repair_saw_foreign_owned_directory)
            if not repair_failure:
                self.assertTrue(repair_saw_foreign_owned_directory[0])
            self.assertIsNotNone(repaired_directory)
        return calls, repair_saw_foreign_owned_directory, output

    def test_capture_nonzero_and_timeout_repair_foreign_owned_partial_before_temp_cleanup(self) -> None:
        for message in (
            "command exited with status 17: docker run: apt failed",
            "command exceeded its 33-second wall-time limit: docker run",
        ):
            with self.subTest(message=message):
                calls, _, _ = self._run_capture_failure_with_mocked_docker(message)
                main_index = next(
                    index for index, command in enumerate(calls)
                    if command[1] == "run" and "bridge" in command
                )
                repair_index = next(
                    index for index, command in enumerate(calls)
                    if command[1] == "run" and "none" in command and "--user" in command
                )
                reap_indexes = [
                    index for index, command in enumerate(calls)
                    if command[1] in {"stop", "wait", "rm"}
                    and "package-capture" in command[-1]
                ]
                self.assertTrue(reap_indexes)
                self.assertLess(main_index, min(reap_indexes))
                self.assertLess(max(reap_indexes), repair_index)
                self.assertNotIn("apt-get", " ".join(calls[repair_index]))

    def test_capture_repair_failure_does_not_publish_candidate(self) -> None:
        calls, _, output = self._run_capture_failure_with_mocked_docker(
            "command exited with status 0: docker run", repair_failure=True, main_failure=False
        )
        self.assertFalse(output.exists())
        repair_commands = [
            command for command in calls if command[1] == "run" and "none" in command and "--user" in command
        ]
        self.assertEqual(len(repair_commands), 1)
        self.assertNotIn("apt-get", " ".join(repair_commands[0]))

    def test_capture_cleanup_validation_failure_does_not_publish_candidate(self) -> None:
        calls, _, output = self._run_capture_failure_with_mocked_docker(
            "cleanup validation failed", cleanup_validation_failure=True, main_failure=False
        )
        self.assertFalse(output.exists())
        repair_commands = [
            command for command in calls if command[1] == "run" and "none" in command and "--user" in command
        ]
        self.assertEqual(len(repair_commands), 1)
        self.assertNotIn("chown", " ".join(repair_commands[0]))

    def test_native_and_image_guards_fail_closed(self) -> None:
        with self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.require_native_environment("x86_64", "linux/arm64", False)
        with self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.require_native_environment("aarch64", "linux/amd64", False)
        with self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.require_native_environment("aarch64", "linux/arm64", True)
        inputs = CAPTURE.load_pinned_inputs(
            ROOT / "fixtures/manifest.json", ROOT / "fixtures/real-samples/manifest.json"
        )
        with self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.inspect_pinned_image(
                {
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RepoDigests": [inputs["image"]],
                    "Id": "sha256:" + "0" * 64,
                },
                inputs,
            )

    def test_manual_capture_script_help_and_candidate_validation_do_not_need_docker(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("candidate-lock", help_result.stdout)
        with tempfile.TemporaryDirectory() as temporary:
            candidate_path = Path(temporary) / "candidate.json"
            candidate_path.write_text(json.dumps(self.candidate_document()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--validate-candidate", str(candidate_path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS candidate-lock metadata schema", result.stdout)

    def test_workflow_capture_is_manual_and_writes_existing_bionic_artifact_root(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("capture_bionic_node_closure:", workflow)
        input_block = workflow.split("capture_bionic_node_closure:", 1)[1].split("run_release_fixtures:", 1)[0]
        self.assertIn("default: false", input_block)
        self.assertIn("type: boolean", input_block)
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && inputs.capture_bionic_node_closure == true",
            workflow,
        )
        self.assertIn("scripts/capture-bionic-node-closure.py", workflow)
        self.assertIn("--validate-candidate", workflow)
        self.assertIn("candidate_root=.artifacts/bionic/c-termux-bionic-pie", workflow)
        self.assertIn('candidate_path="${candidate_root}/nodejs-candidate-lock.json"', workflow)
        self.assertIn("rawArchives=temporary-only-and-removed", workflow)
        self.assertIn("rawNodeBinary=not-captured", workflow)

    def test_nodejs_runner_uses_the_reviewed_locked_path(self) -> None:
        source = (ROOT / "scripts/bionic_node_runner.py").read_text(encoding="utf-8")
        entrypoint = (ROOT / "scripts/run-bionic-node-sample.sh").read_text(encoding="utf-8")
        self.assertIn("--source-archive", source)
        self.assertIn("--outer-mode", source)
        self.assertIn('"$PREFIX/bin/bash" -o pipefail -c', source)
        self.assertIn(
            'dpkg-deb --fsys-tarfile "$archive" |\n  tar --extract --file=- --directory="$stage_dir" '
            "--no-overwrite-dir --no-same-owner --no-same-permissions --touch",
            source,
        )
        self.assertIn('stage_dir="$(mktemp -d /tmp/urprotect-package.XXXXXX)"', source)
        self.assertIn('find "$stage_dir" -mindepth 1 -type d -print0', source)
        self.assertIn('cat -- "$entry" > "$destination"', source)
        self.assertIn('ln -s -- "$target" "$destination"', source)
        self.assertNotIn('--directory=/ --no-overwrite-dir', source)
        self.assertNotIn("dpkg-deb --extract", source)
        self.assertIn('"--network", "none"', source)
        self.assertNotIn("apt-get", source)
        self.assertNotIn("environment-unavailable: bionic Node.js dependency closure is not locked", source)
        self.assertIn("bionic_node_runner.py", entrypoint)
        self.assertIn("containerStatus", source)
        self.assertIn("outputLimitBytes", source)
        self.assertIn("host-generated-after-docker-inspect", source)

    def test_nodejs_runtime_policy_uses_the_reviewed_path_preserving_lock(self) -> None:
        closures = json.loads(
            (ROOT / "fixtures/real-samples/runtime-closures.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (ROOT / "fixtures/real-samples/manifest.json").read_text(encoding="utf-8")
        )
        for layer in ("baseline", "outerWrapper"):
            self.assertEqual(closures["projects"]["nodejs"][layer]["expectedResult"], "accepted-and-runs")
        self.assertEqual(closures["projects"]["nodejs"]["outerWrapper"]["mode"], "outer-path-preserving")
        node = next(project for project in manifest["corpus"]["projects"] if project["projectId"] == "nodejs")
        for layer in ("baseline", "outerWrapper"):
            self.assertEqual(node["executionPolicy"][layer]["expectedResult"], "accepted-and-runs")
        self.assertEqual(node["executionPolicy"]["outerWrapper"]["mode"], "outer-path-preserving")

    def test_matrix_bionic_exit_classification_uses_helper_status_classes(self) -> None:
        matrix = (ROOT / "scripts/run-real-sample-matrix.sh").read_text(encoding="utf-8")
        self.assertIn('125)\n          actual_baseline=environment-unavailable', matrix)
        self.assertIn('124)\n          actual_baseline=runtime-failure', matrix)
        self.assertIn('bionic_preflight_outcome=preflight-runtime-failure', matrix)
        self.assertIn('actual_baseline=unexpected-rejection', matrix)
        self.assertIn("validate_bionic_node_result", matrix)
        self.assertNotIn("without a structured result\"\n      actual_baseline=runtime-failure", matrix)

    def test_shell_entrypoints_remain_syntactically_valid(self) -> None:
        for path in (
            ROOT / "scripts/run-bionic-fixture.sh",
            ROOT / "scripts/run-bionic-node-sample.sh",
            ROOT / "scripts/run-real-sample-matrix.sh",
        ):
            result = subprocess.run(["bash", "-n", str(path)], cwd=ROOT, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
