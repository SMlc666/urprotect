#!/usr/bin/env python3
"""Contract tests for the manual-only bionic Node.js closure capture."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from typing import Any

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

    def test_nodejs_runner_remains_fail_closed_until_a_lock_is_reviewed(self) -> None:
        result = subprocess.run(
            [
                str(ROOT / "scripts/run-bionic-node-sample.sh"),
                "--input",
                "TARGET",
                "--artifact-root",
                "/tmp/urprotect-bionic-node-test",
                "--image",
                "TARGET",
                "--version",
                "TARGET",
                "--sha256",
                "0" * 64,
                "--archive-sha256",
                "0" * 64,
                "--launcher",
                "TARGET",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 125)
        self.assertIn("environment-unavailable", result.stderr)

    def test_nodejs_runtime_policy_remains_environment_unavailable(self) -> None:
        closures = json.loads(
            (ROOT / "fixtures/real-samples/runtime-closures.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (ROOT / "fixtures/real-samples/manifest.json").read_text(encoding="utf-8")
        )
        for layer in ("baseline", "outerWrapper"):
            self.assertEqual(closures["projects"]["nodejs"][layer]["expectedResult"], "environment-unavailable")
        node = next(project for project in manifest["corpus"]["projects"] if project["projectId"] == "nodejs")
        for layer in ("baseline", "outerWrapper"):
            self.assertEqual(node["executionPolicy"][layer]["expectedResult"], "environment-unavailable")

    def test_shell_entrypoints_remain_syntactically_valid(self) -> None:
        for path in (ROOT / "scripts/run-bionic-fixture.sh", ROOT / "scripts/run-bionic-node-sample.sh"):
            result = subprocess.run(["bash", "-n", str(path)], cwd=ROOT, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
