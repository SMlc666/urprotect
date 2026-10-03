#!/usr/bin/env python3
"""Focused contract tests for the reviewed bionic Node.js runtime lock."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "fixtures/real-samples/bionic-node-runtime-lock.json"
MANIFEST = ROOT / "fixtures/real-samples/manifest.json"
CLOSURES = ROOT / "fixtures/real-samples/runtime-closures.json"
RUNNER = ROOT / "scripts/run-bionic-node-sample.sh"
VALIDATOR = ROOT / "scripts/validate-bionic-node-lock.py"
SCHEMA = ROOT / "scripts/real_sample_schema.py"


def load_lock_module():
    spec = importlib.util.spec_from_file_location("bionic_node_lock", ROOT / "scripts/bionic_node_lock.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load bionic lock validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BionicNodeRuntimeLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads(LOCK.read_text(encoding="utf-8"))
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.module = load_lock_module()

    def test_reviewed_lock_validates_and_retains_candidate_provenance(self) -> None:
        self.assertEqual(
            self.module.validate_lock_document(self.lock, manifest=self.manifest), []
        )
        provenance = self.lock["candidateProvenance"]
        self.assertEqual(provenance["workflowRunId"], 37105636258)
        self.assertEqual(
            provenance["artifactSha256"],
            "ccd8022aef3671e4d0f33d9756adfbabd12bb057b1735732246887a155562f53",
        )
        self.assertEqual(provenance["status"], "candidate-lock")
        self.assertFalse(provenance["runtimeEvidence"])
        self.assertEqual(self.lock["compatibilityStatus"], "not-established")
        self.assertFalse(self.lock["runtimeEvidence"])

    def test_runtime_closure_anchors_the_reviewed_lock_digest(self) -> None:
        closures = json.loads(CLOSURES.read_text(encoding="utf-8"))
        bionic = closures["runtimes"]["bionic"]
        self.assertEqual(
            bionic["nodejsLockSha256"],
            self.module.lock_file_sha256(LOCK),
        )
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(LOCK), "--manifest", str(MANIFEST), "--expected-sha256", bionic["nodejsLockSha256"]],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_runtime_closure_identity_is_bound_to_the_reviewed_lock(self) -> None:
        for field, value in (
            ("image", "termux/termux-docker:latest"),
            ("imageId", "sha256:" + "0" * 64),
            ("loader", "/system/bin/other-linker"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                closure = json.loads(CLOSURES.read_text(encoding="utf-8"))
                closure["runtimes"]["bionic"][field] = value
                path = Path(directory) / "runtime-closures.json"
                path.write_text(json.dumps(closure), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/validate-runtime-closures.py"), str(path), str(MANIFEST)],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr)

    def test_changed_package_hash_url_size_architecture_and_dependency_fail(self) -> None:
        mutations = (
            ("sha256", "0" * 64, "package nodejs sha256"),
            ("url", "https://packages-cf.termux.dev/apt/termux-main/other.deb", "package nodejs url"),
            ("sizeBytes", 1, "package nodejs sizeBytes"),
            ("architecture", "amd64", "package nodejs architecture"),
        )
        for field, value, marker in mutations:
            with self.subTest(field=field):
                document = copy.deepcopy(self.lock)
                node = next(item for item in document["packages"] if item["name"] == "nodejs")
                node[field] = value
                errors = self.module.validate_lock_document(document, manifest=self.manifest)
                self.assertTrue(any(marker in error for error in errors), errors)

        document = copy.deepcopy(self.lock)
        node = next(item for item in document["packages"] if item["name"] == "nodejs")
        node["dependencies"]["Depends"] = "libc++ | ${unsupported:subst}"
        errors = self.module.validate_lock_document(document, manifest=self.manifest)
        self.assertTrue(any("unsupported dependency syntax" in error for error in errors), errors)

        wrong_runpath = copy.deepcopy(self.lock)
        wrong_runpath["execution"]["runpath"] = "$ORIGIN/../lib"
        runpath_errors = self.module.validate_lock_document(wrong_runpath, manifest=self.manifest)
        self.assertTrue(any("execution runpath" in error for error in runpath_errors), runpath_errors)

        wrong_artifact = copy.deepcopy(self.manifest)
        project = next(item for item in wrong_artifact["corpus"]["projects"] if item["projectId"] == "nodejs")
        project["provenance"]["artifactPath"] = "data/data/com.termux/files/usr/bin/other"
        artifact_errors = self.module.validate_lock_document(self.lock, manifest=wrong_artifact)
        self.assertTrue(any("manifest Node.js artifactPath" in error for error in artifact_errors), artifact_errors)

    def test_missing_base_provider_fails_the_depends_closure(self) -> None:
        document = copy.deepcopy(self.lock)
        document["basePackageInventory"]["packages"] = [
            package
            for package in document["basePackageInventory"]["packages"]
            if package["name"] != "libffi"
        ]
        document["basePackageInventory"]["count"] = 85
        document["basePackageInventory"]["sha256"] = self.module.inventory_sha256(document["basePackageInventory"]["packages"])
        errors = self.module.validate_lock_document(document, manifest=self.manifest)
        self.assertTrue(any("no locked provider for libffi" in error for error in errors), errors)

    def test_runner_uses_direct_archives_and_data_only_extraction(self) -> None:
        source = (ROOT / "scripts/bionic_node_runner.py").read_text(encoding="utf-8")
        entrypoint = RUNNER.read_text(encoding="utf-8")
        self.assertIn("--source-archive", source)
        self.assertIn("--max-filesize", source)
        self.assertIn("dpkg-deb --extract", source)
        self.assertIn('"--network", "none"', source)
        self.assertIn('"--user", "1000:1000"', source)
        self.assertIn("outer-path-preserving", source)
        self.assertIn("behaviorEquivalent", source)
        self.assertIn('"baseline"', source)
        self.assertIn('"outer"', source)
        self.assertNotIn("apt-get", source)
        self.assertNotIn("dpkg -i", source)
        self.assertIn("_reap_container", source)
        self.assertIn('"stop", "--time", "1"', source)
        self.assertIn('"wait"', source)
        self.assertIn('"rm", "--force"', source)
        self.assertIn("bionic_node_runner.py", entrypoint)
        self.assertNotIn("/artifacts", source)

    def test_capture_and_replay_use_the_same_canonical_package_query(self) -> None:
        capture = (ROOT / "scripts/capture-bionic-node-closure.py").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/bionic_node_runner.py").read_text(encoding="utf-8")
        self.assertIn("${Package}", capture)
        self.assertIn("${Package}", runner)
        self.assertIn("${Architecture}", capture)
        self.assertIn("${Architecture}", runner)
        self.assertNotIn("${binary:Package}", capture)
        self.assertNotIn("${binary:Package}", runner)

    def test_locked_argv_hash_and_policy_gate_align_with_the_manifest(self) -> None:
        execution = self.lock["execution"]
        self.assertEqual(execution["argv"], [execution["artifactPath"], "--version"])
        self.assertEqual(execution["loader"], "/system/bin/linker64")
        self.assertEqual(execution["ldLibraryPath"], "/data/data/com.termux/files/usr/lib")
        self.assertEqual(execution["environment"], {
            "PATH": "/data/data/com.termux/files/usr/bin:/system/bin:/usr/bin",
            "HOME": "/tmp",
            "LD_LIBRARY_PATH": "/data/data/com.termux/files/usr/lib",
        })
        self.assertEqual(execution["shell"], "/data/data/com.termux/files/usr/bin/sh")
        self.assertEqual(execution["outerMode"], "outer-path-preserving")
        self.assertEqual(execution["expectedStatus"], 0)
        self.assertEqual(execution["runpath"], "/data/data/com.termux/files/usr/lib")
        node = next(project for project in self.manifest["corpus"]["projects"] if project["projectId"] == "nodejs")
        self.assertEqual(node["executionPolicy"]["baseline"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(node["executionPolicy"]["outerWrapper"]["expectedResult"], "accepted-and-runs")
        self.assertEqual(node["executionPolicy"]["outerWrapper"]["mode"], "outer-path-preserving")
        changed_manifest = copy.deepcopy(self.manifest)
        changed_node = next(item for item in changed_manifest["corpus"]["projects"] if item["projectId"] == "nodejs")
        changed_node["executionPolicy"]["isolation"]["outputBytes"] += 1
        errors = self.module.validate_lock_document(self.lock, manifest=changed_manifest)
        self.assertTrue(any("isolation outputBytes" in error for error in errors), errors)

    def test_schema_accepts_real_bionic_container_protocol(self) -> None:
        spec = importlib.util.spec_from_file_location("real_sample_schema", SCHEMA)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        schema = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = schema
        spec.loader.exec_module(schema)
        value = {
            "schemaVersion": 2,
            "producer": "run-bionic-node-sample.sh",
            "runtime": "bionic",
            "attempted": True,
            "helperStatus": None,
            "targetStatus": 0,
            "readinessSeen": True,
            "outcome": "target-exit",
            "containerStatus": 0,
            "dockerStatus": 0,
            "cleanupContainerStatus": 0,
            "timeoutSeconds": 30,
            "outputLimitBytes": 1048576,
            "outputBytes": 8,
            "memoryBytes": 536870912,
            "processLimit": 32,
            "lockSha256": self.module.lock_file_sha256(LOCK),
            "pathMode": "outer-path-preserving",
            "pathPolicy": "absolute-dt-runpath-preserved",
            "runpath": "/data/data/com.termux/files/usr/lib",
            "runpathVerified": True,
            "protocolAuthority": "host-generated-after-docker-inspect",
            "cleanupAuthority": "host-generated-after-docker-inspect",
            "allNamedContainersReaped": True,
        }
        self.assertEqual(schema.validate_isolation_result(value), [])

    def test_lock_cli_rejects_changed_lock_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            document = copy.deepcopy(self.lock)
            document["packages"][0]["sizeBytes"] += 1
            path.write_text(json.dumps(document), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(VALIDATOR), str(path), "--manifest", str(MANIFEST)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("package c-ares sizeBytes", result.stderr)


if __name__ == "__main__":
    unittest.main()
