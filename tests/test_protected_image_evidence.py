from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check-protected-image-evidence.py"


def write_closed_manifest(root: Path) -> None:
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}\n")
    (root / "SHA256SUMS").write_text("".join(entries), encoding="utf-8")


def run_checker(root: Path, expect_failure: bool = False) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(CHECKER), str(root), "--tier", "pr", "--runtime", "glibc", "--unit", root.name]
    if expect_failure:
        command.append("--expect-failure")
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True)


def write_tls_evidence(root: Path, stage: dict, *, result: str = "accepted-and-runs") -> None:
    source = root / "source-image.bin"
    source.write_bytes(b"tls source image")
    template = root / "pt-tls-template.bin"
    template.write_bytes(b"initialized tls")
    artifact = root / "protected-image.bin"
    if not artifact.exists():
        body = bytearray(b"UPPI" + b"\x01\x00\xB7\x00\x01\x00\x00\x00" + b"\x00" * 8)
        body[12:16] = (len(body) + 32).to_bytes(4, "little")
        artifact.write_bytes(bytes(body) + hashlib.sha256(body).digest())
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    stage.update({
        "sourceSha256": source_sha,
        "artifactSha256": artifact_sha,
        "artifactSize": artifact.stat().st_size,
        "publicationComplete": True,
    })
    stage["tlsEvidence"] = {
        "schemaVersion": 1,
        "model": "initial-exec",
        "profile": stage["profile"],
        "runtime": "glibc",
        "lifecycle": "current-thread" if result == "accepted-and-runs" else "not-run",
        "result": result,
        "sourcePath": "source-image.bin",
        "sourceSha256": source_sha,
        "transformedPath": "protected-image.bin",
        "transformedSha256": artifact_sha,
        "artifactPath": "protected-image.bin",
        "artifactSha256": artifact_sha,
        "toolchainIdentity": "gcc-13.3;ld-2.42",
        "loaderIdentity": "ld-linux-aarch64.so.1",
        "ptTls": {
            "templatePath": "pt-tls-template.bin",
            "templateSha256": hashlib.sha256(template.read_bytes()).hexdigest(),
            "fileSize": 15,
            "memorySize": 32,
            "zeroFillSize": 17,
            "alignment": 16,
            "owningLoad": 1,
        },
        "perThread": "observed" if result == "accepted-and-runs" else "not-run",
        "zeroFill": "observed" if result == "accepted-and-runs" else "not-run",
        "teardown": "observed" if result == "accepted-and-runs" else "not-run",
        "firstFailureStage": None if result == "accepted-and-runs" else "environment" if result == "environment-unavailable" else "target-loader",
        "publicationResult": "published",
        "rollbackResult": "not-applicable",
    }


class ProtectedImageEvidenceTests(unittest.TestCase):
    def make_tls_tree(self, root: Path, result: str) -> None:
        root.mkdir()
        producer_sha = hashlib.sha256(b"producer").hexdigest()
        stage = {
            "schemaVersion": 1,
            "stage": "protected-image-producer",
            "status": "passed",
            "unitId": root.name,
            "profile": "outer-execveat",
            "sourceSha256": None,
            "requestSha256": hashlib.sha256(b"request").hexdigest(),
            "producerId": "producer.fixture",
            "producerBuildSha256": producer_sha,
            "rehydratorConsumerId": "urprotect.rehydrator.v1",
            "artifactSha256": None,
            "artifactSize": None,
            "commandDigest": hashlib.sha256(b"command").hexdigest(),
            "environmentDigest": hashlib.sha256(b"environment").hexdigest(),
            "artifactPath": "protected-image.bin",
            "rolePath": "protected-image.json",
            "rawEvidenceManifestPath": "SHA256SUMS",
            "transformationStatus": "passed",
            "transformedFunctionCount": 1,
            "selectors": ["name=target"],
            "passes": ["control-flow-flattening"],
            "diagnostics": [],
            "artifactRole": "protected-image",
            "abiId": "urprotect.protected-image.v1",
            "abiVersion": 1,
            "publicationComplete": True,
        }
        write_tls_evidence(root, stage, result=result)
        role = {
            "schemaVersion": 1,
            "artifactRole": "protected-image",
            "abiId": "urprotect.protected-image.v1",
            "abiVersion": 1,
            "unitId": root.name,
            "profile": stage["profile"],
            "sourceSha256": stage["sourceSha256"],
            "artifactSha256": stage["artifactSha256"],
            "artifactSize": stage["artifactSize"],
            "producerId": stage["producerId"],
            "producerBuildSha256": producer_sha,
            "rehydratorConsumerId": stage["rehydratorConsumerId"],
            "requestSha256": stage["requestSha256"],
            "rawArtifactPath": "protected-image.bin",
            "rawArtifactRetained": True,
        }
        (root / "protected-image.json").write_text(json.dumps(role, indent=2) + "\n", encoding="utf-8")
        (root / "stage.json").write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
        (root / "stdout.txt").write_text("structured output\n", encoding="utf-8")
        (root / "stderr.txt").write_text("", encoding="utf-8")
        write_closed_manifest(root)

    def test_tls_accepted_and_runs_projection_is_validated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-tls-evidence-accepted-") as directory:
            root = Path(directory) / "unit"
            self.make_tls_tree(root, "accepted-and-runs")
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_tls_environment_unavailable_has_no_lifecycle_claim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-tls-evidence-environment-") as directory:
            root = Path(directory) / "unit"
            self.make_tls_tree(root, "environment-unavailable")
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_tls_runtime_failure_retains_published_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-tls-evidence-runtime-failure-") as directory:
            root = Path(directory) / "unit"
            self.make_tls_tree(root, "runtime-failure")
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_tls_environment_unavailable_rejects_lifecycle_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-tls-evidence-environment-negative-") as directory:
            root = Path(directory) / "unit"
            self.make_tls_tree(root, "environment-unavailable")
            stage_path = root / "stage.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["tlsEvidence"]["perThread"] = "observed"
            stage_path.write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
            write_closed_manifest(root)
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("lifecycle", result.stderr.lower())

    def test_tls_pt_tls_numeric_bound_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-tls-evidence-bounds-") as directory:
            root = Path(directory) / "unit"
            self.make_tls_tree(root, "accepted-and-runs")
            stage_path = root / "stage.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["tlsEvidence"]["ptTls"]["memorySize"] = 128 * 1024 * 1024 + 1
            stage_path.write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
            write_closed_manifest(root)
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bounded integer", result.stderr.lower())

    def test_tls_nearest_negative_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-tls-evidence-negative-") as directory:
            root = Path(directory) / "unit"
            self.make_tls_tree(root, "accepted-and-runs")
            stage_path = root / "stage.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["tlsEvidence"]["artifactSha256"] = "0" * 64
            stage_path.write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
            write_closed_manifest(root)
            result = run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("hash", result.stderr.lower())

    def test_success_tree_is_closed_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-protected-image-evidence-") as directory:
            root = Path(directory) / "unit"
            root.mkdir()
            artifact_body = bytearray(b"UPPI" + b"\x01\x00\xB7\x00\x01\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 4)
            artifact_body[12:16] = (len(artifact_body) + 32).to_bytes(4, "little")
            artifact = bytes(artifact_body) + hashlib.sha256(artifact_body).digest()
            artifact_path = root / "protected-image.bin"
            artifact_path.write_bytes(artifact)
            source_sha = hashlib.sha256(b"source").hexdigest()
            request_sha = hashlib.sha256(b"request").hexdigest()
            producer_sha = hashlib.sha256(b"producer").hexdigest()
            artifact_sha = hashlib.sha256(artifact).hexdigest()
            role = {
                "schemaVersion": 1,
                "artifactRole": "protected-image",
                "abiId": "urprotect.protected-image.v1",
                "abiVersion": 1,
                "unitId": root.name,
                "profile": "outer-execveat",
                "sourceSha256": source_sha,
                "artifactSha256": artifact_sha,
                "artifactSize": len(artifact),
                "producerId": "producer.fixture",
                "producerBuildSha256": producer_sha,
                "rehydratorConsumerId": "urprotect.rehydrator.v1",
                "requestSha256": request_sha,
                "selectors": ["name=target"],
                "passes": ["control-flow-flattening"],
                "rawArtifactPath": "protected-image.bin",
                "rawArtifactRetained": True,
                "architecture": "AArch64",
            }
            (root / "protected-image.json").write_text(json.dumps(role, indent=2) + "\n", encoding="utf-8")
            stage = {
                "schemaVersion": 1,
                "stage": "protected-image-producer",
                "status": "passed",
                "unitId": root.name,
                "profile": "outer-execveat",
                "sourceSha256": source_sha,
                "requestSha256": request_sha,
                "producerId": "producer.fixture",
                "producerBuildSha256": producer_sha,
                "rehydratorConsumerId": "urprotect.rehydrator.v1",
                "artifactSha256": artifact_sha,
                "artifactSize": len(artifact),
                "commandDigest": hashlib.sha256(b"command").hexdigest(),
                "environmentDigest": hashlib.sha256(b"environment").hexdigest(),
                "artifactPath": "protected-image.bin",
                "rolePath": "protected-image.json",
                "rawEvidenceManifestPath": "SHA256SUMS",
                "transformationStatus": "passed",
                "transformedFunctionCount": 1,
                "selectors": ["name=target"],
                "passes": ["control-flow-flattening"],
                "diagnostics": [],
                "artifactRole": "protected-image",
                "abiId": "urprotect.protected-image.v1",
                "abiVersion": 1,
                "publicationComplete": True,
            }
            (root / "stage.json").write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
            (root / "stdout.txt").write_text("structured output\n", encoding="utf-8")
            (root / "stderr.txt").write_text("", encoding="utf-8")
            write_closed_manifest(root)
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_tree_retains_diagnostics_without_partial_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-protected-image-failure-") as directory:
            root = Path(directory) / "unit"
            root.mkdir()
            producer_sha = hashlib.sha256(b"producer").hexdigest()
            stage = {
                "schemaVersion": 1,
                "stage": "protected-image-producer",
                "status": "failed",
                "unitId": root.name,
                "profile": "outer-execveat",
                "sourceSha256": None,
                "requestSha256": None,
                "producerId": "producer.fixture",
                "producerBuildSha256": producer_sha,
                "rehydratorConsumerId": "urprotect.rehydrator.v1",
                "artifactSha256": None,
                "artifactSize": None,
                "commandDigest": hashlib.sha256(b"command").hexdigest(),
                "environmentDigest": hashlib.sha256(b"environment").hexdigest(),
                "artifactPath": "protected-image.bin",
                "rolePath": "protected-image.json",
                "rawEvidenceManifestPath": "SHA256SUMS",
                "transformationStatus": "failed",
                "transformedFunctionCount": 0,
                "selectors": ["name=target"],
                "passes": ["control-flow-flattening"],
                "diagnostics": [{"severity": "Error", "code": "InputIoFailure", "message": "synthetic", "offset": None}],
                "publicationComplete": False,
            }
            (root / "stage.json").write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
            (root / "stdout.txt").write_text("", encoding="utf-8")
            (root / "stderr.txt").write_text("failure\n", encoding="utf-8")
            write_closed_manifest(root)
            result = run_checker(root, expect_failure=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_checker_rejects_an_unlisted_retained_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="urprotect-protected-image-open-") as directory:
            root = Path(directory) / "unit"
            root.mkdir()
            stage = {
                "schemaVersion": 1,
                "stage": "protected-image-producer",
                "status": "failed",
                "unitId": root.name,
                "profile": "outer-execveat",
                "producerId": "producer.fixture",
                "producerBuildSha256": hashlib.sha256(b"producer").hexdigest(),
                "rehydratorConsumerId": "urprotect.rehydrator.v1",
                "commandDigest": hashlib.sha256(b"command").hexdigest(),
                "environmentDigest": hashlib.sha256(b"environment").hexdigest(),
                "artifactPath": "protected-image.bin",
                "rolePath": "protected-image.json",
                "rawEvidenceManifestPath": "SHA256SUMS",
                "transformationStatus": "failed",
                "selectors": ["name=target"],
                "passes": ["control-flow-flattening"],
                "diagnostics": [{"severity": "Error", "code": "Failure", "message": "synthetic", "offset": None}],
                "publicationComplete": False,
            }
            (root / "stage.json").write_text(json.dumps(stage), encoding="utf-8")
            (root / "stdout.txt").write_text("", encoding="utf-8")
            (root / "stderr.txt").write_text("failure", encoding="utf-8")
            (root / "unlisted.txt").write_text("must be retained in the manifest", encoding="utf-8")
            write_closed_manifest(root)
            lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            (root / "SHA256SUMS").write_text("\n".join(line for line in lines if "unlisted.txt" not in line) + "\n", encoding="utf-8")
            result = run_checker(root, expect_failure=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("closed", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
