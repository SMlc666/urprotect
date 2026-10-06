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


class ProtectedImageEvidenceTests(unittest.TestCase):
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
