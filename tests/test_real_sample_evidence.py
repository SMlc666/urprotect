#!/usr/bin/env python3
"""Evidence-gate regressions without acquiring real samples."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "fixtures/real-samples/manifest.json"
CANDIDATES = ROOT / "fixtures/real-samples/candidates.json"
GATE = ROOT / "scripts/check-real-sample-evidence.py"
PROJECT_FIELDS = ROOT / "scripts/real_sample_project_fields.py"
RUNTIME_CLOSURES = ROOT / "fixtures/real-samples/runtime-closures.json"
BIONIC_NODE_LOCK = ROOT / "fixtures/real-samples/bionic-node-runtime-lock.json"
BIONIC_NODE_LOCK_DOCUMENT = json.loads(BIONIC_NODE_LOCK.read_text(encoding="utf-8"))
BIONIC_NODE_LOCK_SHA256 = hashlib.sha256(BIONIC_NODE_LOCK.read_bytes()).hexdigest()
sys.path.insert(0, str(ROOT / "scripts"))
from real_sample_schema import effective_execution_policy  # noqa: E402


class RealSampleEvidenceTests(unittest.TestCase):
    def run_gate(
        self,
        root: Path,
        manifest: Path = MANIFEST,
        tier: str = "pr",
        closures: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if closures is None:
            closures = getattr(self, "active_closures", RUNTIME_CLOSURES)
        return subprocess.run(
            [sys.executable, str(GATE), str(manifest), "--candidates", str(CANDIDATES), "--runtime-closures", str(closures), "--tier", tier, "--artifact-root", str(root)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def write_complete_text_evidence(self, root: Path, manifest_path: Path = MANIFEST, tier: str = "pr") -> None:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        closure_path = getattr(self, "active_closures", RUNTIME_CLOSURES)
        closures = json.loads(closure_path.read_text(encoding="utf-8"))
        closure_projects = closures.get("projects", {})
        artifact_hash = "a" * 64
        for project in manifest["corpus"]["projects"]:
            project_root = root / project["projectId"]
            (project_root / "logs").mkdir(parents=True, exist_ok=True)
            closure_policy = closure_projects.get(project["projectId"], closure_projects.get("*", {}))
            closure_baseline = closure_policy.get("baseline", {}) if isinstance(closure_policy, dict) else {}
            closure_outer = closure_policy.get("outerWrapper", {}) if isinstance(closure_policy, dict) else {}
            effective_policy = effective_execution_policy(project, tier)
            manifest_baseline = effective_policy["baseline"]
            manifest_outer = effective_policy["outerWrapper"]
            artifact_path = "/" + project["provenance"]["artifactPath"].lstrip("/")
            declared_command = closure_baseline.get("command", manifest_baseline.get("command"))
            invocation = closure_baseline.get("invocation", manifest_baseline.get("invocation"))
            baseline_command = (
                declared_command
                if isinstance(declared_command, list)
                else [artifact_path, "--version"]
                if invocation == "declared-artifact-version"
                else None
            )
            outer_mode = closure_outer.get("mode", manifest_outer.get("mode", "outer-execveat"))
            baseline_expected_status = closure_baseline.get("expectedStatus", manifest_baseline.get("expectedStatus", 0))
            outer_expected_status = closure_outer.get("expectedStatus", baseline_expected_status)
            expected = {
                layer: effective_policy[layer]["expectedResult"]
                for layer in ("static", "baseline", "outerWrapper", "hostContext")
            }
            runtime = project["target"]["runtime"]
            loader = project["target"]["loader"]
            baseline_applicable = expected["baseline"] != "not-applicable"
            outer_applicable = expected["outerWrapper"] != "not-applicable"
            baseline_runs = expected["baseline"] == "accepted-and-runs"
            outer_runs = expected["outerWrapper"] == "accepted-and-runs"
            result = {
                "schemaVersion": 2,
                "tier": tier,
                "projectId": project["projectId"],
                "artifactSha256": artifact_hash,
                "sourceArtifactSha256": artifact_hash,
                "runtimeArtifactSha256": artifact_hash,
                "cliSuccess": True,
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
            fingerprint = {
                "schemaVersion": 2,
                "featureSchemaVersion": 2,
                "projectId": project["projectId"],
                "producer": "contract-test",
                "runtime": runtime,
                "loader": loader,
                "fileSha256": artifact_hash,
                "dependencies": {},
                "relocations": {},
                "symbolVersions": {},
                "tls": {},
                "gnuProperty": {},
                "hardening": {},
                "unknownFields": [],
                "inspection": {"bounded": True},
            }
            if project["projectId"] == "nodejs":
                fingerprint["dependencies"] = {
                    "needed": [],
                    "rpath": [],
                    "runpath": [BIONIC_NODE_LOCK_DOCUMENT["execution"]["runpath"]],
                }
            (project_root / "source.txt").write_text("source metadata\n", encoding="utf-8")
            (project_root / "hashes.txt").write_text(
                f"sourceArtifactSha256={artifact_hash}\n"
                f"runtimeArtifactSha256={artifact_hash}\n",
                encoding="utf-8",
            )
            (project_root / "environment.txt").write_text("network=none\n", encoding="utf-8")
            (project_root / "elf-fingerprint.json").write_text(json.dumps(fingerprint) + "\n", encoding="utf-8")
            (project_root / "fingerprint-comparison.json").write_text(
                json.dumps({
                    "schemaVersion": 2,
                    "projectId": project["projectId"],
                    "status": "passed",
                }) + "\n",
                encoding="utf-8",
            )
            (project_root / "readelf.txt").write_text("readelf evidence\n", encoding="utf-8")
            (project_root / "urprotect-report.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "toolVersion": "contract-test",
                    "success": True,
                    "input": {"byteLength": 1, "sha256": artifact_hash},
                    "summary": {},
                    "diagnostics": [],
                }) + "\n",
                encoding="utf-8",
            )
            runtime_closure = {
                "schemaVersion": 1,
                "projectId": project["projectId"],
                "runtime": runtime,
                "loader": loader,
                "status": "assembled" if baseline_runs else "environment-unavailable" if baseline_applicable else "not-applicable",
                "sourceArtifactSha256": artifact_hash,
                "runtimeArtifactSha256": artifact_hash,
            }
            if project["projectId"] == "nodejs":
                execution_policy = BIONIC_NODE_LOCK_DOCUMENT["execution"]
                runtime_closure.update({
                    "lockSha256": BIONIC_NODE_LOCK_SHA256,
                    "image": BIONIC_NODE_LOCK_DOCUMENT["baseImage"]["requestedRef"],
                    "imageId": BIONIC_NODE_LOCK_DOCUMENT["baseImage"]["id"],
                    "loader": execution_policy["loader"],
                    "pathMode": execution_policy["outerMode"],
                    "pathPolicy": execution_policy["pathPolicy"],
                    "runpath": execution_policy["runpath"],
                    "timeoutSeconds": execution_policy["timeoutSeconds"],
                    "outputLimitBytes": execution_policy["outputBytes"],
                    "memoryBytes": execution_policy["memoryBytes"],
                    "processLimit": execution_policy["processLimit"],
                    "containerStatus": 0,
                    "containerStatuses": {"setup": 0, "baseline": 0, "outer": 0},
                    "cleanupContainerStatuses": {"setup": 0, "baseline": 0, "outer": 0},
                    "executionStatus": "passed",
                    "behaviorEquivalent": True,
                    "runpathVerified": True,
                    "protocolAuthority": "host-generated-after-docker-inspect",
                    "cleanupAuthority": "host-generated-after-docker-inspect",
                    "containerCleanup": {
                        "allNamedContainersReaped": True,
                        "authority": "host-generated-after-docker-inspect",
                    },
                    "temporaryImageCleanup": {
                        "status": "removed-and-verified",
                        "absenceVerified": True,
                        "attempts": 1,
                        "authority": "host-generated-after-docker-inspect",
                        "reason": None,
                    },
                    "cleanupStatus": "passed",
                    "workRootRetained": False,
                })
            (project_root / "runtime-closure.json").write_text(
                json.dumps(runtime_closure) + "\n",
                encoding="utf-8",
            )
            outer_command = (
                ["/usr/local/bin/urprotect-packed", *baseline_command[1:]]
                if outer_applicable and baseline_command is not None
                else None
            )
            execution = {
                "schemaVersion": 1,
                "projectId": project["projectId"],
                "artifactPath": artifact_path,
                "baseline": {
                    "applicable": baseline_applicable,
                    "attempted": baseline_runs,
                    "outcome": "target-exit" if baseline_runs else "preflight-environment-unavailable" if baseline_applicable else "not-applicable",
                    "invocationSource": (
                        "declared" if baseline_runs
                        else "runner-preflight" if baseline_applicable
                        else "not-applicable"
                    ),
                    "resolvedCommand": baseline_command if baseline_applicable else None,
                    "expectedStatus": baseline_expected_status if baseline_applicable else None,
                    "status": 0 if baseline_runs else None,
                    "targetStatus": 0 if baseline_runs else None,
                    "helperStatus": None,
                    "helperStatusPath": None,
                    "helperResultPath": "logs/baseline.helper.json" if baseline_runs else None,
                    "preflightResultPath": "logs/baseline.preflight.json" if baseline_applicable and not baseline_runs else None,
                    "result": expected["baseline"],
                    "stdoutPath": "logs/baseline.stdout" if baseline_applicable else None,
                    "stderrPath": "logs/baseline.stderr" if baseline_applicable else None,
                    "statusPath": "logs/baseline.status" if baseline_runs else None,
                    "reason": "explicit environment-unavailable contract fixture" if baseline_applicable and not baseline_runs else "baseline is not applicable in this contract fixture" if not baseline_applicable else None,
                    "expectedResult": expected["baseline"],
                },
                "outerWrapper": {
                    "applicable": outer_applicable,
                    "attempted": outer_runs,
                    "outcome": "target-exit" if outer_runs else "preflight-environment-unavailable" if outer_applicable else "not-applicable",
                    "mode": outer_mode if outer_applicable else None,
                    "invocationSource": "runner-derived-wrapper" if outer_applicable else "not-applicable",
                    "resolvedCommand": outer_command if outer_applicable else None,
                    "expectedStatus": outer_expected_status if outer_applicable else None,
                    "status": 0 if outer_runs else None,
                    "targetStatus": 0 if outer_runs else None,
                    "helperStatus": None,
                    "helperStatusPath": None,
                    "helperResultPath": "logs/outer.helper.json" if outer_runs else None,
                    "preflightResultPath": "logs/outer.preflight.json" if outer_applicable and not outer_runs else None,
                    "packStatus": 0 if outer_runs else None,
                    "packStatusPath": "logs/outer-pack.status" if outer_runs else None,
                    "result": expected["outerWrapper"],
                    "stdoutPath": "logs/outer.stdout" if outer_applicable else None,
                    "stderrPath": "logs/outer.stderr" if outer_applicable else None,
                    "statusPath": "logs/outer.status" if outer_runs else None,
                    "reason": "explicit environment-unavailable contract fixture" if outer_applicable and not outer_runs else "outer wrapper is not applicable in this contract fixture" if not outer_applicable else None,
                    "expectedResult": expected["outerWrapper"],
                },
            }
            if project["projectId"] == "nodejs":
                execution_policy = BIONIC_NODE_LOCK_DOCUMENT["execution"]
                protocol_authority = "host-generated-after-docker-inspect"
                for layer_name in ("baseline", "outerWrapper"):
                    layer_entry = execution[layer_name]
                    layer_entry.update({
                        "containerStatus": 0,
                        "dockerStatus": 0,
                        "cleanupContainerStatus": 0,
                        "timeoutSeconds": execution_policy["timeoutSeconds"],
                        "outputLimitBytes": execution_policy["outputBytes"],
                        "outputBytes": 0,
                        "memoryBytes": execution_policy["memoryBytes"],
                        "processLimit": execution_policy["processLimit"],
                        "lockSha256": BIONIC_NODE_LOCK_SHA256,
                        "pathMode": execution_policy["outerMode"],
                        "pathPolicy": execution_policy["pathPolicy"],
                        "runpath": execution_policy["runpath"],
                        "protocolAuthority": protocol_authority,
                        "cleanupAuthority": "host-generated-after-docker-inspect",
                        "runpathVerified": True,
                        "allNamedContainersReaped": True,
                    })
            (project_root / "execution.json").write_text(json.dumps(execution) + "\n", encoding="utf-8")
            pack_report = (
                {
                    "schemaVersion": 1,
                    "toolVersion": "contract-test",
                    "success": True,
                    "payload": {"profile": "outer-execveat"},
                    "output": {"published": True},
                    "diagnostics": [],
                    "cliExitCode": 0,
                }
                if outer_runs
                else {
                    "schemaVersion": 1,
                    "toolVersion": "contract-test",
                    "success": False,
                    "payload": {},
                    "output": {"published": False},
                    "diagnostics": [{"severity": "Error", "code": "environment-unavailable", "message": "explicit environment-unavailable contract fixture", "offset": None}],
                }
                if outer_applicable
                else {
                    "schemaVersion": 1,
                    "status": "not-applicable",
                    "reason": "outer wrapper is outside this contract fixture",
                }
            )
            if project["projectId"] == "nodejs":
                execution_policy = BIONIC_NODE_LOCK_DOCUMENT["execution"]
                pack_report.update({
                    "executionMode": execution_policy["outerMode"],
                    "pathPolicy": execution_policy["pathPolicy"],
                    "runpath": execution_policy["runpath"],
                    "lockSha256": BIONIC_NODE_LOCK_SHA256,
                    "image": BIONIC_NODE_LOCK_DOCUMENT["baseImage"]["requestedRef"],
                    "imageId": BIONIC_NODE_LOCK_DOCUMENT["baseImage"]["id"],
                    "loader": execution_policy["loader"],
                    "packInvocation": {"attempted": True, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
                })
            (project_root / "outer-pack.json").write_text(json.dumps(pack_report) + "\n", encoding="utf-8")
            (project_root / "result.json").write_text(json.dumps(result) + "\n", encoding="utf-8")
            (project_root / "raw-inputs-removed.txt").write_text(
                "raw-inputs-removed=true\n", encoding="utf-8"
            )
            for name in ("baseline.stdout", "baseline.stderr", "outer.stdout", "outer.stderr"):
                (project_root / "logs" / name).write_text("", encoding="utf-8")
            if project["projectId"] == "nodejs":
                (project_root / "logs" / "container-setup.status").write_text("0\n", encoding="utf-8")
                (project_root / "logs" / "behavior-equivalent").write_text("true\n", encoding="utf-8")
            if baseline_runs:
                (project_root / "logs" / "baseline.status").write_text("0\n", encoding="utf-8")
                (project_root / "logs" / "baseline.helper.json").write_text(
                    json.dumps({
                        "schemaVersion": 1,
                        "producer": "run-isolated-real-sample.py",
                        "attempted": True,
                        "helperStatus": None,
                        "targetStatus": 0,
                        "readinessSeen": True,
                        "outcome": "target-exit",
                    }) + "\n",
                    encoding="utf-8",
                )
            if outer_runs:
                (project_root / "logs" / "outer.status").write_text("0\n", encoding="utf-8")
                (project_root / "logs" / "outer.helper.json").write_text(
                    json.dumps({
                        "schemaVersion": 1,
                        "producer": "run-isolated-real-sample.py",
                        "attempted": True,
                        "helperStatus": None,
                        "targetStatus": 0,
                        "readinessSeen": True,
                        "outcome": "target-exit",
                    }) + "\n",
                    encoding="utf-8",
                )
                (project_root / "logs" / "outer-pack.status").write_text("0\n", encoding="utf-8")
            for layer_name, log_layer, runs, applicable in (
                ("baseline", "baseline", baseline_runs, baseline_applicable),
                ("outerWrapper", "outer", outer_runs, outer_applicable),
            ):
                if applicable and not runs:
                    (project_root / "logs" / f"{log_layer}.preflight.json").write_text(
                        json.dumps({
                            "schemaVersion": 1,
                            "producer": "run-real-sample-matrix.sh",
                            "layer": layer_name,
                            "stage": layer_name,
                            "outcome": "preflight-environment-unavailable",
                            "reason": "explicit environment-unavailable contract fixture",
                            "attempted": False,
                            "helperStatus": None,
                            "targetStatus": None,
                        }) + "\n",
                        encoding="utf-8",
                    )
            if project["projectId"] == "nodejs":
                execution_policy = BIONIC_NODE_LOCK_DOCUMENT["execution"]
                def bionic_protocol() -> dict[str, object]:
                    return {
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
                        "timeoutSeconds": execution_policy["timeoutSeconds"],
                        "outputLimitBytes": execution_policy["outputBytes"],
                        "outputBytes": 0,
                        "memoryBytes": execution_policy["memoryBytes"],
                        "processLimit": execution_policy["processLimit"],
                        "lockSha256": BIONIC_NODE_LOCK_SHA256,
                        "pathMode": execution_policy["outerMode"],
                        "pathPolicy": execution_policy["pathPolicy"],
                        "runpath": execution_policy["runpath"],
                        "runpathVerified": True,
                        "protocolAuthority": "host-generated-after-docker-inspect",
                        "cleanupAuthority": "host-generated-after-docker-inspect",
                        "allNamedContainersReaped": True,
                    }
                baseline_protocol = bionic_protocol()
                outer_protocol = bionic_protocol()
                (project_root / "logs" / "baseline.helper.json").write_text(json.dumps(baseline_protocol) + "\n", encoding="utf-8")
                (project_root / "logs" / "outer.helper.json").write_text(json.dumps(outer_protocol) + "\n", encoding="utf-8")
                bionic_summary = {
                    "schemaVersion": 2,
                    "producer": "run-bionic-node-sample.sh",
                    "runtime": "bionic",
                    "status": "passed",
                    "lockSha256": BIONIC_NODE_LOCK_SHA256,
                    "image": BIONIC_NODE_LOCK_DOCUMENT["baseImage"]["requestedRef"],
                    "imageId": BIONIC_NODE_LOCK_DOCUMENT["baseImage"]["id"],
                    "loader": execution_policy["loader"],
                    "artifactPath": execution_policy["artifactPath"],
                    "sourceArtifactSha256": artifact_hash,
                    "runtimeArtifactSha256": artifact_hash,
                    "sourceArchiveSha256": BIONIC_NODE_LOCK_DOCUMENT["sourceArchiveLock"]["sha256"],
                    "pathMode": execution_policy["outerMode"],
                    "pathPolicy": execution_policy["pathPolicy"],
                    "runpath": execution_policy["runpath"],
                    "runpathVerified": True,
                    "timeoutSeconds": execution_policy["timeoutSeconds"],
                    "outputLimitBytes": execution_policy["outputBytes"],
                    "memoryBytes": execution_policy["memoryBytes"],
                    "processLimit": execution_policy["processLimit"],
                    "expectedStatus": execution_policy["expectedStatus"],
                    "outputBytes": 0,
                    "behaviorEquivalent": True,
                    "protocolAuthority": "host-generated-after-docker-inspect",
                    "containerStatus": 0,
                    "containerStatuses": {"setup": 0, "baseline": 0, "outer": 0},
                    "cleanupContainerStatuses": {"setup": 0, "baseline": 0, "outer": 0},
                    "cleanupAuthority": "host-generated-after-docker-inspect",
                    "containerCleanup": {
                        "allNamedContainersReaped": True,
                        "authority": "host-generated-after-docker-inspect",
                    },
                    "temporaryImageCleanup": {
                        "status": "removed-and-verified",
                        "absenceVerified": True,
                        "attempts": 1,
                        "authority": "host-generated-after-docker-inspect",
                        "reason": None,
                    },
                    "cleanupStatus": "passed",
                    "workRootRetained": False,
                    "packStatus": 0,
                    "packReport": "outer-pack.json",
                    "baseline": {**baseline_protocol, "protocol": baseline_protocol, "actual": "accepted-and-runs", "reason": "status=0"},
                    "outer": {**outer_protocol, "protocol": outer_protocol, "actual": "accepted-and-runs", "reason": "status=0"},
                }
                (project_root / "logs" / "bionic-node-result.json").write_text(json.dumps(bionic_summary) + "\n", encoding="utf-8")
            (project_root / "logs" / "run.log").write_text("run evidence\n", encoding="utf-8")
        (root / "evidence-sanitized.txt").write_text("evidence-sanitized=true\n", encoding="utf-8")
        render_result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/render-real-sample-report.py"),
                str(manifest_path),
                "--tier",
                tier,
                "--artifact-root",
                str(root),
                "--runtime-closures",
                str(closure_path),
                "--output-json",
                str(root / "aggregate.json"),
                "--output-markdown",
                str(root / "aggregate.md"),
                "--require-evidence",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(render_result.returncode, 0, render_result.stderr or render_result.stdout)

    def make_pr_ready_manifest(self, directory: Path) -> Path:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for project_id in ("busybox", "gnu-coreutils", "nodejs"):
            project = next(project for project in manifest["corpus"]["projects"] if project["projectId"] == project_id)
            for layer in ("baseline", "outerWrapper"):
                project["executionPolicy"][layer]["applicable"] = True
                project["executionPolicy"][layer]["expectedResult"] = "accepted-and-runs"
                project["executionPolicy"][layer]["reason"] = "PR runtime witness contract fixture"
                project.setdefault("expectedResults", {})[layer] = "accepted-and-runs"
        path = directory / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def write_pr_ready_evidence(self, root: Path) -> Path:
        manifest_path = self.make_pr_ready_manifest(root.parent)
        closures = json.loads(RUNTIME_CLOSURES.read_text(encoding="utf-8"))
        closures["projects"]["nodejs"] = {
            "baseline": {
                "expectedResult": "accepted-and-runs",
                "mode": "runtime-closure",
                "invocation": "declared-artifact-version",
                "expectedStatus": 0,
            },
            "outerWrapper": {
                "expectedResult": "accepted-and-runs",
                "mode": "outer-path-preserving",
                "compare": ["status", "stdout", "stderr"],
                "expectedStatus": 0,
            },
        }
        self.active_closures = root.parent / "runtime-closures.json"
        self.active_closures.write_text(json.dumps(closures), encoding="utf-8")
        self.write_complete_text_evidence(root, manifest_path)
        return manifest_path

    def test_project_fields_producer_and_bash_consumer_preserve_empty_invocation_fields(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        project = next(project for project in manifest["corpus"]["projects"] if project["projectId"] == "alpine-7zip")
        produced = subprocess.run(
            [sys.executable, str(PROJECT_FIELDS), json.dumps(project), str(RUNTIME_CLOSURES), "nightly"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(produced.returncode, 0, produced.stderr)
        consumer = r'''set -euo pipefail
IFS=$'\t' read -r id archive_url version archive_path archive_sha archive_format artifact_path producer expected_static baseline_applicable expected_baseline baseline_mode baseline_command_b64 baseline_expected_status baseline_invocation outer_applicable expected_outer outer_mode runtime loader apk_metadata_b64 source_kind <<< "${PROJECT_FIELDS}"
python3 - "${runtime}" "${loader}" "${apk_metadata_b64}" "${source_kind}" "${baseline_invocation}" "${outer_applicable}" "${baseline_command_b64}" <<'PY'
import base64
import json
import sys
print(json.dumps({
    "runtime": sys.argv[1],
    "loader": sys.argv[2],
    "apk": json.loads(base64.urlsafe_b64decode(sys.argv[3]).decode("utf-8")),
    "sourceKind": sys.argv[4],
    "invocation": sys.argv[5],
    "outerApplicable": sys.argv[6],
    "command": json.loads(base64.urlsafe_b64decode(sys.argv[7]).decode("utf-8")),
}, sort_keys=True))
PY'''
        consumed = subprocess.run(
            ["bash", "-c", consumer],
            cwd=ROOT,
            env={**os.environ, "PROJECT_FIELDS": produced.stdout},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(consumed.returncode, 0, consumed.stderr)
        fields = json.loads(consumed.stdout)
        self.assertEqual(fields["runtime"], "musl")
        self.assertEqual(fields["loader"], "/lib/ld-musl-aarch64.so.1")
        self.assertEqual(
            fields["apk"],
            {
                "architecture": "aarch64",
                "license": "LGPL-2.0-only",
                "origin": "7zip",
                "package": "7zip",
                "version": "24.09-r0",
            },
        )
        self.assertEqual(fields["sourceKind"], "alpine-v3.22-main-aarch64-apk")
        self.assertEqual(fields["invocation"], "declared-artifact-version")
        self.assertEqual(fields["outerApplicable"], "true")
        self.assertEqual(fields["command"], ["/usr/bin/7z", "-h"])

    def test_missing_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_gate(Path(directory) / "missing")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact root", result.stderr)

    def test_complete_pr_witness_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            result = self.run_gate(root, manifest_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checked 100 projects", result.stdout)

    def test_node_runpath_must_match_retained_elf_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            fingerprint_path = root / "nodejs" / "elf-fingerprint.json"
            fingerprint = json.loads(fingerprint_path.read_text(encoding="utf-8"))
            fingerprint["dependencies"]["runpath"] = ["/tmp/wrong-runpath"]
            fingerprint_path.write_text(json.dumps(fingerprint) + "\n", encoding="utf-8")
            result = self.run_gate(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fingerprint DT_RUNPATH", result.stderr)

    def test_bionic_runtime_closure_runpath_must_match_the_host_summary_and_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            closure_path = root / "nodejs" / "runtime-closure.json"
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            closure["runpath"] = "/tampered/runpath"
            closure_path.write_text(json.dumps(closure) + "\n", encoding="utf-8")

            result = self.run_gate(root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runtime closure runpath does not match the host summary", result.stderr)

    def test_bionic_inspection_failure_after_container_launch_is_environment_unavailable(self) -> None:
        specification = importlib.util.spec_from_file_location("real_sample_evidence_gate", GATE)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        gate = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = gate
        specification.loader.exec_module(gate)
        execution_lock = BIONIC_NODE_LOCK_DOCUMENT["execution"]
        protocol = {
            "schemaVersion": 2,
            "producer": "run-bionic-node-sample.sh",
            "runtime": "bionic",
            "attempted": True,
            "helperStatus": 125,
            "targetStatus": None,
            "readinessSeen": True,
            "outcome": "helper-environment",
            "containerStatus": None,
            "dockerStatus": 0,
            "cleanupContainerStatus": 0,
            "timeoutSeconds": execution_lock["timeoutSeconds"],
            "outputLimitBytes": execution_lock["outputBytes"],
            "outputBytes": 0,
            "memoryBytes": execution_lock["memoryBytes"],
            "processLimit": execution_lock["processLimit"],
            "lockSha256": BIONIC_NODE_LOCK_SHA256,
            "pathMode": execution_lock["outerMode"],
            "pathPolicy": execution_lock["pathPolicy"],
            "runpath": execution_lock["runpath"],
            "runpathVerified": True,
            "protocolAuthority": "host-generated-after-docker-inspect",
            "cleanupAuthority": "host-generated-after-docker-inspect",
            "allNamedContainersReaped": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            (logs / "baseline.helper.json").write_text(json.dumps(protocol) + "\n", encoding="utf-8")
            (logs / "baseline.helper-status").write_text("125\n", encoding="utf-8")
            (logs / "baseline.stdout").write_text("", encoding="utf-8")
            (logs / "baseline.stderr").write_text("", encoding="utf-8")
            entry = {
                "applicable": True,
                "attempted": True,
                "expectedResult": "environment-unavailable",
                "result": "environment-unavailable",
                "outcome": "helper-environment",
                "invocationSource": "declared",
                "resolvedCommand": [execution_lock["artifactPath"], "--version"],
                "expectedStatus": 0,
                "status": None,
                "targetStatus": None,
                "helperStatus": 125,
                "helperStatusPath": "logs/baseline.helper-status",
                "helperResultPath": "logs/baseline.helper.json",
                "preflightResultPath": None,
                "packStatus": None,
                "stdoutPath": "logs/baseline.stdout",
                "stderrPath": "logs/baseline.stderr",
                "statusPath": None,
                "timeoutSeconds": execution_lock["timeoutSeconds"],
                "outputLimitBytes": execution_lock["outputBytes"],
                "outputBytes": 0,
                "memoryBytes": execution_lock["memoryBytes"],
                "processLimit": execution_lock["processLimit"],
                "lockSha256": BIONIC_NODE_LOCK_SHA256,
                "pathMode": execution_lock["outerMode"],
                "pathPolicy": execution_lock["pathPolicy"],
                "runpath": execution_lock["runpath"],
                "runpathVerified": True,
                "protocolAuthority": protocol["protocolAuthority"],
                "cleanupAuthority": protocol["cleanupAuthority"],
                "allNamedContainersReaped": True,
                "containerStatus": None,
                "dockerStatus": 0,
                "cleanupContainerStatus": 0,
            }
            errors = gate.check_execution_layer(
                root,
                {"artifactPath": execution_lock["artifactPath"], "baseline": entry},
                "nodejs",
                "baseline",
                "environment-unavailable",
                "environment-unavailable",
                expected_command=entry["resolvedCommand"],
                bionic_policy={**execution_lock, "lockSha256": BIONIC_NODE_LOCK_SHA256},
            )

        self.assertEqual(errors, [])

    def test_locked_node_closure_promotes_its_declared_runtime_layers(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "real_sample_evidence_gate", GATE
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        closures = json.loads(RUNTIME_CLOSURES.read_text(encoding="utf-8"))
        node = next(project for project in manifest["corpus"]["projects"] if project["projectId"] == "nodejs")
        expected = module.layer_expectations(node, closures)
        self.assertEqual(expected["baseline"], "accepted-and-runs")
        self.assertEqual(expected["outerWrapper"], "accepted-and-runs")

    def test_pr_contract_evidence_passes_with_locked_node_witness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_status_marker_on_not_applicable_layer_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            marker = root / "gnu-bash" / "logs" / "baseline.status"
            marker.write_text("0\n", encoding="utf-8")

            result = self.run_gate(root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("gnu-bash/baseline/logs/baseline.status", result.stderr)
            self.assertIn("marker has no matching execution record reference", result.stderr)

    def test_stale_outer_pack_status_marker_is_rejected_without_pack_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            marker = root / "gnu-bash" / "logs" / "outer-pack.status"
            marker.write_text("0\n", encoding="utf-8")

            result = self.run_gate(root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("gnu-bash/outerWrapper/logs/outer-pack.status", result.stderr)
            self.assertIn("marker has no matching execution record reference", result.stderr)

    def test_stale_bionic_setup_status_marker_is_rejected_for_non_bionic_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            marker = root / "gnu-bash" / "logs" / "container-setup.status"
            marker.write_text("0\n", encoding="utf-8")

            result = self.run_gate(root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("gnu-bash/bionic/logs/container-setup.status", result.stderr)
            self.assertIn("marker has no matching execution record reference", result.stderr)

    def test_bionic_preflight_conversion_cannot_leave_unowned_helper_markers(self) -> None:
        specification = importlib.util.spec_from_file_location("real_sample_evidence_gate_bionic_markers", GATE)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        gate = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = gate
        specification.loader.exec_module(gate)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        closures = json.loads(RUNTIME_CLOSURES.read_text(encoding="utf-8"))
        project = next(item for item in manifest["corpus"]["projects"] if item["projectId"] == "nodejs")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            sample = root / "nodejs"
            for marker_name in ("baseline.helper-status", "outer.helper-status"):
                (sample / "logs" / marker_name).write_text("125\n", encoding="utf-8")

            errors = gate.check_execution_markers(
                sample,
                json.loads((sample / "execution.json").read_text(encoding="utf-8")),
                "nodejs",
            )
            self.assertTrue(any("marker has no matching execution record reference" in error for error in errors), errors)

            for marker_name in ("baseline.helper-status", "outer.helper-status"):
                (sample / "logs" / marker_name).unlink()
            self.assertEqual(
                gate.check_sample(project, "pr", root, closures),
                [],
            )

    def test_bionic_failure_pack_reports_bind_preflight_and_attempted_failures(self) -> None:
        specification = importlib.util.spec_from_file_location("real_sample_evidence_gate_pack", GATE)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        gate = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = gate
        specification.loader.exec_module(gate)
        lock = BIONIC_NODE_LOCK_DOCUMENT
        execution_policy = lock["execution"]
        identity = {
            "image": lock["baseImage"]["requestedRef"],
            "imageId": lock["baseImage"]["id"],
            "loader": execution_policy["loader"],
            "executionMode": execution_policy["outerMode"],
            "pathPolicy": execution_policy["pathPolicy"],
            "runpath": execution_policy["runpath"],
            "lockSha256": BIONIC_NODE_LOCK_SHA256,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            sample = root / "nodejs"
            execution = json.loads((sample / "execution.json").read_text(encoding="utf-8"))
            execution["outerWrapper"].update({
                "attempted": False,
                "status": None,
                "targetStatus": None,
                "helperStatus": None,
                "helperStatusPath": None,
                "helperResultPath": None,
                "preflightResultPath": "logs/outer.preflight.json",
                "statusPath": None,
                "outcome": "preflight-product-failure",
                "invocationSource": "runner-preflight",
                "reason": "setup unavailable",
                "result": "unexpected-rejection",
                "packStatus": None,
                "packStatusPath": None,
            })
            preflight = {
                "schemaVersion": 1,
                "toolVersion": "runner-boundary",
                "success": False,
                "category": "preflight",
                "payload": {},
                "output": {"published": False},
                "diagnostics": [{"code": "bionic.preflight", "message": "setup unavailable"}],
                "cliExitCode": None,
                "packInvocation": {"attempted": False},
                **identity,
            }
            (sample / "outer-pack.json").write_text(json.dumps(preflight) + "\n", encoding="utf-8")
            (sample / "logs" / "outer.preflight.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "producer": "run-real-sample-matrix.sh",
                    "layer": "outerWrapper",
                    "stage": "outerWrapper",
                    "outcome": "preflight-product-failure",
                    "reason": "setup unavailable",
                    "attempted": False,
                    "helperStatus": None,
                    "targetStatus": None,
                }) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                gate.check_execution_layer(
                    sample,
                    execution,
                    "nodejs",
                    "outerWrapper",
                    "accepted-and-runs",
                    "unexpected-rejection",
                    expected_command=execution["baseline"]["resolvedCommand"],
                    bionic_policy={**execution_policy, "lockSha256": BIONIC_NODE_LOCK_SHA256},
                ),
                [],
            )
            self.assertEqual(
                gate.check_pack_report(sample, "nodejs", "accepted-and-runs", "unexpected-rejection", execution),
                [],
            )

            execution["outerWrapper"].update({"attempted": False, "packStatus": 7})
            attempted = dict(preflight)
            attempted.update({
                "category": "product",
                "cliExitCode": 7,
                "packInvocation": {
                    "attempted": True,
                    "dispatchProfile": "outer-execveat",
                    "pathPreserving": True,
                    "executionMode": "outer-path-preserving",
                },
            })
            (sample / "outer-pack.json").write_text(json.dumps(attempted) + "\n", encoding="utf-8")
            self.assertEqual(
                gate.check_pack_report(sample, "nodejs", "accepted-and-runs", "unexpected-rejection", execution),
                [],
            )

    def test_bionic_no_pack_product_preflight_passes_the_execution_evidence_gate(self) -> None:
        specification = importlib.util.spec_from_file_location("real_sample_evidence_gate_bionic_preflight", GATE)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        gate = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = gate
        specification.loader.exec_module(gate)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        closures = json.loads(RUNTIME_CLOSURES.read_text(encoding="utf-8"))
        project = json.loads(json.dumps(
            next(item for item in manifest["corpus"]["projects"] if item["projectId"] == "nodejs")
        ))
        project["executionPolicy"]["outerWrapper"]["expectedResult"] = "unexpected-rejection"
        closures["projects"]["nodejs"]["outerWrapper"]["expectedResult"] = "unexpected-rejection"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            sample = root / "nodejs"

            result = json.loads((sample / "result.json").read_text(encoding="utf-8"))
            result["layers"]["outerWrapper"].update({
                "expected": "unexpected-rejection",
                "actual": "unexpected-rejection",
                "status": "passed",
                "reason": "expected product preflight",
            })
            (sample / "result.json").write_text(json.dumps(result) + "\n", encoding="utf-8")

            execution = json.loads((sample / "execution.json").read_text(encoding="utf-8"))
            outer = execution["outerWrapper"]
            outer.update({
                "attempted": False,
                "status": None,
                "targetStatus": None,
                "helperStatus": None,
                "helperStatusPath": None,
                "helperResultPath": None,
                "preflightResultPath": "logs/outer.preflight.json",
                "statusPath": None,
                "outcome": "preflight-product-failure",
                "invocationSource": "runner-preflight",
                "reason": "setup unavailable",
                "result": "unexpected-rejection",
                "expectedResult": "unexpected-rejection",
                "packStatus": None,
                "packStatusPath": None,
            })

            summary = json.loads((sample / "logs" / "bionic-node-result.json").read_text(encoding="utf-8"))
            protocol = summary["outer"]["protocol"]
            protocol.update({
                "attempted": False,
                "helperStatus": None,
                "targetStatus": None,
                "containerStatus": None,
                "dockerStatus": None,
                "cleanupContainerStatus": None,
                "outcome": "helper-protocol",
                "readinessSeen": False,
            })
            summary["outer"].update({
                "actual": "unexpected-rejection",
                "reason": "setup unavailable",
                "attempted": False,
                "helperStatus": None,
                "targetStatus": None,
                "containerStatus": None,
                "dockerStatus": None,
                "cleanupContainerStatus": None,
                "outcome": "helper-protocol",
                "preflightOutcome": "preflight-product-failure",
            })
            summary.update({
                "status": "failed",
                "behaviorEquivalent": False,
                "containerStatuses": {"setup": 0, "baseline": 0, "outer": None},
                "cleanupContainerStatuses": {"setup": 0, "baseline": 0, "outer": None},
            })
            for field in (
                "containerStatus",
                "dockerStatus",
                "cleanupContainerStatus",
                "runpathVerified",
                "protocolAuthority",
                "cleanupAuthority",
                "allNamedContainersReaped",
            ):
                outer[field] = summary["outer"].get(field)
            (sample / "logs" / "bionic-node-result.json").write_text(
                json.dumps(summary) + "\n", encoding="utf-8"
            )

            closure = json.loads((sample / "runtime-closure.json").read_text(encoding="utf-8"))
            closure.update({
                "executionStatus": "failed",
                "behaviorEquivalent": False,
                "containerStatuses": {"setup": 0, "baseline": 0, "outer": None},
                "cleanupContainerStatuses": {"setup": 0, "baseline": 0, "outer": None},
            })
            (sample / "runtime-closure.json").write_text(json.dumps(closure) + "\n", encoding="utf-8")

            (sample / "logs" / "outer.preflight.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "producer": "run-real-sample-matrix.sh",
                    "layer": "outerWrapper",
                    "stage": "outerWrapper",
                    "outcome": "preflight-product-failure",
                    "reason": "setup unavailable",
                    "attempted": False,
                    "helperStatus": None,
                    "targetStatus": None,
                }) + "\n",
                encoding="utf-8",
            )
            pack_report = json.loads((sample / "outer-pack.json").read_text(encoding="utf-8"))
            pack_report.update({
                "success": False,
                "category": "preflight",
                "output": {"published": False},
                "diagnostics": [{"code": "bionic.preflight", "message": "setup unavailable"}],
                "cliExitCode": None,
                "packInvocation": {"attempted": False},
            })
            (sample / "outer-pack.json").write_text(json.dumps(pack_report) + "\n", encoding="utf-8")
            (sample / "execution.json").write_text(json.dumps(execution) + "\n", encoding="utf-8")
            (sample / "logs" / "behavior-equivalent").write_text("false\n", encoding="utf-8")
            for marker_name in ("outer.status", "outer.helper-status", "outer-pack.status"):
                (sample / "logs" / marker_name).unlink(missing_ok=True)

            self.assertEqual(gate.check_sample(project, "pr", root, closures), [])

    def test_failed_bionic_summary_cannot_be_hidden_by_passing_result_layers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            sample = root / "nodejs"
            result = json.loads((sample / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["layers"]["baseline"]["actual"], "accepted-and-runs")
            self.assertEqual(result["layers"]["outerWrapper"]["actual"], "accepted-and-runs")

            summary_path = sample / "logs" / "bionic-node-result.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["status"] = "failed"
            summary["containerStatuses"]["setup"] = 125
            summary["runpathVerified"] = False
            summary_path.write_text(json.dumps(summary) + "\n", encoding="utf-8")

            gate_result = self.run_gate(root)
            self.assertNotEqual(gate_result.returncode, 0)
            self.assertIn("status must be passed exactly when both baseline and outer actuals are accepted-and-runs", gate_result.stderr)
            self.assertIn("matching successful setup container status", gate_result.stderr)
            self.assertIn("runpathVerified differs from summary", gate_result.stderr)

    def test_nightly_requires_baseline_and_outer_for_every_identity(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        projects = manifest["corpus"]["projects"]
        self.assertEqual(len(projects), 100)
        for project in projects:
            for layer in ("baseline", "outerWrapper"):
                policy = project["executionPolicy"][layer]
                self.assertTrue(policy["applicable"], f"{project['projectId']}/{layer}")
                self.assertIn(policy["expectedResult"], {"accepted-and-runs", "environment-unavailable"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            result = self.run_gate(root, tier="nightly")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("evidence-sanitized.txt is missing", result.stderr)
            self.assertNotIn("tier runtime coverage policy is incomplete", result.stderr)

    def test_nightly_missing_closure_fails_a_short_circuited_dynamic_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root, tier="nightly")
            closure_path = root / "busybox" / "runtime-closure.json"
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            closure["status"] = "environment-unavailable"
            closure_path.write_text(json.dumps(closure) + "\n", encoding="utf-8")
            result = self.run_gate(root, tier="nightly")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("status=assembled", result.stderr)

    def test_ci_aggregate_is_bound_to_every_result_and_layer_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            aggregate_path = root / "aggregate.json"
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            aggregate["records"] = aggregate["records"][1:]
            aggregate_path.write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
            result = self.run_gate(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("records must contain exactly one record", result.stderr)

            self.write_complete_text_evidence(root)
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            aggregate["layerCounts"]["baseline"] = {"accepted-and-runs": 1}
            aggregate_path.write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
            result = self.run_gate(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("layerCounts do not match", result.stderr)

    def test_aggregate_evidence_fields_are_bound_to_retained_sources(self) -> None:
        for field, forged in (
            ("producer", "forged-producer"),
            ("pageSize", "forged-page-size"),
            ("features", ["forged-feature"]),
            ("firstFailureLayer", "outer"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                root.mkdir()
                self.write_complete_text_evidence(root)
                aggregate_path = root / "aggregate.json"
                aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
                aggregate["records"][0][field] = forged
                aggregate_path.write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
                result = self.run_gate(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            result_path = root / "gnu-bash" / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["firstFailureLayer"] = "outer"
            result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
            gate_result = self.run_gate(root)
            self.assertNotEqual(gate_result.returncode, 0)
            self.assertIn("firstFailureLayer", gate_result.stderr)

    def test_bionic_host_identity_mutations_fail_evidence_validation(self) -> None:
        for field, value in (
            ("image", "termux/termux-docker:latest"),
            ("imageId", "sha256:" + "0" * 64),
            ("loader", "/system/bin/other-linker"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "evidence"
                root.mkdir()
                self.write_complete_text_evidence(root)
                summary_path = root / "nodejs" / "logs" / "bionic-node-result.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                summary[field] = value
                summary_path.write_text(json.dumps(summary) + "\n", encoding="utf-8")
                result = self.run_gate(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr)

    def test_static_execution_success_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            result_path = root / "gnu-bash" / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["layers"]["static"]["expected"] = "accepted-and-runs"
            result["layers"]["static"]["actual"] = "accepted-and-runs"
            result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("static", result.stderr)

    def test_empty_artifact_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            result_path = root / "gnu-bash" / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["artifactSha256"] = ""
            result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifactSha256", result.stderr)

    def test_execution_artifact_path_is_bound_to_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution_path = root / "busybox" / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["artifactPath"] = "/tmp/forged-busybox"
            execution["baseline"]["resolvedCommand"][0] = "/tmp/forged-busybox"
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("execution artifactPath does not match provenance.artifactPath", result.stderr)

    def test_forged_baseline_arguments_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution_path = root / "busybox" / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["baseline"]["resolvedCommand"][1] = "--help"
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("baseline: resolvedCommand does not match the effective declared argv", result.stderr)

    def test_outer_arguments_must_match_derived_baseline_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution_path = root / "busybox" / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["outerWrapper"]["resolvedCommand"][1] = "--help"
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outerWrapper: resolvedCommand must match baseline argv with only the executable replaced", result.stderr)

    def test_outer_mode_must_match_resolved_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution_path = root / "busybox" / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["outerWrapper"]["mode"] = "outer-path-preserving"
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("execution mode does not match the resolved registry/closure policy", result.stderr)

    def test_outer_invocation_source_identifies_runner_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution_path = root / "busybox" / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["outerWrapper"]["invocationSource"] = "declared"
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invocationSource must identify the runner-derived wrapper recipe", result.stderr)

    def test_generic_product_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            (root / "gnu-bash" / "urprotect-report.json").write_text("{}\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("UrProtect report", result.stderr)

    def test_source_and_runtime_artifact_hashes_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            hashes_path = root / "busybox" / "hashes.txt"
            hashes = hashes_path.read_text(encoding="utf-8").replace("runtimeArtifactSha256=" + "a" * 64, "runtimeArtifactSha256=" + "b" * 64)
            hashes_path.write_text(hashes, encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source and reconstructed runtime artifact hashes differ", result.stderr)

    def test_missing_runtime_closure_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            (root / "gnu-bash" / "runtime-closure.json").unlink()
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runtime-closure.json", result.stderr)

    def test_accepted_execution_requires_assembled_runtime_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution = json.loads((root / "busybox" / "execution.json").read_text(encoding="utf-8"))
            self.assertEqual(execution["baseline"]["result"], "accepted-and-runs")
            self.assertEqual(execution["outerWrapper"]["result"], "accepted-and-runs")
            closure_path = root / "busybox" / "runtime-closure.json"
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            self.assertEqual(closure["status"], "assembled")
            closure["status"] = "environment-unavailable"
            closure_path.write_text(json.dumps(closure) + "\n", encoding="utf-8")

            result = self.run_gate(root, manifest_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("status=assembled", result.stderr)

    def test_missing_execution_stream_is_rejected_for_applicable_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            status_path = root / "busybox" / "execution.json"
            execution = json.loads(status_path.read_text(encoding="utf-8"))
            execution["baseline"]["stdoutPath"] = "logs/missing.stdout"
            status_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stdoutPath", result.stderr)

    def test_missing_helper_result_is_rejected_for_applicable_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            execution_path = root / "busybox" / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["baseline"]["helperResultPath"] = "logs/missing.helper.json"
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("helperResultPath", result.stderr)

    def test_target_exit_requires_readiness_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            for layer, helper_name in (
                ("baseline", "baseline.helper.json"),
                ("outerWrapper", "outer.helper.json"),
            ):
                with self.subTest(layer=layer):
                    helper_path = root / "busybox" / "logs" / helper_name
                    helper = json.loads(helper_path.read_text(encoding="utf-8"))
                    self.assertEqual(helper["targetStatus"], 0)
                    self.assertEqual(
                        json.loads((root / "busybox" / "execution.json").read_text(encoding="utf-8"))[layer]["status"],
                        0,
                    )
                    helper["readinessSeen"] = False
                    helper_path.write_text(json.dumps(helper) + "\n", encoding="utf-8")

                    result = self.run_gate(root, manifest_path)

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("readinessSeen", result.stderr)
                    helper["readinessSeen"] = True
                    helper_path.write_text(json.dumps(helper) + "\n", encoding="utf-8")

    def test_accepted_outer_requires_status_and_stream_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            (root / "busybox" / "logs" / "outer.stdout").write_text("different\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outer stdout differ", result.stderr)

    def test_unexpected_acceptance_keeps_actual_cli_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            result_path = root / "gnu-bash" / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["layers"]["static"]["expected"] = "expected-rejected"
            result["layers"]["static"]["actual"] = "unexpected-acceptance"
            result["cliSuccess"] = True
            result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
            gate_result = self.run_gate(root, manifest_path)
            self.assertNotEqual(gate_result.returncode, 0)
            self.assertNotIn("UrProtect report success does not match the actual CLI result", gate_result.stderr)

    def test_environment_preflight_retains_no_helper_status_or_process_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            sample = root / "busybox"
            result_path = sample / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["firstFailureLayer"] = "environment"
            result["layers"]["baseline"]["actual"] = "environment-unavailable"
            result["layers"]["outerWrapper"]["actual"] = "environment-unavailable"
            result["cliSuccess"] = False
            result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
            report_path = sample / "urprotect-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["success"] = False
            report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
            closure_path = sample / "runtime-closure.json"
            closure = json.loads(closure_path.read_text(encoding="utf-8"))
            closure["status"] = "environment-unavailable"
            closure_path.write_text(json.dumps(closure) + "\n", encoding="utf-8")
            execution_path = sample / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            for layer, log_name in (("baseline", "baseline"), ("outerWrapper", "outer")):
                entry = execution[layer]
                entry["attempted"] = False
                entry["status"] = None
                entry["targetStatus"] = None
                entry["helperStatus"] = None
                entry["helperStatusPath"] = None
                entry["helperResultPath"] = None
                entry["preflightResultPath"] = f"logs/{log_name}.preflight.json"
                entry["statusPath"] = None
                entry["outcome"] = "preflight-environment-unavailable"
                entry["invocationSource"] = "runner-preflight"
                entry["reason"] = "locked runtime closure unavailable"
                (sample / entry["preflightResultPath"]).write_text(
                    json.dumps({
                        "schemaVersion": 1,
                        "producer": "run-real-sample-matrix.sh",
                        "layer": layer,
                        "stage": layer,
                        "outcome": "preflight-environment-unavailable",
                        "reason": "locked runtime closure unavailable",
                        "attempted": False,
                        "helperStatus": None,
                        "targetStatus": None,
                    }) + "\n",
                    encoding="utf-8",
                )
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            (sample / "outer-pack.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "toolVersion": "contract-test",
                    "success": False,
                    "payload": {},
                    "output": {"published": False},
                    "diagnostics": [{"code": "environment-unavailable", "message": "setup unavailable"}],
                }) + "\n",
                encoding="utf-8",
            )
            gate_result = self.run_gate(root, manifest_path)
            self.assertNotEqual(gate_result.returncode, 0)
            self.assertNotIn("attempted execution must retain an integer status", gate_result.stderr)
            self.assertNotIn("execution status must be null when no process was attempted", gate_result.stderr)

    def test_runner_preflight_and_helper_environment_outcomes_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_pr_ready_evidence(root)
            specification = importlib.util.spec_from_file_location(
                "real_sample_evidence_gate_preflight", GATE
            )
            self.assertIsNotNone(specification)
            self.assertIsNotNone(specification.loader)
            module = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(module)
            sample = root / "busybox"
            execution_path = sample / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            baseline = execution["baseline"]
            baseline.update({
                "attempted": False,
                "status": None,
                "targetStatus": None,
                "helperStatus": None,
                "helperStatusPath": None,
                "helperResultPath": None,
                "preflightResultPath": "logs/baseline.preflight.json",
                "statusPath": None,
                "outcome": "preflight-environment-unavailable",
                "invocationSource": "runner-preflight",
                "reason": "closure unavailable before helper invocation",
                "result": "environment-unavailable",
            })
            (sample / "logs" / "baseline.preflight.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "producer": "run-real-sample-matrix.sh",
                    "layer": "baseline",
                    "stage": "baseline",
                    "outcome": "preflight-environment-unavailable",
                    "reason": "closure unavailable before helper invocation",
                    "attempted": False,
                    "helperStatus": None,
                    "targetStatus": None,
                }) + "\n",
                encoding="utf-8",
            )
            preflight_errors = module.check_execution_layer(
                sample, execution, "busybox", "baseline", "accepted-and-runs", "environment-unavailable"
            )
            self.assertEqual(preflight_errors, [])
            accepted_errors = module.check_execution_layer(
                sample, execution, "busybox", "baseline", "accepted-and-runs", "accepted-and-runs"
            )
            self.assertIn("accepted-and-runs requires an actual helper result", " ".join(accepted_errors))

            baseline.update({
                "attempted": False,
                "helperStatus": 125,
                "helperStatusPath": "logs/baseline.helper-status",
                "helperResultPath": "logs/baseline.helper.json",
                "preflightResultPath": None,
                "outcome": "helper-environment",
                "reason": None,
                "result": "environment-unavailable",
            })
            (sample / "logs" / "baseline.helper-status").write_text("125\n", encoding="utf-8")
            (sample / "logs" / "baseline.helper.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "producer": "run-isolated-real-sample.py",
                    "attempted": False,
                    "helperStatus": 125,
                    "targetStatus": None,
                    "readinessSeen": False,
                    "outcome": "helper-environment",
                }) + "\n",
                encoding="utf-8",
            )
            helper_errors = module.check_execution_layer(
                sample, execution, "busybox", "baseline", "accepted-and-runs", "environment-unavailable"
            )
            self.assertEqual(helper_errors, [])

    def test_target_reserved_status_is_not_classified_as_helper_environment_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            sample = root / "busybox"
            result_path = sample / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["firstFailureLayer"] = "environment"
            result["layers"]["baseline"]["actual"] = "runtime-failure"
            result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
            execution_path = sample / "execution.json"
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            baseline = execution["baseline"]
            baseline["attempted"] = True
            baseline["status"] = 125
            baseline["targetStatus"] = 125
            baseline["helperStatus"] = None
            baseline["helperStatusPath"] = None
            baseline["statusPath"] = "logs/baseline.status"
            baseline["result"] = "runtime-failure"
            (sample / "logs" / "baseline.status").write_text("125\n", encoding="utf-8")
            (sample / "logs" / "baseline.helper.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "producer": "run-isolated-real-sample.py",
                    "attempted": True,
                    "helperStatus": None,
                    "targetStatus": 125,
                    "readinessSeen": True,
                    "outcome": "target-exit",
                }) + "\n",
                encoding="utf-8",
            )
            execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
            gate_result = self.run_gate(root, manifest_path)
            self.assertNotEqual(gate_result.returncode, 0)
            self.assertIn("observed 'runtime-failure'", gate_result.stderr)
            self.assertNotIn("environment-unavailable must retain helper status", gate_result.stderr)

    def test_raw_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            (root / "gnu-bash" / "source.deb").write_text("not a real archive", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw sample/archive-like", result.stderr)

    def test_sanitization_marker_and_raw_temporary_path_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            manifest_path = self.write_pr_ready_evidence(root)
            (root / "evidence-sanitized.txt").write_text("evidence-sanitized=false\n", encoding="utf-8")
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("evidence-sanitized=true", result.stderr)

            (root / "evidence-sanitized.txt").write_text("evidence-sanitized=true\n", encoding="utf-8")
            (root / "gnu-bash" / "logs" / "run.log").write_text(
                "raw path=/runner/_temp/urprotect-real-samples-123\n", encoding="utf-8"
            )
            result = self.run_gate(root, manifest_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw runner temporary/package-cache path", result.stderr)


if __name__ == "__main__":
    unittest.main()
