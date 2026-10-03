#!/usr/bin/env python3
"""Evidence-gate regressions without acquiring real samples."""
from __future__ import annotations

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
            (project_root / "logs").mkdir(parents=True)
            closure_policy = closure_projects.get(project["projectId"], closure_projects.get("*", {}))
            closure_baseline = closure_policy.get("baseline", {}) if isinstance(closure_policy, dict) else {}
            closure_outer = closure_policy.get("outerWrapper", {}) if isinstance(closure_policy, dict) else {}
            manifest_baseline = project["executionPolicy"]["baseline"]
            manifest_outer = project["executionPolicy"]["outerWrapper"]
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
            expected = {
                layer: project["executionPolicy"][layer]["expectedResult"]
                for layer in ("static", "baseline", "outerWrapper", "hostContext")
            }
            runtime = project["target"]["runtime"]
            loader = project["target"]["loader"]
            baseline_applicable = expected["baseline"] != "not-applicable"
            outer_applicable = expected["outerWrapper"] != "not-applicable"
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
            (project_root / "runtime-closure.json").write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "projectId": project["projectId"],
                    "runtime": runtime,
                    "loader": loader,
                    "status": "assembled" if baseline_applicable else "not-applicable",
                    "sourceArtifactSha256": artifact_hash,
                    "runtimeArtifactSha256": artifact_hash,
                }) + "\n",
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
                    "attempted": baseline_applicable,
                    "outcome": "target-exit" if baseline_applicable else "not-applicable",
                    "invocationSource": (
                        "declared" if "command" in closure_baseline or "command" in manifest_baseline
                        else "validated-wildcard" if baseline_applicable
                        else "not-applicable"
                    ),
                    "resolvedCommand": baseline_command if baseline_applicable else None,
                    "expectedStatus": 0 if baseline_applicable else None,
                    "status": 0 if baseline_applicable else None,
                    "targetStatus": 0 if baseline_applicable else None,
                    "helperStatus": None,
                    "helperStatusPath": None,
                    "helperResultPath": "logs/baseline.helper.json" if baseline_applicable else None,
                    "preflightResultPath": None,
                    "result": expected["baseline"],
                    "stdoutPath": "logs/baseline.stdout" if baseline_applicable else None,
                    "stderrPath": "logs/baseline.stderr" if baseline_applicable else None,
                    "statusPath": "logs/baseline.status" if baseline_applicable else None,
                    "reason": "baseline is not applicable in this contract fixture" if not baseline_applicable else None,
                    "expectedResult": expected["baseline"],
                },
                "outerWrapper": {
                    "applicable": outer_applicable,
                    "attempted": outer_applicable,
                    "outcome": "target-exit" if outer_applicable else "not-applicable",
                    "mode": outer_mode if outer_applicable else None,
                    "invocationSource": "runner-derived-wrapper" if outer_applicable else "not-applicable",
                    "resolvedCommand": outer_command,
                    "expectedStatus": 0 if outer_applicable else None,
                    "status": 0 if outer_applicable else None,
                    "targetStatus": 0 if outer_applicable else None,
                    "helperStatus": None,
                    "helperStatusPath": None,
                    "helperResultPath": "logs/outer.helper.json" if outer_applicable else None,
                    "preflightResultPath": None,
                    "packStatus": 0 if outer_applicable else None,
                    "packStatusPath": "logs/outer-pack.status" if outer_applicable else None,
                    "result": expected["outerWrapper"],
                    "stdoutPath": "logs/outer.stdout" if outer_applicable else None,
                    "stderrPath": "logs/outer.stderr" if outer_applicable else None,
                    "statusPath": "logs/outer.status" if outer_applicable else None,
                    "reason": "outer wrapper is not applicable in this contract fixture" if not outer_applicable else None,
                    "expectedResult": expected["outerWrapper"],
                },
            }
            (project_root / "execution.json").write_text(json.dumps(execution) + "\n", encoding="utf-8")
            (project_root / "outer-pack.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "toolVersion": "contract-test",
                        "success": True,
                        "payload": {},
                        "output": {"published": True},
                        "diagnostics": [],
                        "cliExitCode": 0,
                    }
                    if outer_applicable
                    else {
                        "schemaVersion": 1,
                        "status": "not-applicable",
                        "reason": "outer wrapper is outside this contract fixture",
                    }
                ) + "\n",
                encoding="utf-8",
            )
            (project_root / "result.json").write_text(json.dumps(result) + "\n", encoding="utf-8")
            (project_root / "raw-inputs-removed.txt").write_text(
                "raw-inputs-removed=true\n", encoding="utf-8"
            )
            for name in ("baseline.stdout", "baseline.stderr", "outer.stdout", "outer.stderr"):
                (project_root / "logs" / name).write_text("", encoding="utf-8")
            if baseline_applicable:
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
            if outer_applicable:
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
            (project_root / "logs" / "run.log").write_text("run evidence\n", encoding="utf-8")
        ids = [project["projectId"] for project in manifest["corpus"]["projects"]]
        count = len(ids)
        aggregate = {
            "schemaVersion": 2,
            "tier": "pr",
            "requiredProjectCount": count,
            "observedProjectCount": count,
            "identityCount": count,
            "projectIds": ids,
            "coverage": {
                "approvedTargetProjectCount": manifest["corpus"]["targetProjectCount"],
                "currentIdentityCount": count,
                "shortfall": manifest["corpus"]["targetProjectCount"] - count,
            },
            "featureHistogram": [],
            "firstFailureLayers": {},
        }
        aggregate["tier"] = tier
        (root / "aggregate.json").write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
        (root / "aggregate.md").write_text("# aggregate\n", encoding="utf-8")

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
            },
            "outerWrapper": {
                "expectedResult": "accepted-and-runs",
                "mode": "outer-execveat",
                "compare": ["status", "stdout", "stderr"],
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
            [sys.executable, str(PROJECT_FIELDS), json.dumps(project), str(RUNTIME_CLOSURES)],
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
        self.assertEqual(fields["invocation"], "-")
        self.assertEqual(fields["outerApplicable"], "false")
        self.assertEqual(fields["command"], [])

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

    def test_explicit_environment_boundary_is_not_promoted_by_closure_default(self) -> None:
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
        self.assertEqual(expected["baseline"], "environment-unavailable")
        self.assertEqual(expected["outerWrapper"], "environment-unavailable")

    def test_not_applicable_registry_layers_are_not_promoted_by_default_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.write_complete_text_evidence(root)
            result = self.run_gate(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("tier runtime coverage policy is incomplete", result.stderr)
            self.assertIn("nodejs/baseline", result.stderr)
            self.assertIn("nodejs/outerWrapper", result.stderr)

    def test_nightly_requires_baseline_and_outer_for_every_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            result = self.run_gate(root, tier="nightly")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("tier runtime coverage policy is incomplete", result.stderr)
            self.assertIn("gnu-bash/baseline", result.stderr)
            self.assertIn("nodejs/outerWrapper", result.stderr)

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
                entry["invocationSource"] = (
                    "runner-derived-wrapper" if layer == "outerWrapper" else "runner-preflight"
                )
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


if __name__ == "__main__":
    unittest.main()
