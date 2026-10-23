from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "tests" / "regression-matrix.json"
VALIDATOR = ROOT / "scripts" / "validate-regression-matrix.py"


class RegressionMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(MATRIX.read_text(encoding="utf-8"))

    def validate(self, data: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", dir=ROOT, delete=False) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)

    def test_current_matrix_is_valid_and_covers_required_classes(self) -> None:
        result = self.validate(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("managed.coverage-guided-fuzz", {case["id"] for case in self.data["cases"]})
        self.assertIn("native.host-context-e2e", {case["id"] for case in self.data["cases"]})
        self.assertIn("native.managed-rehydration-host-context-e2e", {case["id"] for case in self.data["cases"]})
        runtime_cases = {case["id"] for case in self.data["cases"]}
        self.assertTrue({
            "fixture.runtime-covering-matrix-pr",
            "fixture.runtime-covering-matrix-nightly",
            "fixture.runtime-covering-matrix-release",
        }.issubset(runtime_cases))
        provider_cases = {
            case["id"]: case
            for case in self.data["cases"]
            if case["id"] in {
                "fixture.indirect-control-external-provider-e2e",
                "native.external-provider-provider-loaded-rollback",
            }
        }
        self.assertEqual(
            {
                "fixture.indirect-control-external-provider-e2e",
                "native.external-provider-provider-loaded-rollback",
            },
            provider_cases.keys(),
        )
        for case in provider_cases.values():
            self.assertTrue(case["required"])
            self.assertEqual("native-arm64", case["platform"])
            self.assertEqual(["pr", "nightly", "release"], case["tiers"])
        e2e = provider_cases["fixture.indirect-control-external-provider-e2e"]
        external_root = ".artifacts/indirect-control/external-provider/current"
        rollback_root = ".artifacts/indirect-control/provider-loaded-rollback/current"
        self.assertIn("run-external-provider-e2e.sh", e2e["command"])
        self.assertIn("--artifact-root " + external_root, e2e["command"])
        self.assertIn(
            external_root + "/runtime.indirect-control.external-provider.glibc.host-context-entry",
            e2e["command"],
        )
        self.assertIn("check-external-provider-evidence.py", e2e["command"])
        self.assertIn(external_root + "/SHA256SUMS", e2e["artifacts"])
        self.assertIn("transformed-native-rollback.json", " ".join(e2e["artifacts"]))
        self.assertIn("provider-ci-logs/external-provider-*.log", " ".join(e2e["artifacts"]))
        rollback = provider_cases["native.external-provider-provider-loaded-rollback"]
        self.assertIn("run-external-provider-rollback-oracle.sh", rollback["command"])
        self.assertIn("--artifact-root " + rollback_root, rollback["command"])
        self.assertIn("--root " + rollback_root, rollback["command"])
        self.assertIn("check-external-provider-rollback-evidence.py", rollback["command"])
        self.assertIn("tests.test_external_provider_rollback_evidence", rollback["command"])
        self.assertIn(rollback_root + "/SHA256SUMS", rollback["artifacts"])
        self.assertIn("provider-ci-logs/provider-loaded-rollback-*.log", " ".join(rollback["artifacts"]))

    def test_shared_musl_indirect_control_e2e_is_registered_with_identity_and_build_evidence(self) -> None:
        case = next(
            item for item in self.data["cases"]
            if item["id"] == "fixture.indirect-control-shared-jump-table-copy-musl"
        )
        self.assertTrue(case["required"])
        self.assertEqual(["pr", "nightly", "release"], case["tiers"])
        self.assertEqual("native-arm64-container", case["platform"])
        self.assertEqual(1200, case["budgetSeconds"])
        self.assertIn("run-shared-jump-table-copy-e2e.sh", case["command"])
        self.assertIn("--runtime musl", case["command"])
        self.assertIn("runtime.indirect-control.shared-table.musl.host-context-entry", case["command"])

        witnesses = "\n".join(case["artifacts"])
        self.assertIn(".artifacts/musl-container/environment.txt", witnesses)
        self.assertIn("shared-table-behavior.json", witnesses)
        for handoff in (
            "source-handoff.json",
            "handoff.json",
            "observer-source-handoff.json",
            "observer-transformed-handoff.json",
        ):
            self.assertIn(handoff, witnesses)
        for identity in (
            "runtime-identity/source/identity.json",
            "runtime-identity/target/identity.json",
            "runtime-identity/observer-source/identity.json",
            "runtime-identity/observer-transformed/identity.json",
        ):
            self.assertIn(identity, witnesses)
        self.assertIn("native-build.command.txt", witnesses)
        self.assertIn("native-build.stdout", witnesses)
        self.assertIn("native-build.stderr", witnesses)
        self.assertIn("native-build.status", witnesses)
        for nested_sidecar in (
            "host-context-image-handoff/native-build.command.txt",
            "host-context-image-handoff/native-build.stdout",
            "host-context-image-handoff/native-build.stderr",
            "host-context-image-handoff/native-build.status",
        ):
            self.assertIn(nested_sidecar, witnesses)

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        shared_step_start = workflow.index("      - name: Run shared musl indirect jump-table evidence")
        shared_step_end = workflow.index("      - name: Upload musl container and indirect-control evidence", shared_step_start)
        shared_step = workflow[shared_step_start:shared_step_end]
        self.assertIn("--runtime musl", shared_step)
        self.assertIn("--require-runtime-identity", shared_step)
        self.assertIn("check-shared-jump-table-evidence.py", shared_step)

    def test_duplicate_case_id_is_rejected(self) -> None:
        data = copy.deepcopy(self.data)
        data["cases"].append(copy.deepcopy(data["cases"][0]))
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr)

    def test_empty_artifact_witness_is_rejected(self) -> None:
        data = copy.deepcopy(self.data)
        data["cases"][0]["artifacts"] = []
        result = self.validate(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifacts", result.stderr)

    def test_missing_artifact_path_is_rejected_when_witness_check_is_requested(self) -> None:
        data = copy.deepcopy(self.data)
        data["cases"][0]["artifacts"] = [".artifacts/does-not-exist/"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", dir=ROOT, delete=False) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    str(path),
                    "--tier",
                    "pr",
                    "--check-artifacts",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact witnesses", result.stderr)

    def test_optional_android_row_is_not_required(self) -> None:
        android = next(case for case in self.data["cases"] if case["class"] == "android-native-bridge")
        self.assertFalse(android["required"])
        self.assertEqual(android["expected"], "pass-or-unavailable")


if __name__ == "__main__":
    unittest.main()
