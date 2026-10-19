from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "fixtures/tls-runtime-matrix.json"
MATRIX_RUNNER = ROOT / "scripts/run-tls-runtime-matrix.py"
MATRIX_CHECKER = ROOT / "scripts/check-tls-runtime-matrix-evidence.py"
PREREQ_RUNNER = ROOT / "scripts/run-tls-prerequisite-probes.py"
PREREQ_CHECKER = ROOT / "scripts/check-tls-prerequisite-evidence.py"


class TlsRuntimeMatrixContractTests(unittest.TestCase):
    def test_registry_is_a_closed_four_dimensional_contract(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(registry["schemaVersion"], 1)
        self.assertEqual(
            registry["models"],
            ["local-exec", "initial-exec", "local-dynamic", "general-dynamic", "tlsdesc"],
        )
        self.assertEqual(registry["profiles"], ["outer-execveat", "host-context-entry"])
        self.assertEqual(registry["runtimes"], ["glibc", "musl", "bionic"])
        self.assertEqual(registry["lifecycles"], ["current-thread", "registered-worker"])
        self.assertEqual(
            len(registry["models"])
            * len(registry["profiles"])
            * len(registry["runtimes"])
            * len(registry["lifecycles"]),
            60,
        )
        self.assertEqual(
            registry["controlRow"],
            "initial-exec.host-context-entry.glibc.current-thread",
        )
        expected_promoted_rows = [
            "general-dynamic.host-context-entry.glibc.current-thread",
            "initial-exec.host-context-entry.glibc.current-thread",
            "local-dynamic.host-context-entry.glibc.current-thread",
            "tlsdesc.host-context-entry.glibc.current-thread",
        ]
        self.assertEqual(registry["promotedRows"], expected_promoted_rows)
        self.assertEqual(
            registry["sourceFixtures"],
            {
                "local-exec": "native/urprotect-runtime/build/host-context-tlsle-fixture.so",
                "initial-exec": "native/urprotect-runtime/build/host-context-tls-fixture.so",
                "local-dynamic": "native/urprotect-runtime/build/host-context-tlsld-fixture.so",
                "general-dynamic": "native/urprotect-runtime/build/host-context-tlsgd-fixture.so",
                "tlsdesc": "native/urprotect-runtime/build/host-context-tlsdesc-fixture.so",
            },
        )
        self.assertEqual(
            {
                tuple(row_id.split("."))
                for row_id in registry["promotedRows"]
            },
            {
                (model, "host-context-entry", "glibc", "current-thread")
                for model in ("initial-exec", "local-dynamic", "general-dynamic", "tlsdesc")
            },
        )

    def test_matrix_runner_and_checker_bind_independent_rows(self) -> None:
        runner = MATRIX_RUNNER.read_text(encoding="utf-8")
        checker = MATRIX_CHECKER.read_text(encoding="utf-8")
        for marker in (
            "model",
            "profile",
            "runtime",
            "lifecycle",
            "environment-unavailable",
            "not-applicable",
            "accepted-and-runs",
            "native-preflight.json",
            "SHA256SUMS",
            "controlRow",
        ):
            self.assertIn(marker, runner if marker != "controlRow" else runner + checker)
        self.assertIn("EXPECTED_ROW_COUNT = 60", checker)
        self.assertIn("promoted rows drifted", checker)
        self.assertIn("is not closed", checker)
        self.assertIn("sourceFixture", checker)
        self.assertIn("sourceSha256", checker)
        self.assertIn("runtimeIdentity", runner)
        self.assertIn("verify_artifact_identity", checker)
        self.assertIn("behavioralOracleSha256", runner)
        self.assertIn("source-handoff.json", runner)
        self.assertIn("check_stage_tls_binding", checker)
        self.assertIn("--lifecycle", runner)
        self.assertIn("find_symbol_selector", runner)
        for fixture in (
            "host-context-tls-fixture.so",
            "host-context-tlsle-fixture.so",
            "host-context-tlsld-fixture.so",
            "host-context-tlsgd-fixture.so",
            "host-context-tlsdesc-fixture.so",
        ):
            self.assertIn(fixture, runner)

    def test_tls_wrapper_requires_explicit_identity_and_has_no_ie_defaults(self) -> None:
        wrapper = (ROOT / "scripts/run-tls-host-context-rehydration-e2e.sh").read_text(encoding="utf-8")
        for field in ("unit", "source_file", "function_id", "model", "profile", "runtime", "lifecycle", "expected_entry_status", "producer_id"):
            self.assertIn(f"{field}=''", wrapper)
        for required in ("--model", "--runtime", "--profile", "--lifecycle", "--unit", "--source", "--function-id", "--producer-id", "--entry-status"):
            self.assertIn(required, wrapper)
        self.assertIn("source fixture does not belong to TLS model", wrapper)
        self.assertIn("function selector does not belong to TLS model", wrapper)
        self.assertNotIn("unit='tls.initial-exec", wrapper)
        self.assertIn("TLS enrichment requires explicit model/runtime/profile/lifecycle/unit", wrapper)

    def test_ci_tls_workflow_invocation_passes_the_complete_tuple(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        start = workflow.index("      - name: Run managed TLS initial-exec transformed-image evidence\n")
        end = workflow.find("\n      - name:", start + 1)
        step = workflow[start:] if end < 0 else workflow[start:end]
        run_marker = step.index("        run: |\n") + len("        run: |\n")
        run_lines = []
        for line in step[run_marker:].splitlines():
            if line.startswith("      - name:"):
                break
            run_lines.append(line[10:] if line.startswith("          ") else line)
        source = "\n".join(run_lines)
        command_lines = source.splitlines()
        call_index = next(i for i, line in enumerate(command_lines) if "./scripts/run-tls-host-context-rehydration-e2e.sh" in line)
        parts = []
        while call_index < len(command_lines):
            line = command_lines[call_index].strip()
            continues = line.endswith("\\")
            parts.append(line[:-1].rstrip() if continues else line)
            call_index += 1
            if not continues:
                break
        invocation = shlex.split(" ".join(parts))
        self.assertEqual(invocation, [
            "./scripts/run-tls-host-context-rehydration-e2e.sh",
            "--tier", "${tier}",
            "--unit", "tls.initial-exec.glibc.host-context-entry",
            "--model", "initial-exec",
            "--profile", "host-context-entry",
            "--runtime", "glibc",
            "--lifecycle", "current-thread",
            "--source", "$source_file",
            "--function-id", "$function_id",
            "--entry-status", "43",
            "--producer-id", "gcc-c-tls-initial-exec",
        ])
        self.assertIn("source_file=native/urprotect-runtime/build/host-context-tls-fixture.so", source)
        self.assertIn("readelf --syms -W", source)
        self.assertLess(source.index("make -C native/urprotect-runtime tls-fixture"), source.index("source_file="))
        self.assertLess(source.index("function_id=\"$(readelf"), source.index("./scripts/run-tls-host-context-rehydration-e2e.sh"))

    def test_non_ie_missing_inputs_and_wrong_selector_fail_before_publication(self) -> None:
        wrapper = ROOT / "scripts/run-tls-host-context-rehydration-e2e.sh"
        with tempfile.TemporaryDirectory(prefix="tls-wrapper-negative-") as temporary:
            artifact_root = Path(temporary) / "out"
            environment = os.environ.copy()
            environment["TLS_EVIDENCE_ARTIFACT_ROOT"] = str(artifact_root)
            missing = subprocess.run(
                ["bash", str(wrapper), "--tier", "release", "--model", "tlsdesc", "--profile", "host-context-entry", "--runtime", "glibc", "--lifecycle", "current-thread", "--entry-status", "43", "--producer-id", "gcc-aarch64-tlsdesc-fixture"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(missing.returncode, 2)
            self.assertIn("missing required TLS identity input", missing.stderr)
            self.assertFalse(artifact_root.exists())
        fixture = ROOT / "native/urprotect-runtime/build/host-context-tlsdesc-fixture.so"
        if not fixture.is_file():
            self.skipTest("TLS descriptor fixture has not been built in this test environment")
        with tempfile.TemporaryDirectory(prefix="tls-selector-negative-") as temporary:
            artifact_root = Path(temporary) / "out"
            environment = os.environ.copy()
            environment["TLS_EVIDENCE_ARTIFACT_ROOT"] = str(artifact_root)
            wrong_selector = subprocess.run(
                ["bash", str(wrapper), "--tier", "release", "--unit", "tlsdesc.host-context-entry.glibc.current-thread", "--model", "tlsdesc", "--profile", "host-context-entry", "--runtime", "glibc", "--lifecycle", "current-thread", "--source", str(fixture), "--function-id", "symtab:0", "--entry-status", "43", "--producer-id", "gcc-aarch64-tlsdesc-fixture"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertFalse(artifact_root.exists())
        self.assertEqual(wrong_selector.returncode, 2)
        self.assertIn("function selector does not belong", wrong_selector.stderr)
        ie_fixture = ROOT / "native/urprotect-runtime/build/host-context-tls-fixture.so"
        if not ie_fixture.is_file():
            self.skipTest("initial-exec fixture has not been built in this test environment")
        with tempfile.TemporaryDirectory(prefix="tls-source-owner-negative-") as temporary:
            artifact_root = Path(temporary) / "out"
            environment = os.environ.copy()
            environment["TLS_EVIDENCE_ARTIFACT_ROOT"] = str(artifact_root)
            wrong_source = subprocess.run(
                ["bash", str(wrapper), "--tier", "release", "--unit", "tlsdesc.host-context-entry.glibc.current-thread", "--model", "tlsdesc", "--profile", "host-context-entry", "--runtime", "glibc", "--lifecycle", "current-thread", "--source", str(ie_fixture), "--function-id", "dynsym:0", "--entry-status", "43", "--producer-id", "gcc-aarch64-tlsdesc-fixture"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(wrong_source.returncode, 2)
            self.assertIn("source fixture does not belong", wrong_source.stderr)
            self.assertFalse(artifact_root.exists())

    def test_native_tls_metadata_has_nearest_negative_boundaries(self) -> None:
        native_test = (ROOT / "native/urprotect-runtime/host_context_tls_validation_test.c").read_text(encoding="utf-8")
        native_validation = (ROOT / "native/urprotect-runtime/host_image_validation.c").read_text(encoding="utf-8")
        for marker in (
            "absolute-VA STT_TLS value",
            "STT_TLS extent beyond PT_TLS",
            "TLS module-id PT_TLS requirement",
            "non-dependency vn_file",
            "duplicate libc dependency with loader vn_file",
        ):
            self.assertIn(marker, native_test)
        self.assertIn("STT_TLS st_value is a TLS-block-relative", native_validation)
        self.assertNotIn("urp_tls_relative_value", native_validation)

    def test_prerequisite_probe_covers_all_android_tags_and_pt_tls_cases(self) -> None:
        runner = PREREQ_RUNNER.read_text(encoding="utf-8")
        checker = PREREQ_CHECKER.read_text(encoding="utf-8")
        for marker in (
            "DT_ANDROID_REL",
            "DT_ANDROID_RELSZ",
            "DT_ANDROID_RELA",
            "DT_ANDROID_RELASZ",
            "DT_ANDROID_RELR",
            "DT_ANDROID_RELRCOUNT",
            "DT_ANDROID_RELRSZ",
            "DT_ANDROID_RELRENT",
            "tls-executable",
            "owner-read-only",
            "tls-empty-memory",
            "filesz-exceeds-memsz",
            "non-power-two-alignment",
            "SHA256SUMS",
        ):
            self.assertIn(marker, runner)
        self.assertIn("exactly eight rows", checker)
        self.assertIn("six bounded cases", checker)

    def test_ci_and_regression_matrix_reference_tls_producers(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        regression = (ROOT / "tests/regression-matrix.json").read_text(encoding="utf-8")
        for marker in (
            "run-tls-prerequisite-probes.py",
            "check-tls-prerequisite-evidence.py",
            "run-tls-runtime-matrix.py",
            "check-tls-runtime-matrix-evidence.py",
            ".artifacts/tls-runtime/",
            ".artifacts/tls-prerequisites/",
        ):
            self.assertIn(marker, workflow)
            self.assertIn(marker, regression)


if __name__ == "__main__":
    unittest.main()
