#!/usr/bin/env python3
"""Regression tests for the repository-owned compatibility matrix contract."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "fixtures" / "manifest.json"
VALIDATOR = REPO_ROOT / "scripts" / "validate-fixtures.py"
RENDERER = REPO_ROOT / "scripts" / "render-compatibility-matrix.py"


class FixtureMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(MANIFEST.read_text())

    def test_runtime_evidence_declarations_bind_exact_current_ci_roots(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()

        def step(name: str) -> str:
            marker = f"      - name: {name}\n"
            start = workflow.index(marker)
            end = workflow.find("\n      - name:", start + len(marker))
            return workflow[start:] if end < 0 else workflow[start:end]

        def feature(feature_id: str) -> dict[str, object]:
            return next(item for item in self.data["features"] if item["id"] == feature_id)

        def producer_root(block: str, script: str) -> str:
            start = block.index(script)
            option = block.index("--artifact-root", start)
            return block[option:].splitlines()[0].split()[1].rstrip(";")

        def generated_paths(record: dict[str, object]) -> list[str]:
            paths = [path for path in record["evidence"] if path.startswith(".artifacts/")]
            self.assertTrue(paths, f"{record['id']} has no generated evidence paths")
            self.assertTrue(
                all(not any(character in path for character in "*?[]") for path in paths),
                f"{record['id']} must declare exact paths, not globs",
            )
            return paths

        rows = (
            (
                "runtime.cfi.transformed-backtrace.glibc.host-context-entry",
                "Run transformed CFI/unwind native evidence",
                "./scripts/run-cfi-host-context-e2e.sh",
                "scripts/check-cfi-evidence.py",
            ),
            (
                "runtime.indirect-control.shared-jump-table-copy.glibc.host-context-entry",
                "Run and check transformed shared jump-table evidence",
                "./scripts/run-shared-jump-table-copy-e2e.sh",
                "scripts/check-shared-jump-table-evidence.py",
            ),
        )
        roots: set[str] = set()
        for feature_id, step_name, runner, checker in rows:
            record = feature(feature_id)
            block = step(step_name)
            root = producer_root(block, runner)
            self.assertTrue(root.startswith(".artifacts/"), root)
            self.assertEqual(Path(root).name, "current", root)
            self.assertNotIn("${tier}", root)
            self.assertNotIn(root, roots, f"distinct producer rows must not share an artifact root: {root}")
            roots.add(root)
            self.assertIn('--tier "${tier}"', block)
            producer = (REPO_ROOT / runner.removeprefix("./")).read_text()
            self.assertIn("--artifact-root", producer)
            if runner == "./scripts/run-cfi-host-context-e2e.sh":
                self.assertIn('requested_artifact_root="$2"', producer)
                self.assertIn('artifact_root="$requested_artifact_root"', producer)
                self.assertIn('if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then', producer)
            else:
                self.assertIn('root_arg="$2"', producer)
                self.assertIn('root="$(realpath -m -- "$root_arg")"', producer)
                self.assertIn('[[ ! -e "$root" && ! -L "$root" ]]', producer)

            declared = generated_paths(record)
            self.assertTrue(
                all(path == root or path.startswith(root + "/") for path in declared),
                f"{feature_id} declarations do not belong to CI producer root {root}: {declared}",
            )
            if checker == "scripts/check-shared-jump-table-evidence.py":
                unit = "runtime.indirect-control.shared-table.glibc.host-context-entry"
                self.assertIn(f"shared_positive={root}/{unit}", block)
                self.assertIn("scripts/check-rehydration-evidence.py", block)
                self.assertIn(f'{checker} "${{shared_positive}}"', block)
                self.assertIn("--selected-function", block)
            else:
                match = re.search(
                    re.escape(checker) + r"\s+\\?\s*([^\s]+)",
                    block,
                )
                self.assertIsNotNone(match, f"CI does not invoke {checker} in {step_name}")
                self.assertEqual(match.group(1), root)

        provider_id = "runtime.indirect-control.external-provider.glibc.host-context-entry"
        provider_feature = feature(provider_id)
        self.assertEqual("unknown", provider_feature["status"])
        self.assertIn("nextEvidence", provider_feature)
        provider_block = step("Run required transformed external-provider evidence")
        provider_root = producer_root(provider_block, "./scripts/run-external-provider-e2e.sh")
        self.assertEqual(
            ".artifacts/indirect-control/external-provider/current",
            provider_root,
        )
        self.assertIn("if: always()", provider_block)
        self.assertIn('--tier "${tier}"', provider_block)
        provider_runner = (REPO_ROOT / "scripts/run-external-provider-e2e.sh").read_text()
        self.assertIn('dotnet "$cli" protect-image', provider_runner)
        self.assertIn('dotnet "$cli" rehydrate-image', provider_runner)
        self.assertIn("environment-unavailable: external-provider evidence requires native AArch64", provider_runner)
        self.assertIn("environment-unavailable: external-provider evidence requires glibc", provider_runner)
        self.assertIn('URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT="$positive"', provider_runner)
        self.assertIn("test_external_provider_evidence.py", provider_runner)
        provider_check = step("Independently check transformed external-provider evidence")
        self.assertIn("if: always()", provider_check)
        self.assertIn("external-provider-${run_key}.status", provider_check)
        self.assertIn("external-provider-${run_key}.root", provider_check)
        self.assertIn("external-provider-check-${run_key}.log", provider_check)
        self.assertIn("external-provider-check-${run_key}.status", provider_check)
        self.assertIn('statuses=("${PIPESTATUS[@]}")', provider_check)
        self.assertIn('python3 scripts/check-external-provider-evidence.py "${positive}"', provider_check)

        rollback_block = step("Run required source-loader provider rollback evidence")
        rollback_root = producer_root(
            rollback_block,
            "./scripts/run-external-provider-rollback-oracle.sh",
        )
        self.assertEqual(
            ".artifacts/indirect-control/provider-loaded-rollback/current",
            rollback_root,
        )
        self.assertIn("if: always()", rollback_block)
        rollback_check = step("Independently check source-loader rollback evidence and root regressions")
        self.assertIn("if: always()", rollback_check)
        self.assertIn("provider-loaded-rollback-${run_key}.root", rollback_check)
        self.assertIn("provider-loaded-rollback-check-${run_key}.log", rollback_check)
        self.assertIn("provider-loaded-rollback-check-${run_key}.status", rollback_check)
        self.assertIn('statuses=("${PIPESTATUS[@]}")', rollback_check)
        self.assertIn("scripts/check-external-provider-rollback-evidence.py --root", rollback_check)
        self.assertIn("URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT=", rollback_check)
        self.assertIn("tests.test_external_provider_rollback_evidence", rollback_check)

        provider_roots = {provider_root, rollback_root}
        self.assertTrue(provider_roots.isdisjoint(roots))
        self.assertEqual(2, len(provider_roots))
        declared_provider_paths = generated_paths(provider_feature)
        self.assertIn(
            f"{provider_root}/runtime.indirect-control.external-provider.glibc.host-context-entry/SHA256SUMS",
            declared_provider_paths,
            "the closed provider root is the unit directory, not the outer runner directory",
        )
        self.assertTrue(
            all(any(path == root or path.startswith(root + "/") for root in provider_roots)
                for path in declared_provider_paths),
            f"{provider_id} evidence must bind only the two exact current provider roots",
        )
        declaration_gate = step("Require full CFI and indirect-control evidence declarations")
        for feature_id, _, _, _ in rows:
            self.assertIn(f"--feature {feature_id}", declaration_gate)
        self.assertIn(
            "--feature runtime.indirect-control.jump-table.glibc.host-context-entry",
            declaration_gate,
        )
        self.assertIn(f"--feature {provider_id}", declaration_gate)
        upload = step("Upload protection-tls evidence")
        self.assertIn(".artifacts/indirect-control/", upload)
        self.assertIn("include-hidden-files: true", upload)
        workflow_triggers = workflow.split("\njobs:", 1)[0]
        self.assertRegex(workflow_triggers, r"(?m)^  push:\s*$")
        self.assertRegex(workflow_triggers, r"(?m)^  pull_request:\s*$")
        self.assertNotRegex(workflow_triggers, r"(?m)^\s+paths(?:-ignore)?:")
        build_job = workflow.split("  build-and-test:", 1)[1].split("\n  real-sample-matrix:", 1)[0]
        self.assertRegex(build_job, r"(?m)^    if: \$\{\{ needs\['ci-event-gate'\]\.outputs\.run_full == 'true' \}\}$")
        self.assertIn("needs: ci-event-gate", build_job)
        self.assertNotIn("proof-binding-fix-20261014T202700Z", workflow)
        self.assertNotIn('cp -a ".artifacts/cfi/', workflow)
        self.assertIn(
            'cp -a ".artifacts/indirect-control/${tier}" .artifacts/indirect-control/pr',
            workflow,
        )

    def run_validator(
        self,
        data: dict[str, object],
        tier: str = "pr",
        emit: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=REPO_ROOT / "fixtures",
            prefix=".matrix-validation-",
            suffix=".json",
            delete=False,
        ) as stream:
            json.dump(data, stream)
            path = Path(stream.name)
        try:
            command = [sys.executable, str(VALIDATOR), str(path), "--tier", tier]
            if emit:
                command.append("--emit")
            return subprocess.run(
                command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            path.unlink(missing_ok=True)

    def test_current_manifest_contains_validated_bionic_handoff_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.bionic-handoff"
        )
        self.assertEqual(feature["status"], "validated")
        self.assertTrue(
            any(path.endswith("/host-context/build-and-test.log") for path in feature["evidence"])
        )

    def test_external_provider_observation_stays_unknown_and_manifest_digest_is_current(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.indirect-control.external-provider.glibc.host-context-entry"
        )
        self.assertEqual("unknown", feature["status"])
        self.assertIn("nextEvidence", feature)
        constraints = " ".join(feature["constraints"])
        self.assertIn("scoped-observation-not-promoted", constraints)
        self.assertIn("No musl, Bionic", constraints)
        roots = {
            ".artifacts/indirect-control/external-provider/current/",
            ".artifacts/indirect-control/provider-loaded-rollback/current/",
        }
        generated = [path for path in feature["evidence"] if path.startswith(".artifacts/")]
        self.assertTrue(generated)
        self.assertTrue(all(any(path.startswith(root) for root in roots) for path in generated))

        corpus_path = REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json"
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        fixture_registry = next(
            item for item in corpus["retainedEvidenceRegistries"]
            if item["registryId"] == "fixture-matrix"
        )
        self.assertEqual(
            hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
            fixture_registry["sha256"],
        )

    def test_release_tier_selects_the_explicit_hardening_witness(self) -> None:
        result = self.run_validator(self.data, tier="release", emit=True)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        selected = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        release_cases = [case for case in selected if case["tier"] == "release"]
        self.assertEqual(
            [case["id"] for case in release_cases],
            ["c-gcc-glibc-release-hardened"],
        )
        release_case = release_cases[0]
        self.assertEqual(release_case["builder"], "gcc-c")
        self.assertEqual(release_case["variant"], "release-hardened")
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "elf.release.full-relro-now"
        )
        self.assertEqual(feature["status"], "validated")
        self.assertIn("GNU RELRO", feature["obligation"])
        self.assertIn("BIND_NOW", " ".join(feature["constraints"]))

    def test_production_host_context_pack_is_current_and_validated(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.production-pack"
        )
        self.assertEqual(feature["status"], "validated")
        self.assertIn("test_managed_host_context.sh", feature["witness"])
        self.assertIn("test_managed_host_context.sh", feature["oracle"])
        self.assertIn("host-context/managed", " ".join(feature["evidence"]))

    def test_bionic_host_context_handoff_has_a_native_adapter_oracle(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        features = {feature["id"]: feature for feature in self.data["features"]}
        handoff = features["runtime.host-context.bionic-handoff"]
        self.assertEqual(handoff["status"], "validated")
        self.assertTrue(
            any(path.endswith("/host-context/build-and-test.log") for path in handoff["evidence"])
        )
        self.assertTrue(
            any("F_SEAL_WRITE" in constraint for constraint in handoff["constraints"])
        )
        self.assertTrue(
            any("production-pack" in constraint for constraint in handoff["constraints"])
        )
        self.assertEqual(features["runtime.host-context.production-pack"]["status"], "validated")

    def test_android_jni_is_labeled_as_a_baseline(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        features = {feature["id"]: feature for feature in self.data["features"]}
        android = features["android.jni.native-bridge"]
        self.assertIn("does not execute packed output", " ".join(android["constraints"]))

    def test_pt_tls_has_a_bounded_initial_exec_slice(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.pt-tls"
        )
        self.assertEqual(feature["status"], "validated")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_tls_fixture.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_image_validation.c")
        self.assertIn(
            "native/urprotect-runtime/host_context_tls_fixture.c",
            feature["evidence"],
        )
        self.assertIn(
            ".artifacts/host-context/managed/tls-result.txt",
            feature["evidence"],
        )
        self.assertTrue(any("initial-exec" in item for item in feature["constraints"]))

    def test_unknown_feature_requires_next_evidence(self) -> None:
        data = copy.deepcopy(self.data)
        feature = next(
            item
            for item in data["features"]
            if item["id"] == "runtime.host-context.production-pack"
        )
        feature["status"] = "unknown"
        feature["nextEvidence"] = "test evidence"
        del feature["nextEvidence"]

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nextEvidence", result.stderr or result.stdout)

    def test_gnu_property_has_a_bounded_bti_slice(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.gnu-property"
        )
        self.assertEqual(feature["status"], "validated")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_property_fixture.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_image_validation.c")
        self.assertIn(
            ".artifacts/host-context/managed/property-result.txt",
            feature["evidence"],
        )
        self.assertTrue(any("BTI" in item for item in feature["constraints"]))

    def test_dependency_resolution_has_a_bounded_validated_slice(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.dependency-resolution"
        )
        self.assertEqual(feature["status"], "validated")
        self.assertIn("DT_NEEDED", " ".join(feature["constraints"]))
        self.assertIn("Search roots", " ".join(feature["constraints"]))
        self.assertIn("COMPATIBILITY.md", feature["evidence"])

        lifecycle = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.constructor-destructor"
        )
        self.assertNotIn("DT_NEEDED", lifecycle["obligation"])

    def test_constructor_destructor_lifecycle_is_separate_from_path_search(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

        feature_ids = [item["id"] for item in self.data["features"]]
        self.assertFalse(
            any(
                feature_id.startswith("runtime.host-context.")
                and "lifecycle" in feature_id
                and "path-search" in feature_id
                for feature_id in feature_ids
            )
        )
        self.assertEqual(
            feature_ids.count("runtime.host-context.constructor-destructor"),
            1,
        )
        self.assertEqual(feature_ids.count("runtime.host-context.path-search"), 1)

        lifecycle = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.constructor-destructor"
        )
        self.assertEqual(lifecycle["status"], "validated")
        self.assertIn("DT_INIT", " ".join(lifecycle["constraints"]))
        self.assertNotIn("DT_RPATH", lifecycle["obligation"])
        self.assertNotIn("DT_RUNPATH", lifecycle["obligation"])
        self.assertNotIn("DT_TEXTREL", lifecycle["obligation"])
        for relocation_tag in (
            "DT_REL",
            "DT_RELSZ",
            "DT_RELENT",
            "DT_RELA",
            "DT_RELASZ",
            "DT_RELAENT",
            "DT_RELR",
            "DT_RELRSZ",
            "DT_RELRENT",
            "DT_JMPREL",
            "DT_PLTRELSZ",
            "DT_PLTREL",
        ):
            self.assertNotIn(relocation_tag, lifecycle["obligation"])
        self.assertIn("COMPATIBILITY.md", lifecycle["evidence"])
        self.assertTrue(any("before urp_entry" in item for item in lifecycle["constraints"]))

        path_search = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.path-search"
        )
        self.assertEqual(path_search["status"], "rejected")
        self.assertIn("DT_RPATH", path_search["obligation"])
        self.assertIn("DT_RUNPATH", path_search["obligation"])
        for lifecycle_tag in (
            "DT_INIT",
            "DT_FINI",
            "DT_INIT_ARRAY",
            "DT_FINI_ARRAY",
            "DT_INIT_ARRAYSZ",
            "DT_FINI_ARRAYSZ",
            "DT_PREINIT_ARRAY",
            "DT_PREINIT_ARRAYSZ",
        ):
            self.assertNotIn(lifecycle_tag, path_search["obligation"])
        self.assertNotIn("DT_NEEDED", path_search["obligation"])
        self.assertNotIn("DT_TEXTREL", path_search["obligation"])
        for relocation_tag in (
            "DT_REL",
            "DT_RELSZ",
            "DT_RELENT",
            "DT_RELA",
            "DT_RELASZ",
            "DT_RELAENT",
            "DT_RELR",
            "DT_RELRSZ",
            "DT_RELRENT",
            "DT_JMPREL",
            "DT_PLTRELSZ",
            "DT_PLTREL",
        ):
            self.assertNotIn(relocation_tag, path_search["obligation"])
        self.assertIn("path-search", path_search["reason"])
        self.assertTrue(any("zero handle" in item for item in path_search["constraints"]))

    def test_text_relocation_is_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.text-relocation"
        )
        self.assertEqual(feature["status"], "rejected")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(
            feature["oracle"],
            "native/urprotect-runtime/host_image_validation.c",
        )
        self.assertIn("DT_TEXTREL", feature["obligation"])
        self.assertIn("writable-text relocation", feature["reason"])
        self.assertIn("W^X", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(
            feature["negativeOracle"],
            "native/urprotect-runtime/host_image_validation.c",
        )
        self.assertIn("COMPATIBILITY.md", feature["evidence"])
        self.assertIn(
            ".trellis/spec/backend/runtime-compatibility.md",
            feature["evidence"],
        )
        self.assertTrue(
            any(
                "DT_NULL" in item and "DT_TEXTREL" in item
                for item in feature["constraints"]
            )
        )
        self.assertTrue(
            any("surrounding bytes" in item for item in feature["constraints"])
        )
        self.assertTrue(
            any(
                "nonzero sentinel" in item and "zero handle" in item
                for item in feature["constraints"]
            )
        )
        self.assertTrue(any("positive" in item for item in feature["constraints"]))
        self.assertTrue(any("RELATIVE/RELR" in item for item in feature["constraints"]))
        text_constraints = " ".join(feature["constraints"])
        self.assertNotIn("DT_REL", text_constraints)
        self.assertNotIn("DT_JMPREL", text_constraints)
        self.assertIn(
            "runtime.host-context.unsupported-relocation-table",
            text_constraints,
        )

        feature_ids = [item["id"] for item in self.data["features"]]
        self.assertEqual(feature_ids.count("runtime.host-context.text-relocation"), 1)
        relative = next(
            item
            for item in self.data["features"]
            if item["id"] == "elf.relocation.aarch64-relative"
        )
        self.assertEqual(relative["status"], "validated")
        relative_description = " ".join(
            [
                relative["obligation"],
                *relative["constraints"],
            ]
        ).lower()
        self.assertNotIn("dt_textrel", relative_description)
        self.assertNotIn("text-relocation", relative_description)

    def test_unsupported_relocation_table_is_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.unsupported-relocation-table"
        )
        self.assertEqual(feature["status"], "rejected")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_image_validation.c")
        for relocation_tag in (
            "DT_REL",
            "DT_RELSZ",
            "DT_RELENT",
        ):
            self.assertIn(relocation_tag, feature["obligation"])
        self.assertNotIn("DT_JMPREL", feature["obligation"])
        self.assertIn("partial", feature["obligation"])
        for dependency_tag in ("DT_NEEDED", "DT_AUXILIARY", "DT_FILTER"):
            self.assertNotIn(dependency_tag, feature["obligation"])
        self.assertIn("RELATIVE/RELR", feature["reason"])
        self.assertIn("weak-undefined JUMP_SLOT subset", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_image_validation.c")
        self.assertIn("COMPATIBILITY.md", feature["evidence"])
        self.assertIn(
            ".trellis/spec/backend/runtime-compatibility.md",
            feature["evidence"],
        )
        self.assertTrue(any("DT_NULL" in item for item in feature["constraints"]))
        self.assertTrue(any("surrounding bytes" in item for item in feature["constraints"]))
        self.assertTrue(
            any(
                "nonzero sentinel" in item and "zero handle" in item
                for item in feature["constraints"]
            )
        )
        self.assertTrue(any("RELATIVE/RELR" in item for item in feature["constraints"]))
        self.assertTrue(any("positive" in item for item in feature["constraints"]))
        self.assertTrue(
            any("JUMP_SLOT in ordinary DT_RELA" in item for item in feature["constraints"])
        )

        plt = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.weak-undefined-jump-slot"
        )
        self.assertEqual(plt["status"], "validated")
        self.assertIn("DT_JMPREL", plt["obligation"])
        self.assertIn("DT_PLTRELSZ", plt["obligation"])
        self.assertIn("DT_PLTREL=DT_RELA", plt["obligation"])
        self.assertEqual(
            plt["negativeWitness"],
            "native/urprotect-runtime/host_context_plt_self_test.c",
        )
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn(
            "--feature runtime.host-context.weak-undefined-jump-slot",
            workflow,
        )

        feature_ids = [item["id"] for item in self.data["features"]]
        self.assertEqual(
            feature_ids.count("runtime.host-context.unsupported-relocation-table"),
            1,
        )
        relative = next(
            item
            for item in self.data["features"]
            if item["id"] == "elf.relocation.aarch64-relative"
        )
        self.assertEqual(relative["status"], "validated")
        relative_description = " ".join(
            [relative["obligation"], *relative["constraints"]]
        )
        self.assertIn("RELATIVE/RELR", relative_description)
        self.assertNotIn("DT_REL", relative_description)
        self.assertNotIn("DT_JMPREL", relative_description)

    def test_android_packed_relocations_are_an_explicit_rejected_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.android-packed-relocation"
        )
        self.assertEqual(feature["status"], "rejected")
        for relocation_tag in (
            "DT_ANDROID_REL",
            "DT_ANDROID_RELSZ",
            "DT_ANDROID_RELA",
            "DT_ANDROID_RELASZ",
            "DT_ANDROID_RELR",
            "DT_ANDROID_RELRSZ",
            "DT_ANDROID_RELRENT",
            "DT_ANDROID_RELRCOUNT",
        ):
            self.assertIn(relocation_tag, feature["obligation"])
        self.assertIn("RELATIVE/RELR", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_image_validation.c")
        self.assertIn("COMPATIBILITY.md", feature["evidence"])
        self.assertTrue(any("DT_NULL" in item for item in feature["constraints"]))
        self.assertTrue(
            any(
                "nonzero sentinel" in item and "zero handle" in item
                for item in feature["constraints"]
            )
        )
        self.assertTrue(any("positive" in item for item in feature["constraints"]))

    def test_symbol_version_fixture_path_and_hash_are_pinned(self) -> None:
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "elf.symbol-version.definitions"
        )
        fixture_path = Path("tests/UrProtect.Core.Tests/Fixtures/SymbolVersions/liburp-versioned.so")
        fixture = REPO_ROOT / fixture_path
        self.assertIn(fixture_path.as_posix(), feature["evidence"])
        self.assertTrue(fixture.is_file())
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        constraints = " ".join(feature["constraints"])
        self.assertIn(digest, constraints)
        self.assertIn(digest, (REPO_ROOT / "tests/UrProtect.Core.Tests/Fixtures/SymbolVersions/README.md").read_text())

    def test_symbol_version_parser_observation_does_not_promote_runtime_support(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        features = {feature["id"]: feature for feature in self.data["features"]}
        parser = features["elf.symbol-version.definitions"]
        requirements = features["elf.symbol-version.requirements"]
        host_context = features["runtime.host-context.symbol-version"]
        libc_requirements = features[
            "runtime.host-context.dependency-symbol-version-requirements"
        ]

        self.assertEqual(parser["status"], "proven")
        self.assertEqual(
            parser["witness"],
            "tests/UrProtect.Core.Tests/Structural/ElfSymbolVersionParserTests.cs",
        )
        self.assertIn(
            "liburp-versioned.so",
            " ".join(parser["evidence"]),
        )
        self.assertTrue(any("not confirmed ELF prevalence" in item for item in parser["constraints"]))
        self.assertTrue(any("actual CI fingerprint histogram" in item for item in parser["constraints"]))
        self.assertEqual(requirements["status"], "proven")
        self.assertIn("DT_VERNEED", requirements["obligation"])
        self.assertEqual(host_context["status"], "rejected")
        self.assertIn("DT_VERDEF", host_context["obligation"])
        self.assertEqual(libc_requirements["status"], "validated")
        self.assertIn("libc.so.6", libc_requirements["obligation"])

    def test_symbol_versions_are_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.symbol-version"
        )
        self.assertEqual(feature["status"], "rejected")
        for symbol_version_tag in (
            "DT_VERSYM",
            "DT_VERDEF",
            "DT_VERDEFNUM",
            "DT_VERNEED",
            "DT_VERNEEDNUM",
        ):
            self.assertIn(symbol_version_tag, feature["obligation"])
        self.assertIn("versioned entry lookup", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_image_validation.c")
        self.assertIn("COMPATIBILITY.md", feature["evidence"])
        self.assertTrue(any("DT_NULL" in item for item in feature["constraints"]))
        self.assertTrue(
            any(
                "nonzero handle sentinel" in item and "zero handle" in item
                for item in feature["constraints"]
            )
        )
        self.assertTrue(any("declared entry name remains unversioned" in item for item in feature["constraints"]))

    def test_feature_covering_strategy_is_required(self) -> None:
        data = copy.deepcopy(self.data)
        data["coverage"]["strategy"] = "cartesian"

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage.strategy", result.stderr or result.stdout)

    def test_case_cannot_repeat_a_feature_identifier(self) -> None:
        data = copy.deepcopy(self.data)
        case = next(item for item in data["cases"] if item["id"] == "c-gcc-glibc-pie")
        case["features"].append(case["features"][0])

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate feature identifiers", result.stderr or result.stdout)

    def test_required_case_cannot_claim_unknown_feature(self) -> None:
        data = copy.deepcopy(self.data)
        case = next(item for item in data["cases"] if item["id"] == "c-termux-bionic-pie")
        case["required"] = True
        production = next(item for item in data["features"] if item["id"] == "runtime.host-context.production-pack")
        production["status"] = "unknown"
        production["nextEvidence"] = "test evidence"
        case["features"].append("runtime.host-context.production-pack")

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-supporting features", result.stderr or result.stdout)

    def test_bionic_case_requires_kernel_and_architecture_facts(self) -> None:
        data = copy.deepcopy(self.data)
        host = next(item for item in data["cases"] if item["id"] == "c-termux-bionic-pie")["host"]
        del host["kernel"]

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host.kernel", result.stderr or result.stdout)

    def test_bionic_case_records_exact_package_hashes_and_licenses(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        host = next(item for item in self.data["cases"] if item["id"] == "c-termux-bionic-pie")["host"]
        self.assertEqual(host["packageIndex"], "live")
        self.assertTrue(host["packageInputsReproducible"])
        self.assertEqual(
            host["packageProvenance"],
            "version-and-sha256-locked-package-set",
        )
        packages = host["compilerPackages"]
        self.assertEqual(
            {package["name"] for package in packages},
            {
                "clang",
                "libcompiler-rt",
                "libllvm",
                "libxml2",
                "lld",
                "llvm",
                "make",
                "ndk-sysroot",
            },
        )
        for package in packages:
            self.assertRegex(package["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(package["filename"].endswith("_aarch64.deb"))
            self.assertTrue(package["licenses"])
            self.assertTrue(package["licenseSource"])

    def test_bionic_package_lock_rejects_missing_hashes_or_unpinned_dependencies(self) -> None:
        for mutation, expected_error in (
            (lambda package: package.pop("sha256"), "sha256"),
            (lambda package: package.__setitem__("sha256", "0" * 63), "sha256"),
            (lambda package: package.pop("licenses"), "licenses"),
        ):
            data = copy.deepcopy(self.data)
            host = next(item for item in data["cases"] if item["id"] == "c-termux-bionic-pie")["host"]
            mutation(host["compilerPackages"][0])

            result = self.run_validator(data)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected_error, result.stderr or result.stdout)

        data = copy.deepcopy(self.data)
        host = next(item for item in data["cases"] if item["id"] == "c-termux-bionic-pie")["host"]
        host["compilerPackages"].pop()
        result = self.run_validator(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact compiler dependency set", result.stderr or result.stdout)

    def test_rejected_feature_requires_a_valid_negative_oracle(self) -> None:
        data = copy.deepcopy(self.data)
        feature = next(
            item
            for item in data["features"]
            if item["id"] == "runtime.host-context.path-search"
        )
        feature["negativeOracle"] = "fixtures/missing-negative-oracle"

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("negativeOracle", result.stderr or result.stdout)

    def test_rendered_matrix_explains_unknown_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "matrix.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(RENDERER),
                    str(MANIFEST),
                    "--output",
                    str(output),
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text()
            self.assertIn("unknown` rows never count as support", rendered)
            self.assertIn("runtime.host-context.bionic-handoff | validated", rendered)
            self.assertIn("runtime.host-context.gnu-property | validated", rendered)
            self.assertIn("runtime.host-context.pt-tls | validated", rendered)
            self.assertIn("runtime.host-context.dependency-resolution | validated", rendered)
            self.assertIn("runtime.host-context.constructor-destructor | validated", rendered)
            self.assertIn("runtime.host-context.path-search | rejected", rendered)
            self.assertIn("runtime.host-context.text-relocation | rejected", rendered)
            self.assertIn("runtime.host-context.unsupported-relocation-table | rejected", rendered)
            self.assertIn("runtime.host-context.android-packed-relocation | rejected", rendered)
            self.assertIn("runtime.host-context.symbol-version | rejected", rendered)
            self.assertIn("elf.symbol-version.definitions | proven", rendered)


if __name__ == "__main__":
    unittest.main()
