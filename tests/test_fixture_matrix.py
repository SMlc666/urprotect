#!/usr/bin/env python3
"""Regression tests for the repository-owned compatibility matrix contract."""

from __future__ import annotations

import copy
import hashlib
import json
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

    def test_legacy_wrapper_and_android_jni_are_labeled_as_baselines(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        features = {feature["id"]: feature for feature in self.data["features"]}
        legacy = features["runtime.wrapper-v1-baseline"]
        self.assertEqual(legacy["status"], "validated")
        self.assertIn("Wrapper 0.2", legacy["obligation"])
        self.assertIn(
            "not an in-process HostContext support claim",
            " ".join(legacy["constraints"]),
        )
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
            "tests/UrProtect.Core.Tests/ElfSymbolVersionParserTests.cs",
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
            self.assertIn("runtime.wrapper-v1-baseline | validated", rendered)


if __name__ == "__main__":
    unittest.main()
