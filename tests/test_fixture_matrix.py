#!/usr/bin/env python3
"""Regression tests for the repository-owned compatibility matrix contract."""

from __future__ import annotations

import copy
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

    def test_current_manifest_contains_unknown_bionic_handoff_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.bionic-handoff"
        )
        self.assertEqual(feature["status"], "unknown")
        self.assertTrue(feature["nextEvidence"])

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

    def test_production_host_context_pack_gap_is_explicitly_unknown(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.production-pack"
        )
        self.assertEqual(feature["status"], "unknown")
        self.assertIn("entry-image adapter", feature["nextEvidence"])
        self.assertIn("v2-capable launcher", feature["nextEvidence"])
        self.assertIn("managed pack/dispatch oracle", feature["nextEvidence"])

    def test_pt_tls_is_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.pt-tls"
        )
        self.assertEqual(feature["status"], "rejected")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn("dlopen", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn(
            "native/urprotect-runtime/host_context_self_test.c",
            feature["evidence"],
        )
        self.assertIn(
            ".artifacts/host-context/pr/self-test.log",
            feature["evidence"],
        )
        self.assertTrue(any("p_filesz" in item for item in feature["constraints"]))

    def test_unknown_feature_requires_next_evidence(self) -> None:
        data = copy.deepcopy(self.data)
        feature = next(
            item
            for item in data["features"]
            if item["id"] == "runtime.host-context.bionic-handoff"
        )
        del feature["nextEvidence"]

        result = self.run_validator(data)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nextEvidence", result.stderr or result.stdout)

    def test_gnu_property_is_an_explicit_rejected_host_context_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.gnu-property"
        )
        self.assertEqual(feature["status"], "rejected")
        self.assertEqual(
            feature["witness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn("property negotiation", feature["reason"])
        self.assertIn("BTI/PAC", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_adapter.c")
        self.assertIn(
            ".artifacts/host-context/pr/self-test.log",
            feature["evidence"],
        )
        self.assertTrue(any("zero image handle" in item for item in feature["constraints"]))

    def test_dependency_resolution_is_an_explicit_rejected_boundary(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        feature = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.dependency-resolution"
        )
        self.assertEqual(feature["status"], "rejected")
        for dependency_tag in ("DT_NEEDED", "DT_AUXILIARY", "DT_FILTER"):
            self.assertIn(dependency_tag, feature["obligation"])
        self.assertIn("dependency-resolution", feature["reason"])
        self.assertIn("search-path", feature["reason"])
        self.assertIn("symbol-scope", feature["reason"])
        self.assertIn("dependency-lifetime", feature["reason"])
        self.assertIn("COMPATIBILITY.md", feature["evidence"])
        self.assertTrue(any("surrounding byte" in item for item in feature["constraints"]))
        self.assertTrue(any("positive" in item for item in feature["constraints"]))

        lifecycle = next(
            item
            for item in self.data["features"]
            if item["id"] == "runtime.host-context.constructor-destructor"
        )
        self.assertNotIn("DT_NEEDED", lifecycle["obligation"])
        self.assertNotIn("DT_NEEDED", lifecycle["reason"])

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
        self.assertEqual(lifecycle["status"], "rejected")
        for tag in (
            "DT_INIT",
            "DT_FINI",
            "DT_INIT_ARRAY",
            "DT_FINI_ARRAY",
            "DT_INIT_ARRAYSZ",
            "DT_FINI_ARRAYSZ",
            "DT_PREINIT_ARRAY",
            "DT_PREINIT_ARRAYSZ",
        ):
            self.assertIn(tag, lifecycle["obligation"])
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
        self.assertIn("constructor/destructor ordering", lifecycle["reason"])
        self.assertIn("reentrancy", lifecycle["reason"])
        self.assertIn("teardown", lifecycle["reason"])
        self.assertIn("lifecycle ownership", lifecycle["reason"])
        self.assertIn("COMPATIBILITY.md", lifecycle["evidence"])
        self.assertTrue(any("nonzero sentinel" in item for item in lifecycle["constraints"]))
        self.assertTrue(any("surrounding bytes" in item for item in lifecycle["constraints"]))
        self.assertTrue(any("positive" in item for item in lifecycle["constraints"]))

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
            "native/urprotect-runtime/host_adapter.c",
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
            "native/urprotect-runtime/host_adapter.c",
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
        self.assertEqual(feature["oracle"], "native/urprotect-runtime/host_adapter.c")
        for relocation_tag in (
            "DT_REL",
            "DT_RELSZ",
            "DT_RELENT",
            "DT_JMPREL",
            "DT_PLTRELSZ",
            "DT_PLTREL",
        ):
            self.assertIn(relocation_tag, feature["obligation"])
        for dependency_tag in ("DT_NEEDED", "DT_AUXILIARY", "DT_FILTER"):
            self.assertNotIn(dependency_tag, feature["obligation"])
        self.assertIn("RELATIVE/RELR", feature["reason"])
        self.assertIn("system-loader", feature["reason"])
        self.assertEqual(
            feature["negativeWitness"],
            "native/urprotect-runtime/host_context_self_test.c",
        )
        self.assertEqual(feature["negativeOracle"], "native/urprotect-runtime/host_adapter.c")
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

    def test_bionic_case_records_live_package_index_and_complete_provenance(self) -> None:
        result = self.run_validator(self.data)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        host = next(item for item in self.data["cases"] if item["id"] == "c-termux-bionic-pie")["host"]
        self.assertEqual(host["packageIndex"], "live")
        self.assertFalse(host["reproducible"])
        self.assertEqual(
            host["packageProvenance"],
            "complete-installed-package-version-inventory",
        )

    def test_rejected_feature_requires_a_valid_negative_oracle(self) -> None:
        data = copy.deepcopy(self.data)
        feature = next(
            item
            for item in data["features"]
            if item["id"] == "runtime.host-context.dependency-resolution"
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
            self.assertIn("runtime.host-context.bionic-handoff | unknown", rendered)
            self.assertIn("runtime.host-context.gnu-property | rejected", rendered)
            self.assertIn("runtime.host-context.pt-tls | rejected", rendered)
            self.assertIn("runtime.host-context.dependency-resolution | rejected", rendered)
            self.assertIn("runtime.host-context.constructor-destructor | rejected", rendered)
            self.assertIn("runtime.host-context.path-search | rejected", rendered)
            self.assertIn("runtime.host-context.text-relocation | rejected", rendered)
            self.assertIn("runtime.host-context.unsupported-relocation-table | rejected", rendered)


if __name__ == "__main__":
    unittest.main()
