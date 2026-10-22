from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
RUNNER = ROOT / "scripts/run-rehydration-e2e.sh"
CHECKER = ROOT / "scripts/check-rehydration-evidence.py"
INDIRECT_RUNNER = ROOT / "scripts/run-indirect-control-e2e.sh"
HANDOFF = ROOT / "native/urprotect-runtime/native_image_handoff.c"
INDIRECT_CHECKER = ROOT / "scripts/check-indirect-control-evidence.py"
INDIRECT_MUTATOR = ROOT / "scripts/mutate-indirect-jump-table.py"
INDIRECT_UNIT = "runtime.indirect-control.jump-table.glibc.host-context-entry"
INDIRECT_NEGATIVES = {
    "negative-malformed-table": "A signed relative jump-table entry resolves outside the selected function closure.",
    "negative-out-of-range-target": "A signed relative jump-table entry resolves outside an executable PT_LOAD range.",
    "negative-index-clobber": "The checked jump-table index register W0/X0 is overwritten between B.HI and the indexed LDRSW.",
    "negative-external-table": "The selected instruction does not match the promoted relative jump-table family.",
}
INDIRECT_CHECKER_SPEC = importlib.util.spec_from_file_location(
    "rehydration_test_indirect_checker", INDIRECT_CHECKER
)
if INDIRECT_CHECKER_SPEC is None or INDIRECT_CHECKER_SPEC.loader is None:
    raise RuntimeError("could not import indirect-control checker by explicit file path")
INDIRECT_PRIVATE_CHECKER = importlib.util.module_from_spec(INDIRECT_CHECKER_SPEC)
INDIRECT_CHECKER_SPEC.loader.exec_module(INDIRECT_PRIVATE_CHECKER)
REHYDRATION_CHECKER_SPEC = importlib.util.spec_from_file_location(
    "rehydration_test_checker_runtime", CHECKER
)
if REHYDRATION_CHECKER_SPEC is None or REHYDRATION_CHECKER_SPEC.loader is None:
    raise RuntimeError("could not import rehydration checker by explicit file path")
REHYDRATION_PRIVATE_CHECKER = importlib.util.module_from_spec(REHYDRATION_CHECKER_SPEC)
REHYDRATION_CHECKER_SPEC.loader.exec_module(REHYDRATION_PRIVATE_CHECKER)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_indirect_manifest(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{_sha(path.read_bytes())}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _jump_table_elf(*, transformed: bool) -> bytes:
    original_segments = (
        (5, 0x200, 0x1000, 0x100, 0x100),
        (4, 0x400, 0x2000, 0x10, 0x10),
    )
    output_segments = (
        (5, 0x600, 0x3000, 0x100, 0x100),
        (4, 0x700, 0x4000, 0x10, 0x10),
    )
    segments = original_segments + (output_segments if transformed else ())
    image = bytearray(0xD00)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        image,
        16,
        3,
        183,
        1,
        0,
        64,
        0xB00,
        0,
        64,
        56,
        len(segments),
        64,
        6,
        5,
    )
    for index, (flags, file_offset, virtual_address, file_size, memory_size) in enumerate(segments):
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            64 + index * 56,
            1,
            flags,
            file_offset,
            virtual_address,
            virtual_address,
            file_size,
            memory_size,
            1,
        )

    dynstr = bytearray(b"\0")
    name_offsets: dict[str, int] = {}
    for name in (
        "urp_jump_table_case1",
        "urp_entry",
        "urp_jump_table_case2",
        "urp_jump_table",
        "urp_jump_table_case3",
        "urp_jump_table_case0",
        "urp_jump_table_outside_closure",
    ):
        name_offsets[name] = len(dynstr)
        dynstr.extend(name.encode("ascii") + b"\0")
    image[0xA00 : 0xA00 + len(dynstr)] = dynstr
    dynamic_rows = (
        ("urp_jump_table_case1", 0x10, 0x1030, 0, 1),
        ("urp_entry", 0x12, 0x1000, 0x7C, 1),
        ("urp_jump_table_case2", 0x10, 0x1038, 0, 1),
        ("urp_jump_table", 0x10, 0x2000, 0, 2),
        ("urp_jump_table_case3", 0x10, 0x1040, 0, 1),
        ("urp_jump_table_case0", 0x10, 0x1028, 0, 1),
        ("urp_jump_table_outside_closure", 0x12, 0x107C, 4, 1),
    )
    for index, (name, info, value, size, section_index) in enumerate(dynamic_rows, start=1):
        struct.pack_into(
            "<IBBHQQ",
            image,
            0x900 + index * 24,
            name_offsets[name],
            info,
            0,
            section_index,
            value,
            size,
        )

    section_names = b"\0.text\0.rodata\0.dynsym\0.dynstr\0.shstrtab\0"
    image[0xAA0 : 0xAA0 + len(section_names)] = section_names
    sh_name = {
        ".text": section_names.index(b".text"),
        ".rodata": section_names.index(b".rodata"),
        ".dynsym": section_names.index(b".dynsym"),
        ".dynstr": section_names.index(b".dynstr"),
        ".shstrtab": section_names.index(b".shstrtab"),
    }
    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (sh_name[".text"], 1, 6, 0x1000, 0x200, 0x100, 0, 0, 4, 0),
        (sh_name[".rodata"], 1, 2, 0x2000, 0x400, 0x10, 0, 0, 4, 0),
        (sh_name[".dynsym"], 11, 2, 0, 0x900, 8 * 24, 4, 1, 8, 24),
        (sh_name[".dynstr"], 3, 2, 0, 0xA00, len(dynstr), 0, 0, 1, 0),
        (sh_name[".shstrtab"], 3, 0, 0, 0xAA0, len(section_names), 0, 0, 1, 0),
    )
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", image, 0xB00 + index * 64, *section)
    struct.pack_into("<iiii", image, 0x400, 0, 8, 16, 24)
    source_dispatch = (0xB0000001, 0x91000021, 0xB8A05822, 0x10000063, 0x8B020061, 0xD61F0020)
    output_dispatch = source_dispatch
    struct.pack_into("<6I", image, 0x210, *source_dispatch)
    if transformed:
        struct.pack_into("<6I", image, 0x610, *output_dispatch)
        struct.pack_into("<iiii", image, 0x700, 0, 8, 16, 24)
        # The live Native Image entry starts with B to the mapped generated body.
        struct.pack_into("<I", image, 0x200, 0x14000800)
        # Keep a valid but dead safe-default chain in emitted bytes for stub-target tampering tests.
        struct.pack_into("<II", image, 0x640, 0x12800000, 0xD65F03C0)
    struct.pack_into("<I", image, 0x238, 0xD65F03C0)
    return bytes(image)


def _external_jump_table_elf() -> bytes:
    image = bytearray(0x3000)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    dynamic_entries = (
        (0x6FFFFEF5, 0x2200),
        (5, 0x2300),
        (10, 1 + len("urp_external_jump_table") + 1 + len("urp_entry") + 1),
        (6, 0x2240),
        (11, 24),
        (7, 0x2340),
        (8, 24),
        (9, 24),
        (0, 0),
    )
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        image,
        16,
        3,
        183,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        3,
        64,
        0,
        0,
    )
    program_headers = (
        (1, 5, 0x1000, 0x1000, 0x100, 0x100, 0x1000),
        (1, 6, 0x2000, 0x2000, 0x1000, 0x1000, 0x1000),
        (2, 6, 0x2100, 0x2100, len(dynamic_entries) * 16, len(dynamic_entries) * 16, 8),
    )
    for index, (kind, flags, file_offset, address, file_size, memory_size, alignment) in enumerate(program_headers):
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            64 + index * 56,
            kind,
            flags,
            file_offset,
            address,
            address,
            file_size,
            memory_size,
            alignment,
        )
    for index, entry in enumerate(dynamic_entries):
        struct.pack_into("<qQ", image, 0x2100 + index * 16, *entry)

    dynstr = b"\0urp_external_jump_table\0urp_entry\0"
    import_name = 1
    entry_name = import_name + len("urp_external_jump_table") + 1
    image[0x2300 : 0x2300 + len(dynstr)] = dynstr
    struct.pack_into("<IIII", image, 0x2200, 1, 1, 1, 5)
    struct.pack_into("<Q", image, 0x2210, 0)
    struct.pack_into("<I", image, 0x2218, 1)

    def gnu_hash(name: bytes) -> int:
        value = 5381
        for character in name:
            value = ((value << 5) + value + character) & 0xFFFFFFFF
        return value

    struct.pack_into("<II", image, 0x221C, gnu_hash(b"urp_external_jump_table") & 0xFFFFFFFE, gnu_hash(b"urp_entry") | 1)
    struct.pack_into("<IBBHQQ", image, 0x2240 + 24, import_name, 0x11, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", image, 0x2240 + 48, entry_name, 0x12, 0, 1, 0x1000, 0x48)
    struct.pack_into("<QQq", image, 0x2340, 0x2400, (1 << 32) | 1025, 0)

    cmp_word = 0x71000C1F
    bhi_word = 0x540001E8
    adrp_immediate = 1
    adrp_word = 0x90000009 | ((adrp_immediate & 3) << 29) | ((adrp_immediate >> 2) << 5)
    ldr_word = 0xF9400000 | ((0x400 // 8) << 10) | (9 << 5) | 9
    adr_immediate = 3 << 2
    adr_word = 0x10000000 | ((adr_immediate & 3) << 29) | ((adr_immediate >> 2) << 5) | 3
    instructions = (
        cmp_word,
        bhi_word,
        adrp_word,
        ldr_word,
        0xB8A05922,
        adr_word,
        0x8B020061,
        0xD61F0020,
        0x52800220,
        0xD65F03C0,
        0x52800CE0,
        0xD65F03C0,
        0x128000C0,
        0xD65F03C0,
        0x52800B60,
        0xD65F03C0,
        0x12800000,
        0xD65F03C0,
    )
    struct.pack_into(f"<{len(instructions)}I", image, 0x1000, *instructions)
    return bytes(image)


class RehydrationEvidenceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.checker = CHECKER.read_text(encoding="utf-8")

    def test_workflow_runs_and_checks_rehydration_after_build(self) -> None:
        build = self.workflow.index("- name: Build\n")
        run = self.workflow.index("Run Generic Rehydration and Native Image handoff")
        check = self.workflow.index("Check retained Generic Rehydration and Native Image evidence", run)
        upload = self.workflow.index("- name: Upload protection-tls evidence", check)
        self.assertLess(build, run)
        self.assertLess(run, check)
        self.assertLess(check, upload)
        self.assertIn("if: always()", self.workflow[run:check])
        self.assertIn("if: always()", self.workflow[check:upload])
        self.assertIn(".artifacts/protected-image/", self.workflow[upload : upload + 800])
        self.assertIn("--profile host-context-entry", self.workflow)
        self.assertIn("compat.protection-host-context-fixture.glibc.host-context-entry", self.workflow)

    def test_runner_retains_all_stage_records_and_closes_manifest(self) -> None:
        for marker in (
            "protected-image.bin",
            "rehydration.json",
            "native-image.bin",
            "handoff.json",
            "target-loader.json",
            "behavioral-oracle.json",
            "SHA256SUMS",
            "close_manifest",
        ):
            self.assertIn(marker, self.runner)
        self.assertIn("run-protected-image-e2e.sh", self.runner)
        self.assertIn("run-host-context-rehydration-e2e.sh", self.runner)
        self.assertIn("host-context-entry", self.runner)
        self.assertIn("execveat", self.runner)

    def test_workflow_runs_the_managed_tls_initial_exec_evidence_lane(self) -> None:
        self.assertIn("run-tls-host-context-rehydration-e2e.sh", self.workflow)
        self.assertIn("tls.initial-exec.glibc.host-context-entry", self.workflow)
        self.assertIn("runtime.host-context.protected-image-tls-initial-exec", self.workflow)
        self.assertIn("--entry-status 43", (ROOT / "scripts/run-tls-host-context-rehydration-e2e.sh").read_text(encoding="utf-8"))

    def test_indirect_runner_closes_and_checks_positive_child_before_outer_manifest(self) -> None:
        runner = INDIRECT_RUNNER.read_text(encoding="utf-8")
        child_close = runner.index('>"$positive/SHA256SUMS"')
        child_check = runner.index('check-rehydration-evidence.py" "$positive"', child_close)
        outer_close = runner.index('>"$root/SHA256SUMS"', child_check)
        outer_check = runner.index('check-indirect-control-evidence.py" "$root"', outer_close)
        self.assertLess(child_close, child_check)
        self.assertLess(child_check, outer_close)
        self.assertLess(outer_close, outer_check)
        self.assertIn("--artifact-root PATH", runner)
        self.assertIn("refusing to overwrite existing indirect evidence root", runner)

    def test_musl_jump_table_runners_separate_compiler_and_linker_and_retain_build_status(self) -> None:
        indirect_runner = INDIRECT_RUNNER.read_text(encoding="utf-8")
        host_context_runner = (ROOT / "scripts/run-host-context-rehydration-e2e.sh").read_text(encoding="utf-8")
        for runner in (indirect_runner, host_context_runner):
            self.assertIn('make_args+=("CC=$runtime_cc" "LD=ld")', runner)
            self.assertNotIn('"LD=$runtime_cc"', runner)

        self.assertIn('native_build_diagnostics_root="${root}.native-build-diagnostics"', indirect_runner)
        self.assertIn('native-build.command.txt', indirect_runner)
        self.assertIn('native-build.status', indirect_runner)
        self.assertIn('native_build_status=$?', indirect_runner)
        self.assertIn('exit "$native_build_status"', indirect_runner)
        self.assertIn('URP_NATIVE_BUILD_DIAGNOSTICS_ROOT="$native_build_diagnostics_root"', indirect_runner)
        self.assertIn('rehydration_status=$?', indirect_runner)
        self.assertIn('exit "$rehydration_status"', indirect_runner)
        self.assertIn('"${native_build_command[@]}"', indirect_runner)
        self.assertIn('make_args+=("HOST_ADAPTER_CFLAGS=-mno-outline-atomics")', host_context_runner)
        makefile = (ROOT / "native/urprotect-runtime/Makefile").read_text(encoding="utf-8")
        self.assertIn("HOST_ADAPTER_CFLAGS ?=", makefile)
        self.assertIn("$(CFLAGS) $(HOST_ADAPTER_CFLAGS) -DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1", makefile)
        self.assertIn("HOST_ADAPTER_CONFIG_STAMP := $(BUILD_DIR)/host_adapter.compile-config", makefile)

    def test_musl_jump_table_runner_retains_and_propagates_stubbed_make_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr29-musl-build-status-") as temporary_directory:
            temporary_root = Path(temporary_directory)
            repository = temporary_root / "repo"
            scripts = repository / "scripts"
            native_root = repository / "native" / "urprotect-runtime"
            stub_bin = temporary_root / "stub-bin"
            scripts.mkdir(parents=True)
            native_root.mkdir(parents=True)
            stub_bin.mkdir()

            isolated_runner = scripts / "run-indirect-control-e2e.sh"
            shutil.copy2(INDIRECT_RUNNER, isolated_runner)
            isolated_runner.chmod(0o755)

            uname_stub = stub_bin / "uname"
            uname_stub.write_text(
                "#!/bin/sh\n"
                "if [ \"$#\" -eq 1 ] && [ \"$1\" = '-m' ]; then\n"
                "  printf 'aarch64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "exit 98\n",
                encoding="utf-8",
            )
            uname_stub.chmod(0o755)

            compiler_stub = stub_bin / "musl-gcc"
            compiler_invoked = temporary_root / "musl-gcc-was-invoked"
            compiler_stub.write_text(
                "#!/bin/sh\n"
                f": > {shlex.quote(str(compiler_invoked))}\n"
                "exit 97\n",
                encoding="utf-8",
            )
            compiler_stub.chmod(0o755)

            make_stub = stub_bin / "make"
            make_stub.write_text(
                "#!/bin/sh\n"
                "printf 'PR29_STUB_MAKE_STDOUT\\n'\n"
                "printf 'PR29_STUB_MAKE_STDERR\\n' >&2\n"
                "exit 23\n",
                encoding="utf-8",
            )
            make_stub.chmod(0o755)

            run_id = "pr29-test-run"
            run_attempt = "1"
            upload_parent = repository / ".artifacts" / "indirect-control" / f"musl-{run_id}-{run_attempt}"
            artifact_root = upload_parent / "ordinary"
            environment = {
                "PATH": os.pathsep.join((str(stub_bin), "/usr/bin", "/bin")),
                "HOME": str(temporary_root),
                "TMPDIR": str(temporary_root),
                "RUNNER_TEMP": str(temporary_root),
                "GITHUB_RUN_ID": run_id,
                "GITHUB_RUN_ATTEMPT": run_attempt,
                "LANG": "C",
                "LC_ALL": "C",
            }
            result = subprocess.run(
                [
                    str(isolated_runner),
                    "--tier",
                    "pr",
                    "--runtime",
                    "musl",
                    "--unit",
                    "runtime.indirect-control.jump-table.musl.host-context-entry",
                    "--artifact-root",
                    str(artifact_root),
                ],
                cwd=repository,
                env=environment,
                capture_output=True,
                timeout=20,
                check=False,
            )

            self.assertEqual(23, result.returncode, result.stderr.decode(errors="replace"))
            self.assertEqual(b"", result.stdout)
            self.assertEqual(
                b"native fixture build failed at native-build with status 23\n",
                result.stderr,
            )
            self.assertEqual(b"PR29_STUB_MAKE_STDOUT\n", (artifact_root / "native-build.stdout").read_bytes())
            self.assertEqual(b"PR29_STUB_MAKE_STDERR\n", (artifact_root / "native-build.stderr").read_bytes())
            self.assertFalse(compiler_invoked.exists(), "the availability-only musl-gcc stub must never execute")

            diagnostics_root = Path(f"{artifact_root}.native-build-diagnostics")
            status_path = diagnostics_root / "native-build.status"
            command_path = diagnostics_root / "native-build.command.txt"
            self.assertTrue(status_path.is_file())
            self.assertTrue(command_path.is_file())
            self.assertEqual(b"23\n", status_path.read_bytes())
            self.assertEqual(upload_parent, diagnostics_root.parent)
            self.assertTrue(diagnostics_root.resolve().is_relative_to(upload_parent.resolve()))

            command_lines = dict(
                line.split("=", 1)
                for line in command_path.read_text(encoding="utf-8").splitlines()
            )
            expected_native_root = str(native_root.resolve())
            self.assertEqual(expected_native_root, command_lines["cwd"])
            self.assertEqual("musl", command_lines["runtime"])
            argv = shlex.split(command_lines["argv"])
            self.assertEqual("make", argv[0])
            self.assertEqual(["-C", expected_native_root], argv[1:3])
            self.assertIn(f"CC={compiler_stub}", argv)
            self.assertIn("LD=ld", argv)
            self.assertIn("BUILD_DIR=build/musl-indirect-control", argv)
            self.assertEqual(
                [
                    "jump-table-fixture",
                    "jump-table-index-clobber-fixture",
                    "external-jump-table-fixture",
                ],
                argv[-3:],
            )

            workflow = WORKFLOW.read_text(encoding="utf-8")
            self.assertIn(
                ".artifacts/indirect-control/musl-${{ github.run_id }}-${{ github.run_attempt }}/",
                workflow,
            )

    def test_musl_host_context_helper_build_failure_retains_nested_make_and_propagates_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr29-musl-nested-build-") as temporary_directory:
            temporary_root = Path(temporary_directory)
            repository = temporary_root / "repo"
            scripts = repository / "scripts"
            native_root = repository / "native" / "urprotect-runtime"
            stub_bin = temporary_root / "stub-bin"
            scripts.mkdir(parents=True)
            native_root.mkdir(parents=True)
            stub_bin.mkdir()

            isolated_runner = scripts / "run-host-context-rehydration-e2e.sh"
            shutil.copy2(ROOT / "scripts/run-host-context-rehydration-e2e.sh", isolated_runner)
            isolated_runner.chmod(0o755)

            uname_stub = stub_bin / "uname"
            uname_stub.write_text(
                "#!/bin/sh\n"
                "if [ \"$#\" -eq 1 ] && [ \"$1\" = '-m' ]; then printf 'aarch64\n'; exit 0; fi\n"
                "exit 98\n",
                encoding="utf-8",
            )
            uname_stub.chmod(0o755)

            compiler_stub = stub_bin / "musl-gcc"
            compiler_invoked = temporary_root / "musl-gcc-was-invoked"
            compiler_stub.write_text(
                "#!/bin/sh\n"
                f": > {shlex.quote(str(compiler_invoked))}\n"
                "exit 97\n",
                encoding="utf-8",
            )
            compiler_stub.chmod(0o755)

            make_stub = stub_bin / "make"
            make_stub.write_text(
                "#!/bin/sh\n"
                "printf 'PR29_NESTED_MAKE_STDOUT\\n'\n"
                "printf 'PR29_NESTED_MAKE_STDERR\\n' >&2\n"
                "exit 23\n",
                encoding="utf-8",
            )
            make_stub.chmod(0o755)

            upload_parent = repository / ".artifacts" / "indirect-control" / "musl-run"
            artifact_root = upload_parent / "ordinary" / "runtime.indirect-control.jump-table.musl.host-context-entry"
            diagnostics_root = upload_parent / "ordinary.native-build-diagnostics"
            diagnostics_root.mkdir(parents=True)
            environment = {
                "PATH": os.pathsep.join((str(stub_bin), "/usr/bin", "/bin")),
                "HOME": str(temporary_root),
                "TMPDIR": str(temporary_root),
                "RUNNER_TEMP": str(temporary_root),
                "PROTECTED_IMAGE_ARTIFACT_ROOT": str(artifact_root),
                "URP_NATIVE_BUILD_DIAGNOSTICS_ROOT": str(diagnostics_root),
                "LANG": "C",
                "LC_ALL": "C",
            }
            result = subprocess.run(
                [
                    str(isolated_runner),
                    "--tier",
                    "pr",
                    "--runtime",
                    "musl",
                    "--native-build-dir",
                    "build/musl-indirect-control",
                    "--unit",
                    "runtime.indirect-control.jump-table.musl.host-context-entry",
                ],
                cwd=repository,
                env=environment,
                capture_output=True,
                timeout=20,
                check=False,
            )

            self.assertEqual(23, result.returncode, result.stderr.decode(errors="replace"))
            self.assertEqual(b"", result.stdout)
            self.assertEqual(
                b"HostContext native fixture/helper build failed with status 23\n",
                result.stderr,
            )
            self.assertFalse(compiler_invoked.exists(), "the musl-gcc availability stub must not execute")
            self.assertEqual([], list(artifact_root.iterdir()), "failed helper build polluted positive evidence")

            nested_diagnostics = diagnostics_root / "host-context-image-handoff"
            self.assertTrue(nested_diagnostics.resolve().is_relative_to(upload_parent.resolve()))
            self.assertTrue(nested_diagnostics.resolve().is_relative_to(diagnostics_root.resolve()))
            self.assertFalse(nested_diagnostics.resolve().is_relative_to(artifact_root.resolve()))
            self.assertEqual(b"23\n", (nested_diagnostics / "native-build.status").read_bytes())
            self.assertEqual(
                b"PR29_NESTED_MAKE_STDOUT\n",
                (nested_diagnostics / "native-build.stdout").read_bytes(),
            )
            self.assertEqual(
                b"PR29_NESTED_MAKE_STDERR\n",
                (nested_diagnostics / "native-build.stderr").read_bytes(),
            )
            command_lines = dict(
                line.split("=", 1)
                for line in (nested_diagnostics / "native-build.command.txt")
                .read_text(encoding="utf-8")
                .splitlines()
            )
            expected_native_root = str(native_root.resolve())
            self.assertEqual(expected_native_root, command_lines["cwd"])
            self.assertEqual("musl", command_lines["runtime"])
            argv = shlex.split(command_lines["argv"])
            self.assertEqual(
                [
                    "make",
                    "-C",
                    expected_native_root,
                    "BUILD_DIR=build/musl-indirect-control",
                    f"CC={compiler_stub}",
                    "LD=ld",
                    "HOST_ADAPTER_CFLAGS=-mno-outline-atomics",
                    "host-context-entry-fixture",
                    "host-context-image-handoff",
                ],
                argv,
            )

    def test_host_adapter_make_rule_rebuilds_only_when_compile_configuration_changes(self) -> None:
        make = shutil.which("make")
        self.assertIsNotNone(make, "make is required to exercise the native object rule")
        makefile_root = ROOT / "native/urprotect-runtime"
        with tempfile.TemporaryDirectory(prefix="pr29-host-adapter-flags-") as temporary_directory:
            temporary_root = Path(temporary_directory)
            compiler_stub = temporary_root / "cc-capture"
            compiler_stub.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "with pathlib.Path(os.environ['URP_TEST_CC_CAPTURE']).open('a', encoding='utf-8') as capture:\n"
                "    capture.write(json.dumps(args) + '\\n')\n"
                "output = pathlib.Path(args[args.index('-o') + 1])\n"
                "output.parent.mkdir(parents=True, exist_ok=True)\n"
                "output.write_bytes(b'compiler-stub-output')\n",
                encoding="utf-8",
            )
            compiler_stub.chmod(0o755)
            standard_cflags = "-std=c11 -O2 -g0 -Wall -Wextra -Werror -Wshadow -Wconversion -pthread"
            environment = os.environ.copy()
            for key in ("CFLAGS", "HOST_ADAPTER_CFLAGS", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS"):
                environment.pop(key, None)

            build_dir = temporary_root / "build-reused-by-default-and-musl"
            capture_path = temporary_root / "compiler-argv.jsonl"
            configurations = (
                ("default", []),
                ("musl", ["HOST_ADAPTER_CFLAGS=-mno-outline-atomics"]),
                ("musl-unchanged", ["HOST_ADAPTER_CFLAGS=-mno-outline-atomics"]),
                ("default-again", []),
            )
            compile_counts = (1, 2, 2, 3)
            config_snapshots: list[bytes] = []
            unchanged_stamp_mtime: int | None = None
            for index, (label, extra_flags) in enumerate(configurations):
                result = subprocess.run(
                    [
                        str(make),
                        "-C",
                        str(makefile_root),
                        f"BUILD_DIR={build_dir}",
                        f"CC={compiler_stub}",
                        f"CFLAGS={standard_cflags}",
                        *extra_flags,
                        str(build_dir / "host_adapter.o"),
                    ],
                    cwd=makefile_root,
                    env={**environment, "URP_TEST_CC_CAPTURE": str(capture_path)},
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(0, result.returncode, f"{label}: {result.stderr.decode(errors='replace')}")
                stamp = build_dir / "host_adapter.compile-config"
                stamp_bytes = stamp.read_bytes()
                config_snapshots.append(stamp_bytes)
                stamp_values = dict(line.split("=", 1) for line in stamp_bytes.decode().splitlines())
                self.assertEqual(str(compiler_stub), stamp_values["CC"])
                self.assertEqual("-Iinclude -I../urprotect-launcher -I../../third_party/miniz", stamp_values["CPPFLAGS"])
                self.assertEqual(standard_cflags, stamp_values["CFLAGS"])
                expected_host_adapter_flags = "-mno-outline-atomics" if label.startswith("musl") else ""
                self.assertEqual(expected_host_adapter_flags, stamp_values["HOST_ADAPTER_CFLAGS"])
                captured = capture_path.read_text(encoding="utf-8").splitlines() if capture_path.exists() else []
                self.assertEqual(compile_counts[index], len(captured), f"{label}: compiler invocation count")
                if label == "musl":
                    unchanged_stamp_mtime = stamp.stat().st_mtime_ns
                elif label == "musl-unchanged":
                    self.assertEqual(unchanged_stamp_mtime, stamp.stat().st_mtime_ns)

            self.assertEqual(config_snapshots[1], config_snapshots[2], "unchanged musl config must keep its provenance stamp")
            self.assertNotEqual(config_snapshots[0], config_snapshots[1])
            self.assertEqual(config_snapshots[0], config_snapshots[3], "returning to default config must restore its stamp content")

            compiler_invocations = [json.loads(line) for line in capture_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(3, len(compiler_invocations))
            cppflags = ["-Iinclude", "-I../urprotect-launcher", "-I../../third_party/miniz"]
            cflags = standard_cflags.split()
            for argv, expected_musl in zip(compiler_invocations, (False, True, False), strict=True):
                self.assertEqual(cppflags, argv[: len(cppflags)])
                self.assertEqual(cflags, argv[len(cppflags) : len(cppflags) + len(cflags)])
                next_flag = len(cppflags) + len(cflags)
                if expected_musl:
                    self.assertEqual("-mno-outline-atomics", argv[next_flag])
                    next_flag += 1
                self.assertEqual("-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1", argv[next_flag])
                self.assertEqual(str(build_dir / "host_adapter.o"), argv[argv.index("-o") + 1])

    def test_checker_requires_stage_specific_bindings_and_closed_evidence(self) -> None:
        for marker in (
            "SHA256SUMS is not closed",
            "preHandoffRecordSha256",
            "handoffRecordSha256",
            "native-image.json",
            "target-loader",
            "behavioral-oracle",
            "execveat-at-empty-path",
            "layoutEvidence",
            "relocated-program-header-table",
        ):
            self.assertIn(marker, self.checker)

    def test_native_helper_uses_sealed_memfd_and_execveat(self) -> None:
        handoff = HANDOFF.read_text(encoding="utf-8")
        for marker in ("memfd_create", "F_ADD_SEALS", "fsync", "execveat", "AT_EMPTY_PATH"):
            self.assertIn(marker, handoff)


class IndirectControlEvidenceTests(unittest.TestCase):
    @staticmethod
    def runtime_elf(*, interpreter: str | None = None, version_marker: bytes | None = None) -> bytes:
        image = bytearray(0x200)
        image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
        struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2 if interpreter else 1, 0, 0, 0)
        struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0, 0, len(image), len(image), 0x1000)
        if interpreter is not None:
            encoded = interpreter.encode("ascii") + b"\0"
            struct.pack_into("<IIQQQQQQ", image, 120, 3, 4, 0x180, 0, 0, len(encoded), len(encoded), 1)
            image[0x180 : 0x180 + len(encoded)] = encoded
        if version_marker is not None:
            image[0x100 : 0x100 + len(version_marker)] = version_marker
        return bytes(image)

    def write_runtime_identity(self, positive: Path, role: str, image_hash: str, *, runtime: str = "glibc", version_marker: bytes | None = None) -> dict[str, object]:
        identity_root = positive / "runtime-identity" / role
        identity_root.mkdir(parents=True)
        if runtime == "glibc":
            version_marker = b"release version 2.43." if version_marker is None else version_marker
            helper = self.runtime_elf(interpreter="/lib/ld-linux-aarch64.so.1")
            libc = self.runtime_elf(version_marker=version_marker)
            loader = self.runtime_elf()
            libc_path = "/usr/lib/aarch64-linux-gnu/libc.so.6"
            loader_path = "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
            loader_inode = 1003
            maps = (
                "0000000000100000-0000000000101000 r-xp 00000000 08:01 1001 /evidence/host-context-image-handoff\n"
                "0000000000150000-0000000000151000 rw-p 00000000 00:00 0 [heap]\n"
                f"0000000000200000-0000000000201000 r-xp 00000000 08:01 1002 {libc_path}\n"
                f"0000000000300000-0000000000301000 r-xp 00000000 08:01 {loader_inode} {loader_path}\n"
            ).encode("ascii")
            runtime_version = "2.43"
            version_source = "glibc-libc-release-version-marker"
        elif runtime == "musl":
            version_marker = b"Version 1.2.3" if version_marker is None else version_marker
            helper = self.runtime_elf(interpreter="/lib/ld-musl-aarch64.so.1")
            libc = self.runtime_elf(version_marker=version_marker)
            loader = libc
            libc_path = "/lib/aarch64-linux-musl/libc.so"
            loader_path = libc_path
            loader_inode = 1002
            maps = (
                "0000000000100000-0000000000101000 r-xp 00000000 08:01 1001 /evidence/host-context-image-handoff\n"
                "0000000000150000-0000000000151000 rw-p 00000000 00:00 0 [heap]\n"
                f"0000000000200000-0000000000201000 r-xp 00000000 08:01 {loader_inode} {loader_path}\n"
            ).encode("ascii")
            runtime_version = "1.2.3"
            version_source = "musl-loader-version-marker"
        else:
            raise ValueError("unsupported test runtime")
        loader_dev_inode = loader_inode
        for name, data in (("helper.elf", helper), ("libc.elf", libc), ("loader.elf", loader), ("maps.txt", maps)):
            (identity_root / name).write_bytes(data)
        def file_record(name: str, mapped_path: str, inode: int) -> dict[str, object]:
            data = (identity_root / name).read_bytes()
            return {
                "mappedPath": mapped_path,
                "deviceMajor": 8,
                "deviceMinor": 1,
                "inode": inode,
                "size": len(data),
                "sha256": _sha(data),
                "retainedPath": f"runtime-identity/{role}/{name}",
            }
        identity = {
            "schemaVersion": 1,
            "runtime": runtime,
            "architecture": "aarch64",
            "role": role,
            "processId": 5000 if role == "source" else 5001,
            "imageSha256": image_hash,
            "runtimeVersion": runtime_version,
            "runtimeVersionSource": version_source,
            "interpreter": {
                "declaredPath": "/lib/ld-linux-aarch64.so.1" if runtime == "glibc" else "/lib/ld-musl-aarch64.so.1",
                "resolvedPath": loader_path,
                "deviceMajor": 8,
                "deviceMinor": 1,
                "inode": loader_dev_inode,
            },
            "maps": {
                "retainedPath": f"runtime-identity/{role}/maps.txt",
                "sha256": _sha(maps),
            },
            "helper": file_record("helper.elf", "/evidence/host-context-image-handoff", 1001),
            "libc": file_record("libc.elf", libc_path, 1002),
            "loader": file_record("loader.elf", loader_path, loader_dev_inode),
        }
        identity_path = identity_root / "identity.json"
        _write_json(identity_path, identity)
        return {
            "schemaVersion": 1,
            "path": f"runtime-identity/{role}/identity.json",
            "sha256": _sha(identity_path.read_bytes()),
        }

    def set_runtime_pt_load_layout(
        self,
        positive: Path,
        role: str,
        loads: tuple[tuple[int, int, int, int, int], ...],
        maps: tuple[tuple[int, int, int, str], ...],
        *,
        file_pages: int = 3,
    ) -> None:
        identity_path = positive / "runtime-identity" / role / "identity.json"
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        libc_record = identity["libc"]
        libc_path = positive / libc_record["retainedPath"]
        old_image = libc_path.read_bytes()
        page_size = os.sysconf("SC_PAGE_SIZE")
        image = bytearray(file_pages * page_size)
        image[: min(len(old_image), len(image))] = old_image[: min(len(old_image), len(image))]
        phoff = struct.unpack_from("<Q", image, 32)[0]
        phentsize = struct.unpack_from("<H", image, 54)[0]
        if phentsize != 56 or phoff + len(loads) * phentsize > len(image):
            raise AssertionError("synthetic runtime ELF has no bounded PT_LOAD header storage")
        struct.pack_into("<H", image, 56, len(loads))
        for index, (file_offset, virtual_address, file_size, memory_size, flags) in enumerate(loads):
            alignment = page_size if file_offset % page_size == virtual_address % page_size else 1
            struct.pack_into(
                "<IIQQQQQQ",
                image,
                phoff + index * phentsize,
                1,
                flags,
                file_offset,
                virtual_address,
                virtual_address,
                file_size,
                memory_size,
                alignment,
            )
        libc_path.write_bytes(image)
        libc_record["size"] = len(image)
        libc_record["sha256"] = _sha(image)

        if identity["runtime"] == "musl":
            loader_record = identity["loader"]
            loader_path = positive / loader_record["retainedPath"]
            loader_path.write_bytes(image)
            loader_record["size"] = len(image)
            loader_record["sha256"] = _sha(image)

        maps_path = positive / identity["maps"]["retainedPath"]
        retained_maps = maps_path.read_text(encoding="ascii").splitlines()
        mapped_path = libc_record["mappedPath"]
        major, minor, inode = libc_record["deviceMajor"], libc_record["deviceMinor"], libc_record["inode"]
        other_maps = []
        for line in retained_maps:
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[3:5] == [f"{major:02x}:{minor:02x}", str(inode)] and fields[5] == mapped_path:
                continue
            other_maps.append(line)
        retained_maps = other_maps
        for virtual_page, file_page, page_count, permissions in maps:
            map_start = 0x200000 + virtual_page * page_size
            map_end = map_start + page_count * page_size
            file_offset = file_page * page_size
            retained_maps.append(
                f"{map_start:016x}-{map_end:016x} {permissions} {file_offset:08x} "
                f"{major:02x}:{minor:02x} {inode} {mapped_path}"
            )
        retained_maps.sort(key=lambda line: int(line.split("-", 1)[0], 16))
        maps_bytes = ("\n".join(retained_maps) + "\n").encode("ascii")
        maps_path.write_bytes(maps_bytes)
        identity["maps"]["sha256"] = _sha(maps_bytes)
        _write_json(identity_path, identity)

    def refresh_runtime_identity(self, positive: Path, role: str) -> None:
        identity_path = positive / "runtime-identity" / role / "identity.json"
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        handoff_name = "source-handoff.json" if role == "source" else "handoff.json"
        handoff_path = positive / handoff_name
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        image_name = "source-image.bin" if role == "source" else "native-image.bin"
        image_hash = _sha((positive / image_name).read_bytes())
        identity["imageSha256"] = image_hash
        handoff["nativeImageSha256"] = image_hash
        _write_json(identity_path, identity)
        handoff["runtimeIdentity"]["sha256"] = _sha(identity_path.read_bytes())
        _write_json(handoff_path, handoff)
        behavior_path = positive / "jump-table-behavior.json"
        if behavior_path.is_file():
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["sourceHandoffSha256" if role == "source" else "targetHandoffSha256"] = _sha(handoff_path.read_bytes())
            _write_json(behavior_path, behavior)

    def reject_runtime_identity_mutation(self, mutate, *, role: str = "target") -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="indirect-control-runtime-identity-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            mutate(positive, role)
            self.refresh_runtime_identity(positive, role)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("SHA256SUMS", result.stderr)
            return result

    def create_evidence(self, root: Path) -> None:
        positive = root / INDIRECT_UNIT
        positive.mkdir(parents=True)
        source = _jump_table_elf(transformed=False)
        protected = b"protected operation image"
        native = _jump_table_elf(transformed=True)
        for name, data in (
            ("source-image.bin", source),
            ("protected-image.bin", protected),
            ("native-image.bin", native),
        ):
            (positive / name).write_bytes(data)
        source_hash = _sha(source)
        protected_hash = _sha(protected)
        native_hash = _sha(native)
        streams = {
            "baseline.stdout": b"",
            "baseline.stderr": b"",
            "target.stdout": b"",
            "target.stderr": b"",
        }
        for name, data in streams.items():
            (positive / name).write_bytes(data)
        source_handoff = {
            "schemaVersion": 1,
            "stage": "host-context-handoff",
            "status": "passed",
            "loaderId": "host-context.sealed-memfd.dlopen",
            "nativeImageSha256": source_hash,
            "entrySymbol": "urp_entry",
            "entryStatus": 91,
            "processStatus": 91,
            "releaseStatus": "passed",
            "releaseOrder": "entry-dispatch-before-release-image",
            "firstFailureStage": None,
        }
        source_handoff["runtimeIdentity"] = self.write_runtime_identity(positive, "source", source_hash)
        target_handoff = {**source_handoff, "nativeImageSha256": native_hash}
        target_handoff["runtimeIdentity"] = self.write_runtime_identity(positive, "target", native_hash)
        _write_json(positive / "source-handoff.json", source_handoff)
        _write_json(positive / "handoff.json", target_handoff)
        code_output_range = {
            "fileOffset": {"value": 0x600},
            "hasVirtualAddress": True,
            "size": 0x100,
            "virtualAddress": {"value": 0x3000},
        }
        table_output_range = {
            "fileOffset": {"value": 0x700},
            "hasVirtualAddress": True,
            "size": 16,
            "virtualAddress": {"value": 0x4000},
        }
        source_table_range = {
            "fileOffset": {"value": 0x400},
            "hasVirtualAddress": True,
            "virtualAddress": {"value": 0x2000},
            "size": 16,
        }
        edits = [
            {"offset": {"value": 0x700 + index * 4}, "bytes": base64.b64encode(target.to_bytes(4, "little", signed=True)).decode(), "kind": 8}
            for index, target in enumerate((0, 8, 16, 24))
        ]
        table_identity = "0x2000:4:0:3"
        target_bindings = [
            {
                "tableIdentity": {"kind": 5, "value": table_identity},
                "sourceTableRange": source_table_range,
                "entryIdentity": {"kind": 6, "value": f"{table_identity}:{index}"},
                "targetIdentity": {"kind": 1, "value": f"0x{target:X}"},
                "targetBaseIdentity": {"kind": 1, "value": "0x1028"},
                "entryIndex": index,
                "sourceEntryRange": {
                    "fileOffset": {"value": 0x400 + index * 4},
                    "virtualAddress": {"value": 0x2000 + index * 4},
                    "size": 4,
                },
                "outputEntryRange": {
                    "fileOffset": {"value": 0x700 + index * 4},
                    "virtualAddress": {"value": 0x4000 + index * 4},
                    "size": 4,
                },
                "sourceTargetAddress": {"value": target},
                "outputTargetAddress": {"value": 0x3028 + index * 8},
                "sourceTargetBaseAddress": {"value": 0x1028},
                "outputTargetBaseAddress": {"value": 0x3028},
                "entryWidth": 4,
                "isSigned": True,
                "scale": 1,
                "addend": 0,
                "sourceEncodedValue": index * 8,
                "outputEncodedValue": index * 8,
            }
            for index, target in enumerate((0x1028, 0x1030, 0x1038, 0x1040))
        ]
        source_table_producers = [
            {"instructionAddress": 0x1010, "kind": 1},
            {"instructionAddress": 0x1014, "kind": 2},
        ]
        table_clone = {
            "tableIdentity": {"kind": 5, "value": table_identity},
            "sourceTableRange": source_table_range,
            "requestedOutputRange": table_output_range,
            "outputRange": table_output_range,
            "permissions": 4,
            "ownership": 0,
            "rewritePolicy": 1,
            "tableReferenceProducers": source_table_producers,
            "ownerReferences": [],
            "ownerInventoryComplete": False,
        }
        layout = {
            "schemaVersion": 3,
            "sourceSha256": source_hash,
            "outputSha256": native_hash,
            "jumpTableEdits": edits,
            "jumpTableTargetBindings": target_bindings,
            "jumpTableClones": [table_clone],
            "addressMap": [
                {
                    "identity": "region:1",
                    "sourceIdentity": "region:1",
                    "sourceRange": {
                        "fileOffset": {"value": 0x200},
                        "hasVirtualAddress": True,
                        "size": 0x100,
                        "virtualAddress": {"value": 0x1000},
                    },
                    "outputRange": code_output_range,
                },
                {
                    "identity": table_identity,
                    "sourceIdentity": table_identity,
                    "sourceRange": source_table_range,
                    "outputRange": table_output_range,
                },
            ],
            "placements": [
                {
                    "identity": "region:1",
                    "sourceIdentity": "region:1",
                    "range": code_output_range,
                },
            ],
        }
        _write_json(
            positive / "rehydration.json",
            {
                "schemaVersion": 1,
                "stage": "rehydration",
                "status": "passed",
                "unitId": INDIRECT_UNIT,
                "profile": "host-context-entry",
                "entrySymbol": "urp_entry",
                "sourceSha256": source_hash,
                "protectedImageSha256": protected_hash,
                "nativeImageSha256": native_hash,
                "nativeImageSize": len(native),
                "layoutEvidence": layout,
            },
        )
        target_addresses = [0x1028 + index * 8 for index in range(4)]
        symbols = [
            "Symbol table '.dynsym' contains 8 entries:",
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name",
            "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND ",
            f"     1: {target_addresses[1]:016x}     0 NOTYPE  GLOBAL DEFAULT    1 urp_jump_table_case1",
            "     2: 0000000000001000   124 FUNC    GLOBAL DEFAULT    1 urp_entry",
            f"     3: {target_addresses[2]:016x}     0 NOTYPE  GLOBAL DEFAULT    1 urp_jump_table_case2",
            "     4: 0000000000002000     0 NOTYPE  GLOBAL DEFAULT    2 urp_jump_table",
            f"     5: {target_addresses[3]:016x}     0 NOTYPE  GLOBAL DEFAULT    1 urp_jump_table_case3",
            f"     6: {target_addresses[0]:016x}     0 NOTYPE  GLOBAL DEFAULT    1 urp_jump_table_case0",
            "     7: 000000000000107c     4 FUNC    GLOBAL DEFAULT    1 urp_jump_table_outside_closure",
            "",
            "Symbol table '.symtab' contains 0 entries:",
        ]
        (positive / "source-readelf.txt").write_text("\n".join(symbols) + "\n", encoding="utf-8")
        case_results = [17, 103, -7, 91]
        trace = 0
        for result in case_results:
            trace = ((trace << 8) | (result & 0xff)) & 0xffffffff
        behavior = {
            "schemaVersion": 2,
            "unitId": INDIRECT_UNIT,
            "selectedFunction": "dynsym:2",
            "sourceSha256": source_hash,
            "protectedSha256": protected_hash,
            "nativeSha256": native_hash,
            "sourceHandoffSha256": _sha((positive / "source-handoff.json").read_bytes()),
            "targetHandoffSha256": _sha((positive / "handoff.json").read_bytes()),
            "baselineStatus": 91,
            "transformedStatus": 91,
            "baselineEntryStatus": 91,
            "transformedEntryStatus": 91,
            "baselineStdoutSha256": _sha(streams["baseline.stdout"]),
            "baselineStderrSha256": _sha(streams["baseline.stderr"]),
            "transformedStdoutSha256": _sha(streams["target.stdout"]),
            "transformedStderrSha256": _sha(streams["target.stderr"]),
            "statusEqual": True,
            "stdoutEqual": True,
            "stderrEqual": True,
            "jumpTableEditCount": 4,
            "addressMapBindings": 2,
            "targetResolutionMode": "bounded-relative-table",
            "targetSelectionFacts": {
                "caseIndices": [0, 1, 2, 3],
                "caseResults": case_results,
                "caseTargetSymbols": [f"urp_jump_table_case{index}" for index in range(4)],
                "sourceTargetAddresses": target_addresses,
                "rewrittenTargetOffsets": [0, 8, 16, 24],
                "expectedTraceValue": f"0x{trace:08x}",
                "traceAcceptanceEntryStatus": 91,
                "observation": "urp_entry returns 91 only after the in-function 0,1,2,3 table walk matches all four exact result bytes",
            },
            "firstFailureStage": None,
        }
        _write_json(positive / "jump-table-behavior.json", behavior)
        _write_json(
            positive / "stage.json",
            {
                "schemaVersion": 1,
                "stage": "protected-image-producer",
                "status": "passed",
                "unitId": INDIRECT_UNIT,
                "profile": "host-context-entry",
            },
        )
        _write_json(
            positive / "native-image.json",
            {
                "schemaVersion": 1,
                "stage": "native-image",
                "status": "passed",
                "unitId": INDIRECT_UNIT,
                "artifactRole": "native-image",
                "profile": "host-context-entry",
                "entrySymbol": "urp_entry",
                "sourceSha256": source_hash,
                "nativeImageSha256": native_hash,
                "nativeImageSize": len(native),
            },
        )

        for negative_name, message in INDIRECT_NEGATIVES.items():
            negative = root / negative_name
            negative.mkdir(parents=True)
            if negative_name == "negative-external-table":
                input_bytes = None
                source_bytes = bytearray(_external_jump_table_elf())
            else:
                input_bytes = _jump_table_elf(transformed=False)
                source_bytes = bytearray(input_bytes)
            mutation = None
            mutation_kinds = {
                "negative-malformed-table": "out-of-closure-executable-target",
                "negative-out-of-range-target": "outside-executable-load-range",
            }
            if negative_name in mutation_kinds:
                encoded_value = 0x54 if negative_name == "negative-malformed-table" else 0x7FFFFFE0
                struct.pack_into("<i", source_bytes, 0x400, encoded_value)
                assert input_bytes is not None
                (negative / "input-image.bin").write_bytes(input_bytes)
                computed_target = 0x1028 + encoded_value
                mutation = {
                    "schemaVersion": 1,
                    "mutationKind": mutation_kinds[negative_name],
                    "inputSha256": _sha(input_bytes),
                    "sourceSha256": _sha(bytes(source_bytes)),
                    "tableSymbol": "urp_jump_table",
                    "tableAddress": 0x2000,
                    "tableFileOffset": 0x400,
                    "tableSize": 16,
                    "entryIndex": 0,
                    "entryAddress": 0x2000,
                    "entryFileOffset": 0x400,
                    "entryWidth": 4,
                    "isSigned": True,
                    "targetBaseSymbol": "urp_jump_table_case0",
                    "targetBaseAddress": 0x1028,
                    "originalEncodedValue": 0,
                    "mutatedEncodedValue": encoded_value,
                    "computedTargetAddress": computed_target,
                    "targetSymbol": "urp_jump_table_outside_closure"
                    if negative_name == "negative-malformed-table"
                    else None,
                }
                _write_json(negative / "mutation.json", mutation)
            negative_source = bytes(source_bytes)
            (negative / "source-image.bin").write_bytes(negative_source)
            if negative_name == "negative-external-table":
                inspection = subprocess.run(
                    [
                        sys.executable,
                        str(INDIRECT_CHECKER),
                        "--inspect-external-table",
                        str(negative / "source-image.bin"),
                        "--selected-function",
                        "dynsym:2",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if inspection.returncode != 0:
                    raise AssertionError(inspection.stderr)
                (negative / "external-table-facts.json").write_text(inspection.stdout, encoding="utf-8")
            diagnostic = {
                "severity": "Error",
                "code": "IndirectTargetUnresolved",
                "message": message,
                "offset": 64,
            }
            negative_unit = f"{INDIRECT_UNIT}.{negative_name}"
            stage = {
                "schemaVersion": 1,
                "stage": "protected-image-producer",
                "status": "failed",
                "unitId": negative_unit,
                "sourceSha256": _sha(negative_source),
                "publicationComplete": False,
                "transformationStatus": "failed",
                "firstFailureStage": "protected-image-producer",
                "diagnostics": [diagnostic],
            }
            _write_json(negative / "stage.json", stage)
            _write_json(
                negative / "producer.stdout",
                {"schemaVersion": 1, "success": False, "stage": stage, "diagnostics": [diagnostic]},
            )
            (negative / "producer.stderr").write_bytes(b"")
            (negative / "producer-exit-status.txt").write_text("4\n", encoding="ascii")
            selected_function = "dynsym:2"
            producer_assembly = ROOT / "src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
            argv = [
                "dotnet", str(producer_assembly), "protect-image", str(negative / "source-image.bin"),
                "--artifact", str(negative / "protected-image.bin"),
                "--role", str(negative / "protected-image.json"),
                "--manifest", str(negative / "producer-manifest.txt"),
                "--stage", str(negative / "stage.json"),
                "--unit", negative_unit,
                "--profile", "host-context-entry",
                "--producer-id", f"gcc-aarch64-jump-table-{negative_name}",
                "--rehydrator", "urprotect.rehydrator.v1",
                "--source-sha256", _sha(negative_source),
                "--function-id", selected_function,
                "--pass", "control-flow-flattening", "--json", "-",
            ]
            _write_json(
                negative / "producer-command.json",
                {
                    "schemaVersion": 1,
                    "workingDirectory": str(ROOT),
                    "sourceSha256": _sha(negative_source),
                    "selectedFunction": selected_function,
                    "unitId": negative_unit,
                    "argv": argv,
                },
            )
            result_record = {
                "schemaVersion": 1,
                "unitId": negative_unit,
                "status": "passed",
                "producerExitStatus": 4,
                "producerStdoutSha256": _sha((negative / "producer.stdout").read_bytes()),
                "producerStderrSha256": _sha(b""),
                "producerCommandSha256": _sha((negative / "producer-command.json").read_bytes()),
                "sourceSha256": _sha(negative_source),
                "protectedImagePublished": False,
                "nativeImagePublished": False,
                "loaderInvoked": False,
                "expectedDiagnosticFamily": "IndirectTargetUnresolved",
                "expectedDiagnosticMessage": message,
                "firstFailureStage": "protected-image-producer",
            }
            if mutation is not None:
                assert input_bytes is not None
                result_record["inputSourceSha256"] = _sha(input_bytes)
                result_record["mutationSha256"] = _sha((negative / "mutation.json").read_bytes())
            if negative_name == "negative-external-table":
                result_record["externalTableFactsSha256"] = _sha((negative / "external-table-facts.json").read_bytes())
            _write_json(negative / "negative-result.json", result_record)
        _refresh_indirect_manifest(root)

    def refresh_native_image_bindings(self, positive: Path) -> None:
        native_path = positive / "native-image.bin"
        native = native_path.read_bytes()
        native_hash = _sha(native)
        rehydration_path = positive / "rehydration.json"
        rehydration = json.loads(rehydration_path.read_text(encoding="utf-8"))
        rehydration["nativeImageSha256"] = native_hash
        rehydration["nativeImageSize"] = len(native)
        rehydration["layoutEvidence"]["outputSha256"] = native_hash
        _write_json(rehydration_path, rehydration)
        handoff_path = positive / "handoff.json"
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        handoff["nativeImageSha256"] = native_hash
        _write_json(handoff_path, handoff)
        native_metadata_path = positive / "native-image.json"
        native_metadata = json.loads(native_metadata_path.read_text(encoding="utf-8"))
        native_metadata["nativeImageSha256"] = native_hash
        native_metadata["nativeImageSize"] = len(native)
        _write_json(native_metadata_path, native_metadata)
        behavior_path = positive / "jump-table-behavior.json"
        behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
        behavior["nativeSha256"] = native_hash
        behavior["targetHandoffSha256"] = _sha(handoff_path.read_bytes())
        _write_json(behavior_path, behavior)
        self.refresh_runtime_identity(positive, "target")

    def add_native_load_alias(
        self,
        positive: Path,
        virtual_address: int,
        file_offset: int,
        size: int,
        flags: int,
        *,
        partial: bool,
    ) -> None:
        if partial:
            virtual_address += size - 1
            file_offset += size - 1
            size = 1
        image_path = positive / "native-image.bin"
        image = bytearray(image_path.read_bytes())
        phoff = struct.unpack_from("<Q", image, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", image, 54)
        if phentsize != 56:
            raise AssertionError("unexpected synthetic ELF program-header size")
        previous_headers = bytes(image[phoff:phoff + phentsize * phnum])
        relocated_phoff = len(image)
        image.extend(previous_headers)
        image.extend(struct.pack(
            "<IIQQQQQQ", 1, flags, file_offset, virtual_address, virtual_address, size, size, 1
        ))
        struct.pack_into("<Q", image, 32, relocated_phoff)
        struct.pack_into("<H", image, 56, phnum + 1)
        image_path.write_bytes(image)

    def run_checker(
        self,
        root: Path,
        *,
        runtime: str = "glibc",
        require_runtime_identity: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(INDIRECT_CHECKER),
            str(root),
            "--tier",
            "pr",
            "--unit",
            INDIRECT_UNIT if runtime == "glibc" else INDIRECT_UNIT.replace("glibc", runtime),
            "--runtime",
            runtime,
        ]
        if require_runtime_identity:
            command.append("--require-runtime-identity")
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def copy_evidence(self, source: Path, parent: Path) -> Path:
        copied = parent / "copy"
        shutil.copytree(source, copied)
        return copied

    def reject_refreshed_mutation(self, mutate) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="indirect-control-target-binding-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            mutate(positive)
            self.refresh_runtime_identity(positive, "source")
            self.refresh_runtime_identity(positive, "target")
            _refresh_indirect_manifest(root)
            return self.run_checker(root)

    def reject_refreshed_negative_mutation(
        self,
        negative_name: str,
        mutate,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="indirect-control-negative-tamper-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            mutate(root / negative_name)
            _refresh_indirect_manifest(root)
            return self.run_checker(root)

    def reject_refreshed_external_fact_mutation(self, mutate) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="indirect-control-external-owner-tamper-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            negative = root / "negative-external-table"
            facts_path = negative / "external-table-facts.json"
            facts = json.loads(facts_path.read_text(encoding="utf-8"))
            mutate(facts)
            _write_json(facts_path, facts)
            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["externalTableFactsSha256"] = _sha(facts_path.read_bytes())
            _write_json(result_path, result)
            _refresh_indirect_manifest(root)
            return self.run_checker(root)

    def _single_file_snapshot(self, root: Path, data: bytes, relative: str = "source-image.bin"):
        root.mkdir()
        (root / relative).write_bytes(data)
        (root / "SHA256SUMS").write_text(
            f"{_sha(data)}  {relative}\n", encoding="ascii"
        )
        return INDIRECT_PRIVATE_CHECKER.EvidenceRootSnapshot(root)

    def test_private_checker_count_bounds_accept_exact_empty_entries_and_reject_plus_one_before_file_open(self) -> None:
        open_calls: list[tuple[object, int]] = []
        original_open = os.open

        def tracked_open(path, flags, *args, **kwargs):
            open_calls.append((path, flags))
            return original_open(path, flags, *args, **kwargs)

        with tempfile.TemporaryDirectory(prefix="indirect-control-empty-count-bounds-") as directory:
            exact_root = Path(directory) / "exact"
            exact_root.mkdir()
            (exact_root / "empty-a").write_bytes(b"")
            (exact_root / "empty-b").write_bytes(b"")
            (exact_root / "one-dir").mkdir()
            with mock.patch.object(INDIRECT_PRIVATE_CHECKER.os, "open", side_effect=tracked_open):
                exact = INDIRECT_PRIVATE_CHECKER.EvidenceRootSnapshot(
                    exact_root, max_files=2, max_directories=2, max_total_bytes=0
                )
                exact.preflight()
            self.assertEqual({"empty-a", "empty-b"}, exact.file_paths)
            self.assertEqual({"one-dir"}, exact.directory_paths)
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for _path, flags in open_calls))

            open_calls.clear()
            over_file_root = Path(directory) / "over-file"
            over_file_root.mkdir()
            for name in ("empty-a", "empty-b", "empty-c"):
                (over_file_root / name).write_bytes(b"")
            with mock.patch.object(INDIRECT_PRIVATE_CHECKER.os, "open", side_effect=tracked_open):
                over_files = INDIRECT_PRIVATE_CHECKER.EvidenceRootSnapshot(
                    over_file_root, max_files=2, max_directories=2, max_total_bytes=0
                )
                with self.assertRaisesRegex(SystemExit, "file-count bound"):
                    over_files.preflight()
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for _path, flags in open_calls))
            self.assertEqual({}, over_files._bytes)

            open_calls.clear()
            over_directory_root = Path(directory) / "over-directory"
            over_directory_root.mkdir()
            for name in ("dir-a", "dir-b"):
                (over_directory_root / name).mkdir()
            with mock.patch.object(INDIRECT_PRIVATE_CHECKER.os, "open", side_effect=tracked_open):
                over_directories = INDIRECT_PRIVATE_CHECKER.EvidenceRootSnapshot(
                    over_directory_root, max_files=2, max_directories=2, max_total_bytes=0
                )
                with self.assertRaisesRegex(SystemExit, "directory-count bound"):
                    over_directories.preflight()
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for _path, flags in open_calls))
            self.assertEqual({}, over_directories._bytes)

    def test_preloaded_range_module_with_foreign_origin_is_rejected_without_module_code_execution(self) -> None:
        helper_path = Path(INDIRECT_PRIVATE_CHECKER.__file__).resolve().with_name("evidence_load_range.py")
        module_name = INDIRECT_PRIVATE_CHECKER._range_helper_module_name(helper_path)
        with tempfile.TemporaryDirectory(prefix="indirect-control-foreign-module-") as directory:
            foreign_path = Path(directory) / "foreign.py"
            foreign_path.write_text("# foreign module origin\n", encoding="utf-8")
            code_runs: list[str] = []

            class ForeignModule(types.ModuleType):
                def __getattribute__(self, name: str):
                    if name not in {"__class__", "__dict__"}:
                        code_runs.append(name)
                    return super().__getattribute__(name)

            foreign = ForeignModule(module_name)
            types.ModuleType.__getattribute__(foreign, "__dict__")["__file__"] = str(foreign_path)
            previous = sys.modules.get(module_name)
            sys.modules[module_name] = foreign
            try:
                with mock.patch.object(
                    INDIRECT_PRIVATE_CHECKER,
                    "_read_sibling_helper_source",
                    side_effect=AssertionError("foreign module must be rejected before opening helper source"),
                ):
                    with self.assertRaisesRegex(ImportError, "is not checker-owned"):
                        INDIRECT_PRIVATE_CHECKER._load_sibling_evidence_range_helper()
            finally:
                if previous is None:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = previous
            self.assertEqual([], code_runs)

    def test_preloaded_range_module_with_matching_origin_and_digest_is_not_trusted(self) -> None:
        helper_path = Path(INDIRECT_PRIVATE_CHECKER.__file__).resolve().with_name("evidence_load_range.py")
        module_name = INDIRECT_PRIVATE_CHECKER._range_helper_module_name(helper_path)
        code_runs: list[str] = []

        class ForgedModule(types.ModuleType):
            def __getattribute__(self, name: str):
                if name not in {"__class__", "__dict__"}:
                    code_runs.append(name)
                return super().__getattribute__(name)

        forged = ForgedModule(module_name)
        namespace = types.ModuleType.__getattribute__(forged, "__dict__")
        namespace["__file__"] = str(helper_path)
        namespace[INDIRECT_PRIVATE_CHECKER._RANGE_MODULE_SOURCE_DIGEST] = (
            types.ModuleType.__getattribute__(INDIRECT_PRIVATE_CHECKER._RANGE_HELPER, "__dict__")[
                INDIRECT_PRIVATE_CHECKER._RANGE_MODULE_SOURCE_DIGEST
            ]
        )
        namespace["resolve_isolated_evidence_root"] = lambda *_args, **_kwargs: "forged"
        previous = sys.modules.get(module_name)
        sys.modules[module_name] = forged
        try:
            with mock.patch.object(
                INDIRECT_PRIVATE_CHECKER,
                "_read_sibling_helper_source",
                side_effect=AssertionError("unowned cache entry must be rejected before source reuse"),
            ):
                with self.assertRaisesRegex(ImportError, "is not checker-owned"):
                    INDIRECT_PRIVATE_CHECKER._load_sibling_evidence_range_helper()
        finally:
            if previous is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous
        self.assertEqual([], code_runs)

    def test_private_checker_file_and_aggregate_bounds_accept_exact_max_and_reject_plus_one_pre_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-bounded-read-") as directory:
            root = Path(directory) / "exact"
            data = b"x" * 16
            with (
                mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_IMAGE_BYTES", 16),
                mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_TOTAL_BYTES", 4096),
            ):
                exact = self._single_file_snapshot(root, data)
                exact.preflight()
                exact.verify_manifest()
                self.assertEqual(data, exact.read("source-image.bin"))
                actual_total = sum(path.stat().st_size for path in root.iterdir())

                with mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_TOTAL_BYTES", actual_total):
                    at_total_limit = INDIRECT_PRIVATE_CHECKER.EvidenceRootSnapshot(root)
                    at_total_limit.preflight()
                with mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_TOTAL_BYTES", actual_total - 1):
                    over_total = INDIRECT_PRIVATE_CHECKER.EvidenceRootSnapshot(root)
                    with mock.patch.object(over_total, "_open_relative", side_effect=AssertionError("file read before aggregate gate")):
                        with self.assertRaisesRegex(SystemExit, "aggregate byte limit"):
                            over_total.preflight()

            with tempfile.TemporaryDirectory(prefix="indirect-control-file-plus-one-") as nested:
                over_root = Path(nested) / "over"
                with (
                    mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_IMAGE_BYTES", 16),
                    mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_TOTAL_BYTES", 4096),
                ):
                    over_file = self._single_file_snapshot(over_root, b"x" * 17)
                    with mock.patch.object(over_file, "_open_relative", side_effect=AssertionError("file read before per-file gate")):
                        with self.assertRaisesRegex(SystemExit, "per-file byte limit"):
                            over_file.preflight()

    def test_private_checker_external_image_reader_observes_exact_limit_and_rejects_plus_one_before_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-external-bounded-read-") as directory:
            image = Path(directory) / "source.elf"
            image.write_bytes(b"x" * 16)
            with mock.patch.object(INDIRECT_PRIVATE_CHECKER, "MAX_EVIDENCE_IMAGE_BYTES", 16):
                self.assertEqual(b"x" * 16, INDIRECT_PRIVATE_CHECKER.read_bounded_external_file(image, 16, "test ELF"))
                image.write_bytes(b"x" * 17)
                with mock.patch.object(INDIRECT_PRIVATE_CHECKER.os, "read", side_effect=AssertionError("read before size gate")):
                    with self.assertRaisesRegex(SystemExit, "not a bounded regular file"):
                        INDIRECT_PRIVATE_CHECKER.read_bounded_external_file(image, 16, "test ELF")

    def test_private_checker_detects_truncation_and_growth_during_bounded_read(self) -> None:
        for mutation, diagnostic in (
            (lambda path: path.write_bytes(b"x"), "truncated while reading"),
            (lambda path: path.write_bytes(b"data-plus-growth"), "grew or changed while reading"),
        ):
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory(prefix="indirect-control-race-") as directory:
                root = Path(directory) / "evidence"
                snapshot = self._single_file_snapshot(root, b"data", relative="evidence.bin")
                snapshot.preflight()
                with self.assertRaisesRegex(SystemExit, diagnostic):
                    snapshot.read(
                        "evidence.bin",
                        after_initial_size_validation=lambda: mutation(root / "evidence.bin"),
                    )

    def test_private_checker_rejects_unlisted_special_files_before_open(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-special-file-") as directory:
            root = Path(directory) / "evidence"
            snapshot = self._single_file_snapshot(root, b"safe")
            os.mkfifo(root / "unlisted-fifo")
            with mock.patch.object(snapshot, "_open_relative", side_effect=AssertionError("opened special file")):
                with self.assertRaisesRegex(SystemExit, "non-regular evidence file"):
                    snapshot.preflight()

    def test_private_checker_rejects_final_symlink_replacement_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-final-symlink-race-") as directory:
            parent = Path(directory)
            root = parent / "evidence"
            snapshot = self._single_file_snapshot(root, b"safe", relative="evidence.bin")
            outside = parent / "outside"
            outside.write_bytes(b"secret")
            snapshot.preflight()
            path = root / "evidence.bin"
            path.unlink()
            path.symlink_to(outside)
            with mock.patch.object(INDIRECT_PRIVATE_CHECKER.os, "read", side_effect=AssertionError("read followed final symlink")):
                with self.assertRaisesRegex(SystemExit, "cannot be opened safely"):
                    snapshot.read("evidence.bin")

    def test_private_checker_detects_final_symlink_replacement_after_same_handle_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-final-symlink-postread-") as directory:
            parent = Path(directory)
            root = parent / "evidence"
            snapshot = self._single_file_snapshot(root, b"safe", relative="evidence.bin")
            outside = parent / "outside"
            outside.write_bytes(b"secret")
            snapshot.preflight()
            path = root / "evidence.bin"

            def replace_after_open() -> None:
                path.unlink()
                path.symlink_to(outside)

            # Depending on filesystem timestamp granularity, unlinking the
            # open inode may either be detected by the same-handle metadata
            # check immediately or leave the original safe bytes readable.
            # It must never follow the replacement symlink, and the final tree
            # verification must reject the changed pathname in either case.
            try:
                data = snapshot.read("evidence.bin", after_initial_size_validation=replace_after_open)
            except SystemExit as error:
                self.assertIn("grew or changed while reading", str(error))
            else:
                self.assertEqual(b"safe", data)
            with self.assertRaises(SystemExit) as changed_tree:
                snapshot.verify_tree_unchanged()
            self.assertRegex(
                str(changed_tree.exception),
                r"(?:contains a symlink: evidence\.bin|root changed after bounded tree preflight|tree changed after bounded snapshot validation)",
            )

    def test_private_checker_fifo_replacement_after_preflight_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-fifo-race-") as directory:
            root = Path(directory) / "evidence"
            snapshot = self._single_file_snapshot(root, b"safe", relative="evidence.bin")
            snapshot.preflight()
            path = root / "evidence.bin"
            path.unlink()
            os.mkfifo(path)
            with self.assertRaisesRegex(SystemExit, "changed after bounded tree preflight"):
                snapshot.read("evidence.bin")

    def test_artifact_root_rejects_symlink_alias_and_nested_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-root-isolation-") as directory:
            parent = Path(directory)
            root = parent / "evidence"
            self.create_evidence(root)
            alias = parent / "evidence-alias"
            alias.symlink_to(root, target_is_directory=True)
            result = self.run_checker(alias)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("must be an isolated non-symlink directory", result.stderr.lower())

            (root / "unlisted-link").symlink_to(root, target_is_directory=True)
            result = self.run_checker(root)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("contains a symlink", result.stderr.lower())

    def test_live_entry_b_stub_must_target_the_mapped_output_function_not_dead_default(self) -> None:
        def retarget_entry_to_default(positive: Path) -> None:
            native_path = positive / "native-image.bin"
            image = bytearray(native_path.read_bytes())
            # B from source dynsym VA 0x1000 to retained emitted MOV W0,#-1; RET at 0x3040.
            struct.pack_into("<I", image, 0x200, 0x14000810)
            native_path.write_bytes(image)
            self.refresh_native_image_bindings(positive)

        result = self.reject_refreshed_mutation(retarget_entry_to_default)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("entry b target bypasses the exact mapped output function entry", result.stderr.lower())
        self.assertNotIn("sha256sum", result.stderr.lower())

    def test_partial_pt_load_intersections_reject_stub_code_and_clone_ranges(self) -> None:
        cases = (
            ("entry-stub", 0x1000, 0x200, 4, 5, "native image urp_entry entry b stub"),
            ("emitted-code", 0x3000, 0x600, 0x100, 5, "selected address-map complete native image output range"),
            ("table-clone", 0x4000, 0x700, 16, 4, "native image jump-table clone"),
        )
        for name, va, offset, size, flags, label in cases:
            with self.subTest(name=name):
                def add_partial(positive: Path) -> None:
                    self.add_native_load_alias(positive, va, offset, size, flags, partial=True)
                    self.refresh_native_image_bindings(positive)

                result = self.reject_refreshed_mutation(add_partial)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(label, result.stderr.lower())
                self.assertIn("partially intersects another pt_load memory interval", result.stderr.lower())
                self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_duplicate_fully_containing_pt_load_owners_reject_stub_code_and_clone(self) -> None:
        cases = (
            ("entry-stub", 0x1000, 0x200, 4, 5, "native image urp_entry entry b stub"),
            ("emitted-code", 0x3000, 0x600, 0x100, 5, "selected address-map complete native image output range"),
            ("table-clone", 0x4000, 0x700, 16, 4, "native image jump-table clone"),
        )
        for name, va, offset, size, flags, label in cases:
            with self.subTest(name=name):
                def add_duplicate_owner(positive: Path) -> None:
                    self.add_native_load_alias(positive, va, offset, size, flags, partial=False)
                    self.refresh_native_image_bindings(positive)

                result = self.reject_refreshed_mutation(add_duplicate_owner)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(label, result.stderr.lower())
                self.assertIn("exactly one fully containing file-backed pt_load owner", result.stderr.lower())
                self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_half_open_adjacent_load_ranges_remain_accepted(self) -> None:
        def add_adjacent_loads(positive: Path) -> None:
            for va, offset, flags in (
                (0x1004, 0x204, 5),
                (0x3100, 0x700, 5),
                (0x4010, 0x710, 4),
            ):
                self.add_native_load_alias(positive, va, offset, 1, flags, partial=False)
            self.refresh_native_image_bindings(positive)

        result = self.reject_refreshed_mutation(add_adjacent_loads)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_musl_runtime_identity_is_independently_verified_from_native_mapped_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="musl-runtime-identity-verified-") as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            image_hash = "c" * 64
            carrier = self.write_runtime_identity(root, "target", image_hash, runtime="musl")
            handoff = {
                "schemaVersion": 1,
                "stage": "host-context-handoff",
                "status": "passed",
                "loaderId": "host-context.sealed-memfd.dlopen",
                "nativeImageSha256": image_hash,
                "entryStatus": 23,
                "processStatus": 23,
                "releaseStatus": "passed",
                "releaseOrder": "entry-dispatch-before-release-image",
                "rehydrationRecordSha256": "d" * 64,
                "runtimeIdentity": carrier,
            }
            identity = REHYDRATION_PRIVATE_CHECKER._RUNTIME_IDENTITY_HELPER.validate_handoff_runtime_identity(
                root, handoff, expected_runtime="musl", expected_role="target",
                expected_image_sha256=image_hash, required=True,
            )
            self.assertEqual(identity["runtime"], "musl")
            with self.assertRaises(ValueError):
                REHYDRATION_PRIVATE_CHECKER._RUNTIME_IDENTITY_HELPER.validate_handoff_runtime_identity(
                    root, handoff, expected_runtime="glibc", expected_role="target",
                    expected_image_sha256=image_hash, required=True,
                )

    def test_rehydration_handoff_checker_preserves_optional_glibc_and_required_native_identity_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rehydration-runtime-identity-gate-") as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            image_hash = "a" * 64
            carrier = self.write_runtime_identity(root, "target", image_hash)
            handoff = {
                "schemaVersion": 1,
                "stage": "host-context-handoff",
                "status": "passed",
                "loaderId": "host-context.sealed-memfd.dlopen",
                "nativeImageSha256": image_hash,
                "entryStatus": 23,
                "processStatus": 23,
                "releaseStatus": "passed",
                "releaseOrder": "entry-dispatch-before-release-image",
                "rehydrationRecordSha256": "b" * 64,
                "runtimeIdentity": carrier,
            }
            rehydration = {
                "status": "passed",
                "processStatus": 23,
                "preHandoffRecordSha256": "b" * 64,
            }
            _write_json(root / "handoff.json", handoff)
            REHYDRATION_PRIVATE_CHECKER.check_handoff(root, rehydration, image_hash, "glibc", True)
            REHYDRATION_PRIVATE_CHECKER.check_handoff(root, rehydration, image_hash, "glibc", False)
            handoff.pop("runtimeIdentity")
            _write_json(root / "handoff.json", handoff)
            with self.assertRaises(SystemExit):
                REHYDRATION_PRIVATE_CHECKER.check_handoff(root, rehydration, image_hash, "glibc", True)

    def test_measured_four_case_evidence_and_four_negatives_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-valid-") as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            self.create_evidence(root)
            result = self.run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("all table cases", result.stdout)
            self.assertIn("four fail-closed negatives", result.stdout)

    def test_missing_or_downgraded_runtime_identity_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-runtime-identity-missing-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            handoff_path = positive / "handoff.json"
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            handoff.pop("runtimeIdentity")
            _write_json(handoff_path, handoff)
            behavior_path = positive / "jump-table-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["targetHandoffSha256"] = _sha(handoff_path.read_bytes())
            source_handoff_path = positive / "source-handoff.json"
            source_handoff = json.loads(source_handoff_path.read_text(encoding="utf-8"))
            source_handoff.pop("runtimeIdentity")
            _write_json(source_handoff_path, source_handoff)
            behavior["sourceHandoffSha256"] = _sha(source_handoff_path.read_bytes())
            _write_json(behavior_path, behavior)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing its required native runtime identity", result.stderr)
            historical_glibc = self.run_checker(root, require_runtime_identity=False)
            self.assertEqual(historical_glibc.returncode, 0, historical_glibc.stderr)

    def test_native_runtime_identity_rejects_wrong_helper_interpreter_and_symlink_claim(self) -> None:
        def wrong_interpreter(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            helper_path = positive / identity["helper"]["retainedPath"]
            helper = bytearray(helper_path.read_bytes())
            encoded = b"/lib/ld-musl-aarch64.so.1\0"
            struct.pack_into("<Q", helper, 120 + 32, len(encoded))
            struct.pack_into("<Q", helper, 120 + 40, len(encoded))
            helper[0x180 : 0x180 + 32] = bytes(32)
            helper[0x180 : 0x180 + len(encoded)] = encoded
            helper_path.write_bytes(helper)
            identity["helper"]["sha256"] = _sha(bytes(helper))
            identity["interpreter"]["declaredPath"] = "/lib/ld-musl-aarch64.so.1"
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(wrong_interpreter)
        self.assertIn("wrong loader family", result.stderr)

        def symlink_alias_claim(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["interpreter"]["resolvedPath"] = identity["interpreter"]["declaredPath"]
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(symlink_alias_claim)
        self.assertIn("does not identify the mapped loader path", result.stderr)

    def test_native_runtime_identity_rejects_maps_inode_and_range_mismatch(self) -> None:
        def wrong_inode(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["helper"]["inode"] += 1
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(wrong_inode)
        self.assertIn("device/inode does not identify", result.stderr)

        def malformed_kernel_region_label(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            maps_path = positive / identity["maps"]["retainedPath"]
            maps = maps_path.read_bytes().replace(b"[heap]", b"[heap", 1)
            maps_path.write_bytes(maps)
            identity["maps"]["sha256"] = _sha(maps)
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(malformed_kernel_region_label)
        self.assertIn("canonical mapped path or kernel region label", result.stderr)

        def out_of_load_range(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            maps_path = positive / identity["maps"]["retainedPath"]
            maps = maps_path.read_bytes().replace(b"0000000000101000", b"0000000000102000", 1)
            maps_path.write_bytes(maps)
            identity["maps"]["sha256"] = _sha(maps)
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(out_of_load_range)
        self.assertIn("partially intersects a PT_LOAD page range", result.stderr)

    def test_native_runtime_identity_rejects_refreshed_version_claim_and_runtime_byte_digest(self) -> None:
        def wrong_version(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["runtimeVersion"] = "2.44"
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(wrong_version)
        self.assertIn("version differs from the retained mapped libc bytes", result.stderr)

        def runtime_bytes_changed_without_digest_refresh(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            libc_path = positive / identity["libc"]["retainedPath"]
            data = bytearray(libc_path.read_bytes())
            data[0x100] ^= 1
            libc_path.write_bytes(data)
        result = self.reject_runtime_identity_mutation(runtime_bytes_changed_without_digest_refresh)
        self.assertIn("retained ELF digest does not match", result.stderr)

    def test_native_runtime_identity_rejects_valid_per_process_runtime_version_divergence(self) -> None:
        def valid_but_different_target_version(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            libc_path = positive / identity["libc"]["retainedPath"]
            data = libc_path.read_bytes().replace(b"release version 2.43.", b"release version 2.44.", 1)
            libc_path.write_bytes(data)
            identity["libc"]["sha256"] = _sha(data)
            identity["runtimeVersion"] = "2.44"
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(valid_but_different_target_version)
        self.assertIn("different runtime families or versions", result.stderr)

    def test_native_runtime_identity_schema_versions_require_exact_integer_tokens(self) -> None:
        for location in ("carrier", "identity"):
            for invalid_version in (True, 1.0, "1"):
                with self.subTest(location=location, invalid_version=invalid_version):
                    def mutate(positive: Path, role: str, *, target: str = location, value=invalid_version) -> None:
                        identity_path = positive / "runtime-identity" / role / "identity.json"
                        identity = json.loads(identity_path.read_text(encoding="utf-8"))
                        if target == "identity":
                            identity["schemaVersion"] = value
                            _write_json(identity_path, identity)
                            return
                        handoff_name = "source-handoff.json" if role == "source" else "handoff.json"
                        handoff_path = positive / handoff_name
                        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                        handoff["runtimeIdentity"]["schemaVersion"] = value
                        _write_json(handoff_path, handoff)
                    result = self.reject_runtime_identity_mutation(mutate)
                    expected = (
                        "schemaVersion must be an exact integer"
                        if location == "identity"
                        else "schemaVersion must be the exact integer 1"
                    )
                    self.assertIn(expected, result.stderr)

    def test_native_runtime_identity_rejects_checksum_refreshed_duplicate_pt_load_owner(self) -> None:
        def duplicate_libc_load(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            libc_record = identity["libc"]
            libc_path = positive / libc_record["retainedPath"]
            libc = bytearray(libc_path.read_bytes())
            phoff = struct.unpack_from("<Q", libc, 32)[0]
            phentsize, phnum = struct.unpack_from("<HH", libc, 54)
            if phentsize != 56 or phnum != 1 or phoff + 2 * phentsize > len(libc):
                raise AssertionError("synthetic libc has no bounded spare program-header slot")
            libc[phoff + phentsize : phoff + 2 * phentsize] = libc[phoff : phoff + phentsize]
            struct.pack_into("<H", libc, 56, phnum + 1)
            libc_path.write_bytes(libc)
            libc_record["size"] = len(libc)
            libc_record["sha256"] = _sha(libc)
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(duplicate_libc_load)
        self.assertIn("exactly one fully-containing PT_LOAD owner", result.stderr)

    def test_native_runtime_identity_rejects_partial_pt_load_file_interval_intersection(self) -> None:
        def extend_libc_mapping(positive: Path, role: str) -> None:
            identity_path = positive / "runtime-identity" / role / "identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            maps_path = positive / identity["maps"]["retainedPath"]
            maps = maps_path.read_bytes().replace(
                b"0000000000201000 r-xp 00000000 08:01 1002",
                b"0000000000202000 r-xp 00000000 08:01 1002",
                1,
            )
            if maps == maps_path.read_bytes():
                raise AssertionError("synthetic libc maps row was not found")
            maps_path.write_bytes(maps)
            identity["maps"]["sha256"] = _sha(maps)
            _write_json(identity_path, identity)
        result = self.reject_runtime_identity_mutation(extend_libc_mapping)
        self.assertIn("partially intersects a PT_LOAD page range", result.stderr)

    def test_native_runtime_identity_rejects_checksum_refreshed_pt_load_virtual_memory_aliases(self) -> None:
        page_size = os.sysconf("SC_PAGE_SIZE")
        primary = (0, 0, 2 * page_size, 2 * page_size, 5)
        cases = (
            (
                "independent review example",
                (primary, (2 * page_size, 0, page_size, page_size, 4)),
                ((0, 0, 1, "r-xp"),),
                "conflicting pt_load virtual-memory owner",
            ),
            (
                "full virtual-only overlap",
                (primary, (2 * page_size, 0, page_size, 2 * page_size, 4)),
                ((0, 0, 2, "r-xp"),),
                "conflicting pt_load virtual-memory owner",
            ),
            (
                "partial virtual-only overlap",
                (primary, (2 * page_size, page_size, page_size, page_size, 4)),
                ((0, 0, 2, "r-xp"),),
                "partially intersects a pt_load virtual-memory interval",
            ),
            (
                "zero-filesz BSS overlap",
                (primary, (2 * page_size, 0, 0, page_size, 4)),
                ((0, 0, 1, "r-xp"),),
                "conflicting pt_load virtual-memory owner",
            ),
            (
                "overflowing page-rounded memsz",
                (
                    primary,
                    (2 * page_size, (1 << 64) - page_size + 1, 0, page_size - 2, 4),
                ),
                ((0, 0, 1, "r-xp"),),
                "pt_load memory interval page rounding overflows",
            ),
        )
        for name, loads, maps, expected_message in cases:
            with self.subTest(name=name):
                def mutate(positive: Path, role: str, *, current_loads=loads, current_maps=maps) -> None:
                    self.set_runtime_pt_load_layout(positive, role, current_loads, current_maps)

                result = self.reject_runtime_identity_mutation(mutate)
                self.assertIn(expected_message, result.stderr.lower())
                self.assertNotIn("sha256sums", result.stderr.lower())
                self.assertNotIn("manifest digest mismatch", result.stderr.lower())
                self.assertNotIn("retained elf digest does not match", result.stderr.lower())

    def test_native_runtime_identity_accepts_adjacent_half_open_pt_load_pages(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-identity-adjacent-half-open-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            page_size = os.sysconf("SC_PAGE_SIZE")
            for role in ("source", "target"):
                self.set_runtime_pt_load_layout(
                    positive,
                    role,
                    (
                        (0, 0, page_size, page_size, 5),
                        (2 * page_size, page_size, page_size, page_size, 5),
                    ),
                    ((0, 0, 1, "r-xp"), (1, 2, 1, "r-xp")),
                )
                self.refresh_runtime_identity(positive, role)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root, runtime="glibc", require_runtime_identity=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_standalone_rehydration_checker_bounds_evidence_directories(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rehydration-directory-cap-") as directory:
            parent = Path(directory)
            self.create_evidence(parent)
            root = parent / INDIRECT_UNIT
            _refresh_indirect_manifest(root)
            maximum_directories = REHYDRATION_PRIVATE_CHECKER.MAX_DIRECTORIES
            existing_directories = 1 + sum(path.is_dir() for path in root.rglob("*"))
            if existing_directories >= maximum_directories:
                self.fail("synthetic evidence tree already exceeds the directory-limit fixture budget")
            for index in range(maximum_directories - existing_directories):
                (root / f"bounded-empty-{index:04d}").mkdir()
            command = [
                sys.executable,
                str(CHECKER),
                str(root),
                "--tier", "pr",
                "--runtime", "glibc",
                "--unit", INDIRECT_UNIT,
            ]
            exact_tree = REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root)
            exact_tree.preflight()
            self.assertEqual(maximum_directories, len(exact_tree.directories))
            at_limit = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertNotEqual(at_limit.returncode, 0)
            self.assertIn("missing or invalid rehydration evidence file: protected-image.json", at_limit.stderr)
            (root / "one-over-directory-bound").mkdir()
            over_limit = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertNotEqual(over_limit.returncode, 0, over_limit.stdout)
            self.assertIn("directory count exceeds its configured bound", over_limit.stderr)

    def test_standalone_rehydration_checker_rejects_directory_overflow_before_descent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rehydration-directory-pre-descent-") as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            exact_child_limit = REHYDRATION_PRIVATE_CHECKER.MAX_DIRECTORIES - 1
            for index in range(exact_child_limit):
                (root / f"dir-{index:04d}").mkdir()
            exact_tree = REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root)
            exact_tree.preflight()
            self.assertEqual(REHYDRATION_PRIVATE_CHECKER.MAX_DIRECTORIES, len(exact_tree.directories))

            (root / "overflow-dir").mkdir()
            original_open = os.open
            child_directory_opens = 0

            def count_child_directory_open(path, *args, **kwargs):
                nonlocal child_directory_opens
                if kwargs.get("dir_fd") is not None and isinstance(path, str):
                    child_directory_opens += 1
                    if child_directory_opens > exact_child_limit:
                        raise AssertionError("standalone evidence checker descended into an over-limit directory")
                return original_open(path, *args, **kwargs)

            with mock.patch.object(REHYDRATION_PRIVATE_CHECKER.os, "open", side_effect=count_child_directory_open):
                with self.assertRaisesRegex(SystemExit, "directory count exceeds its configured bound"):
                    REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root).preflight()
            self.assertEqual(exact_child_limit, child_directory_opens)

    def test_standalone_rehydration_tree_enforces_exact_entry_and_file_caps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rehydration-reader-entry-cap-") as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            for index in range(REHYDRATION_PRIVATE_CHECKER.MAX_FILES):
                (root / f"payload-{index:04d}").touch()
            exact_files = REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root)
            exact_files.preflight()
            self.assertEqual(REHYDRATION_PRIVATE_CHECKER.MAX_FILES, len(exact_files.files))
            (root / "one-over-file-cap").touch()
            with self.assertRaisesRegex(SystemExit, "file count exceeds its configured bound"):
                REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root).preflight()

        with tempfile.TemporaryDirectory(prefix="rehydration-reader-file-cap-") as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            for index in range(REHYDRATION_PRIVATE_CHECKER.MAX_DIRECTORIES - 1):
                (root / f"dir-{index:04d}").mkdir()
            file_count = REHYDRATION_PRIVATE_CHECKER.MAX_ENTRIES - (REHYDRATION_PRIVATE_CHECKER.MAX_DIRECTORIES - 1)
            for index in range(file_count):
                (root / f"payload-{index:04d}").touch()
            exact_entries = REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root)
            exact_entries.preflight()
            self.assertEqual(REHYDRATION_PRIVATE_CHECKER.MAX_ENTRIES, len(exact_entries.files) + len(exact_entries.directories) - 1)
            (root / "one-over-entry-cap").touch()
            with self.assertRaisesRegex(SystemExit, "entry count exceeds its configured bound"):
                REHYDRATION_PRIVATE_CHECKER.BoundedEvidenceTree(root).preflight()

    def test_standalone_rehydration_checker_rejects_root_and_nested_symlink_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rehydration-reader-symlink-guards-") as directory:
            parent = Path(directory)
            self.create_evidence(parent)
            root = parent / INDIRECT_UNIT
            _refresh_indirect_manifest(root)
            command = [
                sys.executable,
                str(CHECKER),
                str(root),
                "--tier", "pr",
                "--runtime", "glibc",
                "--unit", INDIRECT_UNIT,
            ]
            alias_parent = parent / "evidence-alias-parent"
            alias_parent.symlink_to(parent, target_is_directory=True)
            parent_alias = alias_parent / INDIRECT_UNIT
            parent_alias_result = subprocess.run(
                [*command[:2], str(parent_alias), *command[3:]],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(parent_alias_result.returncode, 0)
            self.assertIn("must not contain symlink path components", parent_alias_result.stderr)

            root_alias_parent = parent / "evidence-root-alias"
            root_alias_parent.mkdir()
            alias = root_alias_parent / INDIRECT_UNIT
            alias.symlink_to(root, target_is_directory=True)
            root_alias = subprocess.run(
                [*command[:2], str(alias), *command[3:]],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(root_alias.returncode, 0)
            self.assertIn("must not contain symlink path components", root_alias.stderr)

            outside = parent / "outside"
            outside.mkdir()
            (root / "unlisted-symlink").symlink_to(outside, target_is_directory=True)
            nested_link = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertNotEqual(nested_link.returncode, 0)
            self.assertIn("tree contains a symlink", nested_link.stderr)

    def test_external_table_bhi_targeting_indexed_read_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-external-unsafe-bounds-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            negative = root / "negative-external-table"

            source_path = negative / "source-image.bin"
            source_bytes = bytearray(source_path.read_bytes())
            facts_path = negative / "external-table-facts.json"
            facts = json.loads(facts_path.read_text(encoding="utf-8"))
            function = facts["selectedFunction"]
            guard = facts["instructionBinding"]["guard"]
            indexed_read = facts["instructionBinding"]["indexedRead"]
            branch_address = guard["branchAddress"]
            unsafe_target = indexed_read["address"]
            branch_delta = unsafe_target - branch_address
            self.assertGreater(branch_delta, 0)
            self.assertEqual(branch_delta % 4, 0)
            branch_file_offset = function["fileOffset"] + branch_address - function["value"]
            original_word = struct.unpack_from("<I", source_bytes, branch_file_offset)[0]
            immediate = (branch_delta // 4) & 0x7FFFF
            mutated_word = (original_word & ~(0x7FFFF << 5)) | (immediate << 5)
            struct.pack_into("<I", source_bytes, branch_file_offset, mutated_word)
            self.assertEqual(original_word & 0xFF00001F, 0x54000008)
            self.assertEqual(mutated_word & 0xFF00001F, 0x54000008)
            decoded_immediate = (mutated_word >> 5) & 0x7FFFF
            if decoded_immediate & (1 << 18):
                decoded_immediate -= 1 << 19
            self.assertEqual(branch_address + decoded_immediate * 4, unsafe_target)
            self.assertNotEqual(original_word, mutated_word)
            source_path.write_bytes(source_bytes)

            # Refresh source-derived claims coherently so this negative reaches
            # the semantic B.HI destination guard, not an integrity/hash check.
            source_sha256 = _sha(source_bytes)
            facts["sourceSha256"] = source_sha256
            facts["instructionBinding"]["guard"]["defaultTarget"] = unsafe_target
            branch_row = next(
                row for row in facts["instructionBinding"]["instructions"]
                if row["address"] == branch_address
            )
            branch_row["word"] = f"0x{mutated_word:08x}"
            _write_json(facts_path, facts)

            command_path = negative / "producer-command.json"
            command = json.loads(command_path.read_text(encoding="utf-8"))
            command["sourceSha256"] = source_sha256
            command["argv"][21] = source_sha256
            _write_json(command_path, command)

            stage_path = negative / "stage.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["sourceSha256"] = source_sha256
            _write_json(stage_path, stage)
            producer_path = negative / "producer.stdout"
            producer = json.loads(producer_path.read_text(encoding="utf-8"))
            producer["stage"]["sourceSha256"] = source_sha256
            _write_json(producer_path, producer)

            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["sourceSha256"] = source_sha256
            result["producerCommandSha256"] = _sha(command_path.read_bytes())
            result["producerStdoutSha256"] = _sha(producer_path.read_bytes())
            result["externalTableFactsSha256"] = _sha(facts_path.read_bytes())
            _write_json(result_path, result)
            _refresh_indirect_manifest(root)

            rejected = self.run_checker(root)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "external-table B.HI taken edge is unsafe: target is not the final bounded default-return block",
                rejected.stderr,
            )
            self.assertNotIn("SHA256SUMS hash mismatch", rejected.stderr)
            self.assertNotIn("sourceSha256", rejected.stderr)
            self.assertNotIn("producer output does not prove", rejected.stderr)

    def test_external_table_owner_and_instruction_links_reject_refreshed_claim_tampering(self) -> None:
        mutations = (
            ("dynsym identity", lambda facts: facts["importedTableSymbol"].__setitem__("symbolIndex", 2)),
            ("object binding", lambda facts: facts["importedTableSymbol"].__setitem__("binding", "WEAK")),
            ("object type", lambda facts: facts["importedTableSymbol"].__setitem__("type", "NOTYPE")),
            ("relocation symbol owner", lambda facts: facts["relocation"].__setitem__("symbolIndex", 2)),
            ("relocation class", lambda facts: facts["relocation"].__setitem__("type", 1026)),
            ("GOT mapping", lambda facts: facts["gotSlot"].__setitem__("virtualAddress", facts["gotSlot"]["virtualAddress"] + 8)),
            ("GOT instruction link", lambda facts: facts["instructionBinding"]["gotAddressProducer"].__setitem__("resolvedSlotAddress", 0x2408)),
            ("indexed-read base", lambda facts: facts["instructionBinding"]["indexedRead"].__setitem__("baseRegister", "x10")),
            ("BR target dataflow", lambda facts: facts["instructionBinding"]["indirectBranch"].__setitem__("targetRegister", "x2")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                result = self.reject_refreshed_external_fact_mutation(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("owner/link facts differ", result.stderr)
                self.assertNotIn("SHA256SUMS hash mismatch", result.stderr)

    def test_external_table_diagnostic_tampering_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-external-diagnostic-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            negative = root / "negative-external-table"
            producer_path = negative / "producer.stdout"
            producer = json.loads(producer_path.read_text(encoding="utf-8"))
            producer["diagnostics"][0]["message"] = "claimed external import failure"
            producer["stage"]["diagnostics"][0]["message"] = "claimed external import failure"
            _write_json(producer_path, producer)
            _write_json(negative / "stage.json", producer["stage"])
            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["producerStdoutSha256"] = _sha(producer_path.read_bytes())
            _write_json(result_path, result)
            _refresh_indirect_manifest(root)
            rejected = self.run_checker(root)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("stable diagnostic family and message", rejected.stderr)
            self.assertNotIn("SHA256SUMS hash mismatch", rejected.stderr)

    def test_external_table_failure_stage_tampering_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-external-stage-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            negative = root / "negative-external-table"
            producer_path = negative / "producer.stdout"
            producer = json.loads(producer_path.read_text(encoding="utf-8"))
            producer["stage"]["firstFailureStage"] = "rehydration"
            _write_json(producer_path, producer)
            _write_json(negative / "stage.json", producer["stage"])
            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["firstFailureStage"] = "rehydration"
            result["producerStdoutSha256"] = _sha(producer_path.read_bytes())
            _write_json(result_path, result)
            _refresh_indirect_manifest(root)
            rejected = self.run_checker(root)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("failed Protected Image producer stage", rejected.stderr)
            self.assertNotIn("SHA256SUMS hash mismatch", rejected.stderr)

    def test_forged_behavior_equality_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-equality-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            (positive / "target.stdout").write_bytes(b"different transformed stream\n")
            behavior_path = positive / "jump-table-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["transformedStdoutSha256"] = _sha((positive / "target.stdout").read_bytes())
            _write_json(behavior_path, behavior)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stdoutEqual", result.stderr)

    def test_forged_stream_hash_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-stream-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            (root / INDIRECT_UNIT / "baseline.stderr").write_bytes(b"forged stderr")
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("baselineStderrSha256", result.stderr)

    def test_forged_target_selection_fact_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-target-selection-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            behavior_path = root / INDIRECT_UNIT / "jump-table-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["targetSelectionFacts"]["caseResults"][2] = 91
            _write_json(behavior_path, behavior)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("target-selection facts", result.stderr)

    def test_forged_source_table_edit_offsets_are_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-table-offsets-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            rehydration_path = root / INDIRECT_UNIT / "rehydration.json"
            rehydration = json.loads(rehydration_path.read_text(encoding="utf-8"))
            for index, edit in enumerate(rehydration["layoutEvidence"]["jumpTableEdits"]):
                edit["offset"]["value"] = 0x500 + index * 4
            _write_json(rehydration_path, rehydration)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not confined to the four entries in the distinct output clone", result.stderr)

    def test_forged_source_symbol_report_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-source-symbols-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            readelf_path = root / INDIRECT_UNIT / "source-readelf.txt"
            text = readelf_path.read_text(encoding="utf-8")
            readelf_path.write_text(text.replace("0000000000001028", "0000000000001088", 1), encoding="utf-8")
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match its ELF dynamic symbol entry", result.stderr)

    def test_forged_address_map_range_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-address-map-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            rehydration_path = root / INDIRECT_UNIT / "rehydration.json"
            rehydration = json.loads(rehydration_path.read_text(encoding="utf-8"))
            rehydration["layoutEvidence"]["addressMap"][0]["sourceRange"]["virtualAddress"]["value"] = 0x5000
            _write_json(rehydration_path, rehydration)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source function and all target symbols are not bound by one unique address-map range", result.stderr)

    def test_layout_evidence_requires_schema_v3_clone_preserving_contract(self) -> None:
        def mutate(positive: Path) -> None:
            path = positive / "rehydration.json"
            evidence = json.loads(path.read_text(encoding="utf-8"))
            evidence["layoutEvidence"]["schemaVersion"] = 1
            evidence["layoutEvidence"].pop("jumpTableTargetBindings")
            _write_json(path, evidence)

        result = self.reject_refreshed_mutation(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lacks the current schema v3 clone-preserving contract", result.stderr)

    def test_clone_policy_ranges_and_integer_tokens_reject_refreshed_tampering(self) -> None:
        mutations = {
            "missing clone": lambda layout: layout.__setitem__("jumpTableClones", []),
            "duplicate clone": lambda layout: layout["jumpTableClones"].append(layout["jumpTableClones"][0]),
            "clone file range": lambda layout: layout["jumpTableClones"][0]["outputRange"]["fileOffset"].__setitem__("value", 0x704),
            "clone VA": lambda layout: layout["jumpTableClones"][0]["outputRange"]["virtualAddress"].__setitem__("value", 0x4004),
            "source range": lambda layout: layout["jumpTableClones"][0]["sourceTableRange"].__setitem__("size", 12),
            "permissions": lambda layout: layout["jumpTableClones"][0].__setitem__("permissions", 5),
            "ownership": lambda layout: layout["jumpTableClones"][0].__setitem__("ownership", 2),
            "rewrite policy": lambda layout: layout["jumpTableClones"][0].__setitem__("rewritePolicy", 0),
            "owner inventory": lambda layout: layout["jumpTableClones"][0].__setitem__("ownerInventoryComplete", True),
            "producer address": lambda layout: layout["jumpTableClones"][0]["tableReferenceProducers"][0].__setitem__("instructionAddress", 0x100C),
            "output row": lambda layout: layout["jumpTableTargetBindings"][0]["outputEntryRange"]["fileOffset"].__setitem__("value", 0x704),
            "base identity": lambda layout: layout["jumpTableTargetBindings"][0]["targetBaseIdentity"].__setitem__("value", "0x1030"),
        }
        for key, value in (("schemaVersion", 2), ("schemaVersion", 3.0), ("schemaVersion", "3")):
            mutations[f"{key} {value!r}"] = lambda layout, v=value: layout.__setitem__("schemaVersion", v)
        for key in ("permissions", "ownership", "rewritePolicy"):
            for value in (True, 0.0, "0"):
                mutations[f"{key} {value!r}"] = lambda layout, k=key, v=value: layout["jumpTableClones"][0].__setitem__(k, v)
        for label, change in mutations.items():
            with self.subTest(label=label):
                def mutate(positive: Path) -> None:
                    path = positive / "rehydration.json"
                    record = json.loads(path.read_text(encoding="utf-8"))
                    change(record["layoutEvidence"])
                    _write_json(path, record)
                result = self.reject_refreshed_mutation(mutate)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("checksum mismatch", result.stderr.lower())

    def test_native_original_clone_permissions_and_consumer_bytes_reject_refreshed_tampering(self) -> None:
        mutations = {
            "original table": (lambda image: struct.pack_into("<i", image, 0x400, 4), "changed the original"),
            "clone bytes": (lambda image: struct.pack_into("<i", image, 0x704, 12), "rewritten clone bytes"),
            "clone PT_LOAD permissions": (lambda image: struct.pack_into("<I", image, 64 + 3 * 56 + 4, 6), "PF_R-only"),
            "consumer retargeting": (lambda image: struct.pack_into("<I", image, 0x610, 0xF0FFFFE1), "dispatch chain"),
            "tagged ADDG instead of ADD": (lambda image: struct.pack_into("<I", image, 0x614, 0x91800021), "dispatch chain"),
        }
        for label, (change, message) in mutations.items():
            with self.subTest(label=label):
                def mutate(positive: Path) -> None:
                    native_path = positive / "native-image.bin"
                    image = bytearray(native_path.read_bytes())
                    change(image)
                    native_path.write_bytes(image)
                    native_hash = _sha(bytes(image))
                    handoff_path = positive / "handoff.json"
                    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                    handoff["nativeImageSha256"] = native_hash
                    _write_json(handoff_path, handoff)
                    behavior_path = positive / "jump-table-behavior.json"
                    behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
                    behavior["nativeSha256"] = native_hash
                    behavior["targetHandoffSha256"] = _sha(handoff_path.read_bytes())
                    _write_json(behavior_path, behavior)
                    path = positive / "rehydration.json"
                    record = json.loads(path.read_text(encoding="utf-8"))
                    record["nativeImageSha256"] = native_hash
                    record["layoutEvidence"]["outputSha256"] = native_hash
                    _write_json(path, record)
                    self.refresh_native_image_bindings(positive)
                result = self.reject_refreshed_mutation(mutate)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stderr)

    def test_forged_output_target_va_is_rejected_after_hash_refresh(self) -> None:
        def mutate(positive: Path) -> None:
            path = positive / "rehydration.json"
            evidence = json.loads(path.read_text(encoding="utf-8"))
            binding = evidence["layoutEvidence"]["jumpTableTargetBindings"][0]
            binding["outputTargetAddress"]["value"] += 4
            _write_json(path, evidence)

        result = self.reject_refreshed_mutation(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the retained layout address-map decision", result.stderr)

    def test_forged_output_target_base_is_rejected_after_hash_refresh(self) -> None:
        def mutate(positive: Path) -> None:
            path = positive / "rehydration.json"
            evidence = json.loads(path.read_text(encoding="utf-8"))
            binding = evidence["layoutEvidence"]["jumpTableTargetBindings"][0]
            binding["outputTargetBaseAddress"]["value"] += 4
            _write_json(path, evidence)

        result = self.reject_refreshed_mutation(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the retained layout address-map decision", result.stderr)

    def test_forged_target_binding_entry_index_or_offset_is_rejected_after_hash_refresh(self) -> None:
        mutations = (
            (
                "entry index",
                lambda binding: binding.__setitem__("entryIndex", 1),
                "missing, duplicate, or unknown jump-table entry bindings",
            ),
            (
                "source entry offset",
                lambda binding: binding["sourceEntryRange"]["fileOffset"].__setitem__("value", 0x404),
                "entry index/offset does not identify its source ELF table row",
            ),
            (
                "source entry VA",
                lambda binding: binding["sourceEntryRange"]["virtualAddress"].__setitem__("value", 0x2004),
                "entry index/offset does not identify its source ELF table row",
            ),
        )
        for label, mutate_binding, message in mutations:
            with self.subTest(label=label):
                def mutate(positive: Path) -> None:
                    path = positive / "rehydration.json"
                    evidence = json.loads(path.read_text(encoding="utf-8"))
                    mutate_binding(evidence["layoutEvidence"]["jumpTableTargetBindings"][0])
                    _write_json(path, evidence)

                result = self.reject_refreshed_mutation(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_forged_target_mapping_range_is_rejected_after_hash_refresh(self) -> None:
        def mutate(positive: Path) -> None:
            path = positive / "rehydration.json"
            evidence = json.loads(path.read_text(encoding="utf-8"))
            evidence["layoutEvidence"]["addressMap"][0]["outputRange"]["virtualAddress"]["value"] += 4
            _write_json(path, evidence)

        result = self.reject_refreshed_mutation(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not have exactly one fully containing file-backed PT_LOAD owner", result.stderr)

    def test_missing_or_duplicate_target_binding_is_rejected_after_hash_refresh(self) -> None:
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                def mutate(positive: Path) -> None:
                    path = positive / "rehydration.json"
                    evidence = json.loads(path.read_text(encoding="utf-8"))
                    bindings = evidence["layoutEvidence"]["jumpTableTargetBindings"]
                    if duplicate:
                        bindings.append(dict(bindings[0]))
                    else:
                        bindings.pop(0)
                    _write_json(path, evidence)

                result = self.reject_refreshed_mutation(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("missing one unique output target binding", result.stderr)

    def test_forged_materialized_table_bytes_are_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-native-table-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            native_path = positive / "native-image.bin"
            native = bytearray(native_path.read_bytes())
            struct.pack_into("<i", native, 0x704, 12)
            native_path.write_bytes(native)
            native_hash = _sha(bytes(native))
            behavior_path = positive / "jump-table-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["nativeSha256"] = native_hash
            handoff_path = positive / "handoff.json"
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            handoff["nativeImageSha256"] = native_hash
            _write_json(handoff_path, handoff)
            behavior["targetHandoffSha256"] = _sha(handoff_path.read_bytes())
            _write_json(behavior_path, behavior)
            rehydration_path = positive / "rehydration.json"
            rehydration = json.loads(rehydration_path.read_text(encoding="utf-8"))
            rehydration["nativeImageSha256"] = native_hash
            rehydration["layoutEvidence"]["outputSha256"] = native_hash
            _write_json(rehydration_path, rehydration)
            self.refresh_native_image_bindings(positive)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("rewritten clone bytes", result.stderr)

    def test_forged_handoff_status_is_rejected_after_all_hashes_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-status-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            positive = root / INDIRECT_UNIT
            behavior_path = positive / "jump-table-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            for filename in ("source-handoff.json", "handoff.json"):
                path = positive / filename
                handoff = json.loads(path.read_text(encoding="utf-8"))
                handoff["entryStatus"] = 92
                handoff["processStatus"] = 92
                _write_json(path, handoff)
            behavior["sourceHandoffSha256"] = _sha((positive / "source-handoff.json").read_bytes())
            behavior["targetHandoffSha256"] = _sha((positive / "handoff.json").read_bytes())
            behavior["baselineStatus"] = 92
            behavior["transformedStatus"] = 92
            behavior["baselineEntryStatus"] = 92
            behavior["transformedEntryStatus"] = 92
            _write_json(behavior_path, behavior)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("complete-table execution oracle", result.stderr)

    def test_fake_negative_diagnostic_is_rejected_after_hash_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-negative-diagnostic-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            negative = root / "negative-index-clobber"
            producer_path = negative / "producer.stdout"
            producer = json.loads(producer_path.read_text(encoding="utf-8"))
            producer["diagnostics"][0]["message"] = "fixture claims an unrelated error"
            producer["stage"]["diagnostics"][0]["message"] = "fixture claims an unrelated error"
            _write_json(producer_path, producer)
            _write_json(negative / "stage.json", producer["stage"])
            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["producerStdoutSha256"] = _sha(producer_path.read_bytes())
            _write_json(result_path, result)
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stable diagnostic family and message", result.stderr)

    def test_forged_out_of_range_table_value_is_rejected_after_hash_refresh(self) -> None:
        def mutate(negative: Path) -> None:
            path = negative / "mutation.json"
            facts = json.loads(path.read_text(encoding="utf-8"))
            facts["mutatedEncodedValue"] = 0x7FFFFFDF
            _write_json(path, facts)

        result = self.reject_refreshed_negative_mutation("negative-out-of-range-target", mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mutation facts differ", result.stderr)

    def test_forged_out_of_range_target_claim_is_rejected_after_hash_refresh(self) -> None:
        def mutate(negative: Path) -> None:
            path = negative / "mutation.json"
            facts = json.loads(path.read_text(encoding="utf-8"))
            facts["computedTargetAddress"] = 0x1038
            _write_json(path, facts)

        result = self.reject_refreshed_negative_mutation("negative-out-of-range-target", mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mutation facts differ", result.stderr)

    def test_out_of_range_negative_requires_its_specific_producer_diagnostic(self) -> None:
        def mutate(negative: Path) -> None:
            for filename in ("producer.stdout", "stage.json"):
                path = negative / filename
                record = json.loads(path.read_text(encoding="utf-8"))
                stage = record["stage"] if filename == "producer.stdout" else record
                stage["diagnostics"][0]["message"] = INDIRECT_NEGATIVES["negative-malformed-table"]
                _write_json(path, record)
            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["producerStdoutSha256"] = _sha((negative / "producer.stdout").read_bytes())
            _write_json(result_path, result)

        result = self.reject_refreshed_negative_mutation("negative-out-of-range-target", mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stable diagnostic family and message", result.stderr)

    def test_forged_out_of_range_first_failure_stage_is_rejected_after_checksum_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-negative-stage-") as directory:
            temp_root = Path(directory)
            source = temp_root / "synthetic-valid-evidence"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, temp_root)

            valid = self.run_checker(root)
            self.assertEqual(valid.returncode, 0, valid.stderr)

            negative = root / "negative-out-of-range-target"
            producer_path = negative / "producer.stdout"
            producer = json.loads(producer_path.read_text(encoding="utf-8"))
            producer["stage"]["firstFailureStage"] = "rehydration"
            _write_json(producer_path, producer)

            stage_path = negative / "stage.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["firstFailureStage"] = "rehydration"
            _write_json(stage_path, stage)

            result_path = negative / "negative-result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["firstFailureStage"] = "rehydration"
            result["producerStdoutSha256"] = _sha(producer_path.read_bytes())
            _write_json(result_path, result)

            # Recompute the copied positive child's manifest and the outer
            # evidence manifest so rejection must come from the stage claim.
            _refresh_indirect_manifest(root / INDIRECT_UNIT)
            _refresh_indirect_manifest(root)
            tampered = self.run_checker(root)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn(
                "producer output does not prove a failed Protected Image producer stage",
                tampered.stderr,
            )
            self.assertNotIn("SHA256SUMS hash mismatch", tampered.stderr)

    def test_forged_negative_publication_claim_is_rejected_after_hash_refresh(self) -> None:
        def mutate(negative: Path) -> None:
            path = negative / "negative-result.json"
            result = json.loads(path.read_text(encoding="utf-8"))
            result["protectedImagePublished"] = True
            _write_json(path, result)

        result = self.reject_refreshed_negative_mutation("negative-out-of-range-target", mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("negative-result.json claims", result.stderr)

    def test_published_native_image_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(negative: Path) -> None:
            (negative / "native-image.bin").write_bytes(b"forged publication")

        result = self.reject_refreshed_negative_mutation("negative-out-of-range-target", mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("downstream image/loader artifact", result.stderr)

    def test_out_of_range_relative_table_mutator_records_actual_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-mutate-") as directory:
            root = Path(directory)
            original = root / "input.so"
            mutated = root / "source.so"
            report = root / "mutation.json"
            original.write_bytes(_jump_table_elf(transformed=False))
            result = subprocess.run(
                [
                    sys.executable, str(INDIRECT_MUTATOR),
                    "--input", str(original), "--output", str(mutated), "--report", str(report),
                    "--mode", "out-of-executable-range",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            facts = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(facts["mutatedEncodedValue"], 0x7FFFFFE0)
            self.assertEqual(facts["computedTargetAddress"], 0x1028 + 0x7FFFFFE0)
            self.assertEqual(facts["inputSha256"], _sha(original.read_bytes()))
            self.assertEqual(facts["sourceSha256"], _sha(mutated.read_bytes()))

    def test_required_negative_artifact_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="indirect-control-required-negative-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            self.create_evidence(source)
            root = self.copy_evidence(source, Path(directory))
            (root / "negative-index-clobber" / "producer.stderr").unlink()
            _refresh_indirect_manifest(root)
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("producer.stderr", result.stderr)


if __name__ == "__main__":
    unittest.main()
