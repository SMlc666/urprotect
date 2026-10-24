from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "scripts/run-bionic-host-context-handoff.sh"
CAPTURE = ROOT / "scripts/capture-bionic-handoff.py"
HOST_REHYDRATION = ROOT / "scripts/run-host-context-rehydration-e2e.sh"
ORDINARY = ROOT / "scripts/run-indirect-control-e2e.sh"
SHARED = ROOT / "scripts/run-shared-jump-table-copy-e2e.sh"
IMAGE = "termux/termux-docker@sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4"
BUILD_ROOT = ROOT / ".artifacts/bionic/c-termux-bionic-pie/host-context/indirect-control-build"


class BionicHandoffBridgeTests(unittest.TestCase):
    def run_process(self, command: list[str], env: dict[str, str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=False)

    def test_bionic_fixture_link_flags_are_recorded_passed_and_forwarded(self) -> None:
        runner = (ROOT / "scripts/run-bionic-fixture.sh").read_text(encoding="utf-8")
        variable = "INDIRECT_CONTROL_FIXTURE_LDFLAGS"
        flags = "--pack-dyn-relocs=none --no-relax"
        expected_assignment = f"{variable}={flags}"

        actual_assignment_lines = [
            line.strip() for line in runner.splitlines()
            if line.strip().startswith(f"{variable}=")
        ]
        self.assertEqual(1, len(actual_assignment_lines))
        self.assertEqual(
            [expected_assignment],
            shlex.split(actual_assignment_lines[0].removesuffix("\\").strip()),
        )

        recorded_lines = [
            line.strip() for line in runner.splitlines()
            if '"argv=make -C /workspace/native/urprotect-runtime ' in line
        ]
        self.assertEqual(1, len(recorded_lines))
        self.assertTrue(recorded_lines[0].endswith('" \\'))
        recorded_fields = shlex.split(recorded_lines[0].removesuffix("\\").strip())
        self.assertEqual(1, len(recorded_fields))
        self.assertTrue(recorded_fields[0].startswith("argv="))
        recorded_argv = shlex.split(recorded_fields[0][len("argv=") :])
        self.assertEqual(
            [expected_assignment],
            [argument for argument in recorded_argv if argument.startswith(f"{variable}=")],
        )

        makefile = ROOT / "native/urprotect-runtime/Makefile"
        with tempfile.TemporaryDirectory(prefix="bionic-jump-table-make-dry-run-") as raw_temp:
            env = os.environ.copy()
            env.pop("MAKEFLAGS", None)
            env.pop("MFLAGS", None)
            result = subprocess.run(
                [
                    "make", "--dry-run", "-C", str(makefile.parent),
                    f"BUILD_DIR={Path(raw_temp) / 'build'}", "AS=unused", "LD=ld.lld",
                    expected_assignment, "jump-table-fixture", "shared-jump-table-fixture",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        link_commands = [
            shlex.split(line)
            for line in result.stdout.splitlines()
            if line.startswith("ld.lld ")
        ]
        self.assertEqual(2, len(link_commands), result.stdout)
        by_output = {
            Path(command[command.index("-o") + 1]).name: command
            for command in link_commands
        }
        self.assertEqual(
            {
                "host-context-jump-table-fixture.so",
                "host-context-shared-jump-table-fixture.so",
            },
            set(by_output),
        )
        for command in by_output.values():
            flag_index = command.index("--pack-dyn-relocs=none")
            self.assertEqual(
                ["--pack-dyn-relocs=none", "--no-relax"],
                command[flag_index : flag_index + 2],
            )

    def make_runtime_stub(self, directory: Path, log_path: Path, *, mode: str = "success") -> Path:
        executable = directory / "docker-stub"
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import hashlib, json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['FAKE_CONTAINER_LOG'], 'a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(args) + '\\n')\n"
            "if args and args[0] == 'version':\n"
            "    print('linux/arm64')\n"
            "    raise SystemExit(0)\n"
            "if len(args) >= 2 and args[:2] == ['image', 'inspect']:\n"
            f"    print('sha256:' + 'a' * 64 + '|' + {IMAGE!r})\n"
            "    raise SystemExit(0)\n"
            "if not args or args[0] != 'run':\n"
            "    print('unexpected fake container argv', file=sys.stderr)\n"
            "    raise SystemExit(97)\n"
            "mode = os.environ.get('FAKE_CONTAINER_MODE', 'success')\n"
            "run_calls = [json.loads(line) for line in pathlib.Path(os.environ['FAKE_CONTAINER_LOG']).read_text().splitlines()]\n"
            "run_index = sum(1 for call in run_calls if call and call[0] == 'run') - 1\n"
            "try:\n"
            "    marker = args.index('bionic-handoff')\n"
            "    helper_args = args[marker + 1:]\n"
            "    mounts = [args[index + 1] for index, item in enumerate(args[:-1]) if item == '--mount']\n"
            "    evidence_mount = next(item.split('src=', 1)[1].split(',dst=/evidence', 1)[0] for item in mounts if ',dst=/evidence' in item)\n"
            "except (ValueError, StopIteration, IndexError):\n"
            "    print('fake container protocol missing marker/mount', file=sys.stderr)\n"
            "    raise SystemExit(96)\n"
            "print('fake-container-stdout')\n"
            "print('fake-container-stderr', file=sys.stderr)\n"
            "if mode in ('record-symlink', 'exit-39-with-symlink'):\n"
            "    if len(helper_args) not in (3, 6):\n        raise SystemExit(95)\n"
            "    record_container = helper_args[2]\n"
            "    record_path = pathlib.Path(evidence_mount) / record_container.removeprefix('/evidence/')\n"
            "    record_path.symlink_to(os.environ['FAKE_OUTSIDE_RECORD'])\n"
            "    raise SystemExit(39 if mode == 'exit-39-with-symlink' else 91)\n"
            f"if mode == 'exit-39' or mode == 'target-failure':\n    raise SystemExit(39)\n"
            "if mode == 'source-missing-record' and run_index == 1:\n"
            "    raise SystemExit(91)\n"
            "if mode == 'zero-without-record':\n    raise SystemExit(0)\n"
            "if len(helper_args) not in (3, 6):\n"
            "    print('fake helper argv length is wrong', file=sys.stderr)\n"
            "    raise SystemExit(95)\n"
            "input_container, entry_symbol, record_container = helper_args[:3]\n"
            "if not input_container.startswith('/evidence/') or not record_container.startswith('/evidence/'):\n"
            "    print('fake helper paths are outside evidence mount', file=sys.stderr)\n"
            "    raise SystemExit(94)\n"
            "input_path = pathlib.Path(evidence_mount) / input_container.removeprefix('/evidence/')\n"
            "record_path = pathlib.Path(evidence_mount) / record_container.removeprefix('/evidence/')\n"
            "entry_status = 91\n"
            "if mode == 'malformed-record':\n"
            "    record_path.write_text('{not-json' + chr(10), encoding='utf-8')\n"
            "    raise SystemExit(entry_status)\n"
            "record = {'schemaVersion': 1, 'stage': 'host-context-handoff', 'status': 'passed',\n"
            "          'loaderId': 'host-context.sealed-memfd.dlopen',\n"
            "          'nativeImageSha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),\n"
            "          'entrySymbol': entry_symbol, 'entryStatus': entry_status, 'processStatus': entry_status,\n"
            "          'releaseStatus': 'passed', 'releaseOrder': 'entry-dispatch-before-release-image',\n"
            "          'firstFailureStage': None}\n"
            "record_path.write_text(json.dumps(record) + '\\n', encoding='utf-8')\n"
            "raise SystemExit(entry_status)\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable

    def make_dotnet_stub(self, bin_dir: Path) -> Path:
        executable = bin_dir / "dotnet"
        executable.write_text(
            """#!/usr/bin/env python3
import json, pathlib, sys
args = sys.argv[1:]
action = args[1]
def option(name): return pathlib.Path(args[args.index(name) + 1])
if action == 'protect-image':
    source = pathlib.Path(args[2])
    role = {'requestSha256': 'a' * 64, 'producerId': args[args.index('--producer-id') + 1], 'producerBuildSha256': 'b' * 64}
    option('--artifact').write_bytes(b'protected image')
    option('--role').write_text(json.dumps(role), encoding='utf-8')
    option('--manifest').write_text('fixture manifest\\n', encoding='utf-8')
    option('--stage').write_text(json.dumps({'status': 'passed'}), encoding='utf-8')
    print(json.dumps({'success': True, 'sourceSha256': __import__('hashlib').sha256(source.read_bytes()).hexdigest()}))
elif action == 'rehydrate-image':
    option('--native-image').write_bytes(b'native image')
    option('--role').write_text(json.dumps({'schemaVersion': 1}), encoding='utf-8')
    option('--record').write_text(json.dumps({'schemaVersion': 1}), encoding='utf-8')
    print(json.dumps({'success': True}))
else:
    print('unexpected fake dotnet action', file=sys.stderr)
    raise SystemExit(98)
""",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable

    def fake_environment(self, temp: Path, *, mode: str = "success", with_dotnet: bool = False) -> tuple[dict[str, str], Path]:
        bin_dir = temp / "bin"
        bin_dir.mkdir()
        log_path = temp / "container-argv.jsonl"
        runtime = self.make_runtime_stub(bin_dir, log_path, mode=mode)
        if with_dotnet:
            self.make_dotnet_stub(bin_dir)
        uname = bin_dir / "uname"
        uname.write_text(
            """#!/bin/sh
if [ "$1" = -m ]; then echo aarch64; else exec /usr/bin/uname "$@"; fi
""",
            encoding="utf-8",
        )
        uname.chmod(0o755)
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.update(
            {
                "PATH": f"{bin_dir}:{env['PATH']}",
                "BIONIC_CONTAINER_RUNTIME": str(runtime),
                "BIONIC_TERMUX_IMAGE": IMAGE,
                "BIONIC_INDIRECT_CONTROL_BUILD_ROOT": str(BUILD_ROOT),
                "FAKE_CONTAINER_LOG": str(log_path),
                "FAKE_CONTAINER_MODE": mode,
            }
        )
        return env, log_path

    @contextmanager
    def ensure_test_bridge_helper(self):
        """Create only the ignored fixture paths missing before this test."""
        created_dirs: list[Path] = []
        missing = []
        current = BUILD_ROOT
        while not current.exists():
            missing.append(current)
            current = current.parent
        for path in reversed(missing):
            path.mkdir()
            created_dirs.append(path)
        if BUILD_ROOT.is_symlink() or not BUILD_ROOT.is_dir():
            self.fail("pinned Bionic build root is not a real directory")
        created_files: list[Path] = []
        helper = BUILD_ROOT / "host-context-image-handoff"
        if not helper.exists() and not helper.is_symlink():
            interpreter = b"/system/bin/linker64" + bytes((0,))
            header = bytearray(64)
            header[:16] = bytes((0x7F, 0x45, 0x4C, 0x46, 2, 1, 1)) + bytes(9)
            struct.pack_into("<HHIQQQIHHHHHH", header, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            program_header = struct.pack("<IIQQQQQQ", 3, 0, 120, 0, 0, len(interpreter), len(interpreter), 1)
            helper.write_bytes(header + program_header + interpreter)
            helper.chmod(0o755)
            created_files.append(helper)
        if helper.is_symlink() or not helper.is_file() or not os.access(helper, os.X_OK):
            self.fail("pinned Bionic helper fixture is not a regular executable")
        helper_readelf = subprocess.run(["readelf", "-lW", str(helper)], capture_output=True, text=True, check=False)
        if helper_readelf.returncode != 0 or "Requesting program interpreter: /system/bin/linker64" not in helper_readelf.stdout:
            self.fail(f"Bionic test helper ELF lacks exact Bionic PT_INTERP: {helper_readelf.stderr}")

        for name in (
            "host-context-jump-table-fixture.so",
            "host-context-shared-jump-table-fixture.so",
        ):
            source = BUILD_ROOT / name
            if not source.exists() and not source.is_symlink():
                compiled = subprocess.run(
                    ["cc", "-shared", "-fPIC", "-x", "c", "-", "-o", str(source)],
                    input="int urp_entry(void) { return 91; }" + chr(10),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if compiled.returncode != 0:
                    self.fail(f"could not create source fixture for stubbed Bionic test: {compiled.stderr}")
                created_files.append(source)
        for name, content in (
            ("native-build.command.txt", b"stubbed native fixture/helper build" + bytes((10,))),
            ("native-build.stdout", b"stubbed build stdout" + bytes((10,))),
            ("native-build.stderr", b"stubbed build stderr" + bytes((10,))),
            ("native-build.status", b"0" + bytes((10,))),
        ):
            path = BUILD_ROOT / name
            if not path.exists() and not path.is_symlink():
                path.write_bytes(content)
                created_files.append(path)
        try:
            yield
        finally:
            for path in reversed(created_files):
                path.unlink(missing_ok=True)
            for directory in reversed(created_dirs):
                try:
                    directory.rmdir()
                except OSError:
                    pass

    def make_build_status_runner_environment(self, temp: Path, build_root: Path) -> tuple[dict[str, str], Path, Path]:
        bin_dir = temp / "status-runner-bin"
        bin_dir.mkdir()
        readelf_log = temp / "readelf.log"
        readelf = bin_dir / "readelf"
        readelf.write_text(
            "#!/bin/sh\n"
            "printf '%s\n' \"$*\" >>\"$FAKE_READELF_LOG\"\n"
            "if [ \"$1\" = -lW ]; then echo '      [Requesting program interpreter: /system/bin/linker64]'; fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        readelf.chmod(0o755)
        dotnet_log = temp / "dotnet.log"
        dotnet = bin_dir / "dotnet"
        dotnet.write_text(
            "#!/bin/sh\n"
            "printf '%s\n' \"$*\" >>\"$FAKE_DOTNET_LOG\"\n"
            "exit 73\n",
            encoding="utf-8",
        )
        dotnet.chmod(0o755)
        uname = bin_dir / "uname"
        uname.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -m ]; then echo aarch64; else exec /usr/bin/uname \"$@\"; fi\n",
            encoding="utf-8",
        )
        uname.chmod(0o755)
        runtime_result = temp / "bionic-runtime.json"
        runtime_result.write_text("{}\n", encoding="utf-8")
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.update({
            "PATH": f"{bin_dir}:{env['PATH']}",
            "BIONIC_INDIRECT_CONTROL_BUILD_ROOT": str(build_root),
            "BIONIC_RUNTIME_RESULT": str(runtime_result),
            "BIONIC_TERMUX_IMAGE": IMAGE,
            "FAKE_READELF_LOG": str(readelf_log),
            "FAKE_DOTNET_LOG": str(dotnet_log),
        })
        return env, readelf_log, dotnet_log

    def make_status_test_build_root(self, root: Path, status: bytes | None) -> Path:
        build_root = root / "build"
        build_root.mkdir()
        for name, data in (
            ("native-build.command.txt", b"fake make command\n"),
            ("native-build.stdout", b"captured build stdout\n"),
            ("native-build.stderr", b"captured build stderr\n"),
            ("host-context-jump-table-fixture.so", b"ordinary source fixture"),
            ("host-context-shared-jump-table-fixture.so", b"shared source fixture"),
            ("host-context-entry-fixture.so", b"nested source fixture"),
        ):
            (build_root / name).write_bytes(data)
        helper = build_root / "host-context-image-handoff"
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(0o755)
        if status is not None:
            (build_root / "native-build.status").write_bytes(status)
        return build_root

    def native_build_status_destination(self, runner: Path, root: Path) -> Path:
        if runner == ORDINARY:
            return root.with_name(root.name + ".native-build-diagnostics") / "native-build.status"
        if runner == SHARED:
            return root / "native-build.status"
        return Path(str(root) + ".native-build-diagnostics/host-context-image-handoff/native-build.status")

    def run_bionic_status_runner(self, runner: Path, root: Path, build_root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        unit = (
            "runtime.indirect-control.jump-table.bionic.host-context-entry"
            if runner == ORDINARY
            else "runtime.indirect-control.shared-table.bionic.host-context-entry"
            if runner == SHARED
            else "runtime.indirect-control.jump-table.bionic.host-context-entry"
        )
        if runner in (ORDINARY, SHARED):
            command = [str(runner), "--tier", "pr", "--runtime", "bionic", "--unit", unit,
                       "--artifact-root", str(root)]
        else:
            command = [str(runner), "--tier", "pr", "--runtime", "bionic", "--unit", unit,
                       "--source", str(build_root / "host-context-entry-fixture.so"),
                       "--function-id", "dynsym:2", "--entry-status", "91",
                       "--native-build-dir", "build/bionic-indirect-control"]
            env = {**env, "PROTECTED_IMAGE_ARTIFACT_ROOT": str(root)}
        return self.run_process(command, env)

    def test_native_build_status_parser_requires_exact_bounded_no_follow_decimal(self) -> None:
        parser = ROOT / "scripts/parse-native-build-status.py"
        with tempfile.TemporaryDirectory(prefix="native-build-status-parser-") as raw_temp:
            temp = Path(raw_temp)
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            for data, expected in ((b"0\n", 0), (b"1\n", 1), (b"255\n", 255)):
                with self.subTest(data=data):
                    path = temp / "native-build.status"
                    path.write_bytes(data)
                    result = self.run_process([sys.executable, str(parser), str(path)], env)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(f"{expected}\n", result.stdout)
            for data in (b"", b"0", b"01\n", b"+0\n", b"true\n", b"-1\n", b"256\n", b"0\n1\n", b" 0\n"):
                with self.subTest(rejected=data):
                    path = temp / "native-build.status"
                    path.write_bytes(data)
                    result = self.run_process([sys.executable, str(parser), str(path)], env)
                    self.assertEqual(2, result.returncode)
                    self.assertIn("native build status is invalid", result.stderr)
            missing = temp / "missing.status"
            result = self.run_process([sys.executable, str(parser), str(missing)], env)
            self.assertEqual(2, result.returncode)
            self.assertIn("native build status is invalid", result.stderr)
            target = temp / "valid.status"
            target.write_bytes(b"0\n")
            link = temp / "link.status"
            link.symlink_to(target)
            result = self.run_process([sys.executable, str(parser), str(link)], env)
            self.assertEqual(2, result.returncode)
            directory = temp / "directory.status"
            directory.mkdir()
            result = self.run_process([sys.executable, str(parser), str(directory)], env)
            self.assertEqual(2, result.returncode)

    def test_all_three_bionic_runners_fail_closed_on_missing_empty_and_malformed_status(self) -> None:
        runners = (ORDINARY, SHARED, HOST_REHYDRATION)
        invalid_statuses: tuple[tuple[str, bytes | None], ...] = (
            ("absent", None),
            ("zero-byte", b""),
            ("noncanonical", b"00\n"),
        )
        for runner in runners:
            for label, status in invalid_statuses:
                with self.subTest(runner=runner.name, status=label), tempfile.TemporaryDirectory(
                    prefix="bionic-invalid-native-status-", dir=ROOT / ".artifacts/indirect-control"
                ) as raw_temp:
                    temp = Path(raw_temp)
                    build_root = self.make_status_test_build_root(temp, status)
                    env, readelf_log, dotnet_log = self.make_build_status_runner_environment(temp, build_root)
                    root = temp / "evidence"
                    result = self.run_bionic_status_runner(runner, root, build_root, env)
                    self.assertEqual(1, result.returncode, result.stderr)
                    self.assertIn("native build status is invalid", result.stderr)
                    self.assertFalse(readelf_log.exists(), "status must be checked before readelf")
                    self.assertFalse(dotnet_log.exists(), "status must be checked before downstream producer")
                    if runner == ORDINARY:
                        sidecar_root = root.with_name(root.name + ".native-build-diagnostics")
                        stdout_path, stderr_path = root / "native-build.stdout", root / "native-build.stderr"
                    elif runner == SHARED:
                        sidecar_root = root
                        stdout_path, stderr_path = root / "native-build.stdout", root / "native-build.stderr"
                    else:
                        sidecar_root = Path(str(root) + ".native-build-diagnostics/host-context-image-handoff")
                        stdout_path, stderr_path = sidecar_root / "native-build.stdout", sidecar_root / "native-build.stderr"
                    self.assertEqual(b"fake make command\n", (sidecar_root / "native-build.command.txt").read_bytes())
                    self.assertEqual(b"captured build stdout\n", stdout_path.read_bytes())
                    self.assertEqual(b"captured build stderr\n", stderr_path.read_bytes())
                    self.assertFalse(self.native_build_status_destination(runner, root).exists())
                    for forbidden in (
                        "handoff.json", "source-handoff.json", "jump-table-behavior.json",
                        "shared-table-behavior.json", "bionic-runtime-environment.json", "SHA256SUMS",
                    ):
                        self.assertFalse(any(path.name == forbidden for path in root.rglob("*")), forbidden)

    def test_all_three_bionic_runners_progress_only_on_canonical_zero_and_propagate_nonzero(self) -> None:
        for runner in (ORDINARY, SHARED, HOST_REHYDRATION):
            with self.subTest(runner=runner.name, status="zero"), tempfile.TemporaryDirectory(
                prefix="bionic-zero-native-status-", dir=ROOT / ".artifacts/indirect-control"
            ) as raw_temp:
                temp = Path(raw_temp)
                build_root = self.make_status_test_build_root(temp, b"0\n")
                env, readelf_log, dotnet_log = self.make_build_status_runner_environment(temp, build_root)
                root = temp / "evidence"
                result = self.run_bionic_status_runner(runner, root, build_root, env)
                self.assertTrue(readelf_log.exists(), result.stderr)
                self.assertNotIn("build failed at native-build", result.stderr)
                self.assertEqual(b"0\n", self.native_build_status_destination(runner, root).read_bytes())
                if runner == HOST_REHYDRATION:
                    self.assertTrue(dotnet_log.exists(), result.stderr)
                self.assertTrue(any(path.name == "bionic-runtime-environment.json" for path in root.rglob("*")))
                self.assertFalse((root / "SHA256SUMS").exists())

            with self.subTest(runner=runner.name, status="nonzero"), tempfile.TemporaryDirectory(
                prefix="bionic-nonzero-native-status-", dir=ROOT / ".artifacts/indirect-control"
            ) as raw_temp:
                temp = Path(raw_temp)
                build_root = self.make_status_test_build_root(temp, b"37\n")
                env, readelf_log, dotnet_log = self.make_build_status_runner_environment(temp, build_root)
                root = temp / "evidence"
                result = self.run_bionic_status_runner(runner, root, build_root, env)
                self.assertEqual(37, result.returncode, result.stderr)
                self.assertIn("status 37", result.stderr)
                self.assertFalse(readelf_log.exists(), "nonzero status must stop before readelf")
                self.assertFalse(dotnet_log.exists(), "nonzero status must stop before downstream producer")
                self.assertEqual(b"37\n", self.native_build_status_destination(runner, root).read_bytes())
                self.assertFalse(any(path.name == "bionic-runtime-environment.json" for path in root.rglob("*")))
                self.assertFalse((root / "SHA256SUMS").exists())

    def test_capture_caller_and_bridge_forward_source_and_transformed_inputs_exactly(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(prefix="bionic-bridge-protocol-") as raw_temp:
            temp = Path(raw_temp)
            env, log_path = self.fake_environment(temp)
            with tempfile.TemporaryDirectory(prefix="bridge-evidence-", dir=ROOT / ".artifacts/indirect-control") as raw_root:
                evidence_root = Path(raw_root)
                for role, input_name, record_name in (
                    ("source", "source-image.bin", "source-handoff.json"),
                    ("target", "native-image.bin", "handoff.json"),
                ):
                    (evidence_root / input_name).write_bytes((role + " image bytes").encode())
                for role, input_name, record_name in (
                    ("source", "source-image.bin", "source-handoff.json"),
                    ("target", "native-image.bin", "handoff.json"),
                ):
                    identity_dir = evidence_root / "runtime-identity" / role
                    identity_dir.mkdir(parents=True)
                    command = [
                        sys.executable,
                        str(CAPTURE),
                        "--root", str(evidence_root),
                        "--label", "source-handoff" if role == "source" else "handoff",
                        "--record", str(evidence_root / record_name),
                        "--expected-status", "91",
                        "--",
                        str(BRIDGE), IMAGE,
                        str(evidence_root / input_name), "urp_entry",
                        str(evidence_root / record_name),
                        str(identity_dir), f"runtime-identity/{role}", role,
                    ]
                    result = self.run_process(command, env)
                    self.assertEqual(0, result.returncode, result.stderr)
                    label = "source-handoff" if role == "source" else "handoff"
                    self.assertEqual("91\n", (evidence_root / f"{label}.process-status").read_text())
                    self.assertEqual(b"fake-container-stdout\n", (evidence_root / f"{label}.stdout").read_bytes())
                    self.assertEqual(b"fake-container-stderr\n", (evidence_root / f"{label}.stderr").read_bytes())
                    record = json.loads((evidence_root / record_name).read_text())
                    self.assertEqual("passed", record["status"])
                    self.assertEqual(91, record["entryStatus"])
                    command_record = json.loads((evidence_root / f"{label}.command.json").read_text())
                    self.assertEqual(
                        [str(BRIDGE), IMAGE, str(evidence_root / input_name), "urp_entry",
                         str(evidence_root / record_name), str(identity_dir), f"runtime-identity/{role}", role],
                        command_record["argv"],
                    )

            calls = [json.loads(line) for line in log_path.read_text().splitlines()]
            runs = [call for call in calls if call and call[0] == "run"]
            self.assertEqual(2, len(runs))
            expected_roles = ("source", "target")
            for call, role, input_name, record_name in zip(
                runs, expected_roles, ("source-image.bin", "native-image.bin"), ("source-handoff.json", "handoff.json")
            ):
                self.assertIn("--platform", call)
                self.assertEqual("linux/arm64", call[call.index("--platform") + 1])
                self.assertEqual("1000:1000", call[call.index("--user") + 1])
                self.assertEqual(str(os.getgid()), call[call.index("--group-add") + 1])
                self.assertIn("umask 0007", call[call.index("-c") + 1])
                self.assertIn("--mount", call)
                mounts = [call[index + 1] for index, value in enumerate(call[:-1]) if value == "--mount"]
                self.assertEqual(
                    f"type=bind,src={evidence_root},dst=/evidence", mounts[0]
                )
                self.assertEqual(
                    f"type=bind,src={BUILD_ROOT},dst=/bionic-build,readonly", mounts[1]
                )
                self.assertEqual("/data/data/com.termux/files/usr/bin/sh", call[call.index(IMAGE) + 1])
                marker = call.index("bionic-handoff")
                self.assertEqual(
                    [f"/evidence/{input_name}", "urp_entry", f"/evidence/{record_name}",
                     f"/evidence/runtime-identity/{role}", f"runtime-identity/{role}", role],
                    call[marker + 1 :],
                )

    def test_bridge_rejects_preexisting_output_symlink_before_container_run(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(
            prefix="bionic-bridge-preexisting-tree-"
        ) as raw_temp:
            temp = Path(raw_temp)
            env, log_path = self.fake_environment(temp)
            outside_record = temp / "outside-record.tmp"
            outside_bytes = b"do not truncate before container execution\\n"
            outside_record.write_bytes(outside_bytes)
            with tempfile.TemporaryDirectory(
                prefix="bionic-bridge-preexisting-evidence-", dir=ROOT / ".artifacts/indirect-control"
            ) as raw_root:
                evidence_root = Path(raw_root)
                source = evidence_root / "source-image.bin"
                source.write_bytes(b"source image bytes")
                record = evidence_root / "handoff.json"
                (evidence_root / "handoff.json.tmp").symlink_to(outside_record)
                result = self.run_process(
                    [str(BRIDGE), IMAGE, str(source), "urp_entry", str(record)],
                    env,
                )
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertIn("symlink", result.stderr.lower())
                calls = [json.loads(line) for line in log_path.read_text().splitlines()]
                self.assertFalse(any(call and call[0] in {"run", "image"} for call in calls))
                self.assertEqual(outside_bytes, outside_record.read_bytes())

    def test_bridge_rejects_container_record_symlink_before_capture_can_parse_it(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(
            prefix="bionic-bridge-tree-guard-"
        ) as raw_temp:
            temp = Path(raw_temp)
            env, _ = self.fake_environment(temp, mode="record-symlink")
            outside_record = temp / "outside-record.json"
            outside_bytes = b'{"status":"passed","entryStatus":91}\\n'
            outside_record.write_bytes(outside_bytes)
            env["FAKE_OUTSIDE_RECORD"] = str(outside_record)
            with tempfile.TemporaryDirectory(
                prefix="bionic-bridge-tree-evidence-", dir=ROOT / ".artifacts/indirect-control"
            ) as raw_root:
                evidence_root = Path(raw_root)
                source = evidence_root / "source-image.bin"
                record = evidence_root / "handoff.json"
                source.write_bytes(b"source image bytes")
                result = self.run_process(
                    [sys.executable, str(CAPTURE), "--root", str(evidence_root), "--label", "handoff",
                     "--record", str(record), "--expected-status", "91", "--",
                     str(BRIDGE), IMAGE, str(source), "urp_entry", str(record)],
                    env,
                )
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertIn("artifact tree invalid; success record not read", result.stderr)
                self.assertEqual("91\n", (evidence_root / "handoff.process-status").read_text())
                self.assertTrue(record.is_symlink())
                self.assertIn(b"symlink", (evidence_root / "handoff.stderr").read_bytes().lower())
                self.assertEqual(outside_bytes, outside_record.read_bytes())

    def test_bridge_preserves_nonzero_status_when_container_tree_is_invalid(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(
            prefix="bionic-bridge-tree-failure-"
        ) as raw_temp:
            temp = Path(raw_temp)
            env, _ = self.fake_environment(temp, mode="exit-39-with-symlink")
            outside_record = temp / "outside-record.json"
            outside_record.write_bytes(b"not read from an invalid tree\\n")
            env["FAKE_OUTSIDE_RECORD"] = str(outside_record)
            with tempfile.TemporaryDirectory(
                prefix="bionic-bridge-tree-failure-evidence-", dir=ROOT / ".artifacts/indirect-control"
            ) as raw_root:
                evidence_root = Path(raw_root)
                source = evidence_root / "source-image.bin"
                record = evidence_root / "handoff.json"
                source.write_bytes(b"source image bytes")
                result = self.run_process(
                    [sys.executable, str(CAPTURE), "--root", str(evidence_root), "--label", "handoff",
                     "--record", str(record), "--expected-status", "91", "--",
                     str(BRIDGE), IMAGE, str(source), "urp_entry", str(record)],
                    env,
                )
                self.assertEqual(39, result.returncode, result.stderr)
                self.assertEqual("39\n", (evidence_root / "handoff.process-status").read_text())
                self.assertIn(b"symlink", (evidence_root / "handoff.stderr").read_bytes().lower())
                self.assertTrue(record.is_symlink())
                self.assertEqual(b"not read from an invalid tree\\n", outside_record.read_bytes())

    def test_capture_retains_exact_bridge_failure_before_missing_record_parse(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(prefix="bionic-bridge-failure-") as raw_temp:
            temp = Path(raw_temp)
            env, _ = self.fake_environment(temp, mode="exit-39")
            with tempfile.TemporaryDirectory(prefix="bridge-failure-evidence-", dir=ROOT / ".artifacts/indirect-control") as raw_root:
                evidence_root = Path(raw_root)
                source = evidence_root / "source-image.bin"
                source.write_bytes(b"source")
                result = self.run_process(
                    [sys.executable, str(CAPTURE), "--root", str(evidence_root), "--label", "handoff",
                     "--record", str(evidence_root / "handoff.json"), "--expected-status", "91", "--",
                     str(BRIDGE), IMAGE, str(source), "urp_entry", str(evidence_root / "handoff.json")],
                    env,
                )
                self.assertEqual(39, result.returncode, result.stderr)
                self.assertEqual("39\n", (evidence_root / "handoff.process-status").read_text())
                self.assertEqual(b"fake-container-stdout\n", (evidence_root / "handoff.stdout").read_bytes())
                self.assertEqual(b"fake-container-stderr\n", (evidence_root / "handoff.stderr").read_bytes())
                self.assertFalse((evidence_root / "handoff.json").exists())

    def test_malformed_handoff_output_keeps_the_real_status_streams_and_cannot_publish_success(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(
            prefix="bionic-malformed-handoff-", dir=ROOT / ".artifacts/indirect-control"
        ) as raw_temp:
            env, _ = self.fake_environment(Path(raw_temp), mode="malformed-record")
            root = Path(raw_temp)
            record = root / "handoff.json"
            source = root / "source-image.bin"
            source.write_bytes(b"source")
            result = self.run_process(
                [sys.executable, str(CAPTURE), "--root", raw_temp, "--label", "handoff",
                 "--record", str(record), "--expected-status", "91", "--",
                 str(BRIDGE), IMAGE, str(source), "urp_entry", str(record)],
                env,
            )
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("success record is missing or malformed", result.stderr)
            self.assertEqual("91" + chr(10), (root / "handoff.process-status").read_text())
            self.assertEqual(b"fake-container-stdout" + bytes((10,)), (root / "handoff.stdout").read_bytes())
            self.assertEqual(b"fake-container-stderr" + bytes((10,)), (root / "handoff.stderr").read_bytes())
            self.assertEqual("{not-json" + chr(10), record.read_text())
            self.assertFalse((root / "jump-table-behavior.json").exists())
            self.assertFalse((root / "SHA256SUMS").exists())

    def test_bionic_build_failures_keep_status_streams_and_do_not_publish_positive_evidence(self) -> None:
        for runner, unit in (
            (ORDINARY, "runtime.indirect-control.jump-table.bionic.host-context-entry"),
            (SHARED, "runtime.indirect-control.shared-table.bionic.host-context-entry"),
        ):
            with self.subTest(runner=runner.name), tempfile.TemporaryDirectory(prefix="bionic-build-failure-") as raw_temp:
                temp = Path(raw_temp)
                build_root = temp / "build"
                build_root.mkdir()
                sidecars = {
                    "native-build.command.txt": b"fake build argv\n",
                    "native-build.stdout": b"build standard output\n",
                    "native-build.stderr": b"build standard error\n",
                    "native-build.status": b"37\n",
                }
                for name, content in sidecars.items():
                    (build_root / name).write_bytes(content)
                runtime_environment = temp / "bionic-runtime-environment.json"
                runtime_environment.write_text('{"schemaVersion":1}\n', encoding="utf-8")
                marker = temp / "container-called"
                fake_runtime = temp / "never-run-container"
                fake_runtime.write_text(f"#!/bin/sh\necho called > {marker}\nexit 88\n", encoding="utf-8")
                fake_runtime.chmod(0o755)
                with tempfile.TemporaryDirectory(prefix="bionic-runner-root-", dir=ROOT / ".artifacts/indirect-control") as raw_root:
                    root = Path(raw_root) / "evidence"
                    env = os.environ.copy()
                    env.pop("PYTHONPATH", None)
                    env.update({
                        "BIONIC_INDIRECT_CONTROL_BUILD_ROOT": str(build_root),
                        "BIONIC_RUNTIME_RESULT": str(runtime_environment),
                        "BIONIC_TERMUX_IMAGE": IMAGE,
                        "BIONIC_CONTAINER_RUNTIME": str(fake_runtime),
                    })
                    if runner == ORDINARY:
                        command = [str(runner), "--tier", "pr", "--runtime", "bionic", "--unit", unit,
                                   "--artifact-root", str(root)]
                    else:
                        command = [str(runner), "--tier", "pr", "--runtime", "bionic", "--unit", unit,
                                   "--artifact-root", str(root)]
                    result = self.run_process(command, env)
                    self.assertEqual(37, result.returncode, result.stderr)
                    self.assertFalse(marker.exists(), "container must not run after build failure")
                    if runner == ORDINARY:
                        self.assertEqual(sidecars["native-build.stdout"], (root / "native-build.stdout").read_bytes())
                        self.assertEqual(sidecars["native-build.stderr"], (root / "native-build.stderr").read_bytes())
                        self.assertEqual(sidecars["native-build.status"], (root.with_name(root.name + ".native-build-diagnostics") / "native-build.status").read_bytes())
                        positive = root / unit
                    else:
                        self.assertEqual(sidecars["native-build.stdout"], (root / "native-build.stdout").read_bytes())
                        self.assertEqual(sidecars["native-build.stderr"], (root / "native-build.stderr").read_bytes())
                        self.assertEqual(sidecars["native-build.status"], (root / "native-build.status").read_bytes())
                        positive = root / unit
                    self.assertFalse((positive / "bionic-runtime-environment.json").exists())
                    for forbidden in ("handoff.json", "source-handoff.json", "jump-table-behavior.json", "shared-table-behavior.json", "SHA256SUMS"):
                        self.assertFalse((positive / forbidden).exists(), forbidden)

    def test_ordinary_and_shared_callers_retain_bridge_failure_without_positive_publication(self) -> None:
        cases = (
            (ORDINARY, "runtime.indirect-control.jump-table.bionic.host-context-entry"),
            (SHARED, "runtime.indirect-control.shared-table.bionic.host-context-entry"),
        )
        for runner, unit in cases:
            with self.subTest(runner=runner.name), self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(prefix="bionic-caller-failure-") as raw_temp:
                temp = Path(raw_temp)
                env, _ = self.fake_environment(temp, mode="target-failure", with_dotnet=True)
                runtime_environment = temp / "runtime.json"
                runtime_environment.write_text("{}", encoding="utf-8")
                env["BIONIC_RUNTIME_RESULT"] = str(runtime_environment)
                with tempfile.TemporaryDirectory(prefix="bionic-caller-evidence-", dir=ROOT / ".artifacts/indirect-control") as raw_root:
                    root = Path(raw_root) / "evidence"
                    command = [str(runner), "--tier", "pr", "--runtime", "bionic", "--unit", unit,
                               "--artifact-root", str(root)]
                    result = self.run_process(command, env)
                    self.assertEqual(39, result.returncode, result.stderr)
                    positive = root / unit
                    self.assertEqual("39" + chr(10), (positive / "handoff.process-status").read_text())
                    self.assertEqual(b"fake-container-stdout" + bytes((10,)), (positive / "handoff.stdout").read_bytes())
                    self.assertEqual(b"fake-container-stderr" + bytes((10,)), (positive / "handoff.stderr").read_bytes())
                    bridge_command = json.loads((positive / "handoff.command.json").read_text())["argv"]
                    self.assertEqual(str(BRIDGE), bridge_command[0])
                    self.assertEqual(IMAGE, bridge_command[1])
                    self.assertEqual(str(positive / "native-image.bin"), bridge_command[2])
                    for forbidden in (
                        "handoff.json", "source-handoff.json", "jump-table-behavior.json",
                        "shared-table-behavior.json",
                    ):
                        self.assertFalse((positive / forbidden).exists(), forbidden)
                    self.assertFalse((root / "SHA256SUMS").exists())
                    if runner == SHARED:
                        self.assertIn("status 39", (root / "rehydration.stderr").read_text())
                        self.assertFalse((positive / "observer-source-handoff.json").exists())

    def test_source_missing_record_is_persisted_before_success_parsing_and_stops_publication(self) -> None:
        with self.ensure_test_bridge_helper(), tempfile.TemporaryDirectory(
            prefix="bionic-source-missing-record-", dir=ROOT / ".artifacts/indirect-control"
        ) as raw_temp:
            temp = Path(raw_temp)
            env, log_path = self.fake_environment(temp, mode="source-missing-record", with_dotnet=True)
            runtime_environment = temp / "runtime.json"
            runtime_environment.write_text("{}", encoding="utf-8")
            env["BIONIC_RUNTIME_RESULT"] = str(runtime_environment)
            artifact_root = temp / "host-positive"
            result = self.run_process(
                [str(HOST_REHYDRATION), "--tier", "pr", "--runtime", "bionic",
                 "--unit", "runtime.indirect-control.jump-table.bionic.host-context-entry",
                 "--source", str(BUILD_ROOT / "host-context-jump-table-fixture.so"),
                 "--function-id", "dynsym:2", "--entry-status", "91"],
                {**env, "PROTECTED_IMAGE_ARTIFACT_ROOT": str(artifact_root)},
            )
            self.assertEqual(1, result.returncode, result.stderr + "\ncontainer argv: " + (log_path.read_text() if log_path.exists() else "missing"))
            self.assertIn("source handoff failed", result.stderr)
            self.assertIn("wrapper status=1", result.stderr)
            self.assertEqual("91" + chr(10), (artifact_root / "handoff.process-status").read_text())
            self.assertEqual("91" + chr(10), (artifact_root / "source-handoff.process-status").read_text())
            self.assertEqual(b"fake-container-stdout" + bytes((10,)), (artifact_root / "source-handoff.stdout").read_bytes())
            self.assertEqual(b"fake-container-stderr" + bytes((10,)), (artifact_root / "source-handoff.stderr").read_bytes())
            source_command = json.loads((artifact_root / "source-handoff.command.json").read_text())["argv"]
            self.assertEqual(str(BRIDGE), source_command[0])
            self.assertEqual(str(artifact_root / "source-image.bin"), source_command[2])
            self.assertFalse((artifact_root / "source-handoff.json").exists())
            self.assertFalse((artifact_root / "baseline.stdout").exists())
            self.assertFalse((artifact_root / "jump-table-behavior.json").exists())

    def test_nested_host_build_failure_is_retained_before_any_handoff_or_checker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bionic-host-build-failure-") as raw_temp:
            temp = Path(raw_temp)
            build_root = temp / "build"
            build_root.mkdir()
            expected = {
                "native-build.command.txt": b"nested make argv\n",
                "native-build.stdout": b"nested build stdout\n",
                "native-build.stderr": b"nested build stderr\n",
                "native-build.status": b"41\n",
            }
            for name, content in expected.items():
                (build_root / name).write_bytes(content)
            runtime_environment = temp / "runtime.json"
            runtime_environment.write_text("{}\n", encoding="utf-8")
            marker = temp / "container-called"
            fake_runtime = temp / "never-run-container"
            fake_runtime.write_text(f"#!/bin/sh\necho called > {marker}\nexit 88\n", encoding="utf-8")
            fake_runtime.chmod(0o755)
            artifact_root = temp / "host-positive"
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            env.update({
                "BIONIC_INDIRECT_CONTROL_BUILD_ROOT": str(build_root),
                "BIONIC_RUNTIME_RESULT": str(runtime_environment),
                "BIONIC_TERMUX_IMAGE": IMAGE,
                "BIONIC_CONTAINER_RUNTIME": str(fake_runtime),
                "PROTECTED_IMAGE_ARTIFACT_ROOT": str(artifact_root),
            })
            result = self.run_process(
                [str(HOST_REHYDRATION), "--tier", "pr", "--runtime", "bionic",
                 "--unit", "runtime.indirect-control.jump-table.bionic.host-context-entry"],
                env,
            )
            self.assertEqual(41, result.returncode, result.stderr)
            self.assertIn("native fixture/helper build failed with status 41", result.stderr)
            self.assertFalse(marker.exists())
            nested = Path(str(artifact_root) + ".native-build-diagnostics/host-context-image-handoff")
            for name, content in expected.items():
                self.assertEqual(content, (nested / name).read_bytes())
            self.assertFalse((artifact_root / "handoff.json").exists())
            self.assertFalse((artifact_root / "source-handoff.json").exists())
            self.assertFalse((artifact_root / "behavioral-oracle.json").exists())
            self.assertFalse((artifact_root / "SHA256SUMS").exists())


if __name__ == "__main__":
    unittest.main()
