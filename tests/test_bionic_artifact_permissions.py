from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PREPARE = ROOT / "scripts/prepare-bionic-write-root.py"
STATUS_PARSER = ROOT / "scripts/parse-native-build-status.py"
FIXTURE_RUNNER = ROOT / "scripts/run-bionic-fixture.sh"
PREPARE_SPEC = importlib.util.spec_from_file_location("bionic_write_root_helper_tests", PREPARE)
if PREPARE_SPEC is None or PREPARE_SPEC.loader is None:
    raise RuntimeError("could not load the Bionic write-root helper")
PREPARE_HELPER = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(PREPARE_HELPER)


class BionicArtifactPermissionTests(unittest.TestCase):
    def run_command_as(
        self,
        uid: int,
        gid: int,
        groups: list[int],
        command: list[str],
        *,
        cwd: Path,
        umask: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if os.geteuid() != 0:
            self.skipTest("distinct-UID DAC regression requires a root-capable local test harness")

        def drop_privileges() -> None:
            os.setgroups(groups)
            os.setgid(gid)
            os.setuid(uid)
            if umask is not None:
                os.umask(umask)

        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            preexec_fn=drop_privileges,
        )

    def run_as(
        self,
        uid: int,
        gid: int,
        groups: list[int],
        script: str,
        *arguments: str,
        cwd: Path,
        umask: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command_as(
            uid,
            gid,
            groups,
            [sys.executable, "-c", script, *arguments],
            cwd=cwd,
            umask=umask,
        )

    @staticmethod
    def tree_inventory(root: Path) -> tuple[tuple[object, ...], ...]:
        """Inventory every entry without following symlinks, including bytes and modes."""
        rows: list[tuple[object, ...]] = []

        def visit(path: Path, relative: str) -> None:
            metadata = path.lstat()
            kind = stat.S_IFMT(metadata.st_mode)
            digest = ""
            target = ""
            if stat.S_ISREG(metadata.st_mode):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            elif stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
            rows.append((
                relative,
                kind,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_ino,
                metadata.st_mtime_ns,
                digest,
                target,
            ))
            if stat.S_ISDIR(metadata.st_mode):
                for entry in sorted(os.scandir(path), key=lambda item: item.name):
                    visit(Path(entry.path), f"{relative}/{entry.name}" if relative else entry.name)

        visit(root, "")
        return tuple(sorted(rows))

    @staticmethod
    def copy_tool(source: Path, destination: Path) -> Path:
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
        return destination

    def test_fixture_rejects_symlink_artifact_roots_before_tools_or_outside_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bionic-path-guard-") as raw_temp:
            temp = Path(raw_temp)
            outside = temp / "outside-tree"
            outside.mkdir(mode=0o755)
            (outside / "nested").mkdir(mode=0o750)
            (outside / "nested" / "sentinel.bin").write_bytes(b"preserve every byte\x00\xff\n")
            (outside / "nested" / "sentinel.bin").chmod(0o640)
            (outside / "other.txt").write_text("outside inventory\n", encoding="utf-8")
            (outside / "other.txt").chmod(0o444)
            before = self.tree_inventory(outside)

            runtime_spy = temp / "runtime-spy"
            runtime_marker = temp / "runtime-was-invoked"
            runtime_spy.write_text(
                f"#!/bin/sh\nprintf invoked > {str(runtime_marker)!r}\n",
                encoding="utf-8",
            )
            runtime_spy.chmod(0o755)

            symlink_roots = (
                (temp / "root-alias", outside),
                (temp / "intermediate-alias" / "new-child", outside),
            )
            (temp / "root-alias").symlink_to(outside, target_is_directory=True)
            (temp / "intermediate-alias").symlink_to(outside, target_is_directory=True)

            for artifact_root, _ in symlink_roots:
                with self.subTest(artifact_root=str(artifact_root)):
                    result = subprocess.run(
                        ["bash", str(FIXTURE_RUNNER)],
                        cwd=ROOT,
                        env={
                            **os.environ,
                            "BIONIC_ARTIFACT_ROOT": str(artifact_root),
                            "BIONIC_CONTAINER_RUNTIME": str(runtime_spy),
                        },
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("symlink", result.stderr.lower())
                    self.assertFalse(runtime_marker.exists(), result.stderr)
                    self.assertFalse((outside / "c-termux-bionic-pie").exists())
                    self.assertFalse((outside / "new-child" / "c-termux-bionic-pie").exists())
                    self.assertEqual(before, self.tree_inventory(outside))

            existing_root = temp / "preexisting-descendant"
            case_root = existing_root / "c-termux-bionic-pie"
            case_root.mkdir(parents=True)
            (case_root / "host-context-artifact-ownership.txt").symlink_to(
                outside / "nested" / "sentinel.bin"
            )
            result = subprocess.run(
                ["bash", str(FIXTURE_RUNNER)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "BIONIC_ARTIFACT_ROOT": str(existing_root),
                    "BIONIC_CONTAINER_RUNTIME": str(runtime_spy),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("symlink", result.stderr.lower())
            self.assertFalse(runtime_marker.exists(), result.stderr)
            self.assertEqual(before, self.tree_inventory(outside))

    def test_helper_validates_bounded_tree_without_following_links_or_special_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bionic-tree-validation-") as raw_temp:
            temp = Path(raw_temp)
            valid = temp / "valid"
            (valid / "nested").mkdir(parents=True)
            (valid / "nested" / "report.txt").write_text("evidence\n", encoding="utf-8")
            self.assertEqual(0, subprocess.run(
                [sys.executable, str(PREPARE), "--validate-tree", str(valid)],
                cwd=ROOT,
                env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
                capture_output=True,
                text=True,
                check=False,
            ).returncode)
            descriptor_inventory = Path("/proc/self/fd")
            if descriptor_inventory.is_dir():
                descriptors_before = len(os.listdir(descriptor_inventory))
                for _ in range(5):
                    PREPARE_HELPER.validate_tree(str(valid))
                self.assertEqual(descriptors_before, len(os.listdir(descriptor_inventory)))

            linked_file = valid / "nested" / "outside-link"
            linked_file.symlink_to(temp / "outside-sentinel")
            if descriptor_inventory.is_dir():
                descriptors_before = len(os.listdir(descriptor_inventory))
                with self.assertRaisesRegex(ValueError, "symlink"):
                    PREPARE_HELPER.validate_tree(str(valid))
                self.assertEqual(descriptors_before, len(os.listdir(descriptor_inventory)))
            rejected_link = subprocess.run(
                [sys.executable, str(PREPARE), "--validate-tree", str(valid)],
                cwd=ROOT,
                env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, rejected_link.returncode)
            self.assertIn("symlink", rejected_link.stderr.lower())
            linked_file.unlink()

            fifo = valid / "nested" / "pipe"
            os.mkfifo(fifo)
            rejected_special = subprocess.run(
                [sys.executable, str(PREPARE), "--validate-tree", str(valid)],
                cwd=ROOT,
                env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(2, rejected_special.returncode)
            self.assertIn("non-regular, non-directory", rejected_special.stderr)
            fifo.unlink()

            (valid / "nested" / "hardlink").hardlink_to(valid / "nested" / "report.txt")
            rejected_hardlink = subprocess.run(
                [sys.executable, str(PREPARE), "--validate-tree", str(valid)],
                cwd=ROOT,
                env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, rejected_hardlink.returncode)
            self.assertIn("multiply-linked", rejected_hardlink.stderr)

    def test_helper_closes_new_descriptors_when_fstat_rejects_paths(self) -> None:
        descriptor_inventory = Path("/proc/self/fd")
        if not descriptor_inventory.is_dir():
            self.skipTest("descriptor leak check requires /proc/self/fd")

        with tempfile.TemporaryDirectory(prefix="bionic-fd-cleanup-") as raw_temp:
            temp = Path(raw_temp)
            regular = temp / "regular.txt"
            regular.write_text("bounded input\n", encoding="utf-8")
            real_fstat = os.fstat

            descriptors_before = len(os.listdir(descriptor_inventory))
            with mock.patch.object(PREPARE_HELPER.os, "fstat", side_effect=OSError("forced directory fstat failure")):
                with self.assertRaisesRegex(OSError, "forced directory fstat failure"):
                    PREPARE_HELPER.open_real_directory(str(temp))
            self.assertEqual(descriptors_before, len(os.listdir(descriptor_inventory)))

            def reject_regular_file(descriptor: int) -> os.stat_result:
                metadata = real_fstat(descriptor)
                if stat.S_ISREG(metadata.st_mode):
                    raise OSError("forced regular-file fstat failure")
                return metadata

            descriptors_before = len(os.listdir(descriptor_inventory))
            with mock.patch.object(PREPARE_HELPER.os, "fstat", side_effect=reject_regular_file):
                with self.assertRaisesRegex(OSError, "forced regular-file fstat failure"):
                    PREPARE_HELPER.open_regular_file(str(regular))
            self.assertEqual(descriptors_before, len(os.listdir(descriptor_inventory)))

    def test_helper_enforces_entry_directory_file_and_depth_limits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bionic-tree-limits-") as raw_temp:
            temp = Path(raw_temp)

            entries = temp / "entries"
            entries.mkdir()
            (entries / "one").write_text("1", encoding="ascii")
            (entries / "two").write_text("2", encoding="ascii")
            PREPARE_HELPER.validate_tree(str(entries), maximum_entries=3)
            PREPARE_HELPER.validate_tree(str(entries), maximum_files=2)
            with self.assertRaisesRegex(ValueError, "2 total entries"):
                PREPARE_HELPER.validate_tree(str(entries), maximum_entries=2)
            with self.assertRaisesRegex(ValueError, "1 files"):
                PREPARE_HELPER.validate_tree(str(entries), maximum_files=1)

            directories = temp / "directories"
            (directories / "child").mkdir(parents=True)
            PREPARE_HELPER.validate_tree(str(directories), maximum_directories=2)
            with self.assertRaisesRegex(ValueError, "1 directories"):
                PREPARE_HELPER.validate_tree(str(directories), maximum_directories=1)

            depth = temp / "depth"
            (depth / "one" / "two").mkdir(parents=True)
            PREPARE_HELPER.validate_tree(str(depth), maximum_depth=2)
            with self.assertRaisesRegex(ValueError, "depth 1"):
                PREPARE_HELPER.validate_tree(str(depth), maximum_depth=1)

    def test_apt_phase_uses_termux_prefix_tmp_when_system_tmp_is_absent(self) -> None:
        real_uname = shutil.which("uname")
        real_mktemp = shutil.which("mktemp")
        self.assertIsNotNone(real_uname)
        self.assertIsNotNone(real_mktemp)
        assert real_uname is not None
        assert real_mktemp is not None

        with tempfile.TemporaryDirectory(prefix="bionic-termux-tmp-") as raw_temp:
            temp = Path(raw_temp)
            temp.chmod(0o755)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            fake_uname = fake_bin / "uname"
            fake_uname.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "-m" ]; then printf "aarch64\\n"; '
                'elif [ "$1" = "-r" ]; then printf "test-kernel\\n"; '
                f'else exec "{real_uname}" "$@"; fi\n',
                encoding="utf-8",
            )
            fake_uname.chmod(0o755)

            file_marker = temp / "host-file-command-invoked"
            fake_file = fake_bin / "file"
            fake_file.write_text(
                f"#!/bin/sh\nprintf invoked > {str(file_marker)!r}\nexit 99\n",
                encoding="utf-8",
            )
            fake_file.chmod(0o755)

            termux_prefix = temp / "data/data/com.termux/files/usr"
            termux_prefix.mkdir(parents=True)
            termux_tmp = termux_prefix / "tmp"
            self.assertFalse(termux_tmp.exists())
            observation_path = temp / "apt-cache-observation.json"
            legacy_mktemp_failure = temp / "legacy-mktemp-failure.txt"

            fake_mktemp = fake_bin / "mktemp"
            fake_mktemp.write_text(
                f"#!{sys.executable}\n"
                + """import os
from pathlib import Path
import sys

args = sys.argv[1:]
template = args[args.index("-d") + 1] if "-d" in args else args[-1]
if template.startswith("/tmp/urprotect-bionic-apt-archives."):
    Path(os.environ["BIONIC_TEST_LEGACY_MKTEMP_FAILURE"]).write_text(template, encoding="utf-8")
    print("mktemp: failed to create directory via template: No such file or directory", file=sys.stderr)
    raise SystemExit(1)
real_mktemp = os.environ["BIONIC_TEST_REAL_MKTEMP"]
os.execv(real_mktemp, [real_mktemp, *args])
""",
                encoding="utf-8",
            )
            fake_mktemp.chmod(0o755)

            fake_apt_get = fake_bin / "apt-get"
            fake_apt_get.write_text(
                f"#!{sys.executable}\n"
                + """import json
import os
from pathlib import Path
import stat
import subprocess
import sys

args = sys.argv[1:]
if "--download-only" not in args:
    raise SystemExit(0)
archive_option = next(arg for arg in args if arg.startswith("Dir::Cache::archives="))
cache_dir = Path(archive_option.split("=", 1)[1])
tmp_dir = Path(os.environ["TMPDIR"])
cache_metadata = cache_dir.stat()
tmp_metadata = tmp_dir.stat()
producer_user = subprocess.run(["id", "-un"], check=True, capture_output=True, text=True).stdout.strip()
sandbox_user = next(arg.split("=", 1)[1] for arg in args if arg.startswith("APT::Sandbox::User="))
observation = {
    "prefix": os.environ["PREFIX"],
    "tmpdir": str(tmp_dir),
    "tmp_mode": stat.S_IMODE(tmp_metadata.st_mode),
    "tmp_uid": tmp_metadata.st_uid,
    "tmp_writable": os.access(tmp_dir, os.W_OK | os.X_OK),
    "cache_dir": str(cache_dir),
    "cache_option": archive_option,
    "cache_mode": stat.S_IMODE(cache_metadata.st_mode),
    "cache_uid": cache_metadata.st_uid,
    "producer_uid": os.geteuid(),
    "producer_user": producer_user,
    "sandbox_user": sandbox_user,
}
Path(os.environ["BIONIC_TEST_APT_OBSERVATION"]).write_text(
    json.dumps(observation, sort_keys=True), encoding="utf-8"
)
valid = (
    tmp_dir == Path(os.environ["PREFIX"]) / "tmp"
    and tmp_dir.is_dir()
    and not tmp_dir.is_symlink()
    and tmp_metadata.st_uid == os.geteuid()
    and stat.S_IMODE(tmp_metadata.st_mode) == 0o770
    and observation["tmp_writable"]
    and cache_dir.parent == tmp_dir
    and stat.S_IMODE(cache_metadata.st_mode) == 0o700
    and cache_metadata.st_uid == os.geteuid()
    and archive_option == "Dir::Cache::archives=" + str(cache_dir)
    and sandbox_user == producer_user
)
if not valid:
    print("fake apt observed an invalid temporary/cache configuration", file=sys.stderr)
    raise SystemExit(98)
print("simulated apt download failure after cache validation", file=sys.stderr)
raise SystemExit(47)
""",
                encoding="utf-8",
            )
            fake_apt_get.chmod(0o755)
            fake_dpkg_query = fake_bin / "dpkg-query"
            fake_dpkg_query.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_dpkg_query.chmod(0o755)

            fake_runtime = temp / "fake-container-runtime"
            fake_runtime.write_text(
                f"#!{sys.executable}\n"
                + """import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if args[:1] == ["version"]:
    print("linux/arm64")
elif args[:1] == ["pull"]:
    pass
elif args[:2] == ["image", "inspect"]:
    image = args[2]
    if "--format" not in args:
        print(json.dumps({"Architecture": "arm64", "RepoDigests": [image]}))
    elif "Architecture" in args[args.index("--format") + 1]:
        print("arm64")
    else:
        print(image)
elif args[:1] == ["run"]:
    command_indexes = [index for index, value in enumerate(args) if value == "-c"]
    script_index = command_indexes[-1] + 1
    script = args[script_index]
    script_arguments = args[script_index + 1:]
    if "container_arch=" in script:
        gid = os.environ["BIONIC_TEST_HOST_GID"]
        print("\\n".join((
            "container_arch=aarch64",
            "container_uid=1000",
            "container_user=system",
            "container_gid=1000",
            f"container_groups=1000 {gid}",
            "container_umask=0007",
            f"host_artifact_gid={gid}",
            "container_kernel=test-kernel",
            "container_page_size=4096",
            "android_runtime=absent",
        )))
    elif "apt_get update" in script:
        mount = next(value for value in args if value.startswith("type=bind,src=") and ",dst=/artifacts" in value)
        artifact_root = Path(mount.split("src=", 1)[1].split(",dst=/artifacts", 1)[0])
        actual_script = script.replace("/artifacts", str(artifact_root))
        environment = dict(os.environ)
        environment.update({
            "PREFIX": os.environ["BIONIC_TEST_TERMUX_PREFIX"],
            "TMPDIR": "/tmp",
            "HOST_ARTIFACT_GID": os.environ["BIONIC_TEST_HOST_GID"],
            "TERMUX_PACKAGE_REPOSITORY": "https://packages.termux.dev/apt/termux-main",
        })
        if len(script_arguments) != 9 or script_arguments[0] != "--":
            print("embedded apt phase must receive -- plus eight package specs", file=sys.stderr)
            raise SystemExit(96)
        command = [
            "/bin/sh", "-c", 'umask 0007; exec "$@"', "bionic-umask-boundary",
            "/bin/sh", "-c", actual_script, *script_arguments,
        ]
        phase = subprocess.run(command, env=environment, capture_output=True, text=True, check=False)
        sys.stdout.write(phase.stdout)
        sys.stderr.write(phase.stderr)
        raise SystemExit(phase.returncode)
    else:
        raise SystemExit("unexpected container command: " + repr(args))
else:
    raise SystemExit("unexpected container runtime command: " + repr(args))
""",
                encoding="utf-8",
            )
            fake_runtime.chmod(0o755)

            artifact_root = temp / "artifacts"
            environment = dict(os.environ)
            for name in ("ANDROID_ROOT", "ANDROID_DATA"):
                environment.pop(name, None)
            environment.update({
                "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
                "TMPDIR": "/tmp",
                "BIONIC_ARTIFACT_ROOT": str(artifact_root),
                "BIONIC_CONTAINER_RUNTIME": str(fake_runtime),
                "BIONIC_TEST_HOST_GID": str(os.getgid()),
                "BIONIC_TEST_TERMUX_PREFIX": str(termux_prefix),
                "BIONIC_TEST_APT_OBSERVATION": str(observation_path),
                "BIONIC_TEST_LEGACY_MKTEMP_FAILURE": str(legacy_mktemp_failure),
                "BIONIC_TEST_REAL_MKTEMP": real_mktemp,
                "PYTHONDONTWRITEBYTECODE": "1",
            })
            result = subprocess.run(
                ["bash", str(FIXTURE_RUNNER)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(47, result.returncode, f"stdout={result.stdout!r} stderr={result.stderr!r}")
            self.assertIn("simulated apt download failure after cache validation", result.stderr)
            self.assertFalse(legacy_mktemp_failure.exists(), "apt phase still requested a top-level /tmp cache")
            self.assertFalse(file_marker.exists(), "fixture advanced beyond the apt download phase")
            self.assertTrue(observation_path.is_file())
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            self.assertEqual(str(termux_prefix), observation["prefix"])
            self.assertEqual(str(termux_tmp), observation["tmpdir"])
            self.assertEqual(0o770, observation["tmp_mode"])
            self.assertEqual(os.geteuid(), observation["tmp_uid"])
            self.assertTrue(observation["tmp_writable"])
            self.assertTrue(termux_tmp.is_dir())
            cache_dir = Path(observation["cache_dir"])
            self.assertEqual(termux_tmp, cache_dir.parent)
            self.assertEqual(0o700, observation["cache_mode"])
            self.assertEqual(os.geteuid(), observation["cache_uid"])
            self.assertEqual("Dir::Cache::archives=" + str(cache_dir), observation["cache_option"])
            self.assertEqual(os.geteuid(), observation["producer_uid"])
            self.assertEqual(observation["producer_user"], observation["sandbox_user"])

    def test_fixture_finalization_does_not_follow_container_replaced_apt_paths(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("apt-path adversarial runner regression needs root to orchestrate a group writer")

        host_gid = os.getgid()
        container_uid = 1000
        container_gid = 1001 if host_gid == 1000 else 1000
        real_uname = shutil.which("uname")
        self.assertIsNotNone(real_uname)

        with tempfile.TemporaryDirectory(prefix="bionic-apt-path-guard-") as raw_temp:
            temp = Path(raw_temp)
            temp.chmod(0o755)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            fake_uname = fake_bin / "uname"
            fake_uname.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "-m" ]; then printf "aarch64\\n"; '
                'elif [ "$1" = "-r" ]; then printf "test-kernel\\n"; '
                f'else exec "{real_uname}" "$@"; fi\n',
                encoding="utf-8",
            )
            fake_uname.chmod(0o755)
            # The fixture runs as root only in this adversarial test harness;
            # fake sudo executes its argv unchanged so legacy privileged cleanup
            # would act with the orchestrator's authority and the regression
            # proves it cannot touch the outside tree.
            fake_sudo = fake_bin / "sudo"
            fake_sudo.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
            fake_sudo.chmod(0o755)
            host_report_marker = temp / "host-report-command-ran"
            fake_file = fake_bin / "file"
            fake_file.write_text(
                f"#!/bin/sh\nprintf invoked > {str(host_report_marker)!r}\nexit 0\n",
                encoding="utf-8",
            )
            fake_file.chmod(0o755)

            fake_runtime = temp / "fake-container-runtime"
            fake_runtime.write_text(
                f"#!{sys.executable}\n"
                + """import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if args[:1] == ["version"]:
    print("linux/arm64")
elif args[:1] == ["pull"]:
    pass
elif args[:2] == ["image", "inspect"]:
    image = args[2]
    if "--format" not in args:
        print(json.dumps({"Architecture": "arm64", "RepoDigests": [image]}))
    elif "Architecture" in args[args.index("--format") + 1]:
        print("arm64")
    else:
        print(image)
elif args[:1] == ["run"]:
    command_indexes = [index for index, value in enumerate(args) if value == "-c"]
    script = args[command_indexes[-1] + 1]
    if "container_arch=" in script:
        gid = os.environ["BIONIC_TEST_HOST_GID"]
        print("\\n".join((
            "container_arch=aarch64",
            "container_uid=1000",
            "container_user=test-user",
            "container_gid=1000",
            f"container_groups=1000 {gid}",
            "container_umask=0007",
            f"host_artifact_gid={gid}",
            "container_kernel=test-kernel",
            "container_page_size=4096",
            "android_runtime=absent",
        )))
    elif "apt_get update" in script:
        mount = next(value for value in args if value.startswith("type=bind,src=") and ",dst=/artifacts" in value)
        artifact_root = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
        archive_root = artifact_root / "apt-archives"
        assert archive_root.is_dir() and not archive_root.is_symlink()
        os.setgroups(sorted({
            int(os.environ["BIONIC_TEST_CONTAINER_GID"]),
            int(os.environ["BIONIC_TEST_HOST_GID"]),
        }))
        os.setgid(int(os.environ["BIONIC_TEST_CONTAINER_GID"]))
        os.setuid(int(os.environ["BIONIC_TEST_CONTAINER_UID"]))
        if os.environ.get("BIONIC_TEST_PLANT_HOST_REPORT_SYMLINK") == "true":
            lock = json.loads((artifact_root / "compiler-package-lock.json").read_text(encoding="utf-8"))
            (artifact_root / "packages-before.txt").write_text("", encoding="utf-8")
            (artifact_root / "packages.txt").write_text(
                "".join(
                    f"{package['name']}\\t{package['version']}\\taarch64\\tinstall ok installed\\n"
                    for package in lock
                ),
                encoding="utf-8",
            )
            # This is the first host-side output redirection after the apt
            # container returns. Without post-run tree validation, bash opens
            # file.txt and truncates the outside sentinel before invoking file.
            (artifact_root / "file.txt").symlink_to(
                Path(os.environ["BIONIC_TEST_OUTSIDE"]) / "sentinel.txt"
            )
        else:
            archive_root.rmdir()
            archive_root.symlink_to(os.environ["BIONIC_TEST_OUTSIDE"], target_is_directory=True)
            if os.environ["BIONIC_TEST_RUNTIME_STATUS"] != "0":
                (artifact_root / "apt-update.log").symlink_to(
                    Path(os.environ["BIONIC_TEST_OUTSIDE"]) / "sentinel.txt"
                )
            cleanup = subprocess.run(
                ["find", str(archive_root), "-maxdepth", "1", "-type", "f", "-name", "*.deb", "-delete"],
                check=False,
            )
            if cleanup.returncode != 0:
                raise SystemExit("producer no-follow archive cleanup failed")
        print("FAKE_APT_PHASE")
        raise SystemExit(int(os.environ["BIONIC_TEST_RUNTIME_STATUS"]))
    else:
        raise SystemExit("unexpected container command: " + repr(args))
else:
    raise SystemExit("unexpected container runtime command: " + repr(args))
""",
                encoding="utf-8",
            )
            fake_runtime.chmod(0o755)

            for phase, runtime_status in (("normal", "0"), ("exit", "47"), ("report", "0")):
                with self.subTest(phase=phase):
                    artifact_root = temp / f"artifacts-{phase}"
                    outside = temp / f"outside-{phase}"
                    outside.mkdir(mode=0o755)
                    partial = outside / "partial"
                    partial.mkdir(mode=0o755)
                    (partial / "incomplete.deb").write_bytes(b"must not be removed\n")
                    (partial / "incomplete.deb").chmod(0o600)
                    (outside / "keep.bin").write_bytes(b"must not be chmodded\n")
                    (outside / "keep.bin").chmod(0o600)
                    (outside / "sentinel.txt").write_bytes(b"outside sentinel must remain byte-identical\n")
                    (outside / "sentinel.txt").chmod(0o640)
                    outside_before = self.tree_inventory(outside)

                    environment = dict(os.environ)
                    for name in ("ANDROID_ROOT", "ANDROID_DATA"):
                        environment.pop(name, None)
                    environment.update({
                        "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
                        "BIONIC_ARTIFACT_ROOT": str(artifact_root),
                        "BIONIC_CONTAINER_RUNTIME": str(fake_runtime),
                        "BIONIC_TEST_HOST_GID": str(host_gid),
                        "BIONIC_TEST_CONTAINER_UID": str(container_uid),
                        "BIONIC_TEST_CONTAINER_GID": str(container_gid),
                        "BIONIC_TEST_OUTSIDE": str(outside),
                        "BIONIC_TEST_RUNTIME_STATUS": runtime_status,
                        "BIONIC_TEST_PLANT_HOST_REPORT_SYMLINK": "true" if phase == "report" else "false",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    })
                    result = subprocess.run(
                        ["bash", str(FIXTURE_RUNNER)],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertIn("FAKE_APT_PHASE", result.stdout, result.stderr)
                    if phase == "exit":
                        self.assertEqual(47, result.returncode, result.stderr)
                        self.assertNotIn("outside sentinel must remain byte-identical", result.stderr)
                    elif phase == "report":
                        self.assertEqual(2, result.returncode, result.stderr)
                        self.assertIn("symlink", result.stderr.lower())
                        report = artifact_root / "c-termux-bionic-pie" / "file.txt"
                        self.assertTrue(report.is_symlink())
                        self.assertFalse(host_report_marker.exists(), "host file command ran after invalid-tree detection")
                        self.assertEqual(b"outside sentinel must remain byte-identical\n", (outside / "sentinel.txt").read_bytes())
                    else:
                        # A successful fake producer that replaced apt-archives
                        # is rejected by immediate post-container tree validation.
                        self.assertEqual(2, result.returncode, result.stderr)
                        self.assertIn("symlink", result.stderr.lower())
                    self.assertEqual(outside_before, self.tree_inventory(outside))
                    self.assertTrue((partial / "incomplete.deb").exists())
                    self.assertEqual(0o600, stat.S_IMODE((outside / "keep.bin").stat().st_mode))

    def test_captured_container_status_cannot_continue_after_invalid_tree_before_redirection(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("container-UID symlink race regression needs root to orchestrate the group writer")

        host_gid = os.getgid()
        container_uid = 1000
        container_gid = 1001 if host_gid == 1000 else 1000
        runner_text = FIXTURE_RUNNER.read_text(encoding="utf-8")

        def function_source(name: str) -> str:
            match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}\n", runner_text)
            if match is None:
                self.fail(f"fixture runner is missing {name}()")
            return match.group(0)

        shell_function = function_source("run_shell")
        capture_function = function_source("run_shell_capturing_status")
        with tempfile.TemporaryDirectory(prefix="bionic-status-tree-guard-") as raw_temp:
            temp = Path(raw_temp)
            temp.chmod(0o755)
            case_root = temp / "artifacts"
            case_root.mkdir(mode=0o2770)
            os.chown(case_root, os.geteuid(), host_gid)
            case_root.chmod(0o2770)
            outside = temp / "outside"
            outside.mkdir(mode=0o755)
            sentinel = outside / "sentinel.txt"
            sentinel.write_bytes(b"preserve before the next redirection\n")
            sentinel.chmod(0o644)
            outside_before = self.tree_inventory(outside)
            second_phase_marker = case_root / "second-phase-was-invoked"

            fake_runtime = temp / "fake-container-runtime.py"
            fake_runtime.write_text(
                f"#!{sys.executable}\n"
                + """import os
from pathlib import Path
import sys

root = Path(os.environ["BIONIC_TEST_CASE_ROOT"])
os.setgroups([int(os.environ["BIONIC_TEST_HOST_GID"]), int(os.environ["BIONIC_TEST_CONTAINER_GID"])])
os.setgid(int(os.environ["BIONIC_TEST_CONTAINER_GID"]))
os.setuid(int(os.environ["BIONIC_TEST_CONTAINER_UID"]))
if sys.argv[-1] == "first-phase":
    (root / "later.stdout").symlink_to(os.environ["BIONIC_TEST_OUTSIDE_SENTINEL"])
elif sys.argv[-1] == "second-phase":
    (root / "second-phase-was-invoked").write_text("unexpected\\n", encoding="utf-8")
else:
    raise SystemExit("unexpected fake runtime argv: " + repr(sys.argv))
""",
                encoding="utf-8",
            )
            fake_runtime.chmod(0o755)
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            environment.update({
                "BIONIC_TEST_CASE_ROOT": str(case_root),
                "BIONIC_TEST_OUTSIDE_SENTINEL": str(sentinel),
                "BIONIC_TEST_HOST_GID": str(host_gid),
                "BIONIC_TEST_CONTAINER_UID": str(container_uid),
                "BIONIC_TEST_CONTAINER_GID": str(container_gid),
                "BIONIC_WRITE_ROOT_HELPER": str(PREPARE),
                "BIONIC_FAKE_RUNTIME": str(fake_runtime),
                "PYTHONDONTWRITEBYTECODE": "1",
            })
            harness = "\n".join((
                "set -uo pipefail",
                'case_root="$BIONIC_TEST_CASE_ROOT"',
                'container_runtime="$BIONIC_FAKE_RUNTIME"',
                'container_common=()',
                'image=test-image',
                'termux_shell=/bin/sh',
                'validate_artifact_tree() { python3 "$BIONIC_WRITE_ROOT_HELPER" --validate-tree "$case_root"; }',
                shell_function.rstrip(),
                capture_function.rstrip(),
                'set +e',
                'run_shell_capturing_status -c first-phase > "$case_root/first.stdout" 2> "$case_root/first.stderr"',
                'first_status=$?',
                'run_shell_capturing_status -c second-phase > "$case_root/later.stdout" 2> "$case_root/later.stderr"',
                'exit "$first_status"',
            ))
            result = subprocess.run(
                ["bash", "-c", harness],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            first_stderr = (case_root / "first.stderr").read_text(encoding="utf-8")
            self.assertEqual(
                2,
                result.returncode,
                f"stdout={result.stdout!r} stderr={result.stderr!r} first-stderr={first_stderr!r}",
            )
            self.assertTrue((case_root / "later.stdout").is_symlink())
            self.assertFalse(second_phase_marker.exists(), "later container call ran after tree rejection")
            self.assertEqual(outside_before, self.tree_inventory(outside))
            self.assertEqual(b"preserve before the next redirection\n", sentinel.read_bytes())

    def test_distinct_uid_handoff_retains_all_build_and_identity_bytes_for_unprivileged_host(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("distinct-UID DAC regression requires a root-capable local test harness")

        host_writer = pwd.getpwnam("nobody")
        container_uid = 1000
        container_gid = 1001 if host_writer.pw_gid == 1000 else 1000
        self.assertNotEqual(container_uid, host_writer.pw_uid)
        self.assertNotEqual(container_gid, host_writer.pw_gid)

        with tempfile.TemporaryDirectory(prefix="bionic-dac-boundary-") as raw_temp:
            temp = Path(raw_temp)
            temp.chmod(0o755)
            helper_copy = self.copy_tool(PREPARE, temp / "prepare-bionic-write-root.py")
            parser_copy = self.copy_tool(STATUS_PARSER, temp / "parse-native-build-status.py")
            artifact_root = temp / "owned-artifacts"
            artifact_root.mkdir(mode=0o755)
            os.chown(artifact_root, host_writer.pw_uid, host_writer.pw_gid)
            artifact_root.chmod(0o755)

            outside = temp / "outside-owned-artifacts"
            outside.mkdir(mode=0o755)
            sentinel = outside / "do-not-mutate.txt"
            sentinel.write_bytes(b"outside the owned run root\n")
            sentinel.chmod(0o444)
            outside_nested = outside / "nested"
            outside_nested.mkdir(mode=0o750)
            nested_file = outside_nested / "retain.bin"
            nested_file.write_bytes(b"all outside bytes stay exact\x00\xf0")
            nested_file.chmod(0o640)
            outside_before = self.tree_inventory(outside)

            # Reproduce both plausible pre-handoff ownership/mode cases. A
            # host-UID process must fail at the actual report redirection.
            container_owned = artifact_root / "container-owned-build"
            container_owned.mkdir()
            os.chown(container_owned, container_uid, container_gid)
            container_owned.chmod(0o755)
            root_owned = artifact_root / "root-owned-build"
            root_owned.mkdir(mode=0o755)
            elf_source = Path(sys.executable)
            expected_elf_bytes = elf_source.read_bytes()
            for failed_root in (container_owned, root_owned):
                report = failed_root / "host-context-image-handoff.readelf.txt"
                denied = self.run_command_as(
                    host_writer.pw_uid,
                    host_writer.pw_gid,
                    [host_writer.pw_gid],
                    ["/bin/sh", "-c", 'readelf -hW "$1" > "$2"', "readelf", str(elf_source), str(report)],
                    cwd=temp,
                )
                self.assertNotEqual(0, denied.returncode)
                self.assertIn("Permission denied", denied.stderr)
                self.assertFalse(report.exists())

            shared_parent = artifact_root / "container-shared-root"
            helper_result = self.run_command_as(
                host_writer.pw_uid,
                host_writer.pw_gid,
                [host_writer.pw_gid],
                [
                    sys.executable,
                    str(helper_copy),
                    "--group-gid",
                    str(host_writer.pw_gid),
                    "--create-directory",
                    str(shared_parent),
                ],
                cwd=temp,
            )
            self.assertEqual(0, helper_result.returncode, helper_result.stderr)
            self.assertEqual(host_writer.pw_uid, shared_parent.stat().st_uid)
            self.assertEqual(host_writer.pw_gid, shared_parent.stat().st_gid)
            self.assertEqual(0o2770, stat.S_IMODE(shared_parent.stat().st_mode))

            expected_build = {
                "native-build.command.txt": b"make host-context-image-handoff CC=clang\n",
                "native-build.stdout": b"native build stdout exact\nline two\n",
                "native-build.stderr": b"native build stderr exact\nwarning retained\n",
                "native-build.status": b"0\n",
            }
            producer = (
                "import pathlib, shutil, sys; "
                "root=pathlib.Path(sys.argv[1]); root.mkdir(); "
                "payloads=sys.argv[2:6]; names=('native-build.command.txt','native-build.stdout',"
                "'native-build.stderr','native-build.status'); "
                "[(root/name).write_bytes(bytes.fromhex(value)) for name,value in zip(names,payloads)]; "
                "shutil.copyfile(sys.argv[6],root/'host-context-image-handoff')"
            )
            produced = self.run_as(
                container_uid,
                container_gid,
                [host_writer.pw_gid],
                producer,
                str(shared_parent / "indirect-control-build"),
                *(content.hex() for content in expected_build.values()),
                str(elf_source),
                cwd=temp,
                umask=0o007,
            )
            self.assertEqual(0, produced.returncode, produced.stderr)
            generated = shared_parent / "indirect-control-build"
            retained_elf = generated / "host-context-image-handoff"
            self.assertEqual(expected_elf_bytes, retained_elf.read_bytes())
            generated_metadata = generated.stat()
            self.assertEqual(container_uid, generated_metadata.st_uid)
            self.assertEqual(host_writer.pw_gid, generated_metadata.st_gid)
            self.assertTrue(generated_metadata.st_mode & stat.S_ISGID)
            self.assertTrue(generated_metadata.st_mode & stat.S_IWGRP)
            for name, expected in expected_build.items():
                self.assertEqual(expected, (generated / name).read_bytes())
                self.assertEqual(host_writer.pw_gid, (generated / name).stat().st_gid)

            identity_directory = shared_parent / "runtime-identity" / "target"
            identity_prepared = self.run_command_as(
                host_writer.pw_uid,
                host_writer.pw_gid,
                [host_writer.pw_gid],
                [
                    sys.executable,
                    str(helper_copy),
                    "--group-gid",
                    str(host_writer.pw_gid),
                    "--create-directory",
                    str(identity_directory),
                ],
                cwd=temp,
            )
            self.assertEqual(0, identity_prepared.returncode, identity_prepared.stderr)
            expected_identity = {
                "identity.json": b'{"runtimeVersion":null,"runtimeSource":"test-only"}\n',
                "maps.txt": b"1000-2000 r-xp test identity map\n",
                "libc.elf": expected_elf_bytes,
            }
            identity_producer = (
                "import pathlib,sys; root=pathlib.Path(sys.argv[1]); "
                "[(root/name).write_bytes(bytes.fromhex(value)) for name,value in "
                "zip(('identity.json','maps.txt'),sys.argv[2:4])]; "
                "(root/'libc.elf').write_bytes(pathlib.Path(sys.argv[4]).read_bytes())"
            )
            identity_capture = self.run_as(
                container_uid,
                container_gid,
                [host_writer.pw_gid],
                identity_producer,
                str(identity_directory),
                expected_identity["identity.json"].hex(),
                expected_identity["maps.txt"].hex(),
                str(elf_source),
                cwd=temp,
                umask=0o007,
            )
            self.assertEqual(0, identity_capture.returncode, identity_capture.stderr)

            read_sidecars = (
                "import pathlib,sys; root=pathlib.Path(sys.argv[1]); "
                "items=zip(('native-build.command.txt','native-build.stdout','native-build.stderr',"
                "'native-build.status'),sys.argv[2:6]); "
                "[(lambda path,want: (_ for _ in ()).throw(AssertionError(path.name)) "
                "if path.read_bytes()!=bytes.fromhex(want) else None)(root/name,value) "
                "for name,value in items]; "
                "identity=pathlib.Path(sys.argv[6]); "
                "[(lambda path,want: (_ for _ in ()).throw(AssertionError(path.name)) "
                "if path.read_bytes()!=bytes.fromhex(want) else None)(identity/name,value) "
                "for name,value in zip(('identity.json','maps.txt'),sys.argv[7:9])]; "
                "import hashlib; assert hashlib.sha256((identity/'libc.elf').read_bytes()).hexdigest()==sys.argv[9]; "
                "assert __import__('os').geteuid()!=0; print('all-retained-bytes-match')"
            )
            host_read = self.run_as(
                host_writer.pw_uid,
                host_writer.pw_gid,
                [host_writer.pw_gid],
                read_sidecars,
                str(generated),
                *(content.hex() for content in expected_build.values()),
                str(identity_directory),
                expected_identity["identity.json"].hex(),
                expected_identity["maps.txt"].hex(),
                hashlib.sha256(expected_identity["libc.elf"]).hexdigest(),
                cwd=temp,
            )
            self.assertEqual(0, host_read.returncode, host_read.stderr)
            self.assertIn("all-retained-bytes-match", host_read.stdout)

            parsed_status = self.run_command_as(
                host_writer.pw_uid,
                host_writer.pw_gid,
                [host_writer.pw_gid],
                [sys.executable, str(parser_copy), str(generated / "native-build.status")],
                cwd=temp,
            )
            self.assertEqual(0, parsed_status.returncode, parsed_status.stderr)
            self.assertEqual("0\n", parsed_status.stdout)

            # This exercises host-side DAC only: the executable is a valid
            # local host ELF, not a Bionic runtime or evidence claim.
            report = generated / "host-context-image-handoff.readelf.txt"
            readelf_report = self.run_command_as(
                host_writer.pw_uid,
                host_writer.pw_gid,
                [host_writer.pw_gid],
                ["/bin/sh", "-c", 'readelf -hW -lW -dW "$1" > "$2"', "readelf", str(generated / "host-context-image-handoff"), str(report)],
                cwd=temp,
            )
            self.assertEqual(0, readelf_report.returncode, readelf_report.stderr)
            report_bytes = report.read_bytes()
            self.assertIn(b"ELF Header", report_bytes)
            self.assertEqual(expected_elf_bytes, retained_elf.read_bytes())

            # Recheck all producer-owned bytes after the host read/parse/report
            # operations to prove no retained sidecar was overwritten.
            for name, expected in expected_build.items():
                self.assertEqual(expected, (generated / name).read_bytes())
            for name, expected in expected_identity.items():
                self.assertEqual(expected, (identity_directory / name).read_bytes())
            self.assertEqual(outside_before, self.tree_inventory(outside))

    def test_gid_zero_host_writer_can_share_only_the_setgid_root_with_container(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("GID-0 DAC regression requires a root-capable local test harness")
        if os.getgid() != 0:
            self.skipTest("GID-0 coverage requires an orchestrator whose primary GID is zero")

        with tempfile.TemporaryDirectory(prefix="bionic-dac-gid0-") as raw_temp:
            temp = Path(raw_temp)
            temp.chmod(0o755)
            shared_root = temp / "gid-zero-root"
            prepared = subprocess.run(
                [sys.executable, str(PREPARE), "--group-gid", "0", "--create-directory", str(shared_root)],
                cwd=ROOT,
                env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, prepared.returncode, prepared.stderr)
            self.assertEqual(0, shared_root.stat().st_gid)
            self.assertEqual(0o2770, stat.S_IMODE(shared_root.stat().st_mode))

            container_uid = 1000
            container_gid = 1001
            producer = "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'gid-zero-group-write\\n')"
            written = self.run_as(
                container_uid,
                container_gid,
                [0],
                producer,
                str(shared_root / "container-sidecar.txt"),
                cwd=temp,
                umask=0o007,
            )
            self.assertEqual(0, written.returncode, written.stderr)
            self.assertEqual(0, (shared_root / "container-sidecar.txt").stat().st_gid)
            self.assertEqual(b"gid-zero-group-write\n", (shared_root / "container-sidecar.txt").read_bytes())

    def test_runner_limits_group_handoff_to_exact_roots_and_retains_identity_write_scope(self) -> None:
        fixture = FIXTURE_RUNNER.read_text(encoding="utf-8")
        bridge = (ROOT / "scripts/run-bionic-host-context-handoff.sh").read_text(encoding="utf-8")
        for script in (fixture, bridge):
            self.assertIn("prepare-bionic-write-root.py", script)
            self.assertIn("--group-add", script)
            self.assertIn("host_artifact_gid", script)
        self.assertIn('--create-directory "${case_root}"', fixture)
        self.assertIn('--create-directory "${case_root}/apt-archives"', fixture)
        self.assertNotIn('mkdir -p "${case_root}"', fixture)
        initial_tree_validation = fixture.index("\nvalidate_artifact_tree\n")
        first_host_report = fixture.index('> "${case_root}/matrix-validation.txt"')
        self.assertLess(initial_tree_validation, first_host_report)
        self.assertLess(fixture.index('--create-directory "${case_root}"'), first_host_report)
        run_shell_body = fixture.index("run_shell() {")
        post_container_validation = fixture.index("if validate_artifact_tree;", run_shell_body)
        failure_logs = fixture.index("for log in", run_shell_body)
        self.assertLess(post_container_validation, failure_logs)
        self.assertIn('--validate-tree "${case_root}"', fixture)
        self.assertLess(fixture.index('validate_artifact_tree\n'), fixture.index('> "${case_root}/matrix-validation.txt"'))
        self.assertLess(fixture.index('local tree_status=0'), fixture.index('for log in'))
        self.assertIn("container_uid=%s\\n", fixture)
        self.assertIn("container_user=%s\\n", fixture)
        self.assertIn("container_gid=%s\\n", fixture)
        self.assertIn("container_groups=%s\\n", fixture)
        self.assertIn("container_umask=%s\\n", fixture)
        self.assertIn("umask 0007; exec \"$@\"", fixture)
        self.assertIn("HOST_ARTIFACT_GID=$host_artifact_gid", bridge)
        self.assertIn("host artifact group is missing from the Bionic handoff container", bridge)
        self.assertIn("umask 0007", bridge)
        self.assertIn('--validate-tree "$unit_root"', bridge)
        self.assertIn('if [[ "$tree_status" -ne 0 ]]; then', bridge)
        self.assertNotIn('chmod 0644 "$retained"', bridge)
        identity_writer = (ROOT / "native/urprotect-runtime/native_process_identity.c").read_text(encoding="utf-8")
        self.assertIn("output_mode = 0640;", identity_writer)
        self.assertIn("openat(directory_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, output_mode)", identity_writer)
        self.assertIn('chgrp "$HOST_ARTIFACT_GID" "$build_dir"', fixture)
        self.assertIn('chmod 2770 "$build_dir"', fixture)
        self.assertIn(
            'readelf -hW -lW -dW "${bionic_build_root}/host-context-image-handoff" '
            '> "${bionic_build_root}/host-context-image-handoff.readelf.txt"',
            fixture,
        )
        ownership_helper = PREPARE.read_text(encoding="utf-8")
        self.assertNotIn("chmod 777", fixture + bridge + ownership_helper)
        self.assertNotIn("chmod a+rwx", fixture + bridge)
        self.assertNotIn("sudo ", fixture)
        self.assertNotIn("trap cleanup_incomplete_apt_download EXIT", fixture)
        self.assertNotIn("chmod -R", fixture)
        self.assertIn('termux_tmp_dir="${PREFIX%/}/tmp"', fixture)
        self.assertIn('mkdir -p "${termux_tmp_dir}"', fixture)
        self.assertIn('export TMPDIR="${termux_tmp_dir}"', fixture)
        apt_cache_setup = 'apt_cache_dir="$(mktemp -d "${TMPDIR%/}/urprotect-bionic-apt-archives.XXXXXX")"'
        self.assertIn(apt_cache_setup, fixture)
        self.assertGreater(
            fixture.index('find /artifacts/apt-archives -maxdepth 1 -type f -name "*.deb" -delete'),
            fixture.index(apt_cache_setup),
        )
        self.assertIn('chmod 0640 "${destination_archive}"', fixture)
        self.assertNotIn("chown -R", fixture + bridge + ownership_helper)
        self.assertNotIn("sudo chown", fixture + bridge + ownership_helper)
        self.assertNotIn("os.walk(", ownership_helper)
        self.assertIn("MAX_TREE_ENTRIES = 20000", ownership_helper)
        self.assertIn("MAX_TREE_DIRECTORIES = 4096", ownership_helper)
        self.assertIn("MAX_TREE_FILES = 16000", ownership_helper)
        self.assertIn("MAX_TREE_DEPTH = 64", ownership_helper)
        ordinary = (ROOT / "scripts/run-indirect-control-e2e.sh").read_text(encoding="utf-8")
        shared = (ROOT / "scripts/run-shared-jump-table-copy-e2e.sh").read_text(encoding="utf-8")
        rehydration = (ROOT / "scripts/run-host-context-rehydration-e2e.sh").read_text(encoding="utf-8")
        bridge_create = bridge.index('"${path_validation[@]}"')
        self.assertLess(bridge_create, bridge.index('unit_root="$(realpath'))
        self.assertLess(ordinary.index('"${path_validation[@]}"'), ordinary.index('artifact_base="$(realpath'))
        self.assertLess(shared.index('"${path_validation[@]}"'), shared.index('artifact_base="$(realpath'))
        self.assertLess(
            rehydration.index('--validate-directory "$BIONIC_INDIRECT_CONTROL_BUILD_ROOT"'),
            rehydration.index('native_build_dir="$(realpath'),
        )
        self.assertLess(
            rehydration.index('"${path_validation[@]}"'),
            rehydration.index('artifact_root_resolved="$(realpath'),
        )
        for runner in (ordinary, shared, rehydration):
            self.assertNotIn("chmod a+rwx", runner)

    def test_helper_rejects_symlink_and_directory_not_owned_by_invoking_host(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("ownership guard regression requires a root-capable local test harness")
        with tempfile.TemporaryDirectory(prefix="bionic-dac-guards-") as raw_temp:
            temp = Path(raw_temp)
            owned = temp / "owned"
            owned.mkdir()
            alias = temp / "alias"
            alias.symlink_to(owned, target_is_directory=True)
            linked = subprocess.run(
                [sys.executable, str(PREPARE), "--group-gid", str(os.getgid()), "--directory", str(alias)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, linked.returncode)
            self.assertIn("symlink", linked.stderr)

            overlong_path = "/" + "/".join(["x"] * 129)
            bounded = subprocess.run(
                [sys.executable, str(PREPARE), "--validate-directory", overlong_path],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, bounded.returncode)
            self.assertIn("exceeds 128 components", bounded.stderr)

            foreign = temp / "foreign"
            foreign.mkdir()
            os.chown(foreign, 1000, 1000)
            rejected = subprocess.run(
                [sys.executable, str(PREPARE), "--group-gid", str(os.getgid()), "--directory", str(foreign)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, rejected.returncode)
            self.assertIn("not owned by the host writer", rejected.stderr)
            self.assertEqual(0o755, stat.S_IMODE(foreign.stat().st_mode))


if __name__ == "__main__":
    unittest.main()
