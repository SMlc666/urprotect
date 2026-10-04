#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/run-isolated-real-sample.py"


class IsolatedRealSampleTests(unittest.TestCase):
    def run_helper(
        self,
        bwrap_body: str,
        command: list[str],
        timeout: int = 1,
        *,
        dropper: bool = False,
        fake_sudo: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], float]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o777)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            bwrap = fake_bin / "bwrap"
            bwrap.write_text("#!/bin/sh\n" + bwrap_body + "\n", encoding="utf-8")
            bwrap.chmod(0o755)
            rootfs = root / "rootfs"
            rootfs.mkdir()
            stdout = root / "stdout"
            stderr = root / "stderr"
            result_json = root / "result.json"
            dropper_path = root / "dropper"
            if dropper:
                dropper_path.write_text(
                    "#!/bin/sh\nprintf '__URP_ISOLATION_READY__:%s__' \"$URP_READY_TOKEN\" >&2\nexec \"$@\"\n",
                    encoding="utf-8",
                )
                dropper_path.chmod(0o755)
            sudo_log = root / "sudo.log"
            if fake_sudo:
                sudo_path = fake_bin / "sudo"
                sudo_path.write_text(
                    "#!/bin/sh\n"
                    "[ \"$1\" = -n ] && shift\n"
                    "exec 3>&-\n"
                    "printf '%s\\n' \"$*\" > \"$FAKE_SUDO_LOG\"\n"
                    "exec \"$@\"\n",
                    encoding="utf-8",
                )
                sudo_path.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"
            if fake_sudo:
                environment["FAKE_SUDO_LOG"] = str(sudo_log)
            started = time.monotonic()
            helper_command = ["python3", str(HELPER)]
            if fake_sudo:
                force_sudo = root / "force-sudo.py"
                force_sudo.write_text(
                    "import os, runpy, sys\n"
                    f"sys.path.insert(0, {str(HELPER.parent)!r})\n"
                    "os.geteuid = lambda: 1000\n"
                    f"runpy.run_path({str(HELPER)!r}, run_name='__main__')\n",
                    encoding="utf-8",
                )
                force_sudo.chmod(0o755)
                helper_command = ["python3", str(force_sudo)]

            completed = subprocess.run(
                [
                    *helper_command,
                    "--rootfs",
                    str(rootfs),
                    "--stdout",
                    str(stdout),
                    "--stderr",
                    str(stderr),
                    "--result-json",
                    str(result_json),
                    "--timeout",
                    str(timeout),
                    "--memory-bytes",
                    str(256 * 1024 * 1024),
                    "--process-limit",
                    "32",
                    "--output-limit",
                    str(1024 * 1024),
                    *( ["--dropper", str(dropper_path)] if dropper else [] ),
                    "--",
                    *command,
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            elapsed = time.monotonic() - started
            self.captured_stdout = stdout.read_bytes() if stdout.exists() else b""
            self.captured_stderr = stderr.read_bytes() if stderr.exists() else b""
            self.helper_result = (
                json.loads(result_json.read_text(encoding="utf-8"))
                if result_json.exists()
                else None
            )
            self.sudo_was_used = sudo_log.exists()
            self.sudo_arguments = sudo_log.read_text(encoding="utf-8") if sudo_log.exists() else ""
            return completed, elapsed

    def test_timeout_is_enforced_after_target_closes_both_streams(self) -> None:
        result, elapsed = self.run_helper(
            'source=""; '
            'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do '
            'if [ "$1" = "--ro-bind" ]; then source="$2"; shift 3; '
            'elif [ "$1" = "--setenv" ]; then export "$2=$3"; shift 3; '
            'else shift; fi; done; '
            'shift; '
            'if [ "$1" = "/tmp/urp/dropper" ]; then shift; exec "$source/dropper" "$@"; fi; '
            'exec "$@"',
            ["/bin/sh", "-c", "exec 1>&-; exec 2>&-; sleep 3"],
            dropper=True,
        )
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertLess(elapsed, 2.5)
        self.assertEqual(
            self.helper_result,
            {
                "attempted": True,
                "helperStatus": 124,
                "outcome": "helper-timeout",
                "producer": "run-isolated-real-sample.py",
                "readinessSeen": True,
                "schemaVersion": 1,
                "targetStatus": None,
            },
        )
        self.assertEqual(self.captured_stdout, b"")
        self.assertEqual(self.captured_stderr, b"")

    def test_target_exit_status_is_preserved(self) -> None:
        result, _ = self.run_helper(
            'set -- "$@"; while [ "$1" != "--" ]; do shift; done; shift; exec "$@"',
            ["/bin/sh", "-c", "exit 7"],
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertTrue(self.helper_result["attempted"])
        self.assertIsNone(self.helper_result["helperStatus"])
        self.assertEqual(self.helper_result["targetStatus"], 7)

    def test_dropper_readiness_marker_survives_sudo_descriptor_closing(self) -> None:
        result, _ = self.run_helper(
            'source=""; '
            'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do '
            'if [ "$1" = "--ro-bind" ]; then source="$2"; shift 3; '
            'elif [ "$1" = "--setenv" ]; then export "$2=$3"; shift 3; '
            'else shift; fi; done; '
            'shift; '
            'if [ "$1" = "/tmp/urp/dropper" ]; then shift; exec "$source/dropper" "$@"; fi; '
            'exec "$@"',
            ["/bin/sh", "-c", "exit 7"],
            dropper=True,
            fake_sudo=True,
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertTrue(self.sudo_was_used)
        self.assertTrue(self.helper_result["attempted"])
        self.assertEqual(self.helper_result["targetStatus"], 7)
        self.assertNotIn("--preserve-fds", self.sudo_arguments)
        self.assertNotIn(b"__URP_ISOLATION_READY__", self.captured_stderr)

    def test_target_exit_124_after_readiness_is_a_target_status(self) -> None:
        result, _ = self.run_helper(
            'source=""; '
            'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do '
            'if [ "$1" = "--ro-bind" ]; then source="$2"; shift 3; '
            'elif [ "$1" = "--setenv" ]; then export "$2=$3"; shift 3; '
            'else shift; fi; done; '
            'shift; '
            'if [ "$1" = "/tmp/urp/dropper" ]; then shift; exec "$source/dropper" "$@"; fi; '
            'exec "$@"',
            ["/bin/sh", "-c", "exit 124"],
            dropper=True,
        )
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertTrue(self.helper_result["attempted"])
        self.assertIsNone(self.helper_result["helperStatus"])
        self.assertEqual(self.helper_result["targetStatus"], 124)
        self.assertEqual(self.helper_result["outcome"], "target-exit")

    def test_target_exit_125_after_readiness_is_a_target_status(self) -> None:
        result, _ = self.run_helper(
            'source=""; '
            'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do '
            'if [ "$1" = "--ro-bind" ]; then source="$2"; shift 3; '
            'elif [ "$1" = "--setenv" ]; then export "$2=$3"; shift 3; '
            'else shift; fi; done; '
            'shift; '
            'if [ "$1" = "/tmp/urp/dropper" ]; then shift; exec "$source/dropper" "$@"; fi; '
            'exec "$@"',
            ["/bin/sh", "-c", "exit 125"],
            dropper=True,
        )
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertTrue(self.helper_result["attempted"])
        self.assertIsNone(self.helper_result["helperStatus"])
        self.assertEqual(self.helper_result["targetStatus"], 125)
        self.assertEqual(self.helper_result["outcome"], "target-exit")

    def test_bubblewrap_namespace_failure_is_environment_status_before_readiness(self) -> None:
        result, _ = self.run_helper(
            'echo "bwrap: setting up namespace failed" >&2; exit 1',
            ["/bin/true"],
            dropper=True,
        )
        self.assertEqual(result.returncode, 125)
        self.assertIn("environment-unavailable", result.stderr)
        self.assertFalse(self.helper_result["attempted"])
        self.assertEqual(self.helper_result["helperStatus"], 125)
        self.assertIsNone(self.helper_result["targetStatus"])


if __name__ == "__main__":
    unittest.main()
