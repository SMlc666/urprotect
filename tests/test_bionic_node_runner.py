#!/usr/bin/env python3
"""Focused regressions for the host-owned bionic Node.js witness runner."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts/bionic_node_runner.py"
LOCK_PATH = ROOT / "fixtures/real-samples/bionic-node-runtime-lock.json"
MANIFEST_PATH = ROOT / "fixtures/real-samples/manifest.json"

sys.path.insert(0, str(ROOT / "scripts"))

SPEC = importlib.util.spec_from_file_location("bionic_node_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load bionic Node.js runner")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)

from bionic_node_lock import lock_file_sha256  # noqa: E402
from real_sample_schema import (
    classify_isolated_result,
    validate_bionic_node_result,
    validate_isolation_result,
)  # noqa: E402


class BionicNodeRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.execution = self.lock["execution"]
        self.lock_sha = lock_file_sha256(LOCK_PATH)
        self.context = RUNNER.load_lock_context(
            LOCK_PATH,
            MANIFEST_PATH,
            self.lock["baseImage"]["requestedRef"],
            self.lock["sourceArchiveLock"]["version"],
            "a" * 64,
            self.lock["sourceArchiveLock"]["sha256"],
            "outer-path-preserving",
        )
        self.context["runpath"] = self.execution["runpath"]
        self.context["runpathVerified"] = True

    def _protocol(self, status: int = 0) -> dict[str, object]:
        return {
            "schemaVersion": 2,
            "producer": "run-bionic-node-sample.sh",
            "runtime": "bionic",
            "attempted": True,
            "helperStatus": None,
            "targetStatus": status,
            "readinessSeen": True,
            "outcome": "target-exit",
            "containerStatus": status,
            "dockerStatus": status,
            "cleanupContainerStatus": status,
            "timeoutSeconds": self.execution["timeoutSeconds"],
            "outputLimitBytes": self.execution["outputBytes"],
            "outputBytes": 8,
            "memoryBytes": self.execution["memoryBytes"],
            "processLimit": self.execution["processLimit"],
            "lockSha256": self.lock_sha,
            "pathMode": self.execution["outerMode"],
            "pathPolicy": self.execution["pathPolicy"],
            "runpath": self.execution["runpath"],
            "runpathVerified": True,
            "protocolAuthority": "host-generated-after-docker-inspect",
            "cleanupAuthority": "host-generated-after-docker-inspect",
            "allNamedContainersReaped": True,
        }

    def _passed_summary(self) -> dict[str, object]:
        protocol_baseline = self._protocol()
        protocol_outer = self._protocol()
        baseline = {
            **protocol_baseline,
            "protocol": protocol_baseline,
            "actual": "accepted-and-runs",
            "reason": "status=0",
        }
        outer = {
            **protocol_outer,
            "protocol": protocol_outer,
            "actual": "accepted-and-runs",
            "reason": "status=0",
        }
        return {
            "schemaVersion": 2,
            "producer": "run-bionic-node-sample.sh",
            "runtime": "bionic",
            "status": "passed",
            "image": self.lock["baseImage"]["requestedRef"],
            "imageId": self.lock["baseImage"]["id"],
            "loader": self.execution["loader"],
            "lockSha256": self.lock_sha,
            "sourceArtifactSha256": "a" * 64,
            "sourceArchiveSha256": self.lock["sourceArchiveLock"]["sha256"],
            "runtimeArtifactSha256": "a" * 64,
            "pathMode": self.execution["outerMode"],
            "pathPolicy": self.execution["pathPolicy"],
            "runpath": self.execution["runpath"],
            "runpathVerified": True,
            "timeoutSeconds": self.execution["timeoutSeconds"],
            "outputLimitBytes": self.execution["outputBytes"],
            "memoryBytes": self.execution["memoryBytes"],
            "processLimit": self.execution["processLimit"],
            "expectedStatus": self.execution["expectedStatus"],
            "outputBytes": 32,
            "behaviorEquivalent": True,
            "protocolAuthority": "host-generated-after-docker-inspect",
            "cleanupAuthority": "host-generated-after-docker-inspect",
            "containerStatus": 0,
            "containerStatuses": {"setup": 0, "baseline": 0, "outer": 0},
            "cleanupContainerStatuses": {"setup": 0, "baseline": 0, "outer": 0},
            "containerCleanup": {
                "allNamedContainersReaped": True,
                "authority": "host-generated-after-docker-inspect",
            },
            "temporaryImageCleanup": {
                "status": "removed-and-verified",
                "absenceVerified": True,
                "attempts": 1,
                "authority": "host-generated-after-docker-inspect",
                "reason": None,
            },
            "cleanupStatus": "passed",
            "workRootRetained": False,
            "baseline": baseline,
            "outer": outer,
        }

    def test_named_container_identity_is_written_to_worker_cleanup_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "worker.containers"
            with patch.dict("os.environ", {"URP_WORKER_CONTAINER_REGISTRY": str(registry)}):
                RUNNER._register_container_name("urp-bionic-node-test-123")
            self.assertEqual(json.loads(registry.read_text(encoding="utf-8")), {"name": "urp-bionic-node-test-123"})

    def test_transient_image_is_registered_before_commit_and_marked_only_after_verified_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "worker.containers"
            with patch.dict("os.environ", {"URP_WORKER_CONTAINER_REGISTRY": str(registry)}):
                RUNNER._register_image_name("urprotect-bionic-node:test-image")
                RUNNER._mark_worker_resource_removed("urprotect-bionic-node:test-image", "image")
            rows = [json.loads(line) for line in registry.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0], {"kind": "image", "name": "urprotect-bionic-node:test-image"})
            self.assertEqual(rows[1], {"kind": "image", "name": "urprotect-bionic-node:test-image", "state": "removed"})

    def test_locked_argv_status_limits_and_outer_substitution_are_used(self) -> None:
        context = RUNNER.load_lock_context(
            LOCK_PATH,
            MANIFEST_PATH,
            self.lock["baseImage"]["requestedRef"],
            self.lock["sourceArchiveLock"]["version"],
            "a" * 64,
            self.lock["sourceArchiveLock"]["sha256"],
            self.execution["outerMode"],
        )
        self.assertEqual(context["argv"], self.execution["argv"])
        self.assertEqual(self.execution["expectedStatus"], 0)
        self.assertEqual(self.execution["timeoutSeconds"], 30)
        self.assertEqual(self.execution["outputBytes"], 1_048_576)
        self.assertEqual(self.execution["memoryBytes"], 536_870_912)
        self.assertEqual(self.execution["processLimit"], 32)
        self.assertEqual(
            RUNNER.substitute_outer_argv(context["argv"], "/usr/local/bin/urprotect-packed"),
            ["/usr/local/bin/urprotect-packed", *context["argv"][1:]],
        )
        self.assertEqual(RUNNER.substitute_outer_argv(["/node", "--version", "ARG"], "/wrapper"), ["/wrapper", "--version", "ARG"])

    def test_wrapper_staging_skips_same_file_copy_and_preserves_packed_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wrapper_root = Path(directory) / "wrapper"
            wrapper_root.mkdir()
            wrapper = wrapper_root / "urprotect-packed"
            wrapper.write_bytes(b"packed-wrapper")
            wrapper.chmod(0o555)
            before_hash = RUNNER.sha256_file(wrapper)

            with patch.object(RUNNER.shutil, "copyfile", side_effect=AssertionError("self-copy")) as copyfile:
                staged = RUNNER._stage_wrapper(wrapper, wrapper_root / "urprotect-packed")

            copyfile.assert_not_called()
            self.assertEqual(staged, wrapper)
            self.assertEqual(RUNNER.sha256_file(staged), before_hash)
            self.assertEqual(staged.read_bytes(), b"packed-wrapper")
            self.assertEqual([path.name for path in wrapper_root.iterdir()], ["urprotect-packed"])

    def test_wrapper_staging_reuses_existing_hard_link_without_copying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wrapper_root = Path(directory)
            wrapper = wrapper_root / "source-wrapper"
            destination = wrapper_root / "hard-link-wrapper"
            wrapper.write_bytes(b"packed-wrapper")
            try:
                os.link(wrapper, destination)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"hard links are unsupported: {error}")

            self.assertTrue(os.path.samefile(wrapper, destination))
            with patch.object(RUNNER.shutil, "copyfile", side_effect=AssertionError("self-copy")) as copyfile:
                staged = RUNNER._stage_wrapper(wrapper, destination)

            copyfile.assert_not_called()
            self.assertEqual(staged, destination)
            self.assertEqual(staged.read_bytes(), b"packed-wrapper")

    def test_wrapper_staging_copies_to_a_different_regular_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wrapper_root = Path(directory)
            wrapper = wrapper_root / "source-wrapper"
            destination = wrapper_root / "destination-wrapper"
            wrapper.write_bytes(b"packed-wrapper")
            destination.write_bytes(b"old-wrapper")

            staged = RUNNER._stage_wrapper(wrapper, destination)

            self.assertEqual(staged, destination)
            self.assertEqual(wrapper.read_bytes(), b"packed-wrapper")
            self.assertEqual(destination.read_bytes(), b"packed-wrapper")

    def test_wrapper_staging_rejects_symlink_and_non_regular_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wrapper_root = Path(directory)
            wrapper = wrapper_root / "source-wrapper"
            wrapper.write_bytes(b"packed-wrapper")
            directory_destination = wrapper_root / "destination-directory"
            directory_destination.mkdir()
            symlink_destination = wrapper_root / "destination-symlink"
            symlink_destination.symlink_to(wrapper)

            destinations = (
                (directory_destination, "packed wrapper destination must be a regular file"),
                (symlink_destination, "packed wrapper destination must not be a symlink"),
            )
            with patch.object(RUNNER.shutil, "copyfile", side_effect=AssertionError("copy should not be attempted")) as copyfile:
                for destination, message in destinations:
                    with self.subTest(destination=destination.name):
                        with self.assertRaisesRegex(RUNNER.RunnerError, message):
                            RUNNER._stage_wrapper(wrapper, destination)

            copyfile.assert_not_called()

    def test_runpath_verification_requires_exact_absolute_runpath(self) -> None:
        expected = self.execution["runpath"]
        self.assertEqual(
            RUNNER.verify_absolute_runpath(f"0x00000001 (RUNPATH) Library runpath: [{expected}]", expected),
            expected,
        )
        invalid = (
            f"0x00000001 (RUNPATH) Library runpath: [$ORIGIN/../lib]",
            "0x00000001 (RUNPATH) Library runpath: [relative/lib]",
            "0x00000001 (RUNPATH) Library runpath: [/other/lib]",
            f"0x00000001 (RPATH) Library rpath: [{expected}]",
            f"0x00000001 (RUNPATH) Library runpath: [{expected}:$ORIGIN]",
        )
        for output in invalid:
            with self.subTest(output=output), self.assertRaises(RUNNER.RunnerError):
                RUNNER.verify_absolute_runpath(output, expected)

    def test_host_watchdog_bounds_timeout_and_process_group(self) -> None:
        result = RUNNER.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout_seconds=0.15,
            output_limit=1024,
        )
        self.assertTrue(result.timed_out)
        self.assertIsNotNone(result.status)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024)

    def test_host_pipe_capture_stops_output_above_one_mib(self) -> None:
        limit = 1_048_576
        result = RUNNER.run_bounded(
            [sys.executable, "-c", "import os,time; b=b'x'*65536\nwhile True: os.write(1,b)"],
            timeout_seconds=5,
            output_limit=limit,
        )
        self.assertTrue(result.output_limited)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), limit)

    def test_docker_and_inspected_status_must_agree_even_with_stale_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stale = Path(directory) / "outer.status"
            stale.write_text("0\n", encoding="utf-8")
            observed, reason = RUNNER.validate_target_completion(0, 125, 0)
            self.assertIsNone(observed)
            self.assertIsNotNone(reason)
            summary = self._passed_summary()
            summary["containerStatus"] = 125
            summary["containerStatuses"]["outer"] = 125  # type: ignore[index]
            summary["outer"]["containerStatus"] = 125  # type: ignore[index]
            summary["outer"]["protocol"]["containerStatus"] = 125  # type: ignore[index]
            errors = validate_bionic_node_result(summary, expected_lock_sha256=self.lock_sha, expected_runpath=self.execution["runpath"])
            self.assertTrue(any("accepted status" in error or "outer containerStatus" in error for error in errors), errors)
            self.assertEqual(stale.read_text(encoding="utf-8"), "0\n")

    def test_target_cannot_write_authoritative_artifact_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_script = Path(directory) / "execute-target.sh"
            RUNNER._prepare_target_script(target_script, self.execution)
            baseline = RUNNER.build_target_container_args(
                "target-name",
                "temporary-image",
                self.execution,
                [self.execution["loader"], self.execution["artifactPath"], "--version"],
                exec_script=target_script,
            )
            self.assertIn("--read-only", baseline)
            self.assertIn("local", baseline)
            self.assertIn("max-size=1048576", baseline)
            self.assertNotIn("/artifacts", " ".join(baseline))
            self.assertTrue(all(value.endswith(",readonly") for value in baseline if value.startswith("type=bind")))
            wrapper = Path(directory) / "urprotect-packed"
            wrapper.write_bytes(b"wrapper")
            wrapper.chmod(0o555)
            outer = RUNNER.build_target_container_args(
                "outer-name",
                "temporary-image",
                self.execution,
                ["/usr/local/bin/urprotect-packed", "--version"],
                exec_script=target_script,
                wrapper_file=wrapper,
            )
            self.assertIn("--read-only", outer)
            mounts = [value for value in outer if value.startswith("type=bind")]
            self.assertEqual(len(mounts), 2)
            self.assertTrue(all(value.endswith(",readonly") for value in mounts))
            self.assertNotIn("/artifacts", " ".join(outer))
            execution_script = target_script.read_text(encoding="utf-8")
            self.assertIn("env -i", execution_script)
            self.assertIn('"$@"', execution_script)
            setup = Path(directory) / "setup.sh"
            RUNNER._prepare_setup_script(setup, self.execution, "a" * 64)
            setup_text = setup.read_text(encoding="utf-8")
            self.assertNotIn("/artifacts", setup_text)
            self.assertNotIn("bionic-ready", setup_text)
            self.assertNotIn("/tmp/urp-packages", setup_text)
            self.assertIn("dpkg-query -W -f='${Package}", setup_text)

    def test_container_cleanup_proves_normal_already_exited_container_is_removed(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, *, timeout_seconds, output_limit, deadline=None):
            del timeout_seconds, output_limit, deadline
            command = list(command)
            calls.append(command)
            if command[1] == "inspect" and len([item for item in calls if item[1] == "inspect"]) == 1:
                return RUNNER.CommandResult(0, b'{"Status":"exited","ExitCode":0}', b"")
            if command[1] == "inspect":
                return RUNNER.CommandResult(1, b"", b"Error: No such container: named-container\n")
            return RUNNER.CommandResult(0, b"", b"")

        with patch.object(RUNNER, "run_bounded", side_effect=fake_run):
            errors, status = RUNNER._reap_container(["docker"], "named-container", budget_seconds=3)
        self.assertEqual(errors, [])
        self.assertEqual(status, 0)
        self.assertEqual([command[1] for command in calls], ["inspect", "rm", "inspect"])
        self.assertEqual(calls[1][2], "--force")

    def test_container_cleanup_rejects_unverified_status_one_and_running_container(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, *, timeout_seconds, output_limit, deadline=None):
            del timeout_seconds, output_limit, deadline
            command = list(command)
            calls.append(command)
            if command[1] == "inspect":
                return RUNNER.CommandResult(0, b'{"Status":"running"}', b"")
            if command[1] in {"stop", "wait", "rm"}:
                return RUNNER.CommandResult(1, b"", b"permission denied\n")
            raise AssertionError(command)

        with patch.object(RUNNER, "run_bounded", side_effect=fake_run):
            errors, status = RUNNER._reap_container(["docker"], "named-container", budget_seconds=3)
        self.assertTrue(errors)
        self.assertIsNone(status)
        self.assertIn("status 1", " ".join(errors))
        self.assertEqual([command[1] for command in calls], ["inspect", "stop", "wait", "inspect", "rm", "inspect"])

    def test_transient_image_cleanup_retries_and_requires_verified_absence(self) -> None:
        calls: list[list[str]] = []

        def fake_present(command, *, timeout_seconds, output_limit, deadline=None):
            del timeout_seconds, output_limit, deadline
            command = list(command)
            calls.append(command)
            if command[1:3] == ["image", "rm"]:
                return RUNNER.CommandResult(1, b"", b"image removal failed")
            if command[1:3] == ["image", "inspect"]:
                return RUNNER.CommandResult(0, b"{}", b"")
            raise AssertionError(command)

        with patch.object(RUNNER, "run_bounded", side_effect=fake_present):
            failed = RUNNER._remove_transient_image(["docker"], "temporary-image")
        self.assertEqual(failed["status"], "cleanup-failure")
        self.assertFalse(failed["absenceVerified"])
        self.assertEqual(failed["attempts"], 2)
        self.assertEqual([command[1:3] for command in calls], [["image", "rm"], ["image", "inspect"]] * 2)

        attempts = [0]

        def fake_retry(command, *, timeout_seconds, output_limit, deadline=None):
            del timeout_seconds, output_limit, deadline
            if command[1:3] == ["image", "rm"]:
                attempts[0] += 1
                return RUNNER.CommandResult(1 if attempts[0] == 1 else 0, b"", b"retry")
            if command[1:3] == ["image", "inspect"]:
                if attempts[0] == 1:
                    return RUNNER.CommandResult(0, b"{}", b"")
                return RUNNER.CommandResult(1, b"", b"Error: No such image: temporary-image")
            raise AssertionError(command)

        with patch.object(RUNNER, "run_bounded", side_effect=fake_retry):
            cleaned = RUNNER._remove_transient_image(["docker"], "temporary-image")
        self.assertEqual(cleaned["status"], "removed-and-verified")
        self.assertTrue(cleaned["absenceVerified"])
        self.assertEqual(cleaned["attempts"], 2)

    def test_transient_image_status_one_succeeds_only_after_absence_inspect(self) -> None:
        def fake_absent(command, *, timeout_seconds, output_limit, deadline=None):
            del timeout_seconds, output_limit, deadline
            if command[1:3] in (["image", "rm"], ["image", "inspect"]):
                return RUNNER.CommandResult(1, b"", b"Error: No such image: temporary-image")
            raise AssertionError(command)

        with patch.object(RUNNER, "run_bounded", side_effect=fake_absent):
            result = RUNNER._remove_transient_image(["docker"], "temporary-image")
        self.assertTrue(result["absenceVerified"])
        self.assertEqual(result["status"], "removed-and-verified")

    def test_cache_rejects_symlinked_sha256_and_digest_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cache"
            outside = Path(directory) / "outside"
            outside.mkdir()
            root.mkdir()
            (root / "sha256").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RUNNER.RunnerError, "symlink.*sha256"):
                RUNNER._ensure_cache_directory(root, "sha256", "a" * 64)
            self.assertFalse((outside / ("a" * 64)).exists())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cache"
            outside = Path(directory) / "outside"
            outside.mkdir()
            digest_parent = root / "sha256"
            digest_parent.mkdir(parents=True)
            (digest_parent / ("b" * 64)).symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RUNNER.RunnerError, "directory must not be a symlink"):
                RUNNER._ensure_cache_directory(root, "sha256", "b" * 64)
            self.assertFalse(list(outside.iterdir()))

    def test_work_root_is_retained_until_container_and_image_absence_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory) / "work"
            work_root.mkdir()
            marker = work_root / "inspect-me"
            marker.write_text("retained", encoding="utf-8")
            retained = RUNNER._cleanup_work_root(
                work_root,
                containers_absent=True,
                image_absent=False,
                cleanup_error="image remains",
            )
            self.assertTrue(retained)
            self.assertTrue(marker.is_file())
            removed_retained = RUNNER._cleanup_work_root(
                work_root,
                containers_absent=True,
                image_absent=True,
                cleanup_error=None,
            )
            self.assertFalse(removed_retained)
            self.assertFalse(work_root.exists())

    def test_target_container_create_output_limit_is_helper_126_runtime_failure(self) -> None:
        context = {"execution": self.execution, "lockSha256": self.lock_sha, "runpath": self.execution["runpath"]}
        created = RUNNER.CommandResult(
            status=1,
            stdout=b"",
            stderr=b"docker create output exceeded limit",
            output_limited=True,
        )
        with (
            patch.object(RUNNER, "_create_container", return_value=created),
            patch.object(RUNNER, "_start_attached") as start_attached,
        ):
            result, stdout, stderr = RUNNER._run_one_target(
                docker=["docker"],
                name="named-container",
                create_args=["docker", "create"],
                budget=RUNNER.OutputBudget(self.execution["outputBytes"]),
                deadline=RUNNER.time.monotonic() + 5,
                context=context,
                setup_ready=True,
            )
        start_attached.assert_not_called()
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        self.assertEqual(result["helperStatus"], RUNNER.OUTPUT_LIMIT_STATUS)
        self.assertEqual(result["outcome"], "helper-output-limit")
        self.assertEqual(result["actual"], "runtime-failure")
        self.assertEqual(result["attempted"], False)
        self.assertEqual(validate_isolation_result(result["protocol"]), [])

    def test_target_status_124_and_125_are_runtime_results_not_helper_sentinels(self) -> None:
        for status in (124, 125):
            with self.subTest(status=status):
                self.assertEqual(
                    classify_isolated_result(attempted=True, helper_status=None, target_status=status, expected=0),
                    "runtime-failure",
                )
        self.assertEqual(
            classify_isolated_result(attempted=False, helper_status=125, target_status=None, expected=0),
            "environment-unavailable",
        )
        self.assertEqual(
            classify_isolated_result(attempted=True, helper_status=124, target_status=None, expected=0),
            "runtime-failure",
        )

    def test_output_limit_protocol_is_runtime_failure_and_keeps_target_helper_status_separate(self) -> None:
        protocol = self._protocol()
        protocol.update({
            "attempted": True,
            "helperStatus": 126,
            "targetStatus": None,
            "readinessSeen": True,
            "outcome": "helper-output-limit",
            "containerStatus": None,
            "dockerStatus": None,
            "outputBytes": self.execution["outputBytes"],
        })
        self.assertEqual(validate_isolation_result(protocol), [])
        self.assertEqual(
            classify_isolated_result(attempted=True, helper_status=126, target_status=None, expected=0),
            "runtime-failure",
        )
        for target_status in (124, 125):
            protocol = self._protocol(target_status)
            self.assertEqual(validate_isolation_result(protocol), [])
            self.assertEqual(
                classify_isolated_result(attempted=True, helper_status=None, target_status=target_status, expected=0),
                "runtime-failure",
            )

    def test_bionic_summary_requires_inspected_status_and_host_authority(self) -> None:
        summary = self._passed_summary()
        self.assertEqual(validate_bionic_node_result(summary, expected_lock_sha256=self.lock_sha, expected_runpath=self.execution["runpath"]), [])
        summary["protocolAuthority"] = "target-writable-marker"
        errors = validate_bionic_node_result(summary, expected_lock_sha256=self.lock_sha, expected_runpath=self.execution["runpath"])
        self.assertTrue(any("host-generated" in error for error in errors), errors)

    def test_bionic_summary_identity_is_bound_to_the_reviewed_lock(self) -> None:
        for field, value in (
            ("image", "termux/termux-docker:latest"),
            ("imageId", "sha256:" + "0" * 64),
            ("loader", "/system/bin/other-linker"),
        ):
            with self.subTest(field=field):
                summary = self._passed_summary()
                summary[field] = value
                errors = validate_bionic_node_result(
                    summary,
                    expected_lock_sha256=self.lock_sha,
                    expected_runpath=self.execution["runpath"],
                    expected_image=self.lock["baseImage"]["requestedRef"],
                    expected_image_id=self.lock["baseImage"]["id"],
                    expected_loader=self.execution["loader"],
                )
                self.assertTrue(any(field in error for error in errors), errors)

    def test_helper_sentinels_keep_target_and_container_null_after_cleanup(self) -> None:
        for helper_status, outcome, cleanup_status in (
            (124, "helper-timeout", 124),
            (126, "helper-output-limit", 126),
            (125, "helper-environment", 125),
        ):
            with self.subTest(helper_status=helper_status):
                protocol = self._protocol()
                protocol.update({
                    "attempted": True,
                    "helperStatus": helper_status,
                    "targetStatus": None,
                    "containerStatus": None,
                    "cleanupContainerStatus": cleanup_status,
                    "outcome": outcome,
                })
                self.assertEqual(validate_isolation_result(protocol), [])
                self.assertIsNone(protocol["targetStatus"])
                self.assertIsNone(protocol["containerStatus"])
                self.assertEqual(protocol["cleanupContainerStatus"], cleanup_status)

    def test_helper_and_target_status_125_are_not_interchangeable(self) -> None:
        helper_failure = self._protocol()
        helper_failure.update({
            "attempted": True,
            "helperStatus": 125,
            "targetStatus": None,
            "containerStatus": 1,
            "dockerStatus": 1,
            "outcome": "helper-environment",
        })
        self.assertTrue(any("containerStatus null" in error for error in validate_isolation_result(helper_failure)))

        target_exit = self._protocol(125)
        self.assertEqual(validate_isolation_result(target_exit), [])
        self.assertEqual(
            classify_isolated_result(attempted=True, helper_status=None, target_status=125, expected=0),
            "runtime-failure",
        )

        output_helper = self._protocol()
        output_helper.update({
            "attempted": True,
            "helperStatus": 126,
            "targetStatus": None,
            "containerStatus": 1,
            "dockerStatus": None,
            "outcome": "helper-output-limit",
        })
        self.assertTrue(any("containerStatus null" in error for error in validate_isolation_result(output_helper)))


if __name__ == "__main__":
    unittest.main()
