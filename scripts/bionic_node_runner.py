#!/usr/bin/env python3
"""Run the locked Termux Node.js witness with host-owned bounded evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
LOCK_DEFAULT = REPO_ROOT / "fixtures/real-samples/bionic-node-runtime-lock.json"
MANIFEST_DEFAULT = REPO_ROOT / "fixtures/real-samples/manifest.json"
OUTPUT_LIMIT_STATUS = 126
PROTOCOL_AUTHORITY = "host-generated-after-docker-inspect"
CLEANUP_AUTHORITY = "host-generated-after-docker-inspect"


class RunnerError(Exception):
    def __init__(self, message: str, category: str = "product") -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class CommandResult:
    status: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_limited: bool = False
    error: str | None = None


@dataclass
class OutputBudget:
    limit: int
    used: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def add(self, result: CommandResult) -> None:
        self.used += len(result.stdout) + len(result.stderr)


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
    # The group leader may have exited while a descendant still holds either
    # captured pipe; signal the process group again before returning.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run_bounded(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    output_limit: int,
    deadline: float | None = None,
) -> CommandResult:
    """Run a process group with a hard combined stdout/stderr memory bound."""
    if timeout_seconds <= 0 or output_limit < 0:
        return CommandResult(None, b"", b"", timed_out=timeout_seconds <= 0, error="invalid process budget")
    started = time.monotonic()
    command_deadline = started + timeout_seconds
    if deadline is not None:
        command_deadline = min(command_deadline, deadline)
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as error:
        return CommandResult(None, b"", b"", error=str(error))

    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    streams = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    timed_out = False
    output_limited = False
    total = 0
    try:
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= command_deadline:
                timed_out = True
                _terminate_group(process)
                break
            events = selector.select(timeout=min(0.05, max(0.0, command_deadline - time.monotonic())))
            for key, _ in events:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), min(65536, output_limit - total + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                streams[stream.fileno()].extend(chunk)
                total += len(chunk)
                if total > output_limit:
                    output_limited = True
                    _terminate_group(process)
                    break
            if output_limited:
                break
            if process.poll() is not None and not events and selector.get_map():
                # A descendant retaining a pipe cannot keep the host watchdog alive.
                if time.monotonic() + 0.05 >= command_deadline:
                    timed_out = True
                    _terminate_group(process)
                    break
        if process.poll() is None:
            _terminate_group(process)
        status = process.wait()
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            _terminate_group(process)

    stdout = bytes(streams[stdout_fd])
    stderr = bytes(streams[stderr_fd])
    if len(stdout) + len(stderr) > output_limit:
        stderr = stderr[: max(0, output_limit - len(stdout))]
        stdout = stdout[:output_limit]
    return CommandResult(status, stdout, stderr, timed_out, output_limited)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode_locked_argv(value: Any, artifact_path: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item or any(char in item for char in "\x00\r\n") for item in value)
    ):
        raise RunnerError("locked execution.argv must be a non-empty control-free string array")
    if value[0] != artifact_path:
        raise RunnerError("locked execution.argv[0] must equal the locked artifactPath")
    return list(value)


def substitute_outer_argv(argv: Sequence[str], wrapper_path: str) -> list[str]:
    if not argv or not wrapper_path.startswith("/"):
        raise RunnerError("outer argv substitution requires a locked argv and absolute wrapper path")
    return [wrapper_path, *argv[1:]]


def verify_absolute_runpath(dynamic_output: str, expected_runpath: str) -> str:
    if not isinstance(expected_runpath, str) or not expected_runpath.startswith("/"):
        raise RunnerError("locked Node.js RUNPATH must be absolute")
    rows = re.findall(r"\((RPATH|RUNPATH)\).*?\[([^\]]*)\]", dynamic_output)
    if len(rows) != 1 or rows[0][0] != "RUNPATH":
        raise RunnerError("Node.js ELF must declare exactly one DT_RUNPATH and no DT_RPATH")
    runpath = rows[0][1]
    components = runpath.split(":")
    if (
        len(components) != 1
        or components[0] != expected_runpath
        or "$ORIGIN" in runpath
        or "${ORIGIN}" in runpath
        or not PurePosixPath(runpath).is_absolute()
    ):
        raise RunnerError("Node.js ELF DT_RUNPATH differs from the reviewed absolute path policy")
    return runpath


def verify_runpath(path: Path, expected_runpath: str, *, output_limit: int) -> str:
    result = run_bounded(["readelf", "-dW", str(path)], timeout_seconds=10, output_limit=output_limit)
    if result.error or result.timed_out or result.output_limited or result.status != 0:
        raise RunnerError("readelf could not verify the Node.js dynamic path metadata", "environment" if result.error else "product")
    text = (result.stdout + result.stderr).decode("utf-8", errors="strict")
    return verify_absolute_runpath(text, expected_runpath)


def _project(manifest: dict[str, Any]) -> dict[str, Any]:
    projects = manifest.get("corpus", {}).get("projects")
    if not isinstance(projects, list):
        raise RunnerError("real-sample manifest has no corpus.projects array")
    matches = [item for item in projects if isinstance(item, dict) and item.get("projectId") == "nodejs"]
    if len(matches) != 1:
        raise RunnerError("real-sample manifest must contain exactly one Node.js identity")
    return matches[0]


def load_lock_context(lock_path: Path, manifest_path: Path, image: str, version: str, artifact_sha: str, archive_sha: str, outer_mode: str) -> dict[str, Any]:
    from bionic_node_lock import lock_file_sha256, validate_lock_document

    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"could not read locked bionic inputs: {error}") from error
    errors = validate_lock_document(lock, manifest=manifest)
    if errors:
        raise RunnerError("bionic runtime lock validation failed: " + "; ".join(errors))
    execution = lock["execution"]
    project = _project(manifest)
    provenance = project.get("provenance", {})
    artifact_relative = provenance.get("artifactPath") if isinstance(provenance, dict) else None
    artifact_path = execution["artifactPath"]
    if not isinstance(artifact_relative, str) or "/" + artifact_relative.lstrip("/") != artifact_path:
        raise RunnerError("Node.js manifest artifactPath does not match the reviewed runtime lock")
    source = lock["sourceArchiveLock"]
    if image != lock["baseImage"]["requestedRef"]:
        raise RunnerError("bionic image argument does not match the reviewed runtime lock")
    if version != source["version"] or archive_sha != source["sha256"]:
        raise RunnerError("Node.js version/archive digest arguments do not match the reviewed runtime lock")
    node_package = next(row for row in lock["packages"] if row["name"] == "nodejs")
    if node_package["sha256"] != archive_sha or node_package["sizeBytes"] != source["sizeBytes"]:
        raise RunnerError("Node.js package row differs from sourceArchiveLock")
    if outer_mode != execution["outerMode"] or outer_mode != "outer-path-preserving":
        raise RunnerError("requested bionic execution mode differs from the locked outer-path-preserving policy")
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha):
        raise RunnerError("source artifact digest is malformed")

    baseline_policy = project.get("executionPolicy", {}).get("baseline", {})
    outer_policy = project.get("executionPolicy", {}).get("outerWrapper", {})
    for layer, policy in (("baseline", baseline_policy), ("outerWrapper", outer_policy)):
        if not isinstance(policy, dict) or policy.get("expectedStatus") != execution["expectedStatus"]:
            raise RunnerError(f"manifest {layer} expectedStatus differs from the runtime lock")
    if outer_policy.get("mode") != execution["outerMode"]:
        raise RunnerError("manifest outerWrapper mode differs from the runtime lock")
    argv = decode_locked_argv(execution.get("argv"), artifact_path)
    expected_policy = execution.get("runpath")
    if not isinstance(expected_policy, str):
        raise RunnerError("runtime lock is missing the exact absolute RUNPATH")
    return {
        "lock": lock,
        "manifest": manifest,
        "project": project,
        "execution": execution,
        "argv": argv,
        "artifactPath": artifact_path,
        "expectedRunpath": expected_policy,
        "lockSha256": lock_file_sha256(lock_path),
        "source": source,
    }


def _metadata_files(context: dict[str, Any], root: Path) -> None:
    lock = context["lock"]
    base_rows = sorted(lock["basePackageInventory"]["packages"], key=lambda row: (row["name"], row["version"], row["architecture"], row["status"]))
    (root / "base.tsv").write_text(
        "".join("\t".join((row["name"], row["version"], row["architecture"], row["status"])) + "\n" for row in base_rows),
        encoding="utf-8",
    )
    package_rows = sorted(lock["packages"], key=lambda row: row["name"])
    (root / "packages.tsv").write_text(
        "".join(
            "\t".join((row["name"], row["version"], row["architecture"], row["localFilename"], row["sha256"], str(row["sizeBytes"]), row["url"])) + "\n"
            for row in package_rows
        ),
        encoding="utf-8",
    )


def _checked_command(
    command: Sequence[str],
    *,
    budget: OutputBudget,
    timeout_seconds: float,
    deadline: float | None = None,
) -> CommandResult:
    if budget.remaining <= 0:
        return CommandResult(None, b"", b"", output_limited=True)
    result = run_bounded(
        command,
        timeout_seconds=timeout_seconds,
        output_limit=budget.remaining,
        deadline=deadline,
    )
    budget.add(result)
    return result


def _docker_identity(docker: list[str], budget: OutputBudget) -> tuple[str, dict[str, Any]]:
    version = _checked_command([*docker, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], budget=budget, timeout_seconds=10)
    if version.error or version.status != 0 or version.timed_out or version.output_limited:
        raise RunnerError("Docker server is unavailable for the locked bionic witness", "environment")
    platform = version.stdout.decode("utf-8", errors="replace").strip()
    if platform != "linux/arm64":
        raise RunnerError(f"bionic Node.js requires a native Linux/arm64 Docker server; found {platform!r}", "environment")
    return platform, {}


def _docker_image(docker: list[str], image: str, image_id: str, image_ref: str, budget: OutputBudget) -> None:
    inspected = _checked_command([*docker, "image", "inspect", "--format", "{{json .}}", image], budget=budget, timeout_seconds=10)
    if inspected.status != 0:
        pulled = _checked_command(
            [*docker, "pull", "--quiet", image],
            budget=budget,
            timeout_seconds=180,
        )
        if pulled.error or pulled.status != 0 or pulled.timed_out or pulled.output_limited:
            raise RunnerError("locked Termux image is unavailable from the Docker server", "environment")
        inspected = _checked_command([*docker, "image", "inspect", "--format", "{{json .}}", image], budget=budget, timeout_seconds=10)
    if inspected.error or inspected.status != 0 or inspected.timed_out or inspected.output_limited:
        raise RunnerError("Docker could not inspect the locked Termux image", "environment")
    try:
        facts = json.loads(inspected.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"Docker image inspection returned malformed JSON: {error}", "environment") from error
    if (
        facts.get("Id") != image_id
        or facts.get("Os") != "linux"
        or facts.get("Architecture") not in {"arm64", "aarch64"}
        or image_ref not in facts.get("RepoDigests", [])
    ):
        raise RunnerError("Docker image identity differs from the reviewed Termux runtime lock", "environment")


def _container_state(docker: list[str], name: str, *, timeout_seconds: float, deadline: float | None = None) -> tuple[dict[str, Any] | None, CommandResult]:
    result = run_bounded(
        [*docker, "inspect", "--format", "{{json .State}}", name],
        timeout_seconds=timeout_seconds,
        output_limit=64 * 1024,
        deadline=deadline,
    )
    if result.error or result.status != 0 or result.timed_out or result.output_limited:
        return None, result
    try:
        state = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None, result
    return (state if isinstance(state, dict) else None), result


def _remaining(deadline: float, maximum: float) -> float:
    value = min(maximum, deadline - time.monotonic())
    if value <= 0:
        raise RunnerError("locked 30-second container execution deadline expired", "timeout")
    return value


def _container_common_args(name: str, execution: dict[str, Any], *, read_only: bool) -> list[str]:
    args = [
        "--name", name,
        "--platform", "linux/arm64",
        "--network", "none",
        "--memory", str(execution["memoryBytes"]),
        "--pids-limit", str(execution["processLimit"]),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--log-driver", "local",
        "--log-opt", "compress=false",
        "--log-opt", f"max-size={execution['outputBytes']}",
        "--log-opt", "max-file=1",
        "--user", "1000:1000",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
    ]
    if read_only:
        args.append("--read-only")
    return args


def _prepare_target_script(path: Path, execution: dict[str, Any]) -> None:
    environment = execution.get("environment")
    expected_keys = {"PATH", "HOME", "LD_LIBRARY_PATH"}
    if not isinstance(environment, dict) or set(environment) != expected_keys:
        raise RunnerError("locked execution.environment must declare exactly PATH, HOME, and LD_LIBRARY_PATH")
    assignments = " ".join(
        f"{key}={shlex.quote(environment[key])}"
        for key in ("PATH", "HOME", "LD_LIBRARY_PATH")
    )
    path.write_text(
        "#!/data/data/com.termux/files/usr/bin/sh\nset -eu\n"
        f"exec env -i {assignments} \"$@\"\n",
        encoding="utf-8",
    )
    path.chmod(0o444)


def build_target_container_args(
    name: str,
    image: str,
    execution: dict[str, Any],
    arguments: Sequence[str],
    *,
    exec_script: Path,
    wrapper_file: Path | None = None,
) -> list[str]:
    """Build a read-only target container with no evidence-root bind mounts."""
    if not arguments or any(not isinstance(item, str) or not item for item in arguments):
        raise RunnerError("target container command must be a non-empty argument array")
    if exec_script.is_symlink() or not exec_script.is_file():
        raise RunnerError("target environment launcher must be a host-owned regular file")
    values = _container_common_args(name, execution, read_only=True)
    values.extend(("--mount", f"type=bind,src={exec_script.resolve()},dst=/input/execute-target.sh,readonly"))
    if wrapper_file is not None:
        if wrapper_file.is_symlink() or not wrapper_file.is_file():
            raise RunnerError("packed wrapper mount must be a regular host-owned file")
        values.extend(("--mount", f"type=bind,src={wrapper_file.resolve()},dst=/usr/local/bin/urprotect-packed,readonly"))
    values.extend(("--entrypoint", execution["shell"], image, "/input/execute-target.sh", *arguments))
    return values


def _create_container(docker: list[str], args: list[str], *, budget: OutputBudget, deadline: float) -> CommandResult:
    return _checked_command([*docker, "create", *args], budget=budget, timeout_seconds=_remaining(deadline, 5), deadline=deadline)


def _start_attached(docker: list[str], name: str, *, budget: OutputBudget, deadline: float, timeout_seconds: int) -> CommandResult:
    return _checked_command(
        [*docker, "start", "--attach", name],
        budget=budget,
        timeout_seconds=_remaining(deadline, timeout_seconds),
        deadline=deadline,
    )


def _docker_resource_absent(result: CommandResult, *, kind: str) -> bool:
    """Return whether Docker explicitly reported that a resource is absent."""
    if result.status in (None, 0):
        return False
    detail = (result.stderr + result.stdout).decode("utf-8", errors="replace").lower()
    if kind == "container":
        return "no such container" in detail or "container not found" in detail
    return "no such image" in detail or "image not found" in detail


def _remove_transient_image(
    docker: list[str],
    name: str,
    *,
    budget_seconds: float = 6.0,
) -> dict[str, Any]:
    """Retry bounded image removal and require an independent absence inspection."""
    deadline = time.monotonic() + budget_seconds
    attempts = 0
    detail = "temporary runtime image remained present after removal"
    while attempts < 2:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            detail = "temporary runtime image cleanup budget expired"
            break
        removal = run_bounded(
            [*docker, "image", "rm", "--force", name],
            timeout_seconds=min(2.0, remaining),
            output_limit=4096,
            deadline=deadline,
        )
        attempts += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            detail = "temporary runtime image cleanup budget expired before absence inspection"
            break
        inspected = run_bounded(
            [*docker, "image", "inspect", "--format", "{{json .}}", name],
            timeout_seconds=min(2.0, remaining),
            output_limit=4096,
            deadline=deadline,
        )
        if _docker_resource_absent(inspected, kind="image"):
            return {
                "status": "removed-and-verified",
                "absenceVerified": True,
                "attempts": attempts,
                "authority": CLEANUP_AUTHORITY,
                "reason": None,
            }
        if removal.error or removal.timed_out or removal.status not in (0, 1):
            detail = "temporary runtime image removal command failed and absence was not verified"
        elif inspected.error or inspected.timed_out or inspected.status != 0:
            detail = "temporary runtime image inspection failed; absence was not verified"
        else:
            detail = "temporary runtime image remained present after removal"
    return {
        "status": "cleanup-failure",
        "absenceVerified": False,
        "attempts": attempts,
        "authority": CLEANUP_AUTHORITY,
        "reason": detail,
    }


def _ensure_cache_directory(cache_root: Path, *components: str) -> tuple[Path, Path]:
    """Create cache directories without following symlinks beneath the cache root."""
    if cache_root.is_symlink():
        raise RunnerError("bionic package cache root must not be a symlink")
    cache_root.mkdir(parents=True, exist_ok=True)
    resolved_root = cache_root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise RunnerError("bionic package cache root must resolve to a directory")
    current = cache_root
    for component in components:
        if not component or component in {".", ".."} or "/" in component or "\\" in component:
            raise RunnerError("bionic package cache path component is unsafe")
        current = current / component
        try:
            current.lstat()
        except FileNotFoundError:
            current.mkdir()
        except OSError as error:
            raise RunnerError(f"could not inspect bionic package cache directory: {error}", "environment") from error
        if current.is_symlink():
            raise RunnerError(f"bionic package cache directory must not be a symlink: {current}")
        if not current.is_dir():
            raise RunnerError(f"bionic package cache path is not a directory: {current}")
        resolved = current.resolve(strict=True)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as error:
            raise RunnerError("bionic package cache path resolves outside the declared cache root") from error
    return current, resolved_root


def _checked_cache_file(cache_root: Path, cache_file: Path, resolved_root: Path) -> None:
    try:
        cache_file.absolute().relative_to(cache_root.absolute())
    except ValueError as error:
        raise RunnerError("locked package cache file is outside the declared cache root") from error
    if cache_file.is_symlink() or (cache_file.exists() and not cache_file.is_file()):
        raise RunnerError(f"locked package cache entry is not a regular file: {cache_file.name}")
    resolved = cache_file.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise RunnerError("locked package cache file resolves outside the declared cache root") from error


def _cleanup_work_root(
    work_root: Path | None,
    *,
    containers_absent: bool,
    image_absent: bool,
    cleanup_error: str | None,
) -> bool:
    """Remove private work only after all Docker resources have verified cleanup."""
    if work_root is None:
        return False
    if not containers_absent or not image_absent or cleanup_error is not None:
        return True
    shutil.rmtree(work_root, ignore_errors=True)
    return work_root.exists()


def _reap_container(docker: list[str], name: str, *, budget_seconds: float = 5.0) -> tuple[list[str], int | None]:
    """Prove that a named container is absent, or that it exited and was removed."""
    deadline = time.monotonic() + budget_seconds
    hard_errors: list[str] = []
    status_one_errors: list[str] = []
    exit_status: int | None = None

    def run_cleanup_command(command: list[str], label: str, maximum_seconds: float) -> CommandResult | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            hard_errors.append("container cleanup budget expired")
            return None
        result = run_bounded(
            command,
            timeout_seconds=min(maximum_seconds, remaining),
            output_limit=4096,
            deadline=deadline,
        )
        if result.timed_out:
            hard_errors.append(f"timed out running {shlex.join(command[1:])}")
        elif result.error:
            if not _docker_resource_absent(result, kind="container"):
                hard_errors.append(f"{label}: {result.error}")
        elif result.status is None:
            hard_errors.append(f"{label} did not return an exit status")
        elif result.status != 0:
            if _docker_resource_absent(result, kind="container"):
                pass
            elif result.status == 1:
                # A status of one is not an absence proof.  It can only be
                # ignored after the final inspect independently proves absence.
                status_one_errors.append(f"{label} exited with status 1")
            else:
                hard_errors.append(f"{label} exited with status {result.status}")
        return result

    state, inspected = _container_state(
        docker,
        name,
        timeout_seconds=min(1.0, max(0.01, deadline - time.monotonic())),
        deadline=deadline,
    )
    if _docker_resource_absent(inspected, kind="container"):
        return [], None
    if inspected.timed_out:
        return ["timed out inspecting the container during cleanup"], None
    if inspected.error:
        return [f"container cleanup inspect failed: {inspected.error}"], None
    if inspected.status != 0 or state is None:
        return ["container exit status could not be inspected during cleanup"], None

    initial_status = state.get("Status")
    if initial_status == "exited":
        value = state.get("ExitCode")
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255:
            exit_status = value
        else:
            hard_errors.append("inspected exited container has an invalid ExitCode")
    else:
        # Stop/wait are only needed for a live or otherwise non-terminal
        # container.  A status-one result is retained as an error until the
        # final inspect proves that the name is absent.
        stop_result = run_cleanup_command([*docker, "stop", "--time", "1", name], "docker stop --time 1", 2.0)
        if stop_result is not None and _docker_resource_absent(stop_result, kind="container"):
            state = None
        if state is not None:
            wait_result = run_cleanup_command([*docker, "wait", name], "docker wait", 2.0)
            if wait_result is not None and wait_result.status == 0:
                try:
                    exit_status = int(wait_result.stdout.decode("ascii").strip())
                    if not 0 <= exit_status <= 255:
                        raise ValueError
                except (ValueError, UnicodeError):
                    hard_errors.append("Docker wait did not return a numeric container status")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            hard_errors.append("container cleanup budget expired before exit inspection")
        else:
            state, inspected = _container_state(
                docker,
                name,
                timeout_seconds=min(1.0, remaining),
                deadline=deadline,
            )
            if _docker_resource_absent(inspected, kind="container"):
                state = None
            elif inspected.timed_out:
                hard_errors.append("timed out inspecting the container after stop/wait")
                state = None
            elif inspected.error or inspected.status != 0 or state is None:
                hard_errors.append("container exit status could not be inspected after stop/wait")
                state = None
            elif state.get("Status") == "exited":
                value = state.get("ExitCode")
                if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255:
                    if exit_status is not None and exit_status != value:
                        hard_errors.append("Docker wait status differs from inspected containerStatus")
                    exit_status = value
                else:
                    hard_errors.append("inspected exited container has an invalid ExitCode")
            else:
                # A still-running state is handled by rm --force below.  The
                # post-remove inspect, rather than stop/wait's exit status, is
                # the proof that the force-stop completed.
                pass

    # A force-remove is required even for an already-exited container.  The
    # final inspect is the authoritative proof that no named container can
    # outlive the evidence/root cleanup.
    removed = run_cleanup_command([*docker, "rm", "--force", name], "docker rm --force", 2.0)
    if removed is None:
        return hard_errors + status_one_errors, exit_status

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        hard_errors.append("container cleanup budget expired after force removal")
        return hard_errors + status_one_errors, exit_status
    final_state, final_inspected = _container_state(
        docker,
        name,
        timeout_seconds=min(1.0, remaining),
        deadline=deadline,
    )
    if _docker_resource_absent(final_inspected, kind="container"):
        # Status one is tolerated only because this independent inspect proved
        # absence.  Other command failures remain hard failures.
        return hard_errors, exit_status
    if final_inspected.timed_out:
        hard_errors.append("timed out verifying container removal")
    elif final_inspected.error or final_inspected.status != 0 or final_state is None:
        hard_errors.append("container removal could not be verified")
    else:
        hard_errors.append("container still exists after docker rm --force")
    return hard_errors + status_one_errors, exit_status


BIONIC_PACKAGE_MERGE_SCRIPT = """\\
set -eu
set -o pipefail
archive=$1
root_dir=$2
case "$root_dir" in
  /*) ;;
  *) echo "package merge root must be absolute" >&2; exit 1 ;;
esac
root_prefix=${root_dir%/}
[ -n "$root_prefix" ] || root_prefix=/
stage_dir="$(mktemp -d /tmp/urprotect-package.XXXXXX)"
merge_list_file="${stage_dir}.merge-list"
replace_list_file="${stage_dir}.replace-list"
tar_error_file="${stage_dir}.tar-errors"
cleanup_stage() {
  status=$?
  rm -rf -- "$stage_dir" "$merge_list_file" "$replace_list_file" "$tar_error_file" || status=74
  exit "$status"
}
trap cleanup_stage EXIT

validate_relative_path() {
  case "$1" in
    ""|/*|.|..|./*|*/./*|*/.|../*|*/../*|*/..)
      echo "unsafe package path: $1" >&2
      return 1
      ;;
  esac
}

validate_destination_parent() {
  local destination=$1
  local parent=${destination%/*}
  local current=/ component remainder
  [ -n "$parent" ] || parent=/
  [ "$parent" = / ] && return 0
  remainder=${parent#/}
  while [ -n "$remainder" ]; do
    if [[ "$remainder" == */* ]]; then
      component=${remainder%%/*}
      remainder=${remainder#*/}
    else
      component=$remainder
      remainder=
    fi
    [ -n "$component" ] || continue
    current="${current}${component}"
    if [[ -L "$current" ]]; then
      echo "package path traverses a symlink: $destination" >&2
      return 1
    fi
    if [[ -e "$current" ]]; then
      [[ -d "$current" ]] || { echo "package path parent is not a directory: $destination" >&2; return 1; }
    else
      # Everything below a missing component will be created by tar. There
      # cannot be an existing symlink below it, so the remaining walk is done.
      return 0
    fi
    current="${current}/"
  done
}

validate_stage_entry() {
  local entry=$1
  local relative=${entry#"$stage_dir"/}
  local destination
  validate_relative_path "$relative" || return 1
  destination="$root_prefix/$relative"
  validate_destination_parent "$destination" || return 1

  if [[ -L "$entry" ]]; then
    if [[ -L "$destination" ]]; then
      return 0
    fi
    if [[ -d "$destination" ]]; then
      echo "package symlink conflicts with a directory: $destination" >&2
      return 1
    fi
    if [[ -e "$destination" ]]; then
      [[ -f "$destination" ]] || {
        echo "package symlink conflicts with a non-regular path: $destination" >&2
        return 1
      }
      return 0
    fi
    return 0
  fi

  if [[ -d "$entry" ]]; then
    if [[ -L "$destination" ]]; then
      echo "package directory conflicts with a symlink: $destination" >&2
      return 1
    fi
    if [[ -e "$destination" ]]; then
      [[ -d "$destination" ]] || {
        echo "package directory conflicts with a file: $destination" >&2
        return 1
      }
    fi
    return 0
  fi

  if [[ -f "$entry" ]]; then
    if [[ -L "$destination" ]]; then
      return 0
    fi
    if [[ -e "$destination" ]]; then
      [[ -f "$destination" ]] || {
        echo "package file conflicts with a non-regular path: $destination" >&2
        return 1
      }
    fi
    return 0
  fi

  echo "unsupported package payload entry: $entry" >&2
  return 1
}

validate_stage() {
  local entry relative destination
  : > "$merge_list_file" || return 1
  while IFS= read -r -d "" entry; do
    validate_stage_entry "$entry" || return 1
    relative=${entry#"$stage_dir"/}
    destination="$root_prefix/$relative"
    if [[ ! -L "$entry" && -d "$entry" && ( -e "$destination" || -L "$destination" ) ]]; then
      continue
    fi
    printf '%s\\0' "$relative" >> "$merge_list_file" || return 1
  done
}

# Run only after every staged path has passed validation. The replace list is
# NUL-delimited and contains validated absolute leaf paths, never directories.
prepare_replace_list() {
  local relative entry destination
  : > "$replace_list_file" || return 1
  while IFS= read -r -d "" relative; do
    validate_relative_path "$relative" || return 1
    entry="$stage_dir/$relative"
    destination="$root_prefix/$relative"
    validate_destination_parent "$destination" || return 1
    if [[ -L "$entry" || -f "$entry" ]]; then
      if [[ -L "$destination" || -f "$destination" ]]; then
        printf '%s\\0' "$destination" >> "$replace_list_file" || return 1
      fi
    elif [[ ! -d "$entry" ]]; then
      echo "unsupported staged replacement entry: $entry" >&2
      return 1
    fi
  done < "$merge_list_file"
}

# Keep the package's ordinary executable bits in the user-owned stage while
# still dropping ownership and privileged mode bits. The validated NUL list
# contains every non-directory entry and only directories absent at the
# destination, so the destination tar pass never receives existing directories;
# staged modes apply to new files/directories or replaced files.
if (
  umask 000
  dpkg-deb --fsys-tarfile "$archive" |
  tar --extract --file=- --directory="$stage_dir" --no-overwrite-dir --no-same-owner --no-same-permissions --touch 2>"$tar_error_file"
); then
  :
else
  cat -- "$tar_error_file" >&2
  exit 1
fi
if grep -Fq "Removing leading" "$tar_error_file"; then
  cat -- "$tar_error_file" >&2
  echo "unsafe absolute or traversal package path" >&2
  exit 1
fi
rm -f -- "$tar_error_file"

find "$stage_dir" -mindepth 1 -print0 | validate_stage
prepare_replace_list
# xargs bounds rm's argument batches and preserves each validated path as one
# argument, including names containing whitespace or newlines.
xargs -0 -r rm -f -- < "$replace_list_file"

tar --create --file=- --directory="$stage_dir" --null --no-recursion --files-from="$merge_list_file" |
  tar --extract --file=- --directory="$root_prefix" --no-overwrite-dir --no-same-owner --same-permissions --touch
"""


def _prepare_setup_script(path: Path, execution: dict[str, Any], artifact_sha: str) -> None:
    # The setup script passes the merge program as a single-quoted `bash -c`
    # argument. Escape embedded quotes at this boundary so a future diagnostic
    # or path check cannot change the outer script's command structure.
    package_merge_script = BIONIC_PACKAGE_MERGE_SCRIPT.rstrip().replace("'", "'\"'\"'")
    path.write_text(
        """#!/data/data/com.termux/files/usr/bin/sh
set -eu
PREFIX=/data/data/com.termux/files/usr
export PATH=\"$PREFIX/bin:/system/bin:/usr/bin\"
[ \"$(uname -m)\" = aarch64 ] || { echo 'container architecture is not AArch64' >&2; exit 61; }
[ -x /system/bin/linker64 ] || { echo 'locked bionic linker is missing' >&2; exit 62; }
for tool in qemu-aarch64 qemu-aarch64-static qemu-system-aarch64 waydroid emulator; do
  if command -v \"$tool\" >/dev/null 2>&1; then echo \"forbidden emulation tool: $tool\" >&2; exit 63; fi
done
dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Status}\\n' | sort | cmp -- /metadata/base.tsv - || { echo 'base package inventory mismatch' >&2; exit 64; }
while IFS=\"$(printf '\\t')\" read -r package_name package_version package_arch package_filename package_sha package_size package_url; do
  [ -n \"$package_name\" ] || continue
  if [ \"$package_name\" = nodejs ]; then archive=/input/nodejs-source.deb; else archive=/packages/$package_filename; fi
  [ -f \"$archive\" ] || { echo \"missing locked package: $package_name\" >&2; exit 65; }
  [ \"$(stat -c '%s' \"$archive\")\" = \"$package_size\" ] || { echo \"locked package size mismatch: $package_name\" >&2; exit 66; }
  [ \"$(sha256sum \"$archive\" | awk '{print $1}')\" = \"$package_sha\" ] || { echo \"locked package digest mismatch: $package_name\" >&2; exit 67; }
  [ \"$(dpkg-deb -f \"$archive\" Package)\" = \"$package_name\" ] || { echo \"package identity mismatch: $package_name\" >&2; exit 68; }
  [ \"$(dpkg-deb -f \"$archive\" Version)\" = \"$package_version\" ] || { echo \"package version mismatch: $package_name\" >&2; exit 69; }
  [ \"$(dpkg-deb -f \"$archive\" Architecture)\" = \"$package_arch\" ] || { echo \"package architecture mismatch: $package_name\" >&2; exit 70; }
  if "$PREFIX/bin/bash" -o pipefail -c '
__URP_PACKAGE_MERGE_SCRIPT__
  ' -- "$archive" /; then
    :
  else
    status=$?
    echo "package data extraction failed: $package_name" >&2
    exit 74
  fi
done < /metadata/packages.tsv
dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Status}\\n' | sort | cmp -- /metadata/base.tsv - || { echo 'package extraction changed the package inventory' >&2; exit 71; }
[ -f \"__URP_ARTIFACT_PATH__\" ] || { echo 'extracted Node.js executable is missing' >&2; exit 72; }
actual_sha=\"$(sha256sum \"__URP_ARTIFACT_PATH__\" | awk '{print $1}')\"
[ \"$actual_sha\" = \"__URP_ARTIFACT_SHA__\" ] || { echo 'runtime Node.js executable hash mismatch' >&2; exit 73; }
printf 'URP_RUNTIME_ARTIFACT_SHA256=%s\\n' \"$actual_sha\"
""".replace("__URP_ARTIFACT_PATH__", execution["artifactPath"]).replace("__URP_ARTIFACT_SHA__", artifact_sha).replace("__URP_PACKAGE_MERGE_SCRIPT__", package_merge_script),
        encoding="utf-8",
    )
    path.chmod(0o444)


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def _register_worker_resource(name: str, kind: str) -> None:
    registry_name = os.environ.get("URP_WORKER_CONTAINER_REGISTRY")
    if not registry_name:
        return
    if kind not in {"container", "image"}:
        raise RunnerError(f"unsupported worker cleanup resource kind: {kind}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", name):
        raise RunnerError(f"worker {kind} name is not valid for the cleanup registry")
    registry = Path(registry_name)
    registry.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(registry, flags, 0o600)
        try:
            # Keep the historical container row shape for existing consumers;
            # image rows carry an explicit kind so the supervisor uses image
            # removal rather than accidentally treating an image as a container.
            record = {"name": name} if kind == "container" else {"kind": kind, "name": name}
            os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise RunnerError(f"could not register named bionic {kind} for cleanup: {error}", "environment") from error


def _mark_worker_resource_removed(name: str, kind: str) -> None:
    registry_name = os.environ.get("URP_WORKER_CONTAINER_REGISTRY")
    if not registry_name:
        return
    registry = Path(registry_name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(registry, flags, 0o600)
        try:
            record = {"kind": kind, "name": name, "state": "removed"}
            os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise RunnerError(f"could not mark removed bionic {kind} in cleanup registry: {error}", "environment") from error


def _register_container_name(name: str) -> None:
    _register_worker_resource(name, "container")


def _register_image_name(name: str) -> None:
    _register_worker_resource(name, "image")


def _protocol(
    *,
    context: dict[str, Any],
    attempted: bool,
    helper_status: int | None,
    target_status: int | None,
    container_status: int | None,
    docker_status: int | None,
    output_bytes: int,
    cleanup_container_status: int | None = None,
    outcome: str,
    readiness_seen: bool,
) -> dict[str, Any]:
    execution = context["execution"]
    return {
        "schemaVersion": 2,
        "producer": "run-bionic-node-sample.sh",
        "runtime": "bionic",
        "attempted": attempted,
        "helperStatus": helper_status,
        "targetStatus": target_status,
        "readinessSeen": readiness_seen,
        "outcome": outcome,
        "containerStatus": container_status,
        "dockerStatus": docker_status,
        "cleanupContainerStatus": cleanup_container_status,
        "timeoutSeconds": execution["timeoutSeconds"],
        "outputLimitBytes": execution["outputBytes"],
        "outputBytes": output_bytes,
        "lockSha256": context["lockSha256"],
        "pathMode": execution["outerMode"],
        "pathPolicy": execution["pathPolicy"],
        "memoryBytes": execution["memoryBytes"],
        "processLimit": execution["processLimit"],
        "runpath": context.get("runpath", execution["runpath"]),
        "runpathVerified": context.get("runpathVerified") is True,
        "protocolAuthority": PROTOCOL_AUTHORITY,
        "cleanupAuthority": CLEANUP_AUTHORITY,
        "allNamedContainersReaped": True,
    }


def _actual_for_protocol(protocol: dict[str, Any], expected_status: int) -> str:
    if protocol["helperStatus"] == 125:
        return "environment-unavailable"
    if protocol["helperStatus"] is not None:
        return "runtime-failure"
    if not protocol["attempted"] or protocol["targetStatus"] is None:
        return "environment-unavailable"
    return "accepted-and-runs" if protocol["targetStatus"] == expected_status else "runtime-failure"


def _attach_protocol(result: dict[str, Any], protocol: dict[str, Any], *, actual: str, reason: str) -> None:
    result.update(
        protocol=protocol,
        actual=actual,
        reason=reason,
        attempted=protocol["attempted"],
        helperStatus=protocol["helperStatus"],
        targetStatus=protocol["targetStatus"],
        containerStatus=protocol["containerStatus"],
        dockerStatus=protocol["dockerStatus"],
        cleanupContainerStatus=protocol["cleanupContainerStatus"],
        outcome=protocol["outcome"],
        readinessSeen=protocol["readinessSeen"],
    )


def validate_target_completion(cli_status: int | None, container_status: int | None, expected_status: int) -> tuple[int | None, str | None]:
    """Require Docker attach status and inspected container state to agree."""
    if cli_status is None or container_status is None:
        return None, "Docker target completion lacks a verified process/container status"
    if cli_status != container_status:
        return None, f"Docker client status {cli_status} differs from inspected containerStatus {container_status}"
    if container_status != expected_status:
        return container_status, f"target/container exited with status {container_status}, expected {expected_status}"
    return container_status, None


def _run_one_target(
    *,
    docker: list[str],
    name: str,
    create_args: list[str],
    budget: OutputBudget,
    deadline: float,
    context: dict[str, Any],
    setup_ready: bool,
) -> tuple[dict[str, Any], bytes, bytes]:
    execution = context["execution"]
    result_data = {"stdout": b"", "stderr": b"", "cliStatus": None, "containerStatus": None}
    created = _create_container(docker, create_args, budget=budget, deadline=deadline)
    if created.error or created.status != 0 or created.timed_out or created.output_limited:
        if created.output_limited:
            helper = OUTPUT_LIMIT_STATUS
            outcome = "helper-output-limit"
        elif created.timed_out:
            helper = 124
            outcome = "helper-timeout"
        else:
            helper = 125
            outcome = "helper-environment"
        protocol = _protocol(
            context=context,
            attempted=False,
            helper_status=helper,
            target_status=None,
            container_status=None,
            docker_status=created.status if isinstance(created.status, int) and not isinstance(created.status, bool) and 0 <= created.status <= 255 else None,
            output_bytes=0,
            outcome=outcome,
            readiness_seen=setup_ready,
        )
        _attach_protocol(result_data, protocol, actual=_actual_for_protocol(protocol, execution["expectedStatus"]), reason=created.error or "Docker could not create the target container")
        return result_data, b"", b""

    started = _start_attached(docker, name, budget=budget, deadline=deadline, timeout_seconds=execution["timeoutSeconds"])
    result_data["stdout"] = started.stdout
    result_data["stderr"] = started.stderr
    result_data["cliStatus"] = started.status
    if started.output_limited:
        protocol = _protocol(
            context=context,
            attempted=True,
            helper_status=OUTPUT_LIMIT_STATUS,
            target_status=None,
            container_status=None,
            docker_status=None,
            output_bytes=len(started.stdout) + len(started.stderr),
            outcome="helper-output-limit",
            readiness_seen=setup_ready,
        )
        _attach_protocol(result_data, protocol, actual="runtime-failure", reason="container output exceeded the locked byte limit")
        return result_data, started.stdout, started.stderr
    if started.timed_out:
        protocol = _protocol(
            context=context,
            attempted=True,
            helper_status=124,
            target_status=None,
            container_status=None,
            docker_status=None,
            output_bytes=len(started.stdout) + len(started.stderr),
            outcome="helper-timeout",
            readiness_seen=setup_ready,
        )
        _attach_protocol(result_data, protocol, actual="runtime-failure", reason="target/container exceeded the locked wall-time limit")
        return result_data, started.stdout, started.stderr

    state, inspected = _container_state(docker, name, timeout_seconds=_remaining(deadline, 3), deadline=deadline)
    status = state.get("ExitCode") if state is not None else None
    if started.status is None or not 0 <= started.status <= 255:
        protocol = _protocol(
            context=context,
            attempted=True,
            helper_status=125,
            target_status=None,
            container_status=None,
            docker_status=None,
            output_bytes=len(started.stdout) + len(started.stderr),
            outcome="helper-environment",
            readiness_seen=setup_ready,
        )
        _attach_protocol(result_data, protocol, actual="environment-unavailable", reason="Docker attach process did not return a valid status")
        return result_data, started.stdout, started.stderr
    if state is None or state.get("Status") != "exited" or isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255:
        protocol = _protocol(
            context=context,
            attempted=True,
            helper_status=125,
            target_status=None,
            container_status=None,
            docker_status=started.status,
            output_bytes=len(started.stdout) + len(started.stderr),
            outcome="helper-environment",
            readiness_seen=setup_ready,
        )
        _attach_protocol(result_data, protocol, actual="environment-unavailable", reason="Docker did not provide a completed, inspectable target container state")
        return result_data, started.stdout, started.stderr

    target_status, mismatch = validate_target_completion(started.status, status, execution["expectedStatus"])
    protocol = _protocol(
        context=context,
        attempted=True,
        helper_status=None,
        target_status=status,
        container_status=status,
        docker_status=started.status,
        output_bytes=len(started.stdout) + len(started.stderr),
        outcome="target-exit",
        readiness_seen=setup_ready,
    )
    _attach_protocol(
        result_data,
        protocol,
        actual="accepted-and-runs" if mismatch is None and target_status is not None else "runtime-failure",
        reason=mismatch or f"target/container status={status}",
    )
    return result_data, started.stdout, started.stderr


def _stage_wrapper(wrapper: Path, destination: Path) -> Path:
    """Stage a packed wrapper without copying a file onto itself."""
    if wrapper.is_symlink() or not wrapper.is_file():
        raise RunnerError("packed wrapper output must be a regular host-owned file")
    if destination.is_symlink():
        raise RunnerError("packed wrapper destination must not be a symlink")
    if destination.exists():
        if not destination.is_file():
            raise RunnerError("packed wrapper destination must be a regular file")
        try:
            if os.path.samefile(wrapper, destination):
                return destination
        except OSError as error:
            raise RunnerError(f"could not compare packed wrapper staging files: {error}") from error
    shutil.copyfile(wrapper, destination)
    return destination


def _pack(
    *,
    context: dict[str, Any],
    input_path: Path,
    launcher: Path,
    cli_dll: Path,
    work_root: Path,
    artifact_root: Path,
    output_limit: int,
) -> tuple[Path | None, int | None, dict[str, Any], str | None]:
    wrapper = work_root / "wrapper" / "urprotect-packed"
    report_path = artifact_root / "outer-pack.json"
    pack_log_path = artifact_root / "logs" / "outer-pack.log"
    base_image = context["lock"]["baseImage"]
    identity_fields = {
        "image": base_image["requestedRef"],
        "imageId": base_image["id"],
        "loader": context["execution"]["loader"],
    }

    def write_pack_report(value: dict[str, Any]) -> None:
        value.update(identity_fields)
        _write(report_path, json.dumps(value, indent=2, sort_keys=True) + "\n")

    command = [
        "dotnet", str(cli_dll), "pack", str(input_path),
        "--output", str(wrapper), "--launcher", str(launcher),
        "--profile", "outer-execveat", "--path-preserving",
        "--json", str(work_root / "pack-report.json"),
    ]
    completed = run_bounded(command, timeout_seconds=context["execution"]["timeoutSeconds"], output_limit=output_limit)
    _write(pack_log_path, completed.stdout + completed.stderr)
    cli_status = completed.status
    if completed.timed_out:
        cli_status = 124
    elif completed.output_limited:
        cli_status = OUTPUT_LIMIT_STATUS
    elif completed.error:
        cli_status = 127
    elif cli_status is None or cli_status < 0 or cli_status > 255:
        cli_status = 1
    if completed.error or completed.timed_out or completed.output_limited or cli_status != 0:
        reason = completed.error or ("pack command exceeded its output limit" if completed.output_limited else "pack command timed out" if completed.timed_out else f"profile-matched pack exited {cli_status}")
        report = {
            "schemaVersion": 1,
            "toolVersion": "runner-boundary",
            "success": False,
            "category": "product",
            "input": {"byteLength": input_path.stat().st_size, "sha256": sha256_file(input_path)},
            "payload": {},
            "output": {"published": False},
            "diagnostics": [{"severity": "Error", "code": "bionic.outer-pack-failed", "message": reason, "offset": None}],
            "cliExitCode": cli_status if cli_status is not None else 1,
            "executionMode": context["execution"]["outerMode"],
            "pathPolicy": context["execution"]["pathPolicy"],
            "runpath": context["runpath"],
            "lockSha256": context["lockSha256"],
            "packInvocation": {"attempted": True, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
        }
        write_pack_report(report)
        return None, report["cliExitCode"], report, reason

    try:
        product = json.loads((work_root / "pack-report.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        reason = f"pack report is missing or invalid: {error}"
        report = {
            "schemaVersion": 1,
            "toolVersion": "runner-boundary",
            "success": False,
            "category": "product",
            "input": {"byteLength": input_path.stat().st_size, "sha256": sha256_file(input_path)},
            "payload": {},
            "output": {"published": False},
            "diagnostics": [{"severity": "Error", "code": "bionic.outer-pack-report-invalid", "message": reason, "offset": None}],
            "cliExitCode": 1,
            "executionMode": context["execution"]["outerMode"],
            "pathPolicy": context["execution"]["pathPolicy"],
            "runpath": context["runpath"],
            "lockSha256": context["lockSha256"],
            "packInvocation": {"attempted": True, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
        }
        write_pack_report(report)
        return None, 1, report, reason
    payload = product.get("payload") if isinstance(product, dict) else None
    if (
        not isinstance(product, dict)
        or product.get("success") is not True
        or not isinstance(payload, dict)
        or payload.get("profile") != "outer-execveat"
        or not wrapper.is_file()
        or wrapper.is_symlink()
    ):
        reason = "product pack report/output does not match the outer-execveat dispatch profile"
        product = {
            "schemaVersion": 1,
            "toolVersion": product.get("toolVersion", "runner-boundary") if isinstance(product, dict) else "runner-boundary",
            "success": False,
            "category": "product",
            "input": product.get("input", {}) if isinstance(product, dict) else {},
            "payload": payload if isinstance(payload, dict) else {},
            "output": {"published": False},
            "diagnostics": [{"severity": "Error", "code": "bionic.outer-pack-report-invalid", "message": reason, "offset": None}],
            "cliExitCode": 1,
            "executionMode": context["execution"]["outerMode"],
            "pathPolicy": context["execution"]["pathPolicy"],
            "runpath": context["runpath"],
            "lockSha256": context["lockSha256"],
            "packInvocation": {"attempted": True, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
        }
        write_pack_report(product)
        return None, 1, product, reason

    source_hash = product.get("input", {}).get("sha256") if isinstance(product.get("input"), dict) else None
    if source_hash != sha256_file(input_path):
        reason = "pack report input hash does not match the verified Node.js source artifact"
        product["success"] = False
        product["category"] = "product"
        product["output"] = {"published": False}
        product["diagnostics"] = [{"severity": "Error", "code": "bionic.outer-pack-hash-mismatch", "message": reason, "offset": None}]
        product["cliExitCode"] = 1
        product.update({
            "executionMode": context["execution"]["outerMode"],
            "pathPolicy": context["execution"]["pathPolicy"],
            "runpath": context["runpath"],
            "lockSha256": context["lockSha256"],
            "packInvocation": {"attempted": True, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
        })
        write_pack_report(product)
        return None, 1, product, reason

    wrapper.chmod(0o555)
    host_fields = {
        "executionMode": context["execution"]["outerMode"],
        "pathPolicy": context["execution"]["pathPolicy"],
        "runpath": context["runpath"],
        "lockSha256": context["lockSha256"],
        "wrapperSha256": sha256_file(wrapper),
        "packInvocation": {"attempted": True, "dispatchProfile": "outer-execveat", "pathPreserving": True, "executionMode": "outer-path-preserving"},
    }
    product.update(host_fields)
    product["cliExitCode"] = 0
    write_pack_report(product)
    return wrapper, 0, product, None


def _preflight_layer(context: dict[str, Any], actual: str, reason: str, outcome: str) -> dict[str, Any]:
    helper_status = 125 if outcome == "helper-environment" else 124 if outcome == "helper-timeout" else OUTPUT_LIMIT_STATUS if outcome == "helper-output-limit" else None
    protocol = _protocol(
        context=context,
        attempted=False,
        helper_status=helper_status,
        target_status=None,
        container_status=None,
        docker_status=None,
        output_bytes=0,
        outcome=outcome,
        readiness_seen=False,
    )
    return {**protocol, "protocol": protocol, "actual": actual, "reason": reason, "preflightOutcome": "preflight-environment-unavailable" if actual == "environment-unavailable" else "preflight-product-failure" if actual == "unexpected-rejection" else None}


def _write_evidence(
    *,
    artifact_root: Path,
    work_root: Path,
    context: dict[str, Any],
    image: str,
    image_id: str,
    source_sha: str,
    runtime_sha: str | None,
    setup_status: int | None,
    baseline: dict[str, Any],
    outer: dict[str, Any],
    baseline_streams: tuple[bytes, bytes],
    outer_streams: tuple[bytes, bytes],
    pack_status: int | None,
    pack_report: dict[str, Any],
    runpath: str,
    budget: OutputBudget,
    containers_reaped: bool,
    image_cleanup: dict[str, Any],
    work_root_retained: bool,
) -> dict[str, Any]:
    logs = artifact_root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    for layer, streams in (("baseline", baseline_streams), ("outer", outer_streams)):
        _write(logs / f"{layer}.stdout", streams[0])
        _write(logs / f"{layer}.stderr", streams[1])
        protocol = layer_data = baseline if layer == "baseline" else outer
        protocol = layer_data.get("protocol", layer_data)
        protocol["cleanupAuthority"] = CLEANUP_AUTHORITY
        protocol["allNamedContainersReaped"] = containers_reaped
        for field in ("runpathVerified", "protocolAuthority", "cleanupAuthority", "allNamedContainersReaped"):
            layer_data[field] = protocol.get(field)
        _write(logs / f"{layer}.helper.json", json.dumps(protocol, indent=2, sort_keys=True) + "\n")
        if protocol.get("targetStatus") is not None:
            _write(logs / f"{layer}.status", f"{protocol['targetStatus']}\n")
        if protocol.get("helperStatus") is not None:
            _write(logs / f"{layer}.helper-status", f"{protocol['helperStatus']}\n")
    if setup_status is not None:
        _write(logs / "container-setup.status", f"{setup_status}\n")
    if pack_status is not None:
        _write(logs / "outer-pack.status", f"{pack_status}\n")

    execution = context["execution"]
    image_absent = image_cleanup.get("absenceVerified") is True
    runtime_prerequisites_passed = (
        containers_reaped
        and image_absent
        and not work_root_retained
        and context.get("runpathVerified") is True
        and setup_status == execution["expectedStatus"]
    )
    if not runtime_prerequisites_passed:
        reason = (
            "named Docker container cleanup was not verified" if not containers_reaped
            else "temporary runtime image absence was not verified" if not image_absent
            else "temporary bionic work root was retained after cleanup failure" if work_root_retained
            else "locked Node.js RUNPATH verification did not pass" if context.get("runpathVerified") is not True
            else "package setup container status did not match the locked expected status"
        )
        for observed in (baseline, outer):
            if observed.get("actual") == "accepted-and-runs":
                observed["actual"] = "runtime-failure"
                observed["reason"] = reason
    baseline_actual = baseline["actual"]
    outer_actual = outer["actual"]
    equivalent = (
        baseline_actual == "accepted-and-runs"
        and outer_actual == "accepted-and-runs"
        and baseline.get("targetStatus") == outer.get("targetStatus")
        and baseline_streams == outer_streams
    )
    if baseline_actual == "accepted-and-runs" and outer_actual == "accepted-and-runs" and not equivalent:
        outer_actual = "runtime-failure"
        outer["actual"] = outer_actual
        outer["reason"] = "outer status/stdout/stderr differ from the locked baseline execution"
    _write(logs / "behavior-equivalent", "true\n" if equivalent else "false\n")
    _write(logs / "runner-summary.log", f"baseline={baseline_actual} outer={outer_actual} behaviorEquivalent={str(equivalent).lower()}\n")

    container_status = outer.get("containerStatus")
    if container_status is None:
        container_status = baseline.get("containerStatus")
    statuses = {"setup": setup_status, "baseline": baseline.get("containerStatus"), "outer": outer.get("containerStatus")}
    cleanup_statuses = {
        "setup": setup_status,
        "baseline": baseline.get("cleanupContainerStatus"),
        "outer": outer.get("cleanupContainerStatus"),
    }
    passed = baseline_actual == "accepted-and-runs" and outer_actual == "accepted-and-runs"
    value = {
        "schemaVersion": 2,
        "producer": "run-bionic-node-sample.sh",
        "runtime": "bionic",
        "status": "passed" if passed else "failed",
        "lockSha256": context["lockSha256"],
        "image": image,
        "imageId": image_id,
        "loader": execution["loader"],
        "artifactPath": context["artifactPath"],
        "sourceArtifactSha256": source_sha,
        "runtimeArtifactSha256": runtime_sha,
        "sourceArchiveSha256": context["source"]["sha256"],
        "pathMode": execution["outerMode"],
        "pathPolicy": execution["pathPolicy"],
        "runpath": runpath,
        "runpathVerified": context.get("runpathVerified", False),
        "timeoutSeconds": execution["timeoutSeconds"],
        "outputLimitBytes": execution["outputBytes"],
        "memoryBytes": execution["memoryBytes"],
        "processLimit": execution["processLimit"],
        "expectedStatus": execution["expectedStatus"],
        "outputBytes": budget.used,
        "behaviorEquivalent": equivalent,
        "protocolAuthority": PROTOCOL_AUTHORITY,
        "cleanupAuthority": CLEANUP_AUTHORITY,
        "containerStatus": container_status,
        "containerStatuses": statuses,
        "cleanupContainerStatuses": cleanup_statuses,
        "containerCleanup": {
            "allNamedContainersReaped": containers_reaped,
            "authority": CLEANUP_AUTHORITY,
        },
        "temporaryImageCleanup": image_cleanup,
        "cleanupStatus": "passed" if containers_reaped and image_absent and not work_root_retained else "failed",
        "workRootRetained": work_root_retained,
        "packStatus": pack_status,
        "packReport": "outer-pack.json",
        "baseline": baseline,
        "outer": outer,
    }
    _write(artifact_root / "bionic-node-result.json", json.dumps(value, indent=2, sort_keys=True) + "\n")
    _write(logs / "bionic-node-result.json", json.dumps(value, indent=2, sort_keys=True) + "\n")
    closure = {
        "schemaVersion": 1,
        "projectId": "nodejs",
        "runtime": "bionic",
        "loader": execution["loader"],
        "status": "assembled" if runtime_sha else "environment-unavailable",
        "resolver": "termux-node-lock-v1",
        "lockSha256": context["lockSha256"],
        "image": image,
        "imageId": image_id,
        "sourceArtifactSha256": source_sha,
        "runtimeArtifactSha256": runtime_sha,
        "pathMode": execution["outerMode"],
        "pathPolicy": execution["pathPolicy"],
        "runpath": runpath,
        "timeoutSeconds": execution["timeoutSeconds"],
        "outputLimitBytes": execution["outputBytes"],
        "memoryBytes": execution["memoryBytes"],
        "processLimit": execution["processLimit"],
        "packageManagerUsed": False,
        "packageExtraction": "dpkg-deb-extract-only-no-maintainer-scripts",
        "rawArchivesUploaded": False,
        "containerStatus": container_status,
        "containerStatuses": statuses,
        "cleanupContainerStatuses": cleanup_statuses,
        "executionStatus": value["status"],
        "behaviorEquivalent": equivalent,
        "runpathVerified": context.get("runpathVerified", False),
        "protocolAuthority": PROTOCOL_AUTHORITY,
        "cleanupAuthority": CLEANUP_AUTHORITY,
        "containerCleanup": {
            "allNamedContainersReaped": containers_reaped,
            "authority": CLEANUP_AUTHORITY,
        },
        "temporaryImageCleanup": image_cleanup,
        "cleanupStatus": value["cleanupStatus"],
        "workRootRetained": work_root_retained,
    }
    _write(artifact_root / "runtime-closure.json", json.dumps(closure, indent=2, sort_keys=True) + "\n")
    return value


def _run(args: argparse.Namespace) -> int:
    from bionic_node_lock import lock_file_sha256

    artifact_root = args.artifact_root.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    (artifact_root / "logs").mkdir(parents=True, exist_ok=True)
    for old in (artifact_root / "bionic-node-result.json", artifact_root / "logs" / "bionic-node-result.json"):
        old.unlink(missing_ok=True)

    context: dict[str, Any] | None = None
    work_root: Path | None = None
    docker = shlex.split(os.environ.get("BIONIC_CONTAINER_RUNTIME", "docker"))
    if not docker:
        docker = ["docker"]
    names: list[str] = []
    transient_image: str | None = None
    transient_image_registered = False
    baseline = outer = None
    baseline_streams = (b"", b"")
    outer_streams = (b"", b"")
    runtime_sha: str | None = None
    setup_status: int | None = None
    pack_status: int | None = None
    pack_report: dict[str, Any] = {}
    runpath = ""
    budget = OutputBudget(0)
    failure: RunnerError | None = None
    cleanup_error: str | None = None
    image_cleanup: dict[str, Any] = {
        "status": "not-created",
        "absenceVerified": True,
        "attempts": 0,
        "authority": CLEANUP_AUTHORITY,
        "reason": None,
    }
    work_root_retained = False
    execution_deadline: float | None = None

    def handle_signal(signum: int, _frame: Any) -> None:
        raise RunnerError(f"received signal {signum}; stopping named bionic container", "timeout")

    old_handlers = {signum: signal.signal(signum, handle_signal) for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}
    try:
        if os.uname().machine.lower() not in {"aarch64", "arm64"}:
            raise RunnerError(f"bionic Node.js requires a native AArch64 host; got {os.uname().machine}", "environment")
        if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA") or any(Path(item).exists() for item in ("/system/bin/linker64", "/dev/binder", "/dev/vndbinder")):
            raise RunnerError("bionic Node.js witness requires the locked Linux ARM64 host context", "environment")
        context = load_lock_context(args.lock, args.manifest, args.image, args.version, args.sha256, args.archive_sha256, args.outer_mode)
        execution = context["execution"]
        context["runpath"] = context["expectedRunpath"]
        context["runpathVerified"] = False
        budget = OutputBudget(execution["outputBytes"])
        for name, path in (("input", args.input), ("source archive", args.source_archive), ("launcher", args.launcher), ("CLI assembly", args.cli_dll)):
            if not path.is_file() or path.is_symlink():
                raise RunnerError(f"bionic {name} must be a regular file")
        if not os.access(args.launcher, os.X_OK):
            raise RunnerError("bionic launcher is not executable")
        if sha256_file(args.input) != args.sha256:
            raise RunnerError("extracted Node.js artifact digest differs from the real-sample manifest")
        source = context["source"]
        if args.source_archive.stat().st_size != source["sizeBytes"] or sha256_file(args.source_archive) != source["sha256"]:
            raise RunnerError("Node.js source archive size or digest differs from the reviewed lock")
        runpath = verify_runpath(args.input, context["expectedRunpath"], output_limit=execution["outputBytes"])
        context["runpath"] = runpath
        context["runpathVerified"] = True

        runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
        if not runner_temp.is_absolute():
            raise RunnerError("RUNNER_TEMP must be an absolute temporary directory", "environment")
        runner_temp.mkdir(parents=True, exist_ok=True)
        work_root = Path(tempfile.mkdtemp(prefix="urprotect-bionic-node.", dir=runner_temp))
        os.chmod(work_root, 0o700)
        metadata_root = work_root / "metadata"
        packages_root = work_root / "packages"
        wrapper_root = work_root / "wrapper"
        for directory in (metadata_root, packages_root, wrapper_root):
            directory.mkdir(mode=0o755)
        _metadata_files(context, metadata_root)

        # Validate native host and pinned image before any target process is started.
        server_budget = OutputBudget(execution["outputBytes"])
        _docker_identity(docker, server_budget)
        _docker_image(docker, args.image, context["lock"]["baseImage"]["id"], context["lock"]["baseImage"]["requestedRef"], server_budget)
        budget.used += server_budget.used
        if budget.used > budget.limit:
            raise RunnerError("Docker preflight logs exceeded the reviewed output limit", "output")

        # Download only the four locked dependency archives, outside the evidence tree.
        if args.cache_root.is_symlink():
            raise RunnerError("bionic package cache root must not be a symlink")
        cache_root = args.cache_root.absolute()
        cache_root.mkdir(parents=True, exist_ok=True)
        resolved_cache_root = cache_root.resolve(strict=True)
        for package in context["lock"]["packages"]:
            if package["name"] == "nodejs":
                continue
            cache_dir, resolved_cache_root = _ensure_cache_directory(
                cache_root,
                "sha256",
                package["sha256"],
            )
            cache_file = cache_dir / package["localFilename"]
            _checked_cache_file(cache_root, cache_file, resolved_cache_root)
            valid = cache_file.is_file() and cache_file.stat().st_size == package["sizeBytes"] and sha256_file(cache_file) == package["sha256"]
            if not valid:
                cache_file.unlink(missing_ok=True)
                temporary_fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{package['localFilename']}.",
                    suffix=".tmp",
                    dir=cache_dir,
                )
                os.close(temporary_fd)
                temporary = Path(temporary_name)
                _checked_cache_file(cache_root, temporary, resolved_cache_root)
                curl = run_bounded(
                    ["curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2", "--retry", "3", "--retry-all-errors", "--connect-timeout", "20", "--max-time", "180", "--max-filesize", str(package["sizeBytes"]), "--output", str(temporary), package["url"]],
                    timeout_seconds=180,
                    output_limit=execution["outputBytes"],
                )
                _write(artifact_root / "logs" / "package-acquisition.log", curl.stderr + curl.stdout)
                if curl.error or curl.timed_out or curl.output_limited or curl.status != 0:
                    temporary.unlink(missing_ok=True)
                    raise RunnerError(f"locked dependency archive acquisition failed: {package['name']}", "environment")
                if temporary.stat().st_size != package["sizeBytes"] or sha256_file(temporary) != package["sha256"]:
                    temporary.unlink(missing_ok=True)
                    raise RunnerError(f"locked dependency archive digest/size mismatch: {package['name']}")
                _checked_cache_file(cache_root, cache_file, resolved_cache_root)
                os.replace(temporary, cache_file)
                _checked_cache_file(cache_root, cache_file, resolved_cache_root)
            copied = packages_root / package["localFilename"]
            shutil.copyfile(cache_file, copied)
            copied.chmod(0o444)
        args.source_archive.chmod(args.source_archive.stat().st_mode | stat.S_IROTH)

        wrapper, pack_status, pack_report, pack_error = _pack(
            context=context,
            input_path=args.input,
            launcher=args.launcher,
            cli_dll=args.cli_dll,
            work_root=work_root,
            artifact_root=artifact_root,
            output_limit=execution["outputBytes"],
        )
        if pack_status == 0 and wrapper is not None:
            wrapper_copy = _stage_wrapper(wrapper, wrapper_root / "urprotect-packed")
            wrapper_copy.chmod(0o555)

        # One host-side deadline covers setup and both target containers. Each Docker
        # client is a process group, and timeout/interruption always reaches cleanup.
        execution_deadline = time.monotonic() + execution["timeoutSeconds"]
        setup_name = f"urp-bionic-node-setup-{os.getpid()}-{time.monotonic_ns()}"
        names.append(setup_name)
        _register_container_name(setup_name)
        setup_script = work_root / "setup.sh"
        _prepare_setup_script(setup_script, execution, args.sha256)
        setup_create_args = [
            *_container_common_args(setup_name, execution, read_only=False),
            "--mount", f"type=bind,src={metadata_root},dst=/metadata,readonly",
            "--mount", f"type=bind,src={packages_root},dst=/packages,readonly",
            "--mount", f"type=bind,src={args.source_archive.resolve()},dst=/input/nodejs-source.deb,readonly",
            "--mount", f"type=bind,src={setup_script},dst=/input/setup.sh,readonly",
            args.image,
            "/data/data/com.termux/files/usr/bin/sh", "/input/setup.sh",
        ]
        create_budget = budget
        created = _create_container(docker, setup_create_args, budget=create_budget, deadline=execution_deadline)
        if created.error or created.status != 0 or created.timed_out:
            category = "timeout" if created.timed_out else "environment"
            raise RunnerError(created.error or "Docker could not create the locked package setup container", category)
        setup_run = _start_attached(docker, setup_name, budget=budget, deadline=execution_deadline, timeout_seconds=execution["timeoutSeconds"])
        _write(artifact_root / "logs" / "container-setup.log", setup_run.stdout + setup_run.stderr)
        setup_state, _ = _container_state(docker, setup_name, timeout_seconds=_remaining(execution_deadline, 3), deadline=execution_deadline)
        setup_status = setup_state.get("ExitCode") if setup_state is not None else None
        if setup_run.output_limited:
            raise RunnerError("locked package setup container exceeded the output limit", "output")
        if setup_run.timed_out:
            raise RunnerError("locked package setup container exceeded the 30-second deadline", "timeout")
        if setup_state is None or setup_state.get("Status") != "exited" or setup_status != setup_run.status:
            raise RunnerError("package setup Docker status differs from the inspected containerStatus", "environment")
        if setup_status != 0:
            raise RunnerError(f"locked package extraction/preflight exited with status {setup_status}")
        setup_text = (setup_run.stdout + setup_run.stderr).decode("utf-8", errors="strict")
        hash_matches = re.findall(r"^URP_RUNTIME_ARTIFACT_SHA256=([0-9a-f]{64})$", setup_text, re.MULTILINE)
        if len(hash_matches) != 1 or hash_matches[0] != args.sha256:
            raise RunnerError("container runtime Node.js artifact hash does not match the verified source artifact")
        runtime_sha = hash_matches[0]

        transient_image = f"urprotect-bionic-node:{os.getpid()}-{time.monotonic_ns()}"
        # Publish the image identity before commit.  If the worker is killed
        # between commit and its finally block, the parent supervisor can still
        # inspect and remove this image before releasing the temp root.
        _register_image_name(transient_image)
        transient_image_registered = True
        commit = _checked_command([*docker, "commit", setup_name, transient_image], budget=budget, timeout_seconds=_remaining(execution_deadline, 5), deadline=execution_deadline)
        if commit.error or commit.status != 0 or commit.timed_out or commit.output_limited:
            raise RunnerError("Docker could not create the temporary locked runtime image", "environment")
        setup_reap_errors, _ = _reap_container(docker, setup_name)
        cleanup_error = "; ".join(setup_reap_errors) or None
        if not setup_reap_errors:
            names.remove(setup_name)
        if cleanup_error:
            raise RunnerError(f"package setup container cleanup failed: {cleanup_error}", "environment")

        target_script = work_root / "execute-target.sh"
        _prepare_target_script(target_script, execution)
        baseline_name = f"urp-bionic-node-baseline-{os.getpid()}-{time.monotonic_ns()}"
        names.append(baseline_name)
        _register_container_name(baseline_name)
        baseline_argv = context["argv"]
        baseline_launch_argv = [execution["loader"], *baseline_argv]
        baseline_create_args = build_target_container_args(
            baseline_name, transient_image, execution, baseline_launch_argv, exec_script=target_script
        )
        baseline, baseline_stdout, baseline_stderr = _run_one_target(
            docker=docker, name=baseline_name, create_args=baseline_create_args,
            budget=budget, deadline=execution_deadline, context=context, setup_ready=True,
        )
        baseline_streams = (baseline_stdout, baseline_stderr)
        reap_errors, baseline_reaped_status = _reap_container(docker, baseline_name)
        if not reap_errors:
            names.remove(baseline_name)
        protocol = baseline.get("protocol", {})
        if baseline_reaped_status is not None:
            # Preserve the status observed while reaping in its own field;
            # helper sentinels never become target/container exit statuses.
            protocol["cleanupContainerStatus"] = baseline_reaped_status
            baseline["cleanupContainerStatus"] = baseline_reaped_status
        if reap_errors:
            if baseline.get("actual") == "accepted-and-runs":
                baseline["actual"] = "runtime-failure"
            baseline["reason"] = "baseline container cleanup/status verification failed: " + "; ".join(reap_errors)

        if pack_status == 0 and wrapper is not None:
            outer_name = f"urp-bionic-node-outer-{os.getpid()}-{time.monotonic_ns()}"
            names.append(outer_name)
            _register_container_name(outer_name)
            outer_argv = substitute_outer_argv(baseline_argv, "/usr/local/bin/urprotect-packed")
            outer_create_args = build_target_container_args(
                outer_name,
                transient_image,
                execution,
                outer_argv,
                exec_script=target_script,
                wrapper_file=wrapper_root / "urprotect-packed",
            )
            outer, outer_stdout, outer_stderr = _run_one_target(
                docker=docker, name=outer_name, create_args=outer_create_args,
                budget=budget, deadline=execution_deadline, context=context, setup_ready=True,
            )
            outer_streams = (outer_stdout, outer_stderr)
            reap_errors, outer_reaped_status = _reap_container(docker, outer_name)
            if not reap_errors:
                names.remove(outer_name)
            protocol = outer.get("protocol", {})
            if outer_reaped_status is not None:
                # Never promote a status recovered during helper cleanup to a
                # target/container exit status.
                protocol["cleanupContainerStatus"] = outer_reaped_status
                outer["cleanupContainerStatus"] = outer_reaped_status
            if reap_errors:
                if outer.get("actual") == "accepted-and-runs":
                    outer["actual"] = "runtime-failure"
                outer["reason"] = "outer container cleanup/status verification failed: " + "; ".join(reap_errors)
        else:
            reason = pack_error or "profile-matched pack did not publish a wrapper"
            protocol = _preflight_layer(context, "unexpected-rejection", reason, "helper-protocol")
            outer = {**protocol, "protocol": protocol["protocol"], "preflightOutcome": "preflight-product-failure"}

    except RunnerError as error:
        failure = error
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        failure = RunnerError(f"bionic Node.js runner failed before a verified result: {error}", "product")
    finally:
        # The first HUP/INT/TERM unwinds into this block.  Ignore repeats while
        # each named container is reaped; otherwise a second signal could
        # interrupt Docker cleanup and let the evidence root disappear under a
        # still-running Docker client.
        for signum in old_handlers:
            signal.signal(signum, signal.SIG_IGN)
        if names:
            cleanup_messages: list[str] = []
            for name in list(names):
                reap_errors, _ = _reap_container(docker, name, budget_seconds=5.0)
                cleanup_messages.extend(reap_errors)
                if not reap_errors:
                    names.remove(name)
            cleanup_error = "; ".join(cleanup_messages) if names else None
        if names and transient_image is not None:
            image_cleanup = {
                "status": "blocked-by-live-containers",
                "absenceVerified": False,
                "attempts": 0,
                "authority": CLEANUP_AUTHORITY,
                "reason": "temporary image cleanup was deferred because named containers remain",
            }
            cleanup_error = cleanup_error or image_cleanup["reason"]
        elif transient_image is not None:
            image_cleanup = _remove_transient_image(docker, transient_image)
            if image_cleanup.get("absenceVerified") is not True:
                cleanup_error = cleanup_error or str(image_cleanup.get("reason") or "temporary runtime image cleanup failed")
            elif transient_image_registered:
                try:
                    _mark_worker_resource_removed(transient_image, "image")
                except RunnerError as error:
                    cleanup_error = cleanup_error or str(error)
        work_root_retained = _cleanup_work_root(
            work_root,
            containers_absent=not names,
            image_absent=image_cleanup.get("absenceVerified") is True,
            cleanup_error=cleanup_error,
        )
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)

    if context is None:
        # Lock-validation errors still produce an inspectable host-owned result, but
        # are never promoted to runtime compatibility evidence.  Preserve the
        # reviewed execution/path identity when the lock document itself remains
        # readable, even though semantic lock validation stopped before packing.
        fallback_execution: dict[str, Any] = {
            "timeoutSeconds": 30,
            "outputBytes": 1048576,
            "memoryBytes": 536870912,
            "processLimit": 32,
            "expectedStatus": 0,
            "outerMode": args.outer_mode,
            "pathPolicy": "absolute-dt-runpath-preserved",
            "runpath": "",
            "loader": "/system/bin/linker64",
        }
        try:
            fallback_lock = json.loads(args.lock.read_text(encoding="utf-8"))
            locked_execution = fallback_lock.get("execution")
            if isinstance(locked_execution, dict):
                for field in ("timeoutSeconds", "outputBytes", "memoryBytes", "processLimit", "expectedStatus", "outerMode", "pathPolicy", "runpath", "loader"):
                    if field in locked_execution:
                        fallback_execution[field] = locked_execution[field]
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            pass
        fallback: dict[str, Any] = {
            "execution": fallback_execution,
            "lockSha256": lock_file_sha256(args.lock) if args.lock.is_file() else "0" * 64,
            "artifactPath": "",
            "source": {"sha256": args.archive_sha256},
            "runpath": fallback_execution.get("runpath", ""),
        }
        context = fallback
        budget = OutputBudget(0)
    containers_reaped = not names
    if not containers_reaped:
        for observed in (baseline, outer):
            if observed is not None and observed.get("actual") == "accepted-and-runs":
                observed["actual"] = "runtime-failure"
                observed["reason"] = "named Docker container cleanup was not verified"
    if failure is not None:
        category = failure.category
        actual = "environment-unavailable" if category == "environment" else "runtime-failure" if category in {"timeout", "output"} else "unexpected-rejection"
        outcome = "helper-environment" if category == "environment" else "helper-timeout" if category == "timeout" else "helper-output-limit" if category == "output" else "helper-protocol"
        baseline_was_observed = baseline is not None
        outer_was_observed = outer is not None
        baseline = baseline or _preflight_layer(context, actual, str(failure), outcome)
        outer = outer or _preflight_layer(context, actual, str(failure), outcome)
        for observed, existed in ((baseline, baseline_was_observed), (outer, outer_was_observed)):
            if not existed:
                observed["actual"] = actual
                if actual == "environment-unavailable":
                    observed["preflightOutcome"] = "preflight-environment-unavailable"
                elif actual == "unexpected-rejection":
                    observed["preflightOutcome"] = "preflight-product-failure"
        if cleanup_error:
            if not baseline_was_observed:
                baseline["reason"] = f"{failure}; cleanup: {cleanup_error}"
            if not outer_was_observed:
                outer["reason"] = f"{failure}; cleanup: {cleanup_error}"

    assert baseline is not None and outer is not None
    if context.get("runpath"):
        runpath = context["runpath"]
    else:
        runpath = ""
    if not pack_report:
        locked_base_image = context.get("lock", {}).get("baseImage", {}) if isinstance(context.get("lock"), dict) else {}
        locked_image_id = locked_base_image.get("id") if isinstance(locked_base_image, dict) else None
        if not isinstance(locked_image_id, str) or not locked_image_id:
            try:
                lock_document = json.loads(args.lock.read_text(encoding="utf-8"))
                candidate_image = lock_document.get("baseImage", {}).get("id")
                locked_image_id = candidate_image if isinstance(candidate_image, str) else ""
            except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
                locked_image_id = ""
        pack_report = {
            "schemaVersion": 1,
            "toolVersion": "runner-boundary",
            "success": False,
            "category": failure.category if failure is not None else "preflight",
            "payload": {},
            "output": {"published": False},
            "diagnostics": [{"severity": "Error", "code": "bionic.preflight", "message": str(failure or "preflight did not complete"), "offset": None}],
            "cliExitCode": None,
            "executionMode": context["execution"]["outerMode"],
            "pathPolicy": context["execution"]["pathPolicy"],
            "runpath": runpath or context["execution"].get("runpath", ""),
            "lockSha256": context["lockSha256"],
            "image": locked_base_image.get("requestedRef", args.image) if isinstance(locked_base_image, dict) else args.image,
            "imageId": locked_image_id,
            "loader": context["execution"].get("loader", "/system/bin/linker64"),
            "packInvocation": {"attempted": False},
        }
        _write(args.artifact_root / "outer-pack.json", json.dumps(pack_report, indent=2, sort_keys=True) + "\n")
    report_image_id = (
        pack_report.get("imageId")
        if isinstance(pack_report.get("imageId"), str)
        else context.get("lock", {}).get("baseImage", {}).get("id", "")
    )
    result = _write_evidence(
        artifact_root=args.artifact_root,
        work_root=work_root or args.artifact_root,
        context=context,
        image=args.image,
        image_id=report_image_id,
        source_sha=args.sha256,
        runtime_sha=runtime_sha,
        setup_status=setup_status,
        baseline=baseline,
        outer=outer,
        baseline_streams=baseline_streams,
        outer_streams=outer_streams,
        pack_status=pack_status,
        pack_report=pack_report,
        runpath=runpath,
        budget=budget,
        containers_reaped=containers_reaped,
        image_cleanup=image_cleanup,
        work_root_retained=work_root_retained,
    )
    if failure is not None:
        print(str(failure), file=sys.stderr)
        return 125 if failure.category == "environment" else 124 if failure.category == "timeout" else 1
    return 0 if result["status"] == "passed" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--cli-dll", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=LOCK_DEFAULT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_DEFAULT)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--outer-mode", default="outer-path-preserving")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return _run(args)
    except KeyboardInterrupt:
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
