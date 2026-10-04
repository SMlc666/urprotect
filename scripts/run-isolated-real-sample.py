#!/usr/bin/env python3
"""Run one acquired AArch64 sample inside a bounded networkless bubblewrap root.

Only the real-sample matrix runner calls this helper.  The rootfs is mounted
read-only, the sample gets a temporary /tmp, and the helper retains bounded
stdout/stderr without uploading the rootfs or executable.

The process status is intentionally reported through a small JSON protocol.
The helper's 124/125 sentinels are never inferred from the target's exit code:
``helperStatus`` is populated for helper timeout/setup outcomes, while
``targetStatus`` is populated only after the target has crossed the readiness
boundary.  Every record carries this helper's producer identity. Runner
preflight failures are recorded by the matrix runner separately and never use
this helper-result protocol. The matrix runner consumes this record instead of
treating the helper's process exit status as the target status.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import resource
import secrets
import selectors
import shutil
import signal
import subprocess
import sys
import time

from real_sample_schema import (
    ISOLATION_ENVIRONMENT_STATUS,
    ISOLATION_PRODUCER,
    ISOLATION_PROTOCOL_VERSION,
    ISOLATION_TIMEOUT_STATUS,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--stdout", required=True, type=Path)
    parser.add_argument("--stderr", required=True, type=Path)
    parser.add_argument("--result-json", required=True, type=Path)
    parser.add_argument("--timeout", required=True, type=int)
    parser.add_argument("--memory-bytes", required=True, type=int)
    parser.add_argument("--process-limit", required=True, type=int)
    parser.add_argument("--output-limit", required=True, type=int)
    parser.add_argument("--argv0", default=None)
    parser.add_argument("--dropper", default=None)
    parser.add_argument("--lock", default=None)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def bounded_preexec(
    timeout_seconds: int,
    memory_bytes: int,
    process_limit: int,
    output_limit: int,
    *,
    set_no_new_privs: bool,
) -> None:
    os.setsid()
    # PR_SET_NO_NEW_PRIVS=38, PR_SET_NO_NEW_PRIVS_ON=1.  Keep this in the
    # child before bubblewrap starts so the target cannot gain privileges even
    # on hosts whose bubblewrap predates --disable-setuid.
    if set_no_new_privs:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "prctl(PR_SET_NO_NEW_PRIVS) failed")
    resource.setrlimit(resource.RLIMIT_CPU, (timeout_seconds + 1, timeout_seconds + 1))
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))
    resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))


def append_output(buffers: dict[str, bytearray], name: str, chunk: bytes, limit: int) -> bool:
    current = buffers[name]
    if len(current) + len(chunk) <= limit:
        current.extend(chunk)
        return False
    remaining = max(0, limit - len(current))
    current.extend(chunk[:remaining])
    current.extend(b"\n[output-limit-exceeded]\n")
    return True


def write_result(
    path: Path,
    *,
    attempted: bool,
    helper_status: int | None,
    target_status: int | None,
    readiness_seen: bool,
    signal_number: int | None = None,
) -> None:
    if helper_status == ISOLATION_TIMEOUT_STATUS:
        outcome = "helper-timeout"
    elif helper_status == ISOLATION_ENVIRONMENT_STATUS:
        outcome = "helper-environment"
    elif target_status is not None:
        outcome = "target-exit"
    else:
        outcome = "helper-protocol"
    record: dict[str, object] = {
        "schemaVersion": ISOLATION_PROTOCOL_VERSION,
        "producer": ISOLATION_PRODUCER,
        "attempted": attempted,
        "helperStatus": helper_status,
        "targetStatus": target_status,
        "readinessSeen": readiness_seen,
        "outcome": outcome,
    }
    if signal_number is not None:
        record["targetSignal"] = signal_number
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def initialize_outputs(arguments: argparse.Namespace) -> None:
    for path in (arguments.stdout, arguments.stderr):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    arguments.result_json.parent.mkdir(parents=True, exist_ok=True)


def finish_without_target(
    arguments: argparse.Namespace,
    message: str,
    *,
    helper_status: int | None = ISOLATION_ENVIRONMENT_STATUS,
    return_status: int | None = None,
) -> int:
    print(message, file=sys.stderr)
    write_result(
        arguments.result_json,
        attempted=False,
        helper_status=helper_status,
        target_status=None,
        readiness_seen=False,
    )
    return helper_status if return_status is None else return_status


def main() -> int:
    arguments = parse_args()
    initialize_outputs(arguments)
    rootfs = arguments.rootfs.resolve()
    if not rootfs.is_dir() or rootfs.is_symlink():
        return finish_without_target(arguments, "environment-unavailable: rootfs is not a regular directory")
    if not arguments.command or arguments.command[0] != "--":
        return finish_without_target(
            arguments,
            "usage: command must be preceded by --",
            helper_status=None,
            return_status=2,
        )
    command = arguments.command[1:]
    if not command or any("\x00" in value for value in command):
        return finish_without_target(
            arguments,
            "usage: isolated command is empty or contains NUL",
            helper_status=None,
            return_status=2,
        )
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return finish_without_target(arguments, "environment-unavailable: bubblewrap is missing")

    lock_file = None
    if arguments.lock is not None:
        try:
            lock_file = open(arguments.lock, "a+")
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except OSError as error:
            if lock_file is not None:
                lock_file.close()
            return finish_without_target(arguments, f"environment-unavailable: could not lock isolation: {error}")

    # Mount the archive-derived root as '/', not the checkout or the host's
    # writable filesystem.  /tmp is the only writable target mount.
    argv0 = ["--argv0", arguments.argv0] if arguments.argv0 is not None else []
    dropper_bind: list[str] = []
    dropper_env: list[str] = []
    target_command = command
    if arguments.dropper is not None:
        dropper = Path(arguments.dropper).resolve()
        if not dropper.is_file() or dropper.is_symlink():
            if lock_file is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                lock_file.close()
            return finish_without_target(arguments, "environment-unavailable: isolation dropper is missing")
        dropper_bind = ["--dir", "/tmp/urp", "--ro-bind", str(dropper.parent), "/tmp/urp"]
        dropper_env = ["--setenv", "URP_ARGV0", arguments.argv0 or command[0]]
        argv0 = []
        target_command = [f"/tmp/urp/{dropper.name}", *command]
    ready_expected = arguments.dropper is not None
    ready_token = secrets.token_hex(32) if ready_expected else None
    ready_marker = (
        f"__URP_ISOLATION_READY__:{ready_token}__".encode("ascii")
        if ready_token is not None
        else None
    )
    if ready_token is not None:
        dropper_env.extend(["--setenv", "URP_READY_TOKEN", ready_token])
    # sudo can close unknown descriptors. The static dropper therefore emits
    # a per-run readiness marker on stderr only after bubblewrap has completed
    # namespace setup; the marker is removed before stderr is retained.
    sudo = shutil.which("sudo") if os.geteuid() != 0 else None

    wrapped = ([sudo, "-n"] if sudo else []) + [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--clearenv",
        "--cap-drop", "ALL",
        "--cap-add", "CAP_SETGID",
        "--cap-add", "CAP_SETUID",
        "--ro-bind", str(rootfs), "/",
        "--tmpfs", "/tmp",
        *dropper_bind,
        "--proc", "/proc",
        "--dev", "/dev",
        "--chdir", "/tmp",
        "--setenv", "PATH", "/bin:/usr/bin:/sbin:/usr/sbin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "TERM", "xterm",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "LD_LIBRARY_PATH", "/lib:/usr/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu/blas:/usr/lib/aarch64-linux-gnu/lapack:/lib/arm-linux-gnueabihf:/usr/lib/arm-linux-gnueabihf",
        *dropper_env,
        *argv0,
        "--",
        *target_command,
    ]

    def child_preexec() -> None:
        bounded_preexec(
            arguments.timeout,
            arguments.memory_bytes,
            arguments.process_limit,
            arguments.output_limit,
            set_no_new_privs=sudo is None,
        )

    try:
        process = subprocess.Popen(
            wrapped,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=child_preexec,
        )
    except (OSError, ValueError) as error:
        if lock_file is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
        return finish_without_target(arguments, f"environment-unavailable: could not start bubblewrap: {error}")

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output_limited = False
    timed_out = False
    deadline = time.monotonic() + arguments.timeout

    def kill_process_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def consume(key: selectors.SelectorKey) -> None:
        nonlocal output_limited
        try:
            chunk = os.read(key.fd, 64 * 1024)
        except OSError as error:
            if error.errno in {errno.EIO, errno.EBADF}:
                chunk = b""
            else:
                raise
        if not chunk:
            selector.unregister(key.fileobj)
            return
        if append_output(buffers, key.data, chunk, arguments.output_limit):
            output_limited = True
            kill_process_group()

    # Supervise the process itself, not just its stdout/stderr descriptors. A
    # target can close both streams and remain alive, so selector exhaustion is
    # never a completion condition.
    while process.poll() is None:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            timed_out = True
            kill_process_group()
            break
        if selector.get_map():
            events = selector.select(timeout=min(remaining, 0.25))
            for key, _ in events:
                consume(key)
                if output_limited:
                    break
        else:
            time.sleep(min(remaining, 0.05))
        if output_limited:
            break

    return_code = process.wait()
    # Drain bytes already available after the child exited, but do not wait for
    # a detached descendant that inherited a pipe descriptor.
    for key, _ in selector.select(timeout=0):
        consume(key)
    selector.close()
    process.stdout.close()
    process.stderr.close()

    captured_stderr = bytes(buffers["stderr"])
    ready_seen = ready_marker is not None and ready_marker in captured_stderr
    if ready_marker is not None:
        captured_stderr = captured_stderr.replace(ready_marker, b"")
    stderr_text = captured_stderr.lower()
    bwrap_setup_markers = (
        b"bubblewrap",
        b"bwrap:",
        b"setting up namespace",
        b"setting up uid map",
        b"creating new namespace",
        b"failed to set up",
    )
    setup_failed = not timed_out and not output_limited and not ready_seen and (
        ready_expected or any(marker in stderr_text for marker in bwrap_setup_markers)
    )

    arguments.stdout.write_bytes(bytes(buffers["stdout"]))
    arguments.stderr.write_bytes(captured_stderr)
    if lock_file is not None:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()

    if timed_out or output_limited:
        attempted = ready_seen if ready_expected else True
        write_result(
            arguments.result_json,
            attempted=attempted,
            helper_status=ISOLATION_TIMEOUT_STATUS,
            target_status=None,
            readiness_seen=ready_seen,
        )
        return ISOLATION_TIMEOUT_STATUS
    if setup_failed:
        print("environment-unavailable: bubblewrap setup or namespace creation failed", file=sys.stderr)
        write_result(
            arguments.result_json,
            attempted=False,
            helper_status=ISOLATION_ENVIRONMENT_STATUS,
            target_status=None,
            readiness_seen=False,
        )
        return ISOLATION_ENVIRONMENT_STATUS

    attempted = ready_seen if ready_expected else True
    if return_code >= 0:
        target_status: int | None = return_code
        signal_number = None
    else:
        signal_number = -return_code
        target_status = min(255, 128 + signal_number)
    write_result(
        arguments.result_json,
        attempted=attempted,
        helper_status=None,
        target_status=target_status,
        readiness_seen=ready_seen,
        signal_number=signal_number,
    )
    # Preserve the target's normal exit status for callers that still inspect
    # the process result.  The JSON protocol is authoritative when 124/125
    # collide with helper sentinels.
    return target_status if target_status is not None else 128 + (signal_number or 0)


if __name__ == "__main__":
    raise SystemExit(main())
