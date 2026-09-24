#!/usr/bin/env python3
"""Run one acquired AArch64 sample inside a bounded networkless bubblewrap root.

Only the real-sample matrix runner calls this helper.  The rootfs is mounted
read-only, the sample gets a temporary /tmp, and the helper retains bounded
stdout/stderr without uploading the rootfs or executable.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import os
from pathlib import Path
import resource
import selectors
import signal
import shutil
import subprocess
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--stdout", required=True, type=Path)
    parser.add_argument("--stderr", required=True, type=Path)
    parser.add_argument("--timeout", required=True, type=int)
    parser.add_argument("--memory-bytes", required=True, type=int)
    parser.add_argument("--process-limit", required=True, type=int)
    parser.add_argument("--output-limit", required=True, type=int)
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


def main() -> int:
    arguments = parse_args()
    rootfs = arguments.rootfs.resolve()
    if not rootfs.is_dir() or rootfs.is_symlink():
        print("environment-unavailable: rootfs is not a regular directory", file=sys.stderr)
        return 125
    if not arguments.command or arguments.command[0] != "--":
        print("usage: command must be preceded by --", file=sys.stderr)
        return 2
    command = arguments.command[1:]
    if not command or any("\x00" in value for value in command):
        print("usage: isolated command is empty or contains NUL", file=sys.stderr)
        return 2
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        print("environment-unavailable: bubblewrap is missing", file=sys.stderr)
        return 125
    for path in (arguments.stdout, arguments.stderr):
        path.parent.mkdir(parents=True, exist_ok=True)

    # Mount the archive-derived root as '/', not the checkout or the host's
    # writable filesystem.  /tmp is the only writable target mount.
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
        "--ro-bind", str(rootfs), "/",
        "--tmpfs", "/tmp",
        "--proc", "/proc",
        "--dev", "/dev",
        "--chdir", "/tmp",
        "--setenv", "PATH", "/bin:/usr/bin:/sbin:/usr/sbin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "LANG", "C",
        "--",
        *command,
    ]
    try:
        process = subprocess.Popen(
            wrapped,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=lambda: bounded_preexec(
                arguments.timeout,
                arguments.memory_bytes,
                arguments.process_limit,
                arguments.output_limit,
                set_no_new_privs=sudo is None,
            ),
        )
    except (OSError, ValueError) as error:
        print(f"environment-unavailable: could not start bubblewrap: {error}", file=sys.stderr)
        return 125

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output_limited = False
    deadline = time.monotonic() + arguments.timeout
    while selector.get_map():
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            output_limited = True
            break
        for key, _ in selector.select(timeout=min(remaining, 0.25)):
            try:
                chunk = os.read(key.fd, 64 * 1024)
            except OSError as error:
                if error.errno in {errno.EIO, errno.EBADF}:
                    chunk = b""
                else:
                    raise
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            if append_output(buffers, key.data, chunk, arguments.output_limit):
                output_limited = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    return_code = process.wait()
    selector.close()
    if output_limited and return_code == 0:
        return_code = 124
    arguments.stdout.write_bytes(bytes(buffers["stdout"]))
    arguments.stderr.write_bytes(bytes(buffers["stderr"]))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
