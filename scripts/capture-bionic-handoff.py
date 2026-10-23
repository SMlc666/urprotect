#!/usr/bin/env python3
"""Run one pinned Bionic bridge command and retain its exact invocation/result."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Sequence

LABEL = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> int:
    print(f"Bionic handoff capture: {message}", file=sys.stderr)
    return 2


def write_new(root_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o644, dir_fd=root_fd)
    try:
        offset = 0
        while offset < len(data):
            count = os.write(descriptor, data[offset:])
            if count <= 0:
                raise OSError("no progress while retaining Bionic handoff sidecar")
            offset += count
    finally:
        os.close(descriptor)


def validate_record(path: Path, expected_status: int, process_status: int) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("handoff record read requires O_NOFOLLOW")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > 1024 * 1024:
            raise ValueError("handoff record is not a bounded regular file")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(64 * 1024, before.st_size - len(content)))
            if not chunk:
                raise ValueError("handoff record was truncated while reading")
            content.extend(chunk)
        if os.read(descriptor, 1):
            raise ValueError("handoff record grew while reading")
        after = os.fstat(descriptor)
        before_id = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if before_id != after_id or not stat.S_ISREG(after.st_mode):
            raise ValueError("handoff record changed while reading")
    finally:
        os.close(descriptor)
    record = json.loads(content.decode("utf-8", errors="strict"))
    if not isinstance(record, dict):
        raise ValueError("handoff record is not an object")
    if type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1:
        raise ValueError("handoff record schemaVersion is not the exact integer 1")
    if record.get("stage") != "host-context-handoff" or record.get("status") != "passed":
        raise ValueError("handoff record does not report a passed HostContext handoff")
    if type(record.get("entryStatus")) is not int or record["entryStatus"] != expected_status:
        raise ValueError("handoff record entryStatus differs from the expected exact integer")
    if type(record.get("processStatus")) is not int or record["processStatus"] != process_status:
        raise ValueError("handoff record processStatus differs from the captured process status")
    if record.get("releaseStatus") != "passed" or record.get("releaseOrder") != "entry-dispatch-before-release-image":
        raise ValueError("handoff record release evidence is incomplete")
    if record.get("loaderId") != "host-context.sealed-memfd.dlopen" or record.get("firstFailureStage") is not None:
        raise ValueError("handoff record loader/failure evidence is invalid")
    if not isinstance(record.get("nativeImageSha256"), str) or not DIGEST.fullmatch(record["nativeImageSha256"]):
        raise ValueError("handoff record Native Image digest is malformed")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--root", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--expected-status", required=True)
    try:
        options, command = parser.parse_known_args(argv[1:])
    except SystemExit:
        return 2
    if not LABEL.fullmatch(options.label):
        return fail("label is malformed")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", options.expected_status):
        return fail("expected process status is not a canonical bounded integer")
    expected_status = int(options.expected_status)
    if expected_status > 255:
        return fail("expected process status exceeds the shell exit range")
    if command and command[0] == "--":
        command = command[1:]
    if not command or not command[0]:
        return fail("command is missing")

    root = Path(options.root)
    record_path = Path(options.record)
    try:
        resolved = root.resolve(strict=True)
        if resolved != root.absolute() or not resolved.is_dir():
            return fail("evidence root is not a real directory")
        record_parent = record_path.parent.resolve(strict=True)
        if record_parent != resolved or record_path.is_symlink() or record_path.exists():
            return fail("handoff record must be a new direct child of the evidence root")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            return fail("safe evidence-root flags are unavailable")
        root_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | directory | nofollow)
    except (OSError, RuntimeError) as error:
        return fail(f"evidence root or handoff path cannot be opened safely: {error}")

    status_name = f"{options.label}.process-status"
    stdout_name = f"{options.label}.stdout"
    stderr_name = f"{options.label}.stderr"
    command_name = f"{options.label}.command.json"
    stdout_fd = stderr_fd = -1
    try:
        write_new(
            root_fd,
            command_name,
            (json.dumps({"schemaVersion": 1, "argv": list(command)}, indent=2) + "\n").encode(),
        )
        stdout_fd = os.open(
            stdout_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
            0o644,
            dir_fd=root_fd,
        )
        stderr_fd = os.open(
            stderr_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
            0o644,
            dir_fd=root_fd,
        )
        try:
            completed = subprocess.run(command, stdout=stdout_fd, stderr=stderr_fd, check=False)
            status = completed.returncode if completed.returncode >= 0 else 128 - completed.returncode
        except OSError as error:
            os.write(stderr_fd, f"unable to execute Bionic handoff command: {error}\n".encode())
            status = 127
        write_new(root_fd, status_name, f"{status}\n".encode("ascii"))
    except OSError as error:
        return fail(f"could not retain invocation/result sidecars: {error}")
    finally:
        if stdout_fd >= 0:
            os.close(stdout_fd)
        if stderr_fd >= 0:
            os.close(stderr_fd)
        os.close(root_fd)

    # Status and streams are durable before any success-record parsing begins.
    if status != expected_status:
        print(
            f"Bionic handoff process status {status} differs from expected {expected_status}; sidecars retained",
            file=sys.stderr,
        )
        return status if status != 0 else 1
    try:
        validate_record(record_path, expected_status, status)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"Bionic handoff success record is missing or malformed: {error}; sidecars retained", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
