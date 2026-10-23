#!/usr/bin/env python3
"""Validate one retained native-build exit-status sidecar and print its value."""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys
from typing import Sequence

CANONICAL_STATUS = re.compile(rb"(?:0|[1-9][0-9]{0,2})\n\Z")
MAX_STATUS_BYTES = 4
MAX_EXIT_STATUS = 255


def read_status(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("O_NOFOLLOW is unavailable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("status is not a regular file")
        if before.st_size < 2 or before.st_size > MAX_STATUS_BYTES:
            raise ValueError("status is empty, truncated, or exceeds its four-byte bound")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(content))
            if not chunk:
                raise ValueError("status was truncated while reading")
            content.extend(chunk)
        if os.read(descriptor, 1):
            raise ValueError("status grew while reading")
        after = os.fstat(descriptor)
        before_id = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if before_id != after_id or not stat.S_ISREG(after.st_mode):
            raise ValueError("status changed while reading")
    finally:
        os.close(descriptor)

    data = bytes(content)
    if CANONICAL_STATUS.fullmatch(data) is None:
        raise ValueError("status is not a canonical decimal exit status followed by exactly one LF")
    status = int(data[:-1])
    if status > MAX_EXIT_STATUS:
        raise ValueError("status is outside the shell exit range 0..255")
    return status


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2:
        print("usage: parse-native-build-status.py STATUS-PATH", file=sys.stderr)
        return 2
    try:
        print(read_status(Path(argv[1])))
    except (OSError, ValueError) as error:
        print(f"native build status is invalid: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
