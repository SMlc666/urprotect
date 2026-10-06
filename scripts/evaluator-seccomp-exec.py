#!/usr/bin/env python3
"""Load a minimal network-deny seccomp filter and exec the evaluator command."""
from __future__ import annotations

import ctypes
import os
import platform
import struct
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000 | 1
SECCOMP_RET_ALLOW = 0x7FFF0000
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06
AUDIT_ARCH = {
    "aarch64": (0xC00000B7, (198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 243, 269)),
    "arm64": (0xC00000B7, (198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 243, 269)),
    "x86_64": (0xC000003E, (41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 299, 307)),
}


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: evaluator-seccomp-exec.py COMMAND [ARG ...]", file=sys.stderr)
        return 2
    arch, syscalls = AUDIT_ARCH.get(platform.machine().lower(), AUDIT_ARCH["x86_64"])
    program: list[tuple[int, int, int, int]] = [
        (BPF_LD_W_ABS, 0, 0, 4),
        (BPF_JMP_JEQ_K, 1, 0, arch),
        (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_LD_W_ABS, 0, 0, 0),
    ]
    for syscall in syscalls:
        program.extend(((BPF_JMP_JEQ_K, 0, 1, syscall), (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO)))
    program.append((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    filters = (SockFilter * len(program))(*(SockFilter(*instruction) for instruction in program))
    fprog = SockFprog(len(program), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
