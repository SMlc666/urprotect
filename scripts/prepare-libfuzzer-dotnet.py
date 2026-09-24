#!/usr/bin/env python3
"""Patch the pinned libFuzzer bridge to use file-backed mmap instead of SysV IPC."""

from __future__ import annotations

from pathlib import Path
import sys


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one patch anchor, found {count}: {old[:80]!r}")
    return text.replace(old, new)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare-libfuzzer-dotnet.py SOURCE OUTPUT")

    source, output = map(Path, sys.argv[1:])
    text = source.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '#include <sys/shm.h>\n',
        '#include <fcntl.h>\n#include <limits.h>\n#include <sys/mman.h>\n',
    )
    text = replace_once(
        text,
        'static int shm_id;\n',
        'static int shm_fd;\nstatic char shm_path[PATH_MAX];\n',
    )
    text = replace_once(
        text,
        '''static void remove_shm()\n{\n    shmctl(shm_id, IPC_RMID, NULL);\n}\n''',
        '''static void remove_shm()\n{\n    if (trace_bits && trace_bits != MAP_FAILED)\n    {\n        munmap(trace_bits, MAP_SIZE + DATA_SIZE);\n    }\n    if (shm_fd >= 0)\n    {\n        close(shm_fd);\n    }\n    if (shm_path[0])\n    {\n        unlink(shm_path);\n    }\n}\n''',
    )
    text = replace_once(
        text,
        '''    shm_id = shmget(IPC_PRIVATE, MAP_SIZE + DATA_SIZE, IPC_CREAT | IPC_EXCL | 0600);\n\n    if (shm_id < 0)\n    {\n        die_sys("shmget() failed");\n    }\n\n    atexit(remove_shm);\n\n    trace_bits = static_cast<uint8_t *>(shmat(shm_id, NULL, 0));\n\n    if (trace_bits == (void *)-1)\n    {\n        die_sys("shmat() failed");\n    }\n''',
        '''    char shm_template[] = "/tmp/urprotect-libfuzzer-XXXXXX";\n    shm_fd = mkstemp(shm_template);\n    if (shm_fd < 0)\n    {\n        die_sys("mkstemp() failed");\n    }\n    strncpy(shm_path, shm_template, sizeof(shm_path) - 1);\n    shm_path[sizeof(shm_path) - 1] = '\\0';\n    if (ftruncate(shm_fd, MAP_SIZE + DATA_SIZE) != 0)\n    {\n        die_sys("ftruncate() failed");\n    }\n    trace_bits = static_cast<uint8_t *>(mmap(\n        NULL, MAP_SIZE + DATA_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0));\n    if (trace_bits == MAP_FAILED)\n    {\n        die_sys("mmap() failed");\n    }\n    if (setenv("__LIBFUZZER_SHM_PATH", shm_path, 1))\n    {\n        die_sys("setenv() failed setting shared memory path");\n    }\n    atexit(remove_shm);\n''',
    )
    text = replace_once(
        text,
        '''        char shm_str[12];\n        sprintf(shm_str, "%d", shm_id);\n\n        if (setenv(SHM_ID_VAR, shm_str, 1))\n        {\n            die_sys("setenv() failed setting shared memory ID");\n        }\n\n''',
        '',
    )
    output.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
