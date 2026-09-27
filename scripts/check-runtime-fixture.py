#!/usr/bin/env python3
"""Validate a bounded readelf report for a runtime-matrix PIE fixture."""
import re
import sys
from pathlib import Path

MAX_BYTES = 256 * 1024
MAX_LINES = 4096
MAX_LINE = 4096
MAX_LOADS = 64


def fail(message: str) -> None:
    raise SystemExit(f"runtime fixture: {message}")


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: check-runtime-fixture.py READELF_OUTPUT ALIGN INTERPRETER NEEDED"
        )

    path = Path(sys.argv[1])
    try:
        expected_align = int(sys.argv[2], 0)
    except ValueError:
        fail("expected alignment must be an integer")
    if expected_align <= 0 or expected_align & (expected_align - 1):
        fail("expected alignment must be a positive power of two")

    if path.stat().st_size > MAX_BYTES:
        fail("readelf output exceeds 256KiB bound")
    lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    if len(lines) > MAX_LINES or any(len(line) > MAX_LINE for line in lines):
        fail("readelf output exceeds line-count or line-length bound")

    text = "\n".join(lines)
    headers: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    if headers.get("Class") != "ELF64":
        fail("fixture is not ELF64")
    if headers.get("Data") != "2's complement, little endian":
        fail("fixture is not little-endian")
    if headers.get("Machine") != "AArch64":
        fail("fixture is not AArch64")
    if not headers.get("Type", "").startswith("DYN"):
        fail("fixture is not ET_DYN")
    if "Dynamic section at offset" not in text and "(NEEDED)" not in text:
        fail("fixture has no dynamic section")
    if not re.search(r"^\s*DYNAMIC\s+0x", text, re.MULTILINE):
        fail("fixture has no PT_DYNAMIC program header")

    interpreters = re.findall(
        r"Requesting program interpreter:\s*([^\]\s]+)", text
    )
    if interpreters != [sys.argv[3]]:
        fail(f"expected one {sys.argv[3]} interpreter, got {interpreters}")
    needed = re.findall(r"\(NEEDED\).*?Shared library: \[([^\]]+)\]", text)
    if needed != [sys.argv[4]]:
        fail(f"expected only DT_NEEDED {sys.argv[4]}, got {needed}")
    if re.search(r"\((?:RPATH|RUNPATH)\)", text):
        fail("fixture unexpectedly declares RPATH or RUNPATH")

    load_alignments: list[int] = []
    for line in lines:
        fields = line.split()
        if fields and fields[0] == "LOAD":
            if len(fields) < 8:
                fail(f"malformed PT_LOAD row: {line}")
            try:
                alignment = int(fields[-1], 0)
            except ValueError:
                fail(f"invalid PT_LOAD p_align: {line}")
            load_alignments.append(alignment)
            if len(load_alignments) > MAX_LOADS:
                fail("PT_LOAD count exceeds bound")
    if not load_alignments:
        fail("readelf output contains no PT_LOAD rows")
    if any(alignment != expected_align for alignment in load_alignments):
        fail(
            f"expected every PT_LOAD p_align={expected_align:#x}, "
            f"got {load_alignments}"
        )

    print(f"validated_machine=AArch64")
    print("validated_type=ET_DYN")
    print(f"validated_interpreter={interpreters[0]}")
    print(f"validated_needed={needed[0]}")
    print(f"validated_pt_load_count={len(load_alignments)}")
    print(f"expected_p_align={expected_align:#x}")


if __name__ == "__main__":
    main()
