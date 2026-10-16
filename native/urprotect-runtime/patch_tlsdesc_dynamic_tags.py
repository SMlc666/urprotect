#!/usr/bin/env python3
"""Add the bounded DT_TLSDESC_PLT/GOT pair to the native TLSDESC fixture.

GNU ld omits these optional dynamic tags for the BIND_NOW link shape used by
the HostContext fixture. The fixture already reserves bounded zero dynamic
entries, so this script fills that declared space without changing any load
segment or section payload.
"""

from __future__ import annotations

import argparse
import os
import struct
import tempfile
from pathlib import Path

PT_DYNAMIC = 2
PT_LOAD = 1
SHT_STRTAB = 3
SHT_PROGBITS = 1
DT_NULL = 0
DT_PLTGOT = 3
DT_FLAGS = 30
DT_JMPREL = 23
DT_PLTRELSZ = 2
DT_PLTREL = 20
DT_FLAGS_1 = 0x6FFFFFFB
DT_TLSDESC_PLT = 0x6FFFFEF6
DT_TLSDESC_GOT = 0x6FFFFEF7
DT_RELA = 7
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
R_AARCH64_TLSDESC = 1031
ELF64_HEADER_SIZE = 64
ELF64_PHDR_SIZE = 56
ELF64_SHDR_SIZE = 64
DYNAMIC_ENTRY_SIZE = 16
RELA_ENTRY_SIZE = 24


class FixtureError(Exception):
    pass


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def checked_range(data: bytes, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise FixtureError(f"{label} is outside the bounded fixture")
    return memoryview(data)[offset : offset + size]


def vaddr_to_offset(data: bytes, program_headers: list[tuple[int, int, int, int, int, int]], address: int, size: int) -> int:
    matches: list[int] = []
    for kind, flags, file_offset, virtual_address, file_size, memory_size in program_headers:
        if kind != PT_LOAD:
            continue
        if address < virtual_address:
            continue
        delta = address - virtual_address
        if delta <= file_size and size <= file_size - delta:
            matches.append(file_offset + delta)
    if len(matches) != 1:
        raise FixtureError(f"address 0x{address:x} has {len(matches)} file-backed PT_LOAD mappings")
    checked_range(data, matches[0], size, "mapped range")
    return matches[0]


def section_names(data: bytes) -> dict[str, tuple[int, int, int]]:
    shoff = u64(data, 40)
    shentsize = u16(data, 58)
    shnum = u16(data, 60)
    shstrndx = u16(data, 62)
    if shentsize != ELF64_SHDR_SIZE or shnum == 0 or shstrndx >= shnum:
        raise FixtureError("fixture has no bounded ELF64 section-name table")
    checked_range(data, shoff, shentsize * shnum, "section-header table")
    shstr_offset = u64(data, shoff + shstrndx * shentsize + 24)
    shstr_size = u64(data, shoff + shstrndx * shentsize + 32)
    strings = bytes(checked_range(data, shstr_offset, shstr_size, "section-name table"))

    def read_name(offset: int) -> str:
        if offset >= len(strings):
            raise FixtureError("section name offset is outside the string table")
        end = strings.find(b"\0", offset)
        if end < 0:
            raise FixtureError("section name is unterminated")
        return strings[offset:end].decode("ascii")

    result: dict[str, tuple[int, int, int]] = {}
    for index in range(shnum):
        base = shoff + index * shentsize
        name = read_name(u32(data, base))
        result[name] = (u64(data, base + 16), u64(data, base + 24), u64(data, base + 32))
    return result


def patch(path: Path) -> None:
    original = path.read_bytes()
    if len(original) < ELF64_HEADER_SIZE or original[:4] != b"\x7fELF" or original[4:6] != b"\x02\x01":
        raise FixtureError("fixture must be ELF64 little-endian")
    if u16(original, 16) != 3 or u16(original, 18) != 183:
        raise FixtureError("fixture must be AArch64 ET_DYN")

    phoff = u64(original, 32)
    phentsize = u16(original, 54)
    phnum = u16(original, 56)
    if phentsize != ELF64_PHDR_SIZE or phnum == 0 or phnum > 128:
        raise FixtureError("fixture program-header table is outside the contract")
    checked_range(original, phoff, phentsize * phnum, "program-header table")

    program_headers: list[tuple[int, int, int, int, int, int]] = []
    dynamic_ranges: list[tuple[int, int]] = []
    for index in range(phnum):
        base = phoff + index * phentsize
        kind = u32(original, base)
        flags = u32(original, base + 4)
        file_offset = u64(original, base + 8)
        virtual_address = u64(original, base + 16)
        file_size = u64(original, base + 32)
        memory_size = u64(original, base + 40)
        checked_range(original, file_offset, file_size, f"program header {index}")
        program_headers.append((kind, flags, file_offset, virtual_address, file_size, memory_size))
        if kind == PT_DYNAMIC:
            dynamic_ranges.append((file_offset, file_size))
    if len(dynamic_ranges) != 1:
        raise FixtureError("fixture must contain exactly one PT_DYNAMIC")

    dynamic_offset, dynamic_size = dynamic_ranges[0]
    if dynamic_size == 0 or dynamic_size % DYNAMIC_ENTRY_SIZE:
        raise FixtureError("PT_DYNAMIC size is not a bounded entry table")
    dynamic_count = dynamic_size // DYNAMIC_ENTRY_SIZE
    checked_range(original, dynamic_offset, dynamic_size, "PT_DYNAMIC")

    entries: list[tuple[int, int]] = []
    null_index = -1
    for index in range(dynamic_count):
        tag, value = struct.unpack_from("<QQ", original, dynamic_offset + index * DYNAMIC_ENTRY_SIZE)
        entries.append((tag, value))
        if tag == DT_NULL:
            null_index = index
            break
    if null_index < 0 or null_index + 2 >= dynamic_count:
        raise FixtureError("PT_DYNAMIC has no three-slot insertion point")
    if any(tag in (DT_TLSDESC_PLT, DT_TLSDESC_GOT) for tag, _ in entries):
        raise FixtureError("fixture already contains a TLSDESC dynamic tag")

    # Capacity is defined by physical bytes in PT_DYNAMIC, not by the parsed
    # prefix ending at DT_NULL. Require the terminator and both following slots
    # to be explicitly reserved zero entries before writing any of them.
    reserved_offset = dynamic_offset + null_index * DYNAMIC_ENTRY_SIZE
    reserved_size = 3 * DYNAMIC_ENTRY_SIZE
    checked_range(original, reserved_offset, reserved_size, "TLSDESC reserved dynamic entries")
    reserved_entries = [
        struct.unpack_from("<QQ", original, reserved_offset + index * DYNAMIC_ENTRY_SIZE)
        for index in range(3)
    ]
    if any(tag != DT_NULL or value != 0 for tag, value in reserved_entries):
        raise FixtureError("DT_NULL and the following two TLSDESC slots must be fully zero-filled")

    dynamic_map = {tag: value for tag, value in entries[:null_index]}
    if dynamic_map.get(DT_PLTREL) != DT_RELA:
        raise FixtureError("fixture PLT relocation table is not RELA")
    if not (dynamic_map.get(DT_FLAGS, 0) & DF_BIND_NOW or dynamic_map.get(DT_FLAGS_1, 0) & DF_1_NOW):
        raise FixtureError("fixture must retain BIND_NOW before TLSDESC tags are added")

    sections = section_names(original)
    if ".plt" not in sections:
        raise FixtureError("fixture has no .plt section")
    plt_address, _, plt_size = sections[".plt"]
    if plt_size < 6 * 4:
        raise FixtureError("TLSDESC resolver PLT is shorter than six instructions")

    jmprel = dynamic_map.get(DT_JMPREL)
    pltrelsz = dynamic_map.get(DT_PLTRELSZ)
    if jmprel is None or pltrelsz != RELA_ENTRY_SIZE:
        raise FixtureError("fixture must contain exactly one PLT RELA entry")
    rela_offset = vaddr_to_offset(original, program_headers, jmprel, RELA_ENTRY_SIZE)
    rela_info = u64(original, rela_offset + 8)
    rela_type = rela_info & 0xFFFFFFFF
    descriptor_address = u64(original, rela_offset)
    if rela_type != R_AARCH64_TLSDESC or descriptor_address % 8:
        raise FixtureError("fixture PLT RELA entry is not one aligned TLSDESC owner")
    resolver_got = descriptor_address - 8
    if resolver_got < descriptor_address - 0x1000:
        raise FixtureError("resolver GOT subtraction overflowed")

    def writable(address: int, size: int) -> bool:
        matches = 0
        for kind, flags, _, virtual_address, _, memory_size in program_headers:
            if kind == PT_LOAD and flags & 2 and address >= virtual_address:
                delta = address - virtual_address
                if delta <= memory_size and size <= memory_size - delta:
                    matches += 1
        return matches == 1

    if not writable(resolver_got, 8):
        raise FixtureError("derived DT_TLSDESC_GOT is not in one writable PT_LOAD")

    patched = bytearray(original)
    values = (
        (DT_TLSDESC_PLT, plt_address),
        (DT_TLSDESC_GOT, resolver_got),
        (DT_NULL, 0),
    )
    for index, (tag, value) in enumerate(values):
        struct.pack_into("<QQ", patched, dynamic_offset + (null_index + index) * DYNAMIC_ENTRY_SIZE, tag, value)

    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(patched)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    try:
        patch(args.fixture.resolve())
    except (FixtureError, OSError, struct.error) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
