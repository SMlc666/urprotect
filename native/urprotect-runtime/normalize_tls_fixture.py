#!/usr/bin/env python3
"""Normalize the audited AArch64 TLSGD test fixture's ELF TLS symbol value.

GNU ld linking the deliberately bare-metal test DSO can leave the STT_TLS
symbol's st_value as the section virtual address instead of the required
PT_TLS-relative offset. This script only converts that precise, proven shape.
It never changes the production HostContext validator or the relocation.
"""

import argparse
import struct
from pathlib import Path

def require(ok, message):
    if not ok:
        raise ValueError(message)


def normalize(path: Path, symbol_name: str) -> None:
    data = bytearray(path.read_bytes())
    require(len(data) >= 64 and data[:4] == b"\x7fELF" and
            data[4] == 2 and data[5] == 1, "expected ELF64 little-endian")
    require(struct.unpack_from("<H", data, 16)[0] == 3, "expected ET_DYN")
    require(struct.unpack_from("<H", data, 18)[0] == 183, "expected AArch64 ELF")
    phoff, shoff = struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<Q", data, 40)[0]
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 54)
    require(phentsize == 56 and phnum > 0
            and phoff + phentsize * phnum <= len(data), "invalid program headers")
    require(shentsize == 64 and shnum > 0
            and shoff + shentsize * shnum <= len(data), "invalid section headers")
    tls = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if struct.unpack_from("<I", data, off)[0] != 7:
            continue
        vaddr, filesz, memsz = (
            struct.unpack_from("<Q", data, off + 16)[0],
            struct.unpack_from("<Q", data, off + 32)[0],
            struct.unpack_from("<Q", data, off + 40)[0])
        require(memsz > 0 and filesz <= memsz, "malformed PT_TLS")
        tls.append((vaddr, memsz))
    require(len(tls) == 1, "requires exactly one nonempty PT_TLS")
    tls_vaddr, tls_size = tls[0]

    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        stype, = struct.unpack_from("<I", data, off + 4)
        sec_off, sec_len = struct.unpack_from("<QQ", data, off + 24)
        link, = struct.unpack_from("<I", data, off + 40)
        entsize, = struct.unpack_from("<Q", data, off + 56)
        if sec_len:
            require(sec_off <= len(data) and sec_len <= len(data) - sec_off,
                    "section outside ELF file")
        sections.append((stype, sec_off, sec_len, link, entsize))

    found = {2: 0, 11: 0}
    changed = 0
    for stype, sec_off, sec_len, link, entsize in sections:
        if stype not in found:
            continue
        require(entsize == 24 and sec_len % 24 == 0
                and link < len(sections), "invalid symbol table")
        linked_type, str_off, str_len, _, _ = sections[link]
        require(linked_type == 3, "symbol names not from STRTAB")
        for i in range(sec_len // 24):
            off = sec_off + i * 24
            name_at, = struct.unpack_from("<I", data, off)
            require(name_at < str_len, "invalid symbol name index")
            end = data.find(b"\0", str_off + name_at, str_off + str_len)
            require(end >= 0, "unterminated symbol name")
            name = bytes(data[str_off + name_at:end]).decode("ascii")
            if name != symbol_name:
                continue
            info = data[off + 4]
            shndx, = struct.unpack_from("<H", data, off + 6)
            value, size = struct.unpack_from("<QQ", data, off + 8)
            require((info & 15) == 6 and shndx != 0, "fixture symbol must be defined TLS")
            require(size > 0 and size <= tls_size, "invalid fixture TLS extent")
            if tls_vaddr <= value and value - tls_vaddr <= tls_size - size:
                offset = value - tls_vaddr
                struct.pack_into("<Q", data, off + 8, offset)
                changed += 1
            else:
                # Permit toolchains that already emitted the correct TLS
                # block-relative value. Reject all other representations.
                require(value <= tls_size - size, "TLS symbol neither VA nor valid offset")
            found[stype] += 1

    require(found[2] == 1 and found[11] == 1,
            "exactly one TLS symbol required in SYMTAB and DYNSYM")
    path.write_bytes(data)
    print(f"TLS fixture normalized: {symbol_name}, PT_TLS=0x{tls_vaddr:x}, "
          f"size={tls_size}, repairedTables={changed}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("symbol")
    args = parser.parse_args()
    try:
        normalize(args.image, args.symbol)
    except (ValueError, OSError, UnicodeError) as e:
        parser.exit(1, f"invalid TLS fixture: {e}\n")
