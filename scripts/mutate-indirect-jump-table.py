#!/usr/bin/env python3
"""Create a one-entry mutation for the bounded AArch64 relative-table negatives."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

U64_LIMIT = 1 << 64
PT_LOAD = 1
PF_X = 1
SHT_STRTAB = 3
SHT_DYNSYM = 11
STT_FUNC = 2
TABLE_ENTRY_COUNT = 4
ENTRY_WIDTH = 4
OUT_OF_RANGE_VALUE = 0x7FFFFFE0


def fail(message: str) -> None:
    raise SystemExit(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_image(data: bytes) -> tuple[list[dict[str, int]], dict[str, tuple[int, int, int]], dict[str, int]]:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        fail("input is not a bounded ELF64 little-endian image")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 3 or machine != 183:
        fail("input is not an AArch64 ET_DYN fixture")

    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or phnum == 0 or phnum > 4096 or phoff > len(data) or phnum * phentsize > len(data) - phoff:
        fail("input has an invalid or out-of-bounds program-header table")
    segments: list[dict[str, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, flags, file_offset, virtual_address, _physical, file_size, memory_size, _align = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_type != PT_LOAD:
            continue
        if (
            file_offset > len(data)
            or file_size > len(data) - file_offset
            or file_size > memory_size
            or virtual_address + memory_size > U64_LIMIT
        ):
            fail("input has an invalid PT_LOAD range")
        segments.append(
            {
                "flags": flags,
                "fileOffset": file_offset,
                "virtualAddress": virtual_address,
                "fileSize": file_size,
                "memorySize": memory_size,
            }
        )
    if not segments:
        fail("input has no PT_LOAD range")

    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if (
        shentsize < 64
        or shnum == 0
        or shnum > 4096
        or shstrndx >= shnum
        or shoff > len(data)
        or shnum * shentsize > len(data) - shoff
    ):
        fail("input has invalid or out-of-bounds section metadata")
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
        for index in range(shnum)
    ]
    names_section = sections[shstrndx]
    if names_section[1] != SHT_STRTAB:
        fail("input section-name table is not a string table")
    names_offset, names_size = names_section[4], names_section[5]
    if names_offset > len(data) or names_size > len(data) - names_offset:
        fail("input section-name table is out of bounds")
    names = data[names_offset : names_offset + names_size]
    named_sections: dict[str, tuple[int, ...]] = {}
    for section in sections:
        name_offset = section[0]
        if name_offset >= len(names):
            fail("input section name offset is out of bounds")
        name_end = names.find(b"\0", name_offset)
        if name_end < 0:
            fail("input section name is unterminated")
        try:
            name = names[name_offset:name_end].decode("ascii")
        except UnicodeDecodeError:
            fail("input section name is not ASCII")
        if name:
            named_sections[name] = section

    dynsym = named_sections.get(".dynsym")
    if dynsym is None or dynsym[1] != SHT_DYNSYM or dynsym[6] >= len(sections):
        fail("input has no unique .dynsym table")
    dynstr = sections[dynsym[6]]
    if dynstr[1] != SHT_STRTAB:
        fail("input .dynsym has no linked string table")
    symbol_offset, symbol_size, symbol_entry_size = dynsym[4], dynsym[5], dynsym[9]
    string_offset, string_size = dynstr[4], dynstr[5]
    if (
        symbol_entry_size < 24
        or symbol_size % symbol_entry_size != 0
        or symbol_size // symbol_entry_size > 1_048_576
        or symbol_offset > len(data)
        or symbol_size > len(data) - symbol_offset
        or string_offset > len(data)
        or string_size > len(data) - string_offset
    ):
        fail("input .dynsym/.dynstr ranges are invalid")
    strings = data[string_offset : string_offset + string_size]
    symbols: dict[str, tuple[int, int, int]] = {}
    for index in range(symbol_size // symbol_entry_size):
        offset = symbol_offset + index * symbol_entry_size
        name_offset, info, _other, section_index, value, size = struct.unpack_from("<IBBHQQ", data, offset)
        if name_offset >= len(strings):
            fail("input dynamic symbol name offset is out of bounds")
        name_end = strings.find(b"\0", name_offset)
        if name_end < 0:
            fail("input dynamic symbol name is unterminated")
        try:
            name = strings[name_offset:name_end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("input dynamic symbol name is not UTF-8")
        if not name:
            continue
        item = (value, size, info & 0x0F)
        if name in symbols and symbols[name] != item:
            fail(f"input dynamic symbol {name} has conflicting rows")
        if section_index == 0:
            fail(f"input dynamic symbol {name} is undefined")
        symbols[name] = item

    return segments, symbols, {"sectionHeaderOffset": shoff}


def symbol(symbols: dict[str, tuple[int, int, int]], name: str, expected_type: int | None = None) -> tuple[int, int, int]:
    item = symbols.get(name)
    if item is None or (expected_type is not None and item[2] != expected_type):
        fail(f"input has no defined dynamic symbol {name}")
    return item


def mapped_file_offset(segments: list[dict[str, int]], address: int, size: int) -> int:
    matches = [
        segment for segment in segments
        if address >= segment["virtualAddress"]
        and address + size <= segment["virtualAddress"] + segment["fileSize"]
    ]
    if len(matches) != 1:
        fail("requested jump-table range is not uniquely file-backed by PT_LOAD")
    segment = matches[0]
    return segment["fileOffset"] + address - segment["virtualAddress"]


def is_executable_file_range(segments: list[dict[str, int]], address: int, size: int) -> bool:
    return any(
        segment["flags"] & PF_X
        and address >= segment["virtualAddress"]
        and address + size <= segment["virtualAddress"] + segment["fileSize"]
        for segment in segments
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--mode", choices=("out-of-closure", "out-of-executable-range"), required=True)
    args = parser.parse_args()

    original = args.input.read_bytes()
    segments, symbols, _metadata = parse_image(original)
    entry_value, entry_size, _ = symbol(symbols, "urp_entry", STT_FUNC)
    table_address, _table_size, _ = symbol(symbols, "urp_jump_table")
    target_base, _base_size, _ = symbol(symbols, "urp_jump_table_case0")
    case_targets = [symbol(symbols, f"urp_jump_table_case{index}")[0] for index in range(TABLE_ENTRY_COUNT)]
    table_size = TABLE_ENTRY_COUNT * ENTRY_WIDTH
    table_file_offset = mapped_file_offset(segments, table_address, table_size)
    original_values = [
        struct.unpack_from("<i", original, table_file_offset + index * ENTRY_WIDTH)[0]
        for index in range(TABLE_ENTRY_COUNT)
    ]
    expected_values = [target - target_base for target in case_targets]
    if original_values != expected_values:
        fail("input relative table does not encode its four source case symbols")
    if any(not is_executable_file_range(segments, target, ENTRY_WIDTH) for target in case_targets):
        fail("input case target is not file-backed by an executable PT_LOAD")
    if any(target < entry_value or target + ENTRY_WIDTH > entry_value + entry_size for target in case_targets):
        fail("input case target is outside the selected urp_entry function")

    entry_index = 0
    entry_address = table_address + entry_index * ENTRY_WIDTH
    entry_file_offset = table_file_offset + entry_index * ENTRY_WIDTH
    original_value = original_values[entry_index]
    target_symbol: str | None = None
    if args.mode == "out-of-closure":
        target_symbol = "urp_jump_table_outside_closure"
        target_address, _size, _type = symbol(symbols, target_symbol, STT_FUNC)
        if entry_value <= target_address < entry_value + entry_size:
            fail("out-of-closure fixture target is inside urp_entry")
        if not is_executable_file_range(segments, target_address, ENTRY_WIDTH):
            fail("out-of-closure fixture target is not in a file-backed executable PT_LOAD")
        encoded_value = target_address - target_base
        mutation_kind = "out-of-closure-executable-target"
    else:
        encoded_value = OUT_OF_RANGE_VALUE
        target_address = target_base + encoded_value
        if target_address + ENTRY_WIDTH > U64_LIMIT:
            fail("out-of-range mutation overflows ELF64")
        if is_executable_file_range(segments, target_address, ENTRY_WIDTH):
            fail("out-of-range mutation target is unexpectedly executable/file-backed")
        if any(
            target_address >= segment["virtualAddress"]
            and target_address + ENTRY_WIDTH <= segment["virtualAddress"] + segment["memorySize"]
            for segment in segments
        ):
            fail("out-of-range mutation target is still inside a PT_LOAD memory image")
        mutation_kind = "outside-executable-load-range"

    if not -(1 << 31) <= encoded_value < (1 << 31) or encoded_value % 4 != 0:
        fail("relative jump-table mutation is not a signed aligned 32-bit delta")

    changed = bytearray(original)
    struct.pack_into("<i", changed, entry_file_offset, encoded_value)
    mutated = bytes(changed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(mutated)
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "mutationKind": mutation_kind,
        "inputSha256": sha256(original),
        "sourceSha256": sha256(mutated),
        "tableSymbol": "urp_jump_table",
        "tableAddress": table_address,
        "tableFileOffset": table_file_offset,
        "tableSize": table_size,
        "entryIndex": entry_index,
        "entryAddress": entry_address,
        "entryFileOffset": entry_file_offset,
        "entryWidth": ENTRY_WIDTH,
        "isSigned": True,
        "targetBaseSymbol": "urp_jump_table_case0",
        "targetBaseAddress": target_base,
        "originalEncodedValue": original_value,
        "mutatedEncodedValue": encoded_value,
        "computedTargetAddress": target_address,
        "targetSymbol": target_symbol,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
