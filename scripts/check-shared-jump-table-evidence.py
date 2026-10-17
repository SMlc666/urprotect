#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

PF_X = 1
PF_W = 2
PF_R = 4
PT_LOAD = 1
SHT_SYMTAB = 2
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4
MAX_U64 = (1 << 64) - 1
EXPECTED_ENTRY_STATUS = 91
EXPECTED_OBSERVER_STATUS = 91
EXPECTED_LOADER_ID = "host-context.sealed-memfd.dlopen"
EXPECTED_RELEASE_ORDER = "entry-dispatch-before-release-image"
MAX_EVIDENCE_JSON_BYTES = 16 * 1024 * 1024
MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_OBSERVER_STREAM_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def require_file(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        fail(f"missing or unsafe shared-table evidence file: {relative}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        fail(f"shared-table evidence path escapes artifact root: {relative}")
    return path


def read_json(root: Path, relative: str) -> dict[str, Any]:
    path = require_file(root, relative)
    if path.stat().st_size > MAX_EVIDENCE_JSON_BYTES:
        fail(f"shared-table evidence JSON exceeds its bound: {relative}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON evidence {relative}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON evidence is not an object: {relative}")
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def value(field: dict[str, Any], key: str) -> int:
    nested = field.get(key)
    if not isinstance(nested, dict) or type(nested.get("value")) is not int:
        fail(f"ELF range field {key} has no integer value")
    return nested["value"]


def require_int(obj: dict[str, Any], key: str) -> int:
    result = obj.get(key)
    if type(result) is not int:
        fail(f"evidence field {key} is not an integer")
    return result


def signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def parse_elf(image: bytes, label: str) -> tuple[list[dict[str, int]], list[dict[str, int]]]:
    if len(image) < 64 or image[:4] != b"\x7fELF" or image[4] != 2 or image[5] != 1:
        fail(f"{label} is not a bounded little-endian ELF64 image")
    if struct.unpack_from("<H", image, 18)[0] != 183:
        fail(f"{label} is not AArch64")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    shoff = struct.unpack_from("<Q", image, 40)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    shentsize, shnum = struct.unpack_from("<HH", image, 58)
    if phentsize != 56 or phoff > len(image) or phnum > (len(image) - phoff) // phentsize:
        fail(f"{label} has malformed program-header bounds")
    if shnum and (shentsize != 64 or shoff > len(image) or shnum > (len(image) - shoff) // shentsize):
        fail(f"{label} has malformed section-header bounds")
    phdrs = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, flags = struct.unpack_from("<II", image, offset)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", image, offset + 8)
        if p_offset > len(image) or p_filesz > len(image) - p_offset:
            fail(f"{label} has an out-of-bounds file-backed program segment")
        phdrs.append({
            "type": p_type,
            "flags": flags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
        })
    shdrs = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        name, section_type = struct.unpack_from("<II", image, offset)
        flags, address, section_offset, size = struct.unpack_from("<QQQQ", image, offset + 8)
        link, info = struct.unpack_from("<II", image, offset + 40)
        alignment, entsize = struct.unpack_from("<QQ", image, offset + 48)
        if section_offset > len(image) or size > len(image) - section_offset:
            fail(f"{label} has an out-of-bounds section")
        if address > MAX_U64 - size:
            fail(f"{label} has an overflowing section virtual range")
        shdrs.append({
            "name": name,
            "type": section_type,
            "flags": flags,
            "address": address,
            "offset": section_offset,
            "size": size,
            "link": link,
            "info": info,
            "alignment": alignment,
            "entsize": entsize,
        })
    return phdrs, shdrs


def symbol_records(image: bytes, sections: list[dict[str, int]], label: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for table_index, table in enumerate(sections):
        if table["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if table["link"] >= len(sections) or table["entsize"] != 24 or table["size"] % 24:
            fail(f"{label} has malformed symbol-table links")
        string_table = sections[table["link"]]
        strings = image[string_table["offset"]:string_table["offset"] + string_table["size"]]
        table_bytes = image[table["offset"]:table["offset"] + table["size"]]
        for index in range(table["size"] // 24):
            entry = table_bytes[index * 24:(index + 1) * 24]
            name_offset, info, other, section_index, address, size = struct.unpack("<IBBHQQ", entry)
            if name_offset >= len(strings):
                fail(f"{label} has an out-of-range symbol-name offset")
            end = strings.find(b"\0", name_offset)
            if end < 0:
                fail(f"{label} has an unterminated symbol name")
            try:
                symbol_name = strings[name_offset:end].decode("utf-8")
            except UnicodeDecodeError:
                fail(f"{label} has an invalid UTF-8 symbol name")
            records.append({
                "table_index": table_index,
                "index": index,
                "name": symbol_name,
                "binding": info >> 4,
                "type": info & 0xF,
                "visibility": other & 0x3,
                "section_index": section_index,
                "value": address,
                "size": size,
            })
    return records


def symbol(image: bytes, sections: list[dict[str, int]], name: str, label: str) -> tuple[int, int, int]:
    matches = [record for record in symbol_records(image, sections, label) if record["name"] == name]
    if not matches:
        fail(f"{label} has no symbol named {name}")
    dynamic = [record for record in matches if sections[record["table_index"]]["type"] == SHT_DYNSYM]
    chosen = (dynamic or matches)[0]
    return chosen["index"], chosen["value"], chosen["size"]


def derive_table_owners(
    image: bytes,
    sections: list[dict[str, int]],
    table_va: int,
    table_size: int,
) -> list[dict[str, Any]]:
    symbols = symbol_records(image, sections, "source image")
    symbols_by_table_index = {
        table_index: [record for record in symbols if record["table_index"] == table_index]
        for table_index, section in enumerate(sections)
        if section["type"] in (SHT_SYMTAB, SHT_DYNSYM)
    }
    table_symbols = [record for record in symbols
        if record["name"] == "urp_shared_jump_table"
        and record["type"] == 1
        and record["value"] == table_va
        and record["size"] == table_size]
    functions_by_identity = {
        (record["name"], record["value"], record["size"], record["section_index"]): record
        for record in symbols
        if record["type"] == 2 and record["size"] > 0
        and record["name"] in ("urp_entry", "urp_observer")
    }
    derived: list[dict[str, Any]] = []
    for relocation_section_index, relocation_section in enumerate(sections):
        if relocation_section["type"] != 4:  # SHT_RELA
            continue
        if (relocation_section["entsize"] != 24
            or relocation_section["size"] % 24
            or relocation_section["link"] not in symbols_by_table_index):
            fail("source ELF contains malformed section-owned SHT_RELA records")
        linked_symbols = symbols_by_table_index[relocation_section["link"]]
        relocation_bytes = image[
            relocation_section["offset"]:relocation_section["offset"] + relocation_section["size"]]
        for index in range(relocation_section["size"] // 24):
            r_offset, r_info, addend = struct.unpack_from("<QQq", relocation_bytes, index * 24)
            symbol_index = r_info >> 32
            relocation_type = r_info & 0xFFFFFFFF
            if symbol_index >= len(linked_symbols):
                fail("source ELF relocation references an out-of-range linked symbol")
            linked_symbol = linked_symbols[symbol_index]
            if linked_symbol["name"] != "urp_shared_jump_table":
                continue
            matching_table_symbols = [record for record in table_symbols
                if record["table_index"] == relocation_section["link"]
                and record["index"] == symbol_index]
            if len(matching_table_symbols) != 1 or relocation_type not in (275, 277):
                fail("source table relocation does not bind one exact object symbol and ADRP/ADD family")
            target_section_index = relocation_section["info"]
            if target_section_index >= len(sections):
                fail("source RELA target section index is out of bounds")
            function_matches = [record for record in functions_by_identity.values()
                if r_offset >= record["value"] and r_offset - record["value"] < record["size"]]
            if len(function_matches) != 1:
                fail("source table relocation site does not have one named consumer function owner")
            owner = function_matches[0]
            if target_section_index != owner["section_index"]:
                fail("source RELA target section index does not match the owning function section identity")
            owner_section = sections[owner["section_index"]] if owner["section_index"] < len(sections) else None
            if (owner_section is None
                or owner_section["type"] == SHT_NOBITS
                or not (owner_section["flags"] & SHF_EXECINSTR)):
                fail("source owner function section is not executable and file-backed")
            section_size = owner_section["size"]
            section_address = owner_section["address"]
            section_offset = owner_section["offset"]
            function_delta = owner["value"] - section_address if owner["value"] >= section_address else section_size + 1
            if (section_address > MAX_U64 - section_size
                or owner["value"] > MAX_U64 - owner["size"]
                or r_offset > MAX_U64 - 4
                or function_delta > section_size
                or owner["size"] > section_size - function_delta
                or r_offset % 4
                or r_offset < owner["value"]
                or r_offset - owner["value"] > owner["size"]
                or 4 > owner["size"] - (r_offset - owner["value"])
                or r_offset < section_address
                or r_offset - section_address > section_size
                or 4 > section_size - (r_offset - section_address)):
                fail("source RELA relocation site or owner function is not contained in its executable section")
            site_file_offset = section_offset + (r_offset - section_address)
            if (site_file_offset > len(image)
                or 4 > len(image) - site_file_offset
                or site_file_offset < section_offset
                or site_file_offset - section_offset > section_size
                or 4 > section_size - (site_file_offset - section_offset)):
                fail("source RELA relocation site is not file-backed inside its owner section")
            derived.append({
                "instructionAddress": r_offset,
                "relocationSectionIndex": relocation_section_index,
                "symbolTableSectionIndex": relocation_section["link"],
                "targetSectionIndex": target_section_index,
                "ownerFunctionSectionIndex": owner["section_index"],
                "ownerFunctionSection": {
                    "name": owner_section["name"],
                    "type": owner_section["type"],
                    "flags": owner_section["flags"],
                    "address": owner_section["address"],
                    "offset": owner_section["offset"],
                    "size": owner_section["size"],
                    "link": owner_section["link"],
                    "info": owner_section["info"],
                    "addressAlignment": owner_section["alignment"],
                    "entrySize": owner_section["entsize"],
                },
                "relocationSourceAddress": index * 24,
                "relocationType": relocation_type,
                "addend": addend,
                "symbolIndex": symbol_index,
                "symbolName": linked_symbol["name"],
                "symbolBinding": linked_symbol["binding"],
                "symbolType": linked_symbol["type"],
                "symbolVisibility": linked_symbol["visibility"],
                "symbolSectionIndex": linked_symbol["section_index"],
                "symbolValue": linked_symbol["value"],
                "symbolSize": linked_symbol["size"],
                "ownerFunctionName": owner["name"],
                "ownerFunctionStart": owner["value"],
                "ownerFunctionSize": owner["size"],
                "isSelectedFunction": owner["name"] == "urp_entry",
            })
    derived.sort(key=lambda record: (record["instructionAddress"], record["relocationType"]))
    if len(derived) != 4:
        fail("source ELF does not retain exactly two table-base relocation sites per table consumer")
    return derived


def file_offset_for_va(phdrs: list[dict[str, int]], address: int, size: int, label: str) -> int:
    matches = [segment for segment in phdrs
        if segment["type"] == PT_LOAD
        and address >= segment["vaddr"]
        and address - segment["vaddr"] <= segment["filesz"]
        and size <= segment["filesz"] - (address - segment["vaddr"])]
    if len(matches) != 1:
        fail(f"{label} does not map uniquely through a file-backed PT_LOAD")
    segment = matches[0]
    return segment["offset"] + address - segment["vaddr"]


def adrp_target(word: int, address: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    immediate = signed(immediate, 21) << 12
    return (address & ~0xFFF) + immediate, word & 0x1F


def add_immediate(word: int) -> tuple[int, int, int] | None:
    # 64-bit, non-flag-setting ADD (immediate), including optional LSL #12.
    if word & 0xFF000000 != 0x91000000:
        return None
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return rd, rn, immediate


def adr_target(word: int, address: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x10000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    return address + signed(immediate, 21), word & 0x1F


def check_manifest(root: Path) -> None:
    manifest = require_file(root, "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    entries: dict[str, str] = {}
    for line in manifest:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail("shared-table SHA256SUMS contains a malformed row")
        expected, relative = match.groups()
        if relative in entries:
            fail(f"duplicate manifest path: {relative}")
        path = require_file(root, relative)
        if digest(path) != expected:
            fail(f"shared-table manifest digest mismatch: {relative}")
        entries[relative] = expected
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if actual != set(entries):
        fail("shared-table SHA256SUMS is not closed")


def check_handoff(
    record: dict[str, Any],
    symbol_name: str,
    expected: int,
    expected_image_sha256: str,
) -> None:
    if (record.get("schemaVersion") != 1
        or record.get("stage") != "host-context-handoff"
        or record.get("status") != "passed"
        or record.get("entrySymbol") != symbol_name
        or record.get("entryStatus") != expected
        or record.get("processStatus") != expected
        or record.get("loaderId") != EXPECTED_LOADER_ID
        or record.get("nativeImageSha256") != expected_image_sha256
        or record.get("releaseStatus") != "passed"
        or record.get("releaseOrder") != EXPECTED_RELEASE_ORDER
        or "firstFailureStage" not in record
        or record.get("firstFailureStage") is not None):
        fail(f"{symbol_name} handoff does not bind the expected image, loader, process/entry status, and release order")


def main() -> None:
    parser = argparse.ArgumentParser(description="Independently validate shared jump-table copy-and-retarget evidence")
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--selected-function", required=True)
    args = parser.parse_args()
    root = args.artifact_root.resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.unit):
        parser.error("unit id is malformed")
    if not re.fullmatch(r"dynsym:[0-9]+", args.selected_function):
        parser.error("the shared fixture must select urp_entry by dynsym index")

    source_path = require_file(root, "source-image.bin")
    native_path = require_file(root, "native-image.bin")
    if source_path.stat().st_size > MAX_IMAGE_BYTES or native_path.stat().st_size > MAX_IMAGE_BYTES:
        fail("shared-table Source Image or Native Image exceeds its configured byte bound")
    source = source_path.read_bytes()
    source_sha256 = digest(source_path)
    native = native_path.read_bytes()
    native_sha256 = digest(native_path)
    source_phdrs, source_sections = parse_elf(source, "source image")
    native_phdrs, native_sections = parse_elf(native, "Native Image")
    unit = read_json(root, "stage.json").get("unitId")
    if unit != args.unit:
        fail("stage unit does not match the requested shared-table evidence unit")

    entry_symbol_index, entry_va, entry_size = symbol(source, source_sections, "urp_entry", "source image")
    observer_symbol_index, observer_va, observer_size = symbol(source, source_sections, "urp_observer", "source image")
    if args.selected_function != f"dynsym:{entry_symbol_index}" or entry_size == 0 or observer_size == 0:
        fail("the selected dynsym selector or fixture function ranges do not match")

    rehydration = read_json(root, "rehydration.json")
    layout = rehydration.get("layoutEvidence")
    if not isinstance(layout, dict) or layout.get("schemaVersion") != 3:
        fail("rehydration evidence does not retain the version-3 shared-copy layout contract")
    clones = layout.get("jumpTableClones")
    if not isinstance(clones, list) or len(clones) != 1:
        fail("the shared table does not have exactly one retained physical clone")
    clone = clones[0]
    table_identity = clone.get("tableIdentity")
    if not isinstance(table_identity, dict) or table_identity.get("kind") != 5:
        fail("the retained clone identity is not a jump table")
    source_range = clone.get("sourceTableRange")
    output_range = clone.get("outputRange")
    requested_range = clone.get("requestedOutputRange")
    if not all(isinstance(item, dict) for item in (source_range, output_range, requested_range)):
        fail("the retained clone is missing source, requested, or physical output ranges")
    source_offset = value(source_range, "fileOffset")
    source_va = value(source_range, "virtualAddress")
    source_size = require_int(source_range, "size")
    output_offset = value(output_range, "fileOffset")
    output_va = value(output_range, "virtualAddress")
    output_size = require_int(output_range, "size")
    if (source_size != 16 or output_size != source_size
        or require_int(requested_range, "size") != source_size
        or output_offset == source_offset or output_va == source_va
        or clone.get("permissions") != PF_R
        or clone.get("rewritePolicy") != 1
        or require_int(clone, "ownership") != 2
        or clone.get("ownerInventoryComplete") is not False):
        fail("the clone does not satisfy the distinct read-only shared signed-32 policy")

    source_table_offset = file_offset_for_va(source_phdrs, source_va, source_size, "source table")
    if source_table_offset != source_offset:
        fail("the retained source table range is not the ELF structural file mapping")
    if source_offset + source_size > len(source) or output_offset + output_size > len(native):
        fail("the source or clone byte range exceeds its retained image")
    source_table = source[source_offset:source_offset + source_size]
    if native[source_offset:source_offset + source_size] != source_table:
        fail("copy-and-retarget changed the original shared table bytes")
    read_only_segments = [segment for segment in native_phdrs
        if segment["type"] == PT_LOAD
        and segment["flags"] == PF_R
        and output_va >= segment["vaddr"]
        and output_va - segment["vaddr"] <= segment["filesz"]
        and output_size <= segment["filesz"] - (output_va - segment["vaddr"])
        and output_offset == segment["offset"] + output_va - segment["vaddr"]]
    if len(read_only_segments) != 1:
        fail("the cloned table is not uniquely file-backed by a read-only, non-writable, non-executable PT_LOAD")

    owners = clone.get("ownerReferences")
    if (not isinstance(owners, list) or len(owners) != 4
        or any(not isinstance(reference, dict) for reference in owners)):
        fail("the clone discarded or malformed static owner/reference-site evidence")
    owner_functions = {reference.get("ownerFunctionName") for reference in owners}
    selected_owners = {reference.get("ownerFunctionName") for reference in owners
        if isinstance(reference, dict) and reference.get("isSelectedFunction") is True}
    unselected_owners = {reference.get("ownerFunctionName") for reference in owners
        if isinstance(reference, dict) and reference.get("isSelectedFunction") is False}
    if "urp_entry" not in selected_owners or "urp_observer" not in unselected_owners or not {"urp_entry", "urp_observer"}.issubset(owner_functions):
        fail("static relocation ownership does not prove selected urp_entry and unselected urp_observer consumers")
    independently_parsed_owners = derive_table_owners(source, source_sections, source_va, source_size)
    owner_fields = tuple(independently_parsed_owners[0])
    projected_owners = [
        {field: reference.get(field) for field in owner_fields}
        for reference in owners
        if isinstance(reference, dict)
    ]
    if projected_owners != independently_parsed_owners:
        fail("retained static owner/reference evidence differs from the raw section-linked RELA/symbol tables")
    producer_rows = clone.get("tableReferenceProducers")
    if not isinstance(producer_rows, list) or len(producer_rows) != 2:
        fail("the selected consumer table-base producer chain is incomplete")
    producers = sorted(producer_rows, key=lambda producer: require_int(producer, "instructionAddress"))
    if [require_int(producer, "kind") for producer in producers] != [1, 2]:
        fail("the selected table-base producer chain is not ADRP followed by ADD-low12")
    producer_addresses = [require_int(producer, "instructionAddress") for producer in producers]
    if producer_addresses[1] != producer_addresses[0] + 4:
        fail("the selected ADRP/ADD producer instructions are not the exact adjacent source pair")
    for producer, relocation_type in zip(producers, (275, 277)):
        site = require_int(producer, "instructionAddress")
        selected_sites = [reference for reference in owners
            if isinstance(reference, dict)
            and reference.get("isSelectedFunction") is True
            and reference.get("ownerFunctionName") == "urp_entry"
            and reference.get("instructionAddress") == site
            and reference.get("relocationType") == relocation_type]
        if not selected_sites:
            fail("the selected producer site is not bound to its exact static relocation owner")
    source_page_offset = file_offset_for_va(source_phdrs, producer_addresses[0], 4, "source ADRP producer")
    source_low_offset = file_offset_for_va(source_phdrs, producer_addresses[1], 4, "source ADD producer")
    source_page_word = struct.unpack_from("<I", source, source_page_offset)[0]
    source_low_word = struct.unpack_from("<I", source, source_low_offset)[0]
    decoded_source_page = adrp_target(source_page_word, producer_addresses[0])
    decoded_source_low = add_immediate(source_low_word)
    if (decoded_source_page is None or decoded_source_low is None
        or decoded_source_page[0] != (source_va & ~0xFFF)
        or decoded_source_page[1] != decoded_source_low[0]
        or decoded_source_page[1] != decoded_source_low[1]
        or decoded_source_page[0] + decoded_source_low[2] != source_va):
        fail("the retained source producer bytes do not resolve the owned shared table range")

    bindings = layout.get("jumpTableTargetBindings")
    edits = layout.get("jumpTableEdits")
    if not isinstance(bindings, list) or len(bindings) != 4 or not isinstance(edits, list) or len(edits) != 4:
        fail("the clone does not retain four ordered entry and target bindings")
    bindings = sorted(bindings, key=lambda binding: require_int(binding, "entryIndex"))
    if [require_int(binding, "entryIndex") for binding in bindings] != [0, 1, 2, 3]:
        fail("jump-table entry bindings are not the four ordered indices")
    encoded_entries: list[int] = []
    for index, binding in enumerate(bindings):
        if (require_int(binding, "entryWidth") != 4
            or binding.get("isSigned") is not True
            or require_int(binding, "scale") != 1
            or require_int(binding, "addend") != 0):
            fail("a copied table entry uses an unsupported encoding family")
        target = value(binding, "outputTargetAddress")
        target_base = value(binding, "outputTargetBaseAddress")
        encoded = require_int(binding, "outputEncodedValue")
        if target - target_base != encoded or not -(1 << 31) <= encoded < (1 << 31):
            fail("an output table target is not represented by the retained signed-32 base-relative encoding")
        if value(binding.get("sourceEntryRange", {}), "fileOffset") != source_offset + index * 4:
            fail("the source entry bindings are not contiguous within the shared table")
        encoded_entries.append(encoded)
        target_file_offset = file_offset_for_va(native_phdrs, target, 4, "mapped table target")
        target_segments = [segment for segment in native_phdrs
            if segment["type"] == PT_LOAD and segment["flags"] & PF_X
            and target >= segment["vaddr"]
            and target - segment["vaddr"] <= segment["filesz"]
            and 4 <= segment["filesz"] - (target - segment["vaddr"])]
        if len(target_segments) != 1 or target_file_offset + 4 > len(native):
            fail("a retargeted table entry does not point into one executable file-backed output mapping")
    clone_entries = list(struct.unpack("<4i", native[output_offset:output_offset + output_size]))
    if clone_entries != encoded_entries:
        fail("the physical clone bytes do not match the planner-retained output target bindings")
    edit_offsets = {value(edit, "offset") for edit in edits}
    if edit_offsets != {output_offset + index * 4 for index in range(4)}:
        fail("materialized table edits are not confined to all four clone entries")
    for edit in edits:
        payload = base64.b64decode(edit.get("bytes", ""), validate=True)
        offset = value(edit, "offset")
        if len(payload) != 4 or native[offset:offset + 4] != payload:
            fail("a retained jump-table edit does not match its materialized clone bytes")

    map_rows = [entry for entry in layout.get("addressMap", [])
        if entry.get("identity") == table_identity.get("value")]
    if (len(map_rows) != 1
        or value(map_rows[0].get("sourceRange", {}), "fileOffset") != source_offset
        or value(map_rows[0].get("outputRange", {}), "fileOffset") != output_offset
        or value(map_rows[0].get("outputRange", {}), "virtualAddress") != output_va):
        fail("the layout address map does not bind the source table identity to its physical clone")

    region_rows = [entry for entry in layout.get("addressMap", [])
        if isinstance(entry, dict)
        and entry.get("identity", "").startswith("region:")
        and isinstance(entry.get("sourceRange"), dict)
        and value(entry["sourceRange"], "virtualAddress") == entry_va
        and require_int(entry["sourceRange"], "size") == entry_size]
    if len(region_rows) != 1:
        fail("the selected function has no unique generated code-region mapping")
    code_range = region_rows[0]["outputRange"]
    code_offset = value(code_range, "fileOffset")
    code_va = value(code_range, "virtualAddress")
    code_size = require_int(code_range, "size")
    if code_offset + code_size > len(native) or code_size % 4:
        fail("the generated selected-function code range is malformed")
    words = list(struct.unpack(f"<{code_size // 4}I", native[code_offset:code_offset + code_size]))
    clone_page = output_va & ~0xFFF
    producer_pairs: list[tuple[int, int, int]] = []
    for index, word in enumerate(words[:-1]):
        page = adrp_target(word, code_va + index * 4)
        add = add_immediate(words[index + 1])
        if page is None or add is None:
            continue
        page_target, rd = page
        add_rd, add_rn, low = add
        if page_target == clone_page and rd == add_rd == add_rn and page_target + low == output_va:
            producer_pairs.append((index, rd, page_target + low))
    if len(producer_pairs) != 1:
        fail("selected emitted code does not uniquely retarget its ADRP/ADD table-base chain to the clone")
    pair_index = producer_pairs[0][0]
    if (pair_index + 5 >= len(words)
        or words[pair_index + 2] != 0xB8A05822
        or words[pair_index + 4:pair_index + 6] != [0x8B020061, 0xD61F0020]):
        fail("selected emitted code does not load, compute, and BR through the cloned signed-relative table")
    output_target_base = value(bindings[0], "outputTargetBaseAddress")
    adr = adr_target(words[pair_index + 3], code_va + (pair_index + 3) * 4)
    if adr is None or adr[0] != output_target_base or adr[1] != 3:
        fail("selected computed target base does not point at the mapped case-block base")

    observer_offset = file_offset_for_va(source_phdrs, observer_va, observer_size, "source observer")
    native_observer_offset = file_offset_for_va(native_phdrs, observer_va, observer_size, "Native Image observer")
    if source[observer_offset:observer_offset + observer_size] != native[native_observer_offset:native_observer_offset + observer_size]:
        fail("the unselected observer code or its original table-base producer chain was modified")
    source_handoff = read_json(root, "source-handoff.json")
    target_handoff = read_json(root, "handoff.json")
    check_handoff(source_handoff, "urp_entry", EXPECTED_ENTRY_STATUS, source_sha256)
    check_handoff(target_handoff, "urp_entry", EXPECTED_ENTRY_STATUS, native_sha256)
    observer_source = read_json(root, "observer-source-handoff.json")
    observer_target = read_json(root, "observer-transformed-handoff.json")
    check_handoff(observer_source, "urp_observer", EXPECTED_OBSERVER_STATUS, source_sha256)
    check_handoff(observer_target, "urp_observer", EXPECTED_OBSERVER_STATUS, native_sha256)
    behavior = read_json(root, "shared-table-behavior.json")
    process_statuses: dict[str, int] = {}
    process_status_digests: dict[str, str] = {}
    for prefix, handoff, expected in (
        ("observer-source", observer_source, EXPECTED_OBSERVER_STATUS),
        ("observer-transformed", observer_target, EXPECTED_OBSERVER_STATUS),
    ):
        status_path = require_file(root, f"{prefix}.process-status")
        status_bytes = status_path.read_bytes()
        if len(status_bytes) > 16 or not re.fullmatch(rb"[0-9]+\n?", status_bytes):
            fail(f"{prefix} process-status evidence is malformed")
        observed_status = int(status_bytes.strip())
        if observed_status != expected or handoff.get("processStatus") != observed_status:
            fail(f"{prefix} process exit status does not match its observed handoff entry result")
        process_statuses[prefix] = observed_status
        process_status_digests[prefix] = digest(status_path)

    observer_streams: dict[tuple[str, str], bytes] = {}
    observer_stream_digests: dict[tuple[str, str], str] = {}
    for prefix in ("observer-source", "observer-transformed"):
        for suffix in ("stdout", "stderr"):
            stream_path = require_file(root, f"{prefix}.{suffix}")
            if stream_path.stat().st_size > MAX_OBSERVER_STREAM_BYTES:
                fail(f"{prefix} {suffix} exceeds the observer stream bound")
            stream_bytes = stream_path.read_bytes()
            observer_streams[(prefix, suffix)] = stream_bytes
            observer_stream_digests[(prefix, suffix)] = digest(stream_path)
            # The controlled observer returns a status only; it emits no stream
            # bytes. Retain this exact fixture behavior, not a copied claim.
            if stream_bytes != b"":
                fail(f"{prefix} {suffix} differs from the fixture's expected empty stream")
    for suffix in ("stdout", "stderr"):
        if observer_streams[("observer-source", suffix)] != observer_streams[("observer-transformed", suffix)]:
            fail(f"observer source/transformed {suffix} observations differ")
        if require_file(root, f"baseline.{suffix}").read_bytes() != require_file(root, f"target.{suffix}").read_bytes():
            fail("selected source/transformed host-context streams differ")

    behavior_stream_facts = {
        "observerSourceStdoutSha256": observer_stream_digests[("observer-source", "stdout")],
        "observerSourceStdoutSize": len(observer_streams[("observer-source", "stdout")]),
        "observerSourceStderrSha256": observer_stream_digests[("observer-source", "stderr")],
        "observerSourceStderrSize": len(observer_streams[("observer-source", "stderr")]),
        "observerTransformedStdoutSha256": observer_stream_digests[("observer-transformed", "stdout")],
        "observerTransformedStdoutSize": len(observer_streams[("observer-transformed", "stdout")]),
        "observerTransformedStderrSha256": observer_stream_digests[("observer-transformed", "stderr")],
        "observerTransformedStderrSize": len(observer_streams[("observer-transformed", "stderr")]),
    }
    if (behavior.get("schemaVersion") != 2
        or behavior.get("unitId") != args.unit
        or behavior.get("selectedEntryStatus") != EXPECTED_ENTRY_STATUS
        or behavior.get("observerSourceStatus") != EXPECTED_OBSERVER_STATUS
        or behavior.get("observerTransformedStatus") != EXPECTED_OBSERVER_STATUS
        or behavior.get("observerSourceProcessStatus") != process_statuses["observer-source"]
        or behavior.get("observerTransformedProcessStatus") != process_statuses["observer-transformed"]
        or behavior.get("observerSourceProcessStatusSha256") != process_status_digests["observer-source"]
        or behavior.get("observerTransformedProcessStatusSha256") != process_status_digests["observer-transformed"]
        or behavior.get("observerSourceNativeImageSha256") != source_sha256
        or behavior.get("observerTransformedNativeImageSha256") != native_sha256
        or any(behavior.get(field) != expected for field, expected in behavior_stream_facts.items())
        or behavior.get("sourceTableUnchanged") is not True
        or behavior.get("selectedConsumerReadsClone") is not True
        or behavior.get("unselectedObserverUsesOriginalTable") is not True
        or behavior.get("selectedSourceHandoffSha256") != digest(require_file(root, "source-handoff.json"))
        or behavior.get("selectedTransformedHandoffSha256") != digest(require_file(root, "handoff.json"))
        or behavior.get("observerSourceHandoffSha256") != digest(require_file(root, "observer-source-handoff.json"))
        or behavior.get("observerTransformedHandoffSha256") != digest(require_file(root, "observer-transformed-handoff.json"))):
        fail("shared-table behavior evidence does not bind both consumers, process results, streams, and cloned-table assertions")
    check_manifest(root)
    print("Shared jump-table evidence valid: selected consumer loads the read-only clone; observer and source table remain unchanged")


if __name__ == "__main__":
    main()
