#!/usr/bin/env python3
"""Independently check the bounded static local callback HostContext evidence row."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 65536
MAX_SYMBOLS = 2_000_000
DIGEST = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_ENTRY_STATUS = 97
EXPECTED_LOADER_ID = "host-context.sealed-memfd.dlopen"
EXPECTED_RELEASE_ORDER = "entry-dispatch-before-release-image"


class EvidenceError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha256(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"not a regular evidence file: {path}")
    require(path.stat().st_size <= MAX_IMAGE_BYTES, f"evidence file exceeds bound: {path}")
    data = path.read_bytes()
    require(len(data) <= MAX_IMAGE_BYTES, f"evidence file exceeds bound: {path}")
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON evidence {path.name}: {exc}") from exc
    require(isinstance(value, dict), f"JSON evidence is not an object: {path.name}")
    return value


def cstring(data: bytes, offset: int) -> str:
    require(0 <= offset < len(data), "ELF string offset is out of range")
    end = data.find(b"\0", offset)
    require(end >= 0, "unterminated ELF string")
    try:
        return data[offset:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError("ELF name is not valid UTF-8") from exc


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class Segment:
    kind: int
    flags: int
    offset: int
    address: int
    file_size: int
    memory_size: int


@dataclass(frozen=True)
class Symbol:
    table: str
    table_index: int
    name: str
    name_offset: int
    info: int
    other: int
    section_index: int
    value: int
    size: int

    @property
    def symbol_type(self) -> int:
        return self.info & 0xF

    @property
    def binding(self) -> int:
        return self.info >> 4

    @property
    def visibility(self) -> int:
        return self.other & 0x3


class ElfImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        require(0 < len(self.data) <= MAX_IMAGE_BYTES, f"ELF image size out of bound: {path.name}")
        require(len(self.data) >= 64, f"truncated ELF header: {path.name}")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
        ident, self.kind, self.machine, version, _, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = header
        require(ident[:6] == b"\x7fELF\x02\x01" and ident[6] == 1, f"not ELF64 little-endian: {path.name}")
        require(self.kind == 3 and self.machine == 183 and version == 1, f"not AArch64 ET_DYN: {path.name}")
        require(ehsize == 64 and phentsize == 56 and shentsize == 64, f"unsupported ELF table entry sizes: {path.name}")
        require(0 < phnum <= MAX_SECTIONS and 0 < shnum <= MAX_SECTIONS, f"unsupported extended ELF table numbering: {path.name}")
        require(shstrndx < shnum, f"invalid ELF section-name table: {path.name}")
        require(phoff <= len(self.data) and phnum * phentsize <= len(self.data) - phoff, f"program table exceeds ELF: {path.name}")
        require(shoff <= len(self.data) and shnum * shentsize <= len(self.data) - shoff, f"section table exceeds ELF: {path.name}")
        self.segments: list[Segment] = []
        for index in range(phnum):
            kind, flags, offset, address, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", self.data, phoff + index * phentsize)
            require(offset <= len(self.data) and filesz <= len(self.data) - offset, f"program segment exceeds ELF: {path.name}")
            require(filesz <= memsz, f"invalid program segment size: {path.name}")
            self.segments.append(Segment(kind, flags, offset, address, filesz, memsz))
        raw_sections = []
        for index in range(shnum):
            raw_sections.append(struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + index * shentsize))
        names_header = raw_sections[shstrndx]
        names_offset, names_size = names_header[4], names_header[5]
        require(names_offset <= len(self.data) and names_size <= len(self.data) - names_offset, f"section-name table exceeds ELF: {path.name}")
        names = self.data[names_offset:names_offset + names_size]
        self.sections: list[Section] = []
        for index, raw in enumerate(raw_sections):
            name_offset, kind, flags, address, offset, size, link, info, alignment, entry_size = raw
            if kind != 8:
                require(offset <= len(self.data) and size <= len(self.data) - offset, f"section exceeds ELF: {path.name}")
            self.sections.append(Section(index, cstring(names, name_offset) if names else "", kind, flags, address, offset, size, link, info, alignment, entry_size))
        self.by_section_name = {section.name: section for section in self.sections if section.name}
        self.symbols: dict[int, list[Symbol]] = {}
        for section in self.sections:
            if section.kind not in (2, 11):
                continue
            require(section.entry_size == 24 and section.size % 24 == 0, f"malformed symbol table {section.name}: {path.name}")
            require(section.link < len(self.sections), f"invalid symbol string-table link: {path.name}")
            strings_section = self.sections[section.link]
            strings = self.data[strings_section.offset:strings_section.offset + strings_section.size]
            count = section.size // 24
            require(count <= MAX_SYMBOLS, f"symbol table exceeds bound: {path.name}")
            rows: list[Symbol] = []
            for index in range(count):
                name_offset, info, other, section_index, value, size = struct.unpack_from("<IBBHQQ", self.data, section.offset + index * 24)
                rows.append(Symbol(section.name, index, cstring(strings, name_offset) if name_offset else "", name_offset, info, other, section_index, value, size))
            self.symbols[section.index] = rows
        self.relocations: dict[int, list[tuple[int, int, int]]] = {}
        for section in self.sections:
            if section.kind != 4:
                continue
            require(section.entry_size == 24 and section.size % 24 == 0, f"malformed RELA table {section.name}: {path.name}")
            count = section.size // 24
            require(count <= MAX_SYMBOLS, f"RELA table exceeds bound: {path.name}")
            rows = []
            for index in range(count):
                address, info, addend = struct.unpack_from("<QQq", self.data, section.offset + index * 24)
                rows.append((address, info, addend))
            self.relocations[section.index] = rows

    def unique_symbol(self, table_name: str, name: str) -> Symbol:
        table = next((section for section in self.sections if section.name == table_name), None)
        require(table is not None and table.index in self.symbols, f"missing {table_name}")
        matches = [symbol for symbol in self.symbols[table.index] if symbol.name == name]
        require(len(matches) == 1, f"expected one {table_name} symbol {name}, found {len(matches)}")
        return matches[0]

    def function_symbols(self, name: str) -> list[Symbol]:
        return [symbol for rows in self.symbols.values() for symbol in rows if symbol.name == name and symbol.symbol_type == 2 and symbol.section_index != 0]

    def section_for_symbol(self, symbol: Symbol) -> Section:
        require(0 < symbol.section_index < len(self.sections), f"symbol {symbol.name} has invalid section index")
        section = self.sections[symbol.section_index]
        require(section.kind == 1 and section.flags & 4 != 0, f"symbol {symbol.name} is not in executable PROGBITS")
        require(symbol.size > 0 and symbol.value <= 0xFFFFFFFFFFFFFFFF - symbol.size, f"symbol {symbol.name} has invalid range")
        require(section.address <= symbol.value and symbol.size <= section.address + section.size - symbol.value, f"symbol {symbol.name} exceeds its section")
        require(section.offset <= 0xFFFFFFFFFFFFFFFF - section.size, f"section {section.name} file range overflows")
        return section

    def file_offset(self, address: int, size: int, executable: bool = True) -> int:
        matches = []
        for segment in self.segments:
            if segment.kind != 1 or (executable and segment.flags & 1 == 0):
                continue
            if address >= segment.address and address - segment.address <= segment.file_size and size <= segment.file_size - (address - segment.address):
                matches.append(segment.offset + address - segment.address)
        require(len(matches) == 1, f"VA 0x{address:x} does not have one unique file-backed PT_LOAD mapping")
        return matches[0]

    def read_virtual(self, address: int, size: int, executable: bool = True) -> bytes:
        offset = self.file_offset(address, size, executable)
        return self.data[offset:offset + size]


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_adrp(word: int, pc: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    immediate = ((word >> 29) & 0x3) | (((word >> 5) & 0x7FFFF) << 2)
    page_delta = sign_extend(immediate, 21) << 12
    page = (pc & ~0xFFF) + page_delta
    return word & 0x1F, page


def decode_add(word: int) -> tuple[int, int, int] | None:
    if word & 0xFFC00000 != 0x91000000:
        return None
    return (word >> 5) & 0x1F, word & 0x1F, (word >> 10) & 0xFFF


def decode_stack_memory(word: int, load: bool) -> tuple[int, int] | None:
    expected = 0xF9400000 if load else 0xF9000000
    if word & 0xFFC00000 != expected or (word >> 5) & 0x1F != 31:
        return None
    return word & 0x1F, ((word >> 10) & 0xFFF) * 8


def decode_blr(word: int) -> int | None:
    if word & 0xFFFFFC1F != 0xD63F0000:
        return None
    return (word >> 5) & 0x1F


def decode_b(word: int, pc: int) -> int | None:
    if word & 0xFC000000 != 0x14000000:
        return None
    displacement = sign_extend(word & 0x03FFFFFF, 26) << 2
    return pc + displacement


def find_chain_in_range(image: ElfImage, start: int, size: int, name: str, callback: Symbol) -> dict[str, Any]:
    image.section_for_symbol(callback)
    code = image.read_virtual(start, size)
    require(len(code) % 4 == 0, f"caller {name} is not instruction aligned")
    chains = []
    for offset in range(0, len(code) - 16, 4):
        pc = start + offset
        words = struct.unpack_from("<IIIII", code, offset)
        adrp = decode_adrp(words[0], pc)
        add = decode_add(words[1])
        store = decode_stack_memory(words[2], load=False)
        load = decode_stack_memory(words[3], load=True)
        call_register = decode_blr(words[4])
        if not (adrp and add and store and load and call_register is not None):
            continue
        page_register, page = adrp
        add_source, add_target, low = add
        stored_register, stack_slot = store
        loaded_register, load_slot = load
        if not (page_register == add_source == add_target == stored_register):
            continue
        if not (stack_slot == load_slot and loaded_register == call_register):
            continue
        target = page + low
        if target != callback.value:
            continue
        chains.append({
            "adrpAddress": pc,
            "addAddress": pc + 4,
            "storeAddress": pc + 8,
            "loadAddress": pc + 12,
            "callAddress": pc + 16,
            "targetRegister": call_register,
            "stackSlotOffset": stack_slot,
            "targetAddress": target,
            "pageAddress": page,
            "low12": low,
            "instructions": [f"0x{word:08x}" for word in words],
        })
    require(len(chains) == 1, f"expected exactly one validated ADRP/ADD/stack/BLR chain in {name}, found {len(chains)}")
    return chains[0]


def find_chain(image: ElfImage, caller: Symbol, callback: Symbol) -> dict[str, Any]:
    image.section_for_symbol(caller)
    return find_chain_in_range(image, caller.value, caller.size, caller.name, callback)


def check_source_relocations(image: ElfImage, caller: Symbol, callback: Symbol, chain: dict[str, Any]) -> dict[str, Any]:
    caller_section = image.section_for_symbol(caller)
    callback_section = image.section_for_symbol(callback)
    candidates = []
    for section in image.sections:
        if section.kind != 4 or section.link >= len(image.sections) or section.info != caller_section.index:
            continue
        if image.sections[section.link].name != ".symtab":
            continue
        for row_index, (offset, info, addend) in enumerate(image.relocations[section.index]):
            symbol_index = info >> 32
            relocation_type = info & 0xFFFFFFFF
            if offset in (chain["adrpAddress"], chain["addAddress"]):
                candidates.append((section, row_index, offset, relocation_type, symbol_index, addend))
    require(len(candidates) == 2, f"expected exactly two caller-owned section-linked RELA rows, found {len(candidates)}")
    by_site = {row[2]: row for row in candidates}
    require(set(by_site) == {chain["adrpAddress"], chain["addAddress"]}, "RELA rows do not match exact ADRP/ADD sites")
    adrp, add = by_site[chain["adrpAddress"]], by_site[chain["addAddress"]]
    require(adrp[0].index == add[0].index, "ADRP and ADD rows have different RELA table owners")
    require((adrp[3], add[3]) == (275, 277), "static callback relocation pair is not ADR_PREL_PG_HI21 / ADD_ABS_LO12_NC")
    require(adrp[4] == add[4] and adrp[4] != 0, "ADRP and ADD rows do not share one nonzero symbol index")
    require(adrp[5] == add[5] == 0, "static callback relocations have nonzero addends")
    symtab = image.sections[adrp[0].link]
    symbol_rows = image.symbols[symtab.index]
    require(adrp[4] < len(symbol_rows), "static callback relocation symbol index is out of range")
    relocation_symbol = symbol_rows[adrp[4]]
    require(relocation_symbol.name == callback.name and relocation_symbol.value == callback.value and relocation_symbol.size == callback.size, "RELA symbol row does not exactly identify the callback")
    require(relocation_symbol.symbol_type == 2 and relocation_symbol.section_index == callback_section.index, "RELA symbol row is not the callback STT_FUNC in its exact target section")
    require(relocation_symbol.binding == 0 or relocation_symbol.visibility in (1, 2, 3), "callback is preemptible")
    return {
        "relocationSectionIndex": adrp[0].index,
        "relocationSectionName": adrp[0].name,
        "relocationSectionType": adrp[0].kind,
        "relocationSectionLink": adrp[0].link,
        "relocationSectionInfo": adrp[0].info,
        "symbolTableSectionIndex": symtab.index,
        "callerSectionIndex": caller_section.index,
        "targetSectionIndex": callback_section.index,
        "symbolIndex": adrp[4],
        "symbolName": relocation_symbol.name,
        "symbolValue": relocation_symbol.value,
        "symbolSize": relocation_symbol.size,
        "symbolBinding": relocation_symbol.binding,
        "symbolVisibility": relocation_symbol.visibility,
        "rows": [
            {"siteAddress": row[2], "relocationType": row[3], "symbolIndex": row[4], "addend": row[5], "rowIndex": row[1]}
            for row in (adrp, add)
        ],
    }


def verify_manifest(root: Path) -> None:
    manifest = root / "SHA256SUMS"
    require(manifest.is_file() and not manifest.is_symlink(), "closed evidence manifest is missing")
    expected: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8", errors="strict").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "malformed SHA256SUMS line")
        digest, name = match.groups()
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts and name not in expected, "manifest path is unsafe or duplicate")
        expected[name] = digest
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    require(set(expected) == actual_paths, "SHA256SUMS does not describe the closed evidence root exactly")
    for name, digest in expected.items():
        path = root / name
        require(not path.is_symlink() and path.is_file(), f"manifest file is not a regular file: {name}")
        require(sha256(path) == digest, f"manifest digest mismatch: {name}")


def current_runtime_identity() -> dict[str, Any]:
    helper = Path(__file__).with_name("tls_runtime_identity.py")
    result = subprocess.run([sys.executable, str(helper)], check=True, capture_output=True, text=True)
    value = json.loads(result.stdout)
    require(value.get("runtime") == "glibc" and value.get("architecture") in ("aarch64", "arm64"), "current process is not native AArch64 glibc")
    return value


def validate_handoff(
    handoff: dict[str, Any],
    label: str,
    entry_symbol: str,
    image_sha256: str,
) -> None:
    require(handoff.get("status") == "passed", f"{label} handoff did not pass")
    require(handoff.get("stage") == "host-context-handoff", f"{label} handoff has the wrong stage")
    require(handoff.get("entrySymbol") == entry_symbol, f"{label} handoff selected the wrong entry symbol")
    require(handoff.get("nativeImageSha256") == image_sha256, f"{label} handoff image hash does not bind the retained image bytes")
    require(type(handoff.get("entryStatus")) is int, f"{label} entry status is not an integer")
    require(type(handoff.get("processStatus")) is int, f"{label} process status is not an integer")
    require(handoff["processStatus"] == handoff["entryStatus"], f"{label} process and entry statuses disagree")
    require(handoff["entryStatus"] == EXPECTED_ENTRY_STATUS, f"{label} entry status is not {EXPECTED_ENTRY_STATUS}")
    require(handoff["processStatus"] == EXPECTED_ENTRY_STATUS, f"{label} process status is not {EXPECTED_ENTRY_STATUS}")
    require(handoff.get("releaseStatus") == "passed", f"{label} release status is not passed")
    require(handoff.get("releaseOrder") == EXPECTED_RELEASE_ORDER, f"{label} release order differs from the HostContext contract")
    require("firstFailureStage" in handoff and handoff["firstFailureStage"] is None, f"{label} handoff records a failure stage")
    require(handoff.get("loaderId") == EXPECTED_LOADER_ID, f"{label} handoff has the wrong HostContext loader identity")


def process_status_file(root: Path, filename: str, label: str) -> int:
    path = root / filename
    require(path.is_file() and not path.is_symlink(), f"{label} process-status evidence is missing or not a regular file")
    try:
        text = path.read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(f"invalid {label} process-status evidence: {exc}") from exc
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)\n", text) is not None, f"{label} process-status evidence is not one canonical decimal status")
    return int(text[:-1])


def validate_observer_evidence(
    root: Path,
    source_path: Path,
    native_path: Path,
    selected_target_handoff: dict[str, Any],
    unit: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    observer = read_json(root / "observer-handoff-evidence.json")
    observer_source = read_json(root / "observer-source-handoff.json")
    observer_target = read_json(root / "observer-target-handoff.json")
    source_image_sha = sha256(source_path)
    native_image_sha = sha256(native_path)
    require(observer.get("status") == "passed" and observer.get("unitId") == unit, "observer handoff evidence does not pass for this unit")
    validate_handoff(observer_source, "source observer", "urp_observer", source_image_sha)
    validate_handoff(observer_target, "transformed observer", "urp_observer", native_image_sha)
    source_process_status = process_status_file(root, "observer-source-process-status.txt", "source observer")
    target_process_status = process_status_file(root, "observer-target-process-status.txt", "transformed observer")
    require(source_process_status == observer_source["processStatus"], "source observer process-status file differs from its handoff")
    require(target_process_status == observer_target["processStatus"], "transformed observer process-status file differs from its handoff")
    require(observer_source["loaderId"] == observer_target["loaderId"] == selected_target_handoff.get("loaderId"), "observer and selected entry loader identities differ")
    require(observer.get("sourceImageSha256") == source_image_sha, "observer summary source-image hash does not bind retained Source Image bytes")
    require(observer.get("nativeImageSha256") == native_image_sha, "observer summary Native Image hash does not bind retained Native Image bytes")
    require(observer.get("sourceHandoffSha256") == sha256(root / "observer-source-handoff.json"), "observer summary source-handoff hash is stale")
    require(observer.get("nativeHandoffSha256") == sha256(root / "observer-target-handoff.json"), "observer summary transformed-handoff hash is stale")
    require(observer.get("sourceProcessStatus") == source_process_status == EXPECTED_ENTRY_STATUS, "observer summary source process status is not bound to expected status 97")
    require(observer.get("nativeProcessStatus") == target_process_status == EXPECTED_ENTRY_STATUS, "observer summary transformed process status is not bound to expected status 97")
    require(observer.get("sourceEntryStatus") == observer_source["entryStatus"] == EXPECTED_ENTRY_STATUS, "observer summary source entry status is not bound to expected status 97")
    require(observer.get("nativeEntryStatus") == observer_target["entryStatus"] == EXPECTED_ENTRY_STATUS, "observer summary transformed entry status is not bound to expected status 97")
    require(observer.get("sourceReleaseStatus") == observer_source["releaseStatus"] == "passed", "observer summary source release status is not bound to the handoff")
    require(observer.get("nativeReleaseStatus") == observer_target["releaseStatus"] == "passed", "observer summary transformed release status is not bound to the handoff")
    require(observer.get("loaderId") == observer_source["loaderId"] == observer_target["loaderId"] == EXPECTED_LOADER_ID, "observer summary loader identity is not bound to the exact HostContext loader")
    for side in ("source", "target"):
        for stream in ("stdout", "stderr"):
            filename = f"observer-{side}.{stream}"
            stream_path = root / filename
            require(stream_path.is_file() and not stream_path.is_symlink(), f"observer {side} {stream} evidence is missing or not a regular file")
            require(stream_path.read_bytes() == b"", f"observer {side} {stream} must be empty for this fixture")
            digest_field = f"{('source' if side == 'source' else 'native')}{stream.capitalize()}Sha256"
            require(observer.get(digest_field) == sha256(stream_path), f"observer summary {digest_field} does not bind the captured stream")
    return observer, observer_source, observer_target


def inspect(root: Path, tier: str, unit: str) -> dict[str, Any]:
    require(platform.machine() in ("aarch64", "arm64"), "checker requires native AArch64")
    source_path, protected_path, native_path = (root / name for name in ("source-image.bin", "protected-image.bin", "native-image.bin"))
    source, native = ElfImage(source_path), ElfImage(native_path)
    selected_source = source.unique_symbol(".dynsym", "urp_entry")
    source_observer = source.unique_symbol(".dynsym", "urp_observer")
    selected_native = native.unique_symbol(".dynsym", "urp_entry")
    native_observer = native.unique_symbol(".dynsym", "urp_observer")
    source_callback = source.unique_symbol(".symtab", "urp_static_callback")
    callback_candidates = native.function_symbols("urp_static_callback")
    require(len(callback_candidates) == 1, f"expected one retained native callback symbol, found {len(callback_candidates)}")
    native_callback = callback_candidates[0]
    require(source_callback.symbol_type == 2 and (source_callback.binding == 0 or source_callback.visibility in (1, 2, 3)), "source callback is not non-preemptible STT_FUNC")
    require(native_callback.value == source_callback.value and native_callback.size == source_callback.size, "callback symbol moved or changed identity in Native Image")
    require(selected_native.value == selected_source.value and selected_native.size == selected_source.size, "selected entry symbol identity changed unexpectedly")
    source_chain = find_chain(source, selected_source, source_callback)
    source_observer_chain = find_chain(source, source_observer, source_callback)
    native_observer_chain = find_chain(native, native_observer, native_callback)
    rehydration = read_json(root / "rehydration.json")
    physical_layout = rehydration.get("layoutEvidence", {})
    layout_entries = physical_layout.get("addressMap", [])
    source_entry_offset = source.file_offset(selected_source.value, selected_source.size)
    selected_regions = [entry for entry in layout_entries
        if isinstance(entry, dict)
        and isinstance(entry.get("sourceRange"), dict)
        and entry["sourceRange"].get("hasVirtualAddress") is True
        and entry["sourceRange"].get("virtualAddress", {}).get("value") == selected_source.value
        and entry["sourceRange"].get("fileOffset", {}).get("value") == source_entry_offset
        and entry["sourceRange"].get("size") == selected_source.size]
    require(len(selected_regions) == 1, f"expected one physical layout mapping for selected urp_entry, found {len(selected_regions)}")
    selected_region = selected_regions[0]
    output_range = selected_region.get("outputRange", {})
    native_entry_va = output_range.get("virtualAddress", {}).get("value")
    native_entry_file_offset = output_range.get("fileOffset", {}).get("value")
    native_entry_size = output_range.get("size")
    require(isinstance(native_entry_va, int) and isinstance(native_entry_file_offset, int)
        and isinstance(native_entry_size, int) and native_entry_size > 0,
        "physical layout mapping for selected urp_entry is malformed")
    require(native.file_offset(native_entry_va, native_entry_size) == native_entry_file_offset,
        "physical selected-function layout mapping does not match the Native Image PT_LOAD bytes")
    native_entry_code = native.read_virtual(native_entry_va, native_entry_size)
    native_chain = find_chain_in_range(native, native_entry_va, native_entry_size, "rehydrated emitted urp_entry", native_callback)
    redirect_word = struct.unpack_from("<I", native.read_virtual(selected_native.value, 4), 0)[0]
    redirect_target = decode_b(redirect_word, selected_native.value)
    if native_entry_va != selected_native.value:
        require(redirect_target == native_entry_va, "Native Image urp_entry stub does not branch to the emitted selected-function region")
    else:
        require(native_chain["adrpAddress"] >= native_entry_va
            and native_chain["callAddress"] < native_entry_va + native_entry_size,
            "in-place selected callback chain is outside its emitted function region")
    source_relocations = check_source_relocations(source, selected_source, source_callback, source_chain)
    observer_relocations = check_source_relocations(source, source_observer, source_callback, source_observer_chain)
    require(source_observer.value == native_observer.value and source_observer.size == native_observer.size, "unselected observer symbol moved in Native Image")
    source_observer_bytes = source.read_virtual(source_observer.value, source_observer.size)
    native_observer_bytes = native.read_virtual(native_observer.value, native_observer.size)
    require(source_observer_bytes == native_observer_bytes, "unselected observer function bytes changed in Native Image")
    source_callback_bytes = source.read_virtual(source_callback.value, source_callback.size)
    native_callback_bytes = native.read_virtual(native_callback.value, native_callback.size)
    require(source_callback_bytes == native_callback_bytes, "callback bytes changed at original VA in Native Image")
    require(source_chain["targetAddress"] == native_chain["targetAddress"] == source_callback.value, "selected source/output callback target is not the preserved original VA")
    require(source_observer_chain["targetAddress"] == native_observer_chain["targetAddress"] == source_callback.value, "observer no longer calls the preserved callback")
    require(native_chain["targetAddress"] == source_callback.value
        and native_chain["adrpAddress"] >= native_entry_va
        and native_chain["callAddress"] < native_entry_va + native_entry_size,
        "executed emitted callback chain is not in the selected physical Native Image region")
    require(sha256(root / "fixture-source.c") == sha256(Path(__file__).resolve().parents[1] / "native/urprotect-runtime/host_context_static_function_pointer_fixture.c"), "retained fixture source differs from checked-in source")
    require(sha256(root / "fixture-shared-object.so") == sha256(source_path), "retained fixture ELF differs from HostContext source image")
    require(root.joinpath("fixture-object.o").is_file(), "retained fixture object is missing")
    build = read_json(root / "fixture-build.json")
    require(build.get("compileCommand") == "aarch64-linux-gnu-gcc -std=c11 -O1 -fPIC -fno-inline -fno-optimize-sibling-calls -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror -c host_context_static_function_pointer_fixture.c -o host-context-static-function-pointer-fixture.o", "fixture compile command differs from the bounded native build")
    require(build.get("linkCommand") == "aarch64-linux-gnu-ld -shared --build-id=none --no-undefined --emit-relocs -z now host-context-static-function-pointer-fixture.o -o host-context-static-function-pointer-fixture.so", "fixture link command does not retain relocation evidence")
    runtime = read_json(root / "runtime-identity.json")
    require(runtime == current_runtime_identity(), "retained runtime identity differs from current native glibc")
    identity_hash = hashlib.sha256(json.dumps(runtime, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    stage = read_json(root / "stage.json")
    require(stage.get("status") == "passed" and stage.get("unitId") == unit, "producer stage record does not match the requested evidence row")
    producer = read_json(root / "producer.json")
    role = read_json(root / "protected-image.json")
    rehydration = read_json(root / "rehydration.json")
    native_role = read_json(root / "native-image.json")
    require(role.get("sourceSha256") == sha256(source_path) and role.get("artifactSha256") == sha256(protected_path), "Protected Image role hashes do not bind retained bytes")
    require(native_role.get("nativeImageSha256") == sha256(native_path), "Native Image role hash does not bind retained bytes")
    require(rehydration.get("status") == "passed" and rehydration.get("isPassed") is True and rehydration.get("nativeImageSha256") == sha256(native_path), "rehydration record does not bind the successful Native Image")
    require(producer.get("success") is True and producer.get("stage", {}).get("status") == "passed", "Protected Image producer record is not successful")
    comparison = read_json(root / "behavior-comparison.json")
    oracle = read_json(root / "behavioral-oracle.json")
    source_handoff = read_json(root / "source-handoff.json")
    target_handoff = read_json(root / "handoff.json")
    require(oracle.get("status") == "passed" and oracle.get("expectedEntryStatus") == EXPECTED_ENTRY_STATUS, "selected entry behavioral oracle failed or has wrong expected status")
    validate_handoff(source_handoff, "source entry", "urp_entry", sha256(source_path))
    validate_handoff(target_handoff, "transformed entry", "urp_entry", sha256(native_path))
    require(comparison.get("sourceSha256") == sha256(source_path) and comparison.get("protectedSha256") == sha256(protected_path) and comparison.get("nativeImageSha256") == sha256(native_path), "selected behavior record does not bind all image hashes")
    require(comparison.get("sourceHandoffSha256") == sha256(root / "source-handoff.json") and comparison.get("targetHandoffSha256") == sha256(root / "handoff.json"), "selected behavior record does not bind the actual handoffs")
    require(comparison.get("sourceEntryStatus") == source_handoff["entryStatus"] == EXPECTED_ENTRY_STATUS
        and comparison.get("targetEntryStatus") == target_handoff["entryStatus"] == EXPECTED_ENTRY_STATUS,
        "selected behavior record entry statuses do not bind expected status 97")
    require(comparison.get("sourceProcessStatus") == source_handoff["processStatus"] == EXPECTED_ENTRY_STATUS
        and comparison.get("targetProcessStatus") == target_handoff["processStatus"] == EXPECTED_ENTRY_STATUS,
        "selected behavior record process statuses do not bind expected status 97")
    require(comparison.get("sourceReleaseStatus") == source_handoff["releaseStatus"] == "passed"
        and comparison.get("targetReleaseStatus") == target_handoff["releaseStatus"] == "passed",
        "selected behavior record release statuses do not bind the successful handoffs")
    require(comparison.get("statusEqual") is True and comparison.get("stdoutEqual") is True and comparison.get("stderrEqual") is True, "selected source/transformed behavior is not equivalent")
    for side in ("baseline", "target"):
        for stream in ("stdout", "stderr"):
            stream_path = root / f"{side}.{stream}"
            require(stream_path.read_bytes() == b"", f"selected entry {side} {stream} must be empty for this fixture")
            digest_field = f"{side}{stream.capitalize()}Sha256"
            require(comparison.get(digest_field) == sha256(stream_path), f"selected behavior record {digest_field} does not bind the captured stream")
    observer, observer_source, observer_target = validate_observer_evidence(
        root,
        source_path,
        native_path,
        target_handoff,
        unit,
    )
    expected_report = {
        "schemaVersion": 1,
        "status": "passed",
        "tier": tier,
        "unitId": unit,
        "sourceSha256": sha256(source_path),
        "protectedSha256": sha256(protected_path),
        "nativeImageSha256": sha256(native_path),
        "runtimeIdentitySha256": identity_hash,
        "selected": {"sourceSymbol": "urp_entry", "sourceSymbolTableIndex": selected_source.table_index, "sourceAddress": selected_source.value, "sourceSize": selected_source.size, "sourceSectionIndex": selected_source.section_index, "nativeSymbolTableIndex": selected_native.table_index, "nativeSymbolAddress": selected_native.value, "nativeAddress": native_entry_va, "nativeFileOffset": native_entry_file_offset, "nativeSize": native_entry_size, "nativeCodeSha256": hashlib.sha256(native_entry_code).hexdigest(), "entryRedirectInstruction": f"0x{redirect_word:08x}", "entryRedirectTarget": redirect_target, "sourceCall": source_chain, "nativeCall": native_chain, "sourceHandoffSha256": sha256(root / "source-handoff.json"), "nativeHandoffSha256": sha256(root / "handoff.json"), "sourceStdoutSha256": sha256(root / "baseline.stdout"), "nativeStdoutSha256": sha256(root / "target.stdout"), "sourceStderrSha256": sha256(root / "baseline.stderr"), "nativeStderrSha256": sha256(root / "target.stderr"), "sourceReleaseStatus": source_handoff["releaseStatus"], "nativeReleaseStatus": target_handoff["releaseStatus"]},
        "observer": {"sourceAddress": source_observer.value, "sourceSize": source_observer.size, "sourceSectionIndex": source_observer.section_index, "nativeAddress": native_observer.value, "nativeSize": native_observer.size, "nativeSectionIndex": native_observer.section_index, "sourceCall": source_observer_chain, "nativeCall": native_observer_chain, "sourceBytesSha256": hashlib.sha256(source_observer_bytes).hexdigest(), "nativeBytesSha256": hashlib.sha256(native_observer_bytes).hexdigest(), "sourceHandoffSha256": sha256(root / "observer-source-handoff.json"), "nativeHandoffSha256": sha256(root / "observer-target-handoff.json"), "sourceProcessStatus": observer_source["processStatus"], "nativeProcessStatus": observer_target["processStatus"], "sourceReleaseStatus": observer_source["releaseStatus"], "nativeReleaseStatus": observer_target["releaseStatus"], "sourceStdoutSha256": sha256(root / "observer-source.stdout"), "nativeStdoutSha256": sha256(root / "observer-target.stdout"), "sourceStderrSha256": sha256(root / "observer-source.stderr"), "nativeStderrSha256": sha256(root / "observer-target.stderr")},
        "callback": {"name": source_callback.name, "sourceVa": source_callback.value, "nativeVa": native_callback.value, "size": source_callback.size, "mappingPolicy": "preserve-original-va", "sourceBytesSha256": hashlib.sha256(source_callback_bytes).hexdigest(), "nativeBytesSha256": hashlib.sha256(native_callback_bytes).hexdigest(), "sourceRelocations": source_relocations, "observerRelocations": observer_relocations},
        "selectedEntryStatus": 97,
        "sourceEntryStatus": source_handoff["entryStatus"],
        "nativeEntryStatus": target_handoff["entryStatus"],
        "sourceProcessStatus": source_handoff["processStatus"],
        "nativeProcessStatus": target_handoff["processStatus"],
        "sourceReleaseOrder": source_handoff.get("releaseOrder"),
        "nativeReleaseOrder": target_handoff.get("releaseOrder"),
        "loaderId": target_handoff.get("loaderId"),
    }
    report_path = root / "static-function-pointer-evidence.json"
    if report_path.exists():
        require(read_json(report_path) == expected_report, "static function-pointer evidence report differs from independently recomputed facts")
    return expected_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--write-report", action="store_true", help="write independently derived facts before closing SHA256SUMS")
    parser.add_argument("--verify-manifest", action="store_true", help="require SHA256SUMS to cover the exact evidence root")
    args = parser.parse_args()
    try:
        root = args.artifact_root.resolve(strict=True)
        require(root.is_dir() and not args.artifact_root.is_symlink(), "artifact root is not a regular directory")
        report = inspect(root, args.tier, args.unit)
        report_path = root / "static-function-pointer-evidence.json"
        if args.write_report:
            report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        else:
            require(report_path.is_file(), "static function-pointer evidence report is missing")
        if args.verify_manifest:
            verify_manifest(root)
        print(f"static function-pointer evidence: PASS ({args.unit}; callback VA 0x{report['callback']['sourceVa']:x}; entry/observer status 97)")
        return 0
    except (EvidenceError, OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError, KeyError, ValueError, struct.error) as exc:
        print(f"static function-pointer evidence: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
