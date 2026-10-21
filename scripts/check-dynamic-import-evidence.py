#!/usr/bin/env python3
"""Bind a glibc HostContext GLOB_DAT indirect-call oracle to its ELF and handoffs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
UNIT_ID = "runtime.host-context.dynamic-import.glibc.host-context-entry"
PRODUCER_ID = "project-aarch64-glob-dat-import-fixture"
ENTRY_SYMBOL = "urp_entry"
IMPORT_SYMBOL = "getpid"
EXPECTED_ENTRY_STATUS = 97
FAIL_CLOSED_STATUS = 96
ELF_MACHINE_AARCH64 = 183
ELF_TYPE_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_PLTRELSZ = 2
DT_JMPREL = 23
DT_PLTREL = 20
DT_GNU_HASH = 0x6FFFFEF5
R_AARCH64_GLOB_DAT = 1025
MAX_ELF_BYTES = 128 * 1024 * 1024
MAX_PROGRAM_HEADERS = 4096
MAX_DYNAMIC_ENTRIES = 65536
MAX_DYNAMIC_SYMBOLS = 1_048_576
MAX_RELOCATIONS = 1_048_576
MAX_REPORT_BYTES = 1024 * 1024
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        fail(f"{label} is missing, unsafe, or exceeds its evidence bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} is not a JSON object")
    return value


def checked_slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        fail(f"{label} is outside the bounded ELF file")
    return data[offset : offset + size]


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


class ElfImage:
    """Minimal program-header/dynamic-table reader for independently binding this fixture."""

    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        if len(data) < 64 or len(data) > MAX_ELF_BYTES:
            fail(f"{label} has an unsupported ELF file size")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        ident, self.elf_type, machine, version, self.entry, phoff, _shoff, _flags, ehsize, phentsize, phnum, _shentsize, _shnum, _shstrndx = header
        self.program_header_count = phnum
        if (
            ident[:6] != b"\x7fELF\x02\x01"
            or ident[6] != 1
            or self.elf_type != ELF_TYPE_DYN
            or machine != ELF_MACHINE_AARCH64
            or version != 1
            or ehsize != 64
            or phentsize != 56
            or phnum == 0
            or phnum > MAX_PROGRAM_HEADERS
        ):
            fail(f"{label} is not a bounded ELF64 little-endian AArch64 ET_DYN image")
        checked_slice(data, phoff, phnum * phentsize, f"{label} program-header table")
        self.loads: list[dict[str, int]] = []
        self.dynamic_segments: list[dict[str, int]] = []
        for index in range(phnum):
            kind, flags, offset, vaddr, _paddr, filesz, memsz, align = struct.unpack_from(
                "<IIQQQQQQ", data, phoff + index * phentsize
            )
            if filesz > memsz:
                fail(f"{label} program header {index} has p_filesz greater than p_memsz")
            checked_slice(data, offset, filesz, f"{label} program-header {index} file range")
            segment = {
                "index": index,
                "type": kind,
                "flags": flags,
                "offset": offset,
                "vaddr": vaddr,
                "filesz": filesz,
                "memsz": memsz,
                "align": align,
            }
            if kind == PT_LOAD:
                self.loads.append(segment)
            elif kind == PT_DYNAMIC:
                self.dynamic_segments.append(segment)
        if not self.loads or len(self.dynamic_segments) != 1:
            fail(f"{label} must have PT_LOAD mappings and exactly one PT_DYNAMIC")
        self.dynamic = self._read_dynamic()
        self.dynsym_count = self._gnu_hash_symbol_count()
        self.symbols = self._read_symbols()
        self.rela_rows = self._read_rela()

    def map_va(self, address: int, size: int, label: str, required_flags: int = 0) -> tuple[int, dict[str, int]]:
        matches: list[tuple[int, dict[str, int]]] = []
        for segment in self.loads:
            if required_flags and segment["flags"] & required_flags != required_flags:
                continue
            if address < segment["vaddr"]:
                continue
            relative = address - segment["vaddr"]
            if relative <= segment["filesz"] and size <= segment["filesz"] - relative:
                matches.append((segment["offset"] + relative, segment))
        if len(matches) != 1:
            fail(f"{self.label} {label} does not map uniquely to one file-backed PT_LOAD")
        return matches[0]

    def _dynamic_value(self, tag: int, label: str, *, optional: bool = False) -> int | None:
        values = self.dynamic.get(tag, [])
        if optional and not values:
            return None
        if len(values) != 1:
            fail(f"{self.label} requires exactly one {label} dynamic tag")
        return values[0]

    def _read_dynamic(self) -> dict[int, list[int]]:
        segment = self.dynamic_segments[0]
        if segment["filesz"] == 0 or segment["filesz"] % 16 != 0 or segment["filesz"] // 16 > MAX_DYNAMIC_ENTRIES:
            fail(f"{self.label} PT_DYNAMIC is malformed or exceeds its work bound")
        tags: dict[int, list[int]] = {}
        terminated = False
        for offset in range(segment["offset"], segment["offset"] + segment["filesz"], 16):
            tag, value = struct.unpack_from("<qQ", self.data, offset)
            if tag == DT_NULL:
                terminated = True
                break
            tags.setdefault(tag, []).append(value)
        if not terminated:
            fail(f"{self.label} PT_DYNAMIC is not terminated")
        for required, name in (
            (DT_GNU_HASH, "DT_GNU_HASH"),
            (DT_STRTAB, "DT_STRTAB"),
            (DT_SYMTAB, "DT_SYMTAB"),
            (DT_STRSZ, "DT_STRSZ"),
            (DT_SYMENT, "DT_SYMENT"),
            (DT_RELA, "DT_RELA"),
            (DT_RELASZ, "DT_RELASZ"),
            (DT_RELAENT, "DT_RELAENT"),
        ):
            if len(tags.get(required, [])) != 1:
                fail(f"{self.label} requires exactly one {name} tag")
        if tags.get(DT_HASH):
            fail(f"{self.label} unexpectedly combines SysV and GNU hash metadata")
        return tags

    def _gnu_hash_symbol_count(self) -> int:
        hash_vaddr = self._dynamic_value(DT_GNU_HASH, "DT_GNU_HASH")
        assert hash_vaddr is not None
        header_offset, _segment = self.map_va(hash_vaddr, 16, "DT_GNU_HASH header")
        bucket_count, symbol_offset, bloom_count, _bloom_shift = struct.unpack_from("<IIII", self.data, header_offset)
        if (
            bucket_count == 0
            or bucket_count > MAX_DYNAMIC_SYMBOLS
            or symbol_offset == 0
            or symbol_offset > MAX_DYNAMIC_SYMBOLS
            or bloom_count == 0
            or bloom_count > MAX_DYNAMIC_SYMBOLS
        ):
            fail(f"{self.label} GNU hash bounds are malformed")
        buckets_vaddr = hash_vaddr + 16 + bloom_count * 8
        buckets_file, _ = self.map_va(buckets_vaddr, bucket_count * 4, "GNU hash buckets")
        chain_vaddr = buckets_vaddr + bucket_count * 4
        largest_symbol = symbol_offset - 1
        for bucket_index in range(bucket_count):
            first_symbol = struct.unpack_from("<I", self.data, buckets_file + bucket_index * 4)[0]
            if first_symbol == 0:
                continue
            if first_symbol < symbol_offset or first_symbol >= MAX_DYNAMIC_SYMBOLS:
                fail(f"{self.label} GNU hash bucket has an out-of-range symbol index")
            symbol_index = first_symbol
            while True:
                chain_index = symbol_index - symbol_offset
                chain_file, _ = self.map_va(chain_vaddr + chain_index * 4, 4, "GNU hash chain row")
                chain = struct.unpack_from("<I", self.data, chain_file)[0]
                largest_symbol = max(largest_symbol, symbol_index)
                if chain & 1:
                    break
                symbol_index += 1
                if symbol_index >= MAX_DYNAMIC_SYMBOLS:
                    fail(f"{self.label} GNU hash chain exceeds its symbol work bound")
        count = max(symbol_offset, largest_symbol + 1)
        if count == 0 or count > MAX_DYNAMIC_SYMBOLS:
            fail(f"{self.label} GNU hash-derived dynamic symbol count is outside its bound")
        symbol_table_vaddr = self._dynamic_value(DT_SYMTAB, "DT_SYMTAB")
        symbol_entry_size = self._dynamic_value(DT_SYMENT, "DT_SYMENT")
        assert symbol_table_vaddr is not None and symbol_entry_size is not None
        if symbol_entry_size != 24:
            fail(f"{self.label} DT_SYMENT is not the ELF64 symbol size")
        self.map_va(symbol_table_vaddr, count * symbol_entry_size, "DT_SYMTAB")
        return count

    def _read_string(self, string_table: bytes, name_offset: int, label: str) -> str:
        if name_offset >= len(string_table):
            fail(f"{self.label} {label} name offset is outside DT_STRTAB")
        end = string_table.find(b"\0", name_offset)
        if end < 0 or end - name_offset > 4096:
            fail(f"{self.label} {label} name is unterminated or oversized")
        try:
            return string_table[name_offset:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail(f"{self.label} {label} name is not UTF-8")

    def _read_symbols(self) -> list[dict[str, int | str]]:
        strtab_vaddr = self._dynamic_value(DT_STRTAB, "DT_STRTAB")
        strtab_size = self._dynamic_value(DT_STRSZ, "DT_STRSZ")
        symtab_vaddr = self._dynamic_value(DT_SYMTAB, "DT_SYMTAB")
        syment = self._dynamic_value(DT_SYMENT, "DT_SYMENT")
        assert strtab_vaddr is not None and strtab_size is not None and symtab_vaddr is not None and syment is not None
        if strtab_size == 0 or strtab_size > MAX_ELF_BYTES or syment != 24:
            fail(f"{self.label} dynamic string/symbol table sizes are invalid")
        strings_offset, _ = self.map_va(strtab_vaddr, strtab_size, "DT_STRTAB")
        strings = checked_slice(self.data, strings_offset, strtab_size, f"{self.label} DT_STRTAB")
        symbols_offset, _ = self.map_va(symtab_vaddr, self.dynsym_count * syment, "DT_SYMTAB")
        result: list[dict[str, int | str]] = []
        for index in range(self.dynsym_count):
            row_offset = symbols_offset + index * syment
            name_offset, info, other, section_index, value, size = struct.unpack_from("<IBBHQQ", self.data, row_offset)
            result.append({
                "index": index,
                "nameOffset": name_offset,
                "name": self._read_string(strings, name_offset, f"dynamic symbol {index}"),
                "info": info,
                "binding": info >> 4,
                "type": info & 0xF,
                "other": other,
                "visibility": other & 0x3,
                "sectionIndex": section_index,
                "value": value,
                "size": size,
                "fileOffset": row_offset,
            })
        return result

    def _read_rela(self) -> list[dict[str, int]]:
        rela_vaddr = self._dynamic_value(DT_RELA, "DT_RELA")
        rela_size = self._dynamic_value(DT_RELASZ, "DT_RELASZ")
        rela_entry_size = self._dynamic_value(DT_RELAENT, "DT_RELAENT")
        assert rela_vaddr is not None and rela_size is not None and rela_entry_size is not None
        if rela_entry_size != 24 or rela_size % rela_entry_size != 0 or rela_size // rela_entry_size > MAX_RELOCATIONS:
            fail(f"{self.label} DT_RELA tuple is malformed or exceeds its bound")
        rela_offset, _ = self.map_va(rela_vaddr, rela_size, "DT_RELA")
        rows: list[dict[str, int]] = []
        for index in range(rela_size // rela_entry_size):
            offset, info, addend = struct.unpack_from("<QQq", self.data, rela_offset + index * rela_entry_size)
            rows.append({
                "index": index,
                "tableVirtualAddress": rela_vaddr,
                "tableFileOffset": rela_offset,
                "offset": offset,
                "info": info,
                "type": info & 0xFFFFFFFF,
                "symbolIndex": info >> 32,
                "addend": addend,
                "isPlt": False,
            })
        plt_size = self._dynamic_value(DT_PLTRELSZ, "DT_PLTRELSZ", optional=True) or 0
        plt_table = self._dynamic_value(DT_JMPREL, "DT_JMPREL", optional=True)
        plt_kind = self._dynamic_value(DT_PLTREL, "DT_PLTREL", optional=True)
        if plt_size != 0 or plt_table is not None or plt_kind is not None:
            fail(f"{self.label} has PLT relocation metadata outside this non-PLT GLOB_DAT fixture")
        return rows

    def facts(self, *, require_source_oracle: bool = True) -> dict[str, Any]:
        imports = [symbol for symbol in self.symbols if symbol["name"] == IMPORT_SYMBOL]
        entries = [symbol for symbol in self.symbols if symbol["name"] == ENTRY_SYMBOL]
        if len(imports) != 1 or len(entries) != 1:
            fail(f"{self.label} does not have unique dynamic {IMPORT_SYMBOL} and {ENTRY_SYMBOL} symbols")
        imported = imports[0]
        entry = entries[0]
        if (
            imported["type"] != 0
            or imported["binding"] != 1
            or imported["visibility"] != 0
            or imported["other"] != 0
            or imported["sectionIndex"] != 0
            or imported["value"] != 0
            or imported["size"] != 0
        ):
            fail(f"{self.label} imported getpid dynsym row is not undefined global default-visible STT_NOTYPE")
        if (
            entry["type"] != 2
            or entry["binding"] != 1
            or entry["visibility"] != 0
            or entry["sectionIndex"] == 0
            or entry["value"] == 0
            or entry["size"] != 60
        ):
            fail(f"{self.label} urp_entry dynsym row is not the expected defined global function")
        if len(self.rela_rows) != 1:
            fail(f"{self.label} must contain exactly one non-PLT dynamic RELA row")
        relocation = self.rela_rows[0]
        if (
            relocation["type"] != R_AARCH64_GLOB_DAT
            or relocation["symbolIndex"] != imported["index"]
            or relocation["addend"] != 0
            or relocation["isPlt"]
            or relocation["offset"] & 7
        ):
            fail(f"{self.label} does not have the exact aligned non-PLT getpid GLOB_DAT relocation")
        got_file_offset, got_segment = self.map_va(relocation["offset"], 8, "GLOB_DAT GOT slot", PF_W)
        if got_segment["flags"] & PF_X:
            fail(f"{self.label} GLOB_DAT GOT slot is unexpectedly executable")
        entry_file_offset, entry_segment = self.map_va(entry["value"], entry["size"], "urp_entry function", PF_X)
        source_oracle: dict[str, int] | None = None
        if require_source_oracle:
            code = checked_slice(self.data, entry_file_offset, entry["size"], f"{self.label} urp_entry bytes")
            words = list(struct.unpack("<15I", code))
            if (
                words[0] != 0xA9BF7BFD  # stp x29, x30, [sp, #-16]!: preserve caller LR across BLR
                or words[2] != 0xAA0103E2  # mov x2, x1: retain ADRP page provenance
                or words[3] != 0xAA1F03E1  # mov x1, xzr: clobber the original page register
                or words[4] != 0xAA1F03E0  # initialize X0 so a skipped BLR fails closed
                or words[5] & 0xFFC003FF != 0xF9400049  # ldr x9, [x2, #imm]
                or words[6] != 0xD63F0120  # blr x9
                or words[7] != 0x7100001F  # cmp w0, #0
                or words[9] != 0x52800C20  # mov w0, #97 on positive getpid result
                or words[10] != 0xA8C17BFD  # ldp x29, x30, [sp], #16: restore caller LR
                or words[11] != 0xD65F03C0  # ret
                or words[12] != 0x52800C00  # mov w0, #96 on failed call result
                or words[13] != 0xA8C17BFD  # restore caller LR on fail-closed path
                or words[14] != 0xD65F03C0  # ret
            ):
                fail(f"{self.label} urp_entry is not the LR-preserving fail-closed getpid BLR oracle")
            adrp = words[1]
            if (adrp & 0x9F00001F) != 0x90000001:
                fail(f"{self.label} imported-call sequence does not contain ADRP X1")
            immediate = ((adrp >> 29) & 0x3) | (((adrp >> 5) & 0x7FFFF) << 2)
            adrp_pc = entry["value"] + 4
            page_address = (adrp_pc & ~0xFFF) + (sign_extend(immediate, 21) << 12)
            load = words[5]
            load_target = page_address + (((load >> 10) & 0xFFF) * 8)
            if load_target != relocation["offset"]:
                fail(f"{self.label} ADRP/LDR chain does not name the exact GLOB_DAT GOT slot")
            branch = words[8]
            if (branch & 0xFF000010) != 0x54000000 or (branch & 0xF) != 13:
                fail(f"{self.label} getpid result is not guarded by B.LE fail-closed control flow")
            branch_target = entry["value"] + 32 + (sign_extend((branch >> 5) & 0x7FFFF, 19) << 2)
            if branch_target != entry["value"] + 48:
                fail(f"{self.label} fail-closed branch does not select the status-96 return")
            source_oracle = {
                "functionSize": entry["size"],
                "callAddress": entry["value"] + 24,
                "callInstructionWord": words[6],
                "targetRegister": 9,
                "preCallX0ZeroWord": words[4],
                "returnAddressSaveWord": words[0],
                "returnAddressRestoreWord": words[10],
                "resultCompareWord": words[7],
                "failureBranchWord": words[8],
                "failureBranchTarget": branch_target,
                "positiveStatus": EXPECTED_ENTRY_STATUS,
                "failClosedStatus": FAIL_CLOSED_STATUS,
            }
        return {
            "elf": {
                "type": self.elf_type,
                "machine": ELF_MACHINE_AARCH64,
                "data": "little",
                "programHeaderCount": self.program_header_count,
            },
            "selectedFunction": {
                "selector": f"dynsym:{entry['index']}",
                "name": ENTRY_SYMBOL,
                "symbolIndex": entry["index"],
                "value": entry["value"],
                "size": entry["size"],
                "fileOffset": entry_file_offset,
                "programHeaderIndex": entry_segment["index"],
                "symbolFileOffset": entry["fileOffset"],
            },
            "importSymbol": {
                "name": IMPORT_SYMBOL,
                "symbolIndex": imported["index"],
                "nameOffset": imported["nameOffset"],
                "fileOffset": imported["fileOffset"],
                "info": imported["info"],
                "binding": imported["binding"],
                "type": imported["type"],
                "other": imported["other"],
                "visibility": imported["visibility"],
                "sectionIndex": imported["sectionIndex"],
                "value": imported["value"],
                "size": imported["size"],
            },
            "relocation": {
                "source": "DT_RELA",
                "tableVirtualAddress": relocation["tableVirtualAddress"],
                "tableFileOffset": relocation["tableFileOffset"],
                "tableIndex": relocation["index"],
                "virtualAddress": relocation["offset"],
                "info": relocation["info"],
                "type": relocation["type"],
                "symbolIndex": relocation["symbolIndex"],
                "addend": relocation["addend"],
                "isPlt": relocation["isPlt"],
            },
            "got": {
                "virtualAddress": relocation["offset"],
                "fileOffset": got_file_offset,
                "size": 8,
                "programHeaderIndex": got_segment["index"],
                "segmentFlags": got_segment["flags"],
            },
            "sourceOracle": source_oracle,
        }


def validate_source_facts(evidence: dict[str, Any], source_path: Path, native_path: Path | None = None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    source_data = source_path.read_bytes()
    source_facts = ElfImage(source_data, "Source Image").facts()
    if evidence.get("sourceElfFacts") != source_facts:
        fail("dynamic-import source ELF claims do not match independently parsed PT_DYNAMIC/PT_LOAD/dynsym/RELA facts")
    if evidence.get("sourceSha256") != sha256_bytes(source_data):
        fail("dynamic-import source hash does not match Source Image bytes")
    if evidence.get("selectedFunction") != source_facts["selectedFunction"]:
        fail("selected function identity does not bind the actual urp_entry dynsym record")
    native_facts = None
    if native_path is not None:
        native_data = native_path.read_bytes()
        native_facts = ElfImage(native_data, "Native Image").facts(require_source_oracle=False)
        if evidence.get("nativeElfFacts") != native_facts:
            fail("dynamic-import Native Image facts do not match independently parsed loader metadata")
        source_import = source_facts["importSymbol"]
        native_import = native_facts["importSymbol"]
        source_rela = source_facts["relocation"]
        native_rela = native_facts["relocation"]
        if (
            native_import["name"] != source_import["name"]
            or native_import["symbolIndex"] != source_import["symbolIndex"]
            or native_import["info"] != source_import["info"]
            or native_rela["type"] != source_rela["type"]
            or native_rela["symbolIndex"] != source_rela["symbolIndex"]
            or native_rela["addend"] != source_rela["addend"]
            or native_rela["isPlt"] is not False
            or native_facts["got"]["virtualAddress"] != native_rela["virtualAddress"]
        ):
            fail("Native Image no longer carries the same non-PLT getpid GLOB_DAT symbol/GOT ownership")
    return source_facts, native_facts


def check_closed_manifest(root: Path) -> dict[str, str]:
    manifest = root / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 16 * 1024 * 1024:
        fail("dynamic-import evidence has no bounded SHA256SUMS")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or not DIGEST.fullmatch(parts[0]):
            fail(f"dynamic-import SHA256SUMS entry {line_number} is malformed")
        relative = Path(parts[1])
        if relative.is_absolute() or ".." in relative.parts or "\\" in parts[1] or relative.as_posix() in entries:
            fail(f"dynamic-import SHA256SUMS path at line {line_number} is unsafe or duplicated")
        path = root / relative
        if path.is_symlink() or not path.is_file() or sha256_file(path) != parts[0]:
            fail(f"dynamic-import SHA256SUMS file is missing, unsafe, or changed: {parts[1]}")
        entries[relative.as_posix()] = parts[0]
    observed: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            fail("dynamic-import evidence refuses symlinks, including dangling links")
        if path.is_file() and path != manifest:
            observed.add(path.relative_to(root).as_posix())
    if observed != set(entries):
        fail("dynamic-import SHA256SUMS is not closed over the evidence root")
    return entries


def load_runtime_identity_module() -> Any:
    identity_script = ROOT / "scripts" / "tls_runtime_identity.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("dynamic_import_tls_runtime_identity", identity_script)
    if spec is None or spec.loader is None:
        fail("could not load the native glibc runtime identity verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_runtime_identity(root: Path) -> dict[str, Any]:
    identity = read_json(root / "runtime-identity.json", "runtime identity")
    module = load_runtime_identity_module()
    try:
        return module.verify_identity(identity, verify_current_process=True)
    except SystemExit:
        raise
    except Exception as error:
        fail(f"native producer runtime identity verification failed: {error}")


def validate_behavior(root: Path, evidence: dict[str, Any], source_hash: str, native_hash: str) -> None:
    source_handoff_path = root / "source-handoff.json"
    target_handoff_path = root / "handoff.json"
    source_handoff = read_json(source_handoff_path, "source handoff")
    target_handoff = read_json(target_handoff_path, "transformed handoff")
    expected_handoffs = (
        ("source", source_handoff, source_hash),
        ("transformed", target_handoff, native_hash),
    )
    for label, handoff, expected_image in expected_handoffs:
        if (
            handoff.get("status") != "passed"
            or handoff.get("loaderId") != "host-context.sealed-memfd.dlopen"
            or handoff.get("nativeImageSha256") != expected_image
            or handoff.get("entrySymbol") != ENTRY_SYMBOL
            or type(handoff.get("entryStatus")) is not int
            or type(handoff.get("processStatus")) is not int
            or handoff.get("processStatus") != handoff.get("entryStatus")
            or handoff.get("releaseStatus") != "passed"
            or handoff.get("releaseOrder") != "entry-dispatch-before-release-image"
        ):
            fail(f"{label} handoff is not a measured successful urp_entry dispatch")
    if (
        source_handoff["entryStatus"] != EXPECTED_ENTRY_STATUS
        or target_handoff["entryStatus"] != EXPECTED_ENTRY_STATUS
        or source_handoff["processStatus"] != EXPECTED_ENTRY_STATUS
        or target_handoff["processStatus"] != EXPECTED_ENTRY_STATUS
    ):
        fail("source/transformed entry statuses do not satisfy the fail-closed getpid fixture oracle")
    for label, path, handoff in (
        ("source", source_handoff_path, source_handoff),
        ("transformed", target_handoff_path, target_handoff),
    ):
        expected_sha = evidence["sourceHandoffSha256"] if label == "source" else evidence["transformedHandoffSha256"]
        if expected_sha != sha256_file(path):
            fail(f"{label} handoff hash is not bound to retained handoff bytes")
        if evidence["handoffs"][label] != {
            "sha256": sha256_file(path),
            "status": handoff["status"],
            "entrySymbol": handoff["entrySymbol"],
            "entryStatus": handoff["entryStatus"],
            "processStatus": handoff["processStatus"],
            "releaseStatus": handoff["releaseStatus"],
            "releaseOrder": handoff["releaseOrder"],
        }:
            fail(f"{label} handoff observations differ from the evidence summary")
    streams = {
        "sourceStdout": (root / "baseline.stdout").read_bytes(),
        "sourceStderr": (root / "baseline.stderr").read_bytes(),
        "transformedStdout": (root / "target.stdout").read_bytes(),
        "transformedStderr": (root / "target.stderr").read_bytes(),
    }
    summary = evidence.get("streams")
    if not isinstance(summary, dict):
        fail("dynamic-import source/transformed stream summary is malformed")
    for name, contents in streams.items():
        if len(contents) > 1024 * 1024:
            fail(f"dynamic-import {name} exceeds the retained stream bound")
        if summary.get(name) != {"bytes": len(contents), "sha256": sha256_bytes(contents)}:
            fail(f"dynamic-import {name} summary does not match retained bytes")
    comparison = {
        "statusEqual": source_handoff["processStatus"] == target_handoff["processStatus"]
        and source_handoff["entryStatus"] == target_handoff["entryStatus"]
        and source_handoff["status"] == target_handoff["status"]
        and source_handoff["releaseStatus"] == target_handoff["releaseStatus"],
        "stdoutEqual": streams["sourceStdout"] == streams["transformedStdout"],
        "stderrEqual": streams["sourceStderr"] == streams["transformedStderr"],
    }
    if evidence.get("comparison") != comparison or not all(comparison.values()):
        fail("source/transformed status or actual stdout/stderr byte comparison failed")


def verify_producer_binding(root: Path, evidence: dict[str, Any], source_facts: dict[str, Any]) -> None:
    producer = read_json(root / "producer.json", "Protected Image producer report")
    role = read_json(root / "protected-image.json", "Protected Image role")
    stage = read_json(root / "stage.json", "Protected Image producer stage")
    source = source_facts["selectedFunction"]
    selector = f"table=dynsym, index={source['symbolIndex']}"
    report_role = producer.get("role")
    report_stage = producer.get("stage")
    if (
        producer.get("success") is not True
        or not isinstance(report_role, dict)
        or not isinstance(report_stage, dict)
        or report_role.get("selectors") != [selector]
        or report_stage.get("selectors") != [selector]
        or report_stage.get("transformedFunctionCount") != 1
        or report_stage.get("transformationStatus") != "passed"
        or report_stage.get("status") != "passed"
    ):
        fail("producer report does not bind the actual urp_entry dynsym selector to one transformed function")
    source_hash = evidence["sourceSha256"]
    protected_hash = evidence["protectedImageSha256"]
    if (
        role.get("artifactRole") != "protected-image"
        or role.get("abiId") != "urprotect.protected-image.v1"
        or role.get("unitId") != UNIT_ID
        or role.get("profile") != "host-context-entry"
        or role.get("sourceSha256") != source_hash
        or role.get("artifactSha256") != protected_hash
        or role.get("producerId") != PRODUCER_ID
    ):
        fail("Protected Image role does not bind the scoped producer/source/artifact facts")
    if (
        stage.get("stage") != "protected-image-producer"
        or stage.get("status") != "passed"
        or stage.get("unitId") != UNIT_ID
        or stage.get("profile") != "host-context-entry"
        or stage.get("sourceSha256") != source_hash
        or stage.get("artifactSha256") != protected_hash
        or stage.get("producerId") != PRODUCER_ID
    ):
        fail("Protected Image producer stage does not bind the scoped producer/source/artifact facts")
    if evidence.get("producerId") != role.get("producerId"):
        fail("evidence producer identity differs from the emitted Protected Image role")
    rehydration = read_json(root / "rehydration.json", "GenericRehydrationEngine record")
    if (
        rehydration.get("status") != "passed"
        or rehydration.get("profile") != "host-context-entry"
        or rehydration.get("sourceSha256") != source_hash
        or rehydration.get("protectedImageSha256") != protected_hash
        or rehydration.get("nativeImageSha256") != evidence.get("nativeImageSha256")
        or rehydration.get("materializationStatus") != "passed"
    ):
        fail("GenericRehydrationEngine did not publish the bound HostContext Native Image")


def verify_negative_witness(root: Path) -> dict[str, Any]:
    source_path = root / "protected-image.bin"
    negative_path = root / "negative-protected-image.bin"
    if source_path.is_symlink() or negative_path.is_symlink() or not source_path.is_file() or not negative_path.is_file():
        fail("tampered Protected Image negative lacks regular source/corrupt artifact files")
    source_bytes = source_path.read_bytes()
    negative_bytes = negative_path.read_bytes()
    if (
        len(source_bytes) < 64
        or len(negative_bytes) != len(source_bytes)
        or negative_bytes[:-1] != source_bytes[:-1]
        or negative_bytes[-1] != (source_bytes[-1] ^ 1)
        or sha256_bytes(negative_bytes[:-32]) == negative_bytes[-32:].hex()
    ):
        fail("negative Protected Image is not the exact bounded final-digest corruption")
    command = read_json(root / "negative-rehydration-command.json", "negative rehydration command report")
    record = read_json(root / "negative-rehydration.json", "negative rehydration record")
    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, list):
        fail("negative rehydration diagnostics are malformed")
    matching = [item for item in diagnostics if isinstance(item, dict) and item.get("code") == "ProtectedImageIntegrityMismatch"]
    native_paths = ("negative-native-image.bin", "negative-native-image.json")
    handoff_paths = ("negative-handoff.json", "negative-handoff.stdout", "negative-handoff.stderr")
    native_published = any((root / name).exists() or (root / name).is_symlink() for name in native_paths)
    handoff_published = any((root / name).exists() or (root / name).is_symlink() for name in handoff_paths)
    exit_path = root / "negative-rehydration-exit-status.txt"
    if exit_path.is_symlink() or not exit_path.is_file():
        fail("negative rehydration process exit status is missing")
    try:
        exit_status = int(exit_path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeDecodeError, ValueError):
        fail("negative rehydration process exit status is malformed")
    if (
        exit_status != 5
        or command.get("success") is not False
        or command.get("record") != record
        or record.get("status") != "failed"
        or record.get("stage") != "rehydration"
        or record.get("firstFailureStage") != "rehydration"
        or record.get("materializationStatus") != "failed"
        or record.get("unitId") != UNIT_ID
        or len(matching) != 1
        or native_published
        or handoff_published
    ):
        fail("corrupt Protected Image did not fail at rehydration before Native Image/loader publication")
    expected_witness = {
        "schemaVersion": 1,
        "kind": "strict-chain-negative-witness",
        "status": "passed",
        "unitId": record["unitId"],
        "stage": record["firstFailureStage"],
        "failureClass": matching[0]["code"],
        "rollbackStatus": "passed",
        "nativeImagePublished": native_published,
        "loaderInvoked": handoff_published,
        "loaderMarkerObserved": (root / "negative-handoff.stdout").is_file(),
        "artifactPath": "negative-protected-image.bin",
        "nativeImagePath": "negative-native-image.bin",
        "loaderMarkerPath": "negative-handoff.json",
        "producerExitStatus": exit_status,
        "negativeRecordSha256": sha256_file(root / "negative-rehydration.json"),
    }
    witness = read_json(root / "negative-rollback.json", "negative rollback witness")
    if witness != expected_witness:
        fail("negative rollback witness is not derived from the retained failed rehydration and publication state")
    return {
        "recordSha256": sha256_file(root / "negative-rehydration.json"),
        "commandSha256": sha256_file(root / "negative-rehydration-command.json"),
        "producerExitStatus": exit_status,
        "failureDiagnostic": matching[0]["code"],
        "firstFailureStage": record["firstFailureStage"],
        "nativeImagePublished": native_published,
        "handoffPublished": handoff_published,
    }


def build_report(root: Path, unit: str) -> dict[str, Any]:
    if unit != UNIT_ID or root.name != unit:
        fail("dynamic-import evidence root/unit is outside the scoped fixture identity")
    runtime = verify_runtime_identity(root)
    source_path = root / "source-image.bin"
    protected_path = root / "protected-image.bin"
    native_path = root / "native-image.bin"
    for path, label in ((source_path, "Source Image"), (protected_path, "Protected Image"), (native_path, "Native Image")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            fail(f"{label} is missing or unsafe")
    source_hash = sha256_file(source_path)
    protected_hash = sha256_file(protected_path)
    native_hash = sha256_file(native_path)
    source_facts = ElfImage(source_path.read_bytes(), "Source Image").facts()
    native_facts = ElfImage(native_path.read_bytes(), "Native Image").facts(require_source_oracle=False)
    build = read_json(root / "dynamic-import-build.json", "fixture build provenance")
    source_copy = root / "fixture-source.S"
    object_copy = root / "fixture-object.o"
    if (
        source_copy.is_symlink()
        or object_copy.is_symlink()
        or not source_copy.is_file()
        or not object_copy.is_file()
    ):
        fail("project fixture source/object provenance files are missing or unsafe")
    source_sha = sha256_file(source_copy)
    object_sha = sha256_file(object_copy)
    current_source = ROOT / "native/urprotect-runtime/host_context_dynamic_import_fixture.S"
    makefile = ROOT / "native/urprotect-runtime/Makefile"
    if (
        source_copy.read_bytes() != current_source.read_bytes()
        or build.get("sourceAssemblyPath") != "native/urprotect-runtime/host_context_dynamic_import_fixture.S"
        or build.get("sourceAssemblySha256") != source_sha
        or build.get("objectSha256") != object_sha
        or build.get("fixtureSha256") != source_hash
        or build.get("makefileSha256") != sha256_file(makefile)
        or build.get("buildCommand") != ["make", "-C", "native/urprotect-runtime", "dynamic-import-fixture"]
    ):
        fail("fixture build provenance does not bind the project assembly/object/ELF inputs")
    # Reparse the source/native ELF rather than trusting any producer-supplied metadata.
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "evidenceScope": "glibc-aarch64-host-context-entry-project-built-getpid-glob-dat-indirect-call",
        "acceptanceState": "scoped-observation-pending-independent-review",
        "unitId": UNIT_ID,
        "profile": "host-context-entry",
        "runtime": "glibc",
        "runtimeIdentity": runtime,
        "producerId": PRODUCER_ID,
        "sourceSha256": source_hash,
        "protectedImageSha256": protected_hash,
        "nativeImageSha256": native_hash,
        "sourceElfFacts": source_facts,
        "nativeElfFacts": native_facts,
        "selectedFunction": source_facts["selectedFunction"],
        "sourceHandoffSha256": sha256_file(root / "source-handoff.json"),
        "transformedHandoffSha256": sha256_file(root / "handoff.json"),
        "handoffs": {},
        "streams": {},
        "comparison": {},
        "rehydrationRecordSha256": sha256_file(root / "rehydration.json"),
        "fixtureBuild": {
            "sourceAssemblyPath": build["sourceAssemblyPath"],
            "sourceAssemblySha256": source_sha,
            "objectSha256": object_sha,
            "makefileSha256": build["makefileSha256"],
            "fixtureSha256": source_hash,
            "assembler": build["assembler"],
            "linker": build["linker"],
        },
    }
    validate_source_facts(report, source_path, native_path)
    verify_producer_binding(root, report, source_facts)
    for label, name in (("source", "source-handoff.json"), ("transformed", "handoff.json")):
        handoff = read_json(root / name, f"{label} handoff")
        report["handoffs"][label] = {
            "sha256": sha256_file(root / name),
            "status": handoff.get("status"),
            "entrySymbol": handoff.get("entrySymbol"),
            "entryStatus": handoff.get("entryStatus"),
            "processStatus": handoff.get("processStatus"),
            "releaseStatus": handoff.get("releaseStatus"),
            "releaseOrder": handoff.get("releaseOrder"),
        }
    for name, path_name in (
        ("sourceStdout", "baseline.stdout"),
        ("sourceStderr", "baseline.stderr"),
        ("transformedStdout", "target.stdout"),
        ("transformedStderr", "target.stderr"),
    ):
        stream_path = root / path_name
        data = stream_path.read_bytes()
        if len(data) > 1024 * 1024:
            fail(f"{path_name} exceeds its evidence bound")
        report["streams"][name] = {"bytes": len(data), "sha256": sha256_bytes(data)}
    source_handoff = report["handoffs"]["source"]
    target_handoff = report["handoffs"]["transformed"]
    report["comparison"] = {
        "statusEqual": source_handoff["status"] == target_handoff["status"]
        and source_handoff["processStatus"] == target_handoff["processStatus"]
        and source_handoff["entryStatus"] == target_handoff["entryStatus"]
        and source_handoff["releaseStatus"] == target_handoff["releaseStatus"],
        "stdoutEqual": (root / "baseline.stdout").read_bytes() == (root / "target.stdout").read_bytes(),
        "stderrEqual": (root / "baseline.stderr").read_bytes() == (root / "target.stderr").read_bytes(),
    }
    validate_behavior(root, report, source_hash, native_hash)
    report["genericRollback"] = verify_negative_witness(root)
    producer = read_json(root / "producer.json", "producer report")
    if producer.get("success") is not True:
        fail("Protected Image producer did not report success")
    return report


def write_manifest(root: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            fail("dynamic-import evidence refuses symlinks, including dangling links")
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    manifest = root / "SHA256SUMS"
    temporary = root / ".SHA256SUMS.tmp"
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temporary, manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--unit", default=UNIT_ID)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), default="pr")
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    root = args.artifact_root
    if root.is_symlink() or not root.is_dir():
        fail("dynamic-import evidence root is missing or a symlink")
    root = root.resolve()
    if args.write_report:
        report = build_report(root, args.unit)
        output = root / "dynamic-import-evidence.json"
        temporary = root / ".dynamic-import-evidence.json.tmp"
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, output)
        write_manifest(root)
    entries = check_closed_manifest(root)
    evidence = read_json(root / "dynamic-import-evidence.json", "dynamic-import evidence report")
    source_path = root / "source-image.bin"
    native_path = root / "native-image.bin"
    source_facts, _native_facts = validate_source_facts(evidence, source_path, native_path)
    runtime = verify_runtime_identity(root)
    if (
        evidence.get("schemaVersion") != 1
        or evidence.get("unitId") != args.unit
        or evidence.get("profile") != "host-context-entry"
        or evidence.get("runtime") != "glibc"
        or evidence.get("runtimeIdentity") != runtime
        or evidence.get("evidenceScope") != "glibc-aarch64-host-context-entry-project-built-getpid-glob-dat-indirect-call"
        or evidence.get("acceptanceState") != "scoped-observation-pending-independent-review"
        or evidence.get("sourceSha256") != sha256_file(source_path)
        or evidence.get("protectedImageSha256") != sha256_file(root / "protected-image.bin")
        or evidence.get("nativeImageSha256") != sha256_file(native_path)
        or evidence.get("rehydrationRecordSha256") != sha256_file(root / "rehydration.json")
    ):
        fail("dynamic-import evidence identity or artifact hashes do not match retained bytes")
    verify_producer_binding(root, evidence, source_facts)
    validate_behavior(root, evidence, evidence["sourceSha256"], evidence["nativeImageSha256"])
    if evidence.get("genericRollback") != verify_negative_witness(root):
        fail("dynamic-import evidence rollback facts differ from the observed negative artifacts")
    rehydration_checker = ROOT / "scripts" / "check-rehydration-evidence.py"
    result = subprocess.run(
        [sys.executable, str(rehydration_checker), str(root), "--tier", args.tier, "--runtime", "glibc", "--unit", args.unit],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"generic rehydration evidence check failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
    print(f"PASS dynamic-import evidence: root={root} unit={args.unit} scoped=glibc/aarch64/HostContext/GLOB_DAT/getpid")
    print(f"source={evidence['sourceSha256']} protected={evidence['protectedImageSha256']} native={evidence['nativeImageSha256']}")
    print(f"source-handoff={evidence['sourceHandoffSha256']} transformed-handoff={evidence['transformedHandoffSha256']}")
    del entries


if __name__ == "__main__":
    main()
