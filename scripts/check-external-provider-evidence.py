#!/usr/bin/env python3
"""Independently validate one native AArch64/glibc external-table provider run."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shlex
import stat
import struct
import sys
import tarfile
import types
import zlib
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from typing import Any, Iterator

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
UNIT_ID = "runtime.indirect-control.external-provider.glibc.host-context-entry"
PRODUCER_ID = "project-aarch64-external-jump-table-provider-fixture"
PROVIDER_SONAME = "liburprotect-jump-table-provider.so.1"
PROVIDER_TABLE = "urp_external_jump_table"
TARGET_SYMBOLS = tuple(f"urp_provider_target_{index}" for index in range(4))
ENTRY_SYMBOLS = ("urp_entry", "urp_observer")
INDICES = (0, 1, 2, 3, 4)
ENTRY_STATUSES = (17, 103, -7, 91, -1)
PROCESS_STATUSES = (17, 103, 249, 91, 255)
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_RUNTIME_IMAGE_BYTES = 256 * 1024 * 1024
MAX_PROVIDER_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
MAX_PROVIDER_ROOT_FILES = 256
MAX_PROVIDER_ROOT_DIRECTORIES = 32  # Includes the evidence root itself.
MAX_PROVIDER_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_MANIFEST_ENTRIES = MAX_PROVIDER_ROOT_FILES
MAX_PRIVATE_HELPER_SOURCE_BYTES = 16 * 1024 * 1024
_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY = "_urprotect_active_evidence_root_snapshot"
_ACTIVE_ROOT_SNAPSHOT: Any | None = None
NATIVE_BUILD_COMMAND = ["make", "-C", "native/urprotect-runtime", "-B", "external-provider-image-handoff"]
MANAGED_BUILD_COMMAND = ["dotnet", "build", "UrProtect.sln", "--configuration", "Release", "--no-restore"]
CPP_FLAGS = ["-Iinclude", "-I../urprotect-launcher", "-I../../third_party/miniz"]
C_FLAGS = ["-std=c11", "-O2", "-g0", "-Wall", "-Wextra", "-Werror", "-Wshadow", "-Wconversion", "-pthread"]
EVIDENCE_TOOL_FILES = {
    "providerProducerSha256": "build-inputs/evidence-tools/scripts/run-external-provider-e2e.sh",
    "providerCheckerSha256": "build-inputs/evidence-tools/scripts/check-external-provider-evidence.py",
    "dynamicImportParserSha256": "build-inputs/evidence-tools/scripts/check-dynamic-import-evidence.py",
    "indirectControlParserSha256": "build-inputs/evidence-tools/scripts/check-indirect-control-evidence.py",
    "evidenceLoadRangeHelperSha256": "build-inputs/evidence-tools/scripts/evidence_load_range.py",
    "runtimeIdentityVerifierSha256": "build-inputs/evidence-tools/scripts/tls_runtime_identity.py",
    "rollbackProducerSha256": "build-inputs/evidence-tools/scripts/run-external-provider-rollback-oracle.sh",
    "rollbackCheckerSha256": "build-inputs/evidence-tools/scripts/check-external-provider-rollback-evidence.py",
}
BUILD_PROVENANCE_FILES = {
    "native-build.stdout", "native-build.stderr", "managed-build.stdout", "managed-build.stderr",
    "host-adapter.o", "rollback-host-adapter.o", "host-image-validation.o",
    "rollback-host-image-validation-test.o", "sha256.o",
    "build-inputs/Makefile", "build-inputs/host_context_external_provider_image_handoff.c",
    "build-inputs/host_context_external_provider_self_test.c",
    "build-inputs/host_adapter_provider_rollback_test.h",
    "build-inputs/host_adapter.c", "build-inputs/host_image_validation.c", "build-inputs/host_image_validation.h",
    "build-inputs/android_packed_relocation_tags.h", "build-inputs/include/urp/host_adapter.h",
    "build-inputs/include/urp/host_context.h", "build-inputs/sha256.c", "build-inputs/sha256.h",
    "build-inputs/host_context_external_provider_fixture.S",
    "build-inputs/host_context_external_provider_consumer_fixture.S",
    "toolchain/cc-driver", "toolchain/cc1", "toolchain/as", "toolchain/ld",
    "toolchain/cc-version.txt", "toolchain/as-version.txt", "toolchain/ld-version.txt", "toolchain/target-triple.txt",
    "managed-build/urprotect.dll", "managed-build/UrProtect.Core.dll", "managed-build/dotnet-version.txt",
    *EVIDENCE_TOOL_FILES.values(),
}
# Compressed input and its expanded tar are independently bounded. The accepted
# retained bundle expands to 41,164,800 bytes; 64 MiB leaves room for that
# provenance while bounding all regular-file and hidden metadata bytes.
MAX_PROVENANCE_BYTES = 128 * 1024 * 1024
MAX_PROVENANCE_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_PROVENANCE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_PROVENANCE_PAX_HEADER_BYTES = 4096
MAX_PROVENANCE_PAX_TOTAL_BYTES = 64 * 1024
MAX_PROVENANCE_PAX_RECORDS_PER_HEADER = 16
MAX_PROVENANCE_MEMBERS = len(BUILD_PROVENANCE_FILES)
MAX_PROVENANCE_EXTENSION_HEADERS = len(BUILD_PROVENANCE_FILES)
MAX_PROVENANCE_TAR_HEADERS = len(BUILD_PROVENANCE_FILES) * 2
DIGEST = re.compile(r"^[0-9a-f]{64}$")
HEX_BUILD_ID = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"external-provider evidence: {message}")




def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def same_json(left: Any, right: Any) -> bool:
    # Canonical JSON preserves bool/int/float distinctions (unlike Python equality).
    return canonical(left) == canonical(right)


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (metadata.st_size, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_file(root: Path, relative: str, *, allow_empty: bool = False, limit: int = MAX_FILE_BYTES) -> bytes:
    if type(limit) is not int or limit < 0:
        fail("evidence file byte limit is invalid")
    parts = safe_relative(relative, "evidence file path").parts
    active = _ACTIVE_ROOT_SNAPSHOT or sys.modules.get(_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY)
    if active is not None and Path(os.path.abspath(active.root)) == Path(os.path.abspath(root)):
        data = active.read(relative, limit=limit)
        if not allow_empty and not data:
            fail(f"evidence file is not a bounded regular file: {relative}")
        return data

    root_fd = -1
    directory_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_fd = root_fd
        for part in parts[:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > limit or (not allow_empty and before.st_size == 0):
            fail(f"evidence file is not a bounded regular file: {relative}")
        result = bytearray(before.st_size)
        position = 0
        while position < before.st_size:
            chunk = os.read(file_fd, min(1024 * 1024, before.st_size - position))
            if not chunk:
                fail(f"evidence file changed size or exceeds its byte bound: {relative}")
            result[position : position + len(chunk)] = chunk
            position += len(chunk)
        growth_probe = os.read(file_fd, 1)
        after = os.fstat(file_fd)
        if growth_probe or _metadata_identity(after) != _metadata_identity(before) or not stat.S_ISREG(after.st_mode):
            fail(f"evidence file changed size or exceeds its byte bound: {relative}")
        data = bytes(result)
        if not allow_empty and not data:
            fail(f"evidence file is not a bounded regular file: {relative}")
        return data
    except OSError as error:
        fail(f"cannot safely read evidence file {relative}: {error}")
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0 and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def read_json(root: Path, relative: str, *, limit: int = MAX_REPORT_BYTES) -> dict[str, Any]:
    data = read_file(root, relative, limit=limit)
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON in {relative}: {error}")
    if not isinstance(value, dict):
        fail(f"{relative} must contain a JSON object")
    return value


def safe_relative(value: str, label: str) -> Path:
    candidate = Path(value)
    windows = PureWindowsPath(value)
    if (
        not value
        or "\\" in value
        or candidate.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or candidate.as_posix() != value
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(part in {"", ".", ".."} for part in windows.parts)
    ):
        fail(f"{label} is not a safe relative path")
    return candidate


def load_python_module(name: str, path: Path) -> Any:
    try:
        relative = path.relative_to(ROOT).as_posix()
    except ValueError:
        fail(f"retained helper module escapes its source root: {path.name}")
    source = read_file(ROOT, relative, limit=MAX_PRIVATE_HELPER_SOURCE_BYTES)
    module = types.ModuleType(name)
    namespace = types.ModuleType.__getattribute__(module, "__dict__")
    namespace.update({"__file__": str(path), "__package__": ""})
    sys.modules[name] = module
    try:
        exec(compile(source, str(path), "exec"), namespace)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


_DYNAMIC = load_python_module("urp_external_provider_dynamic_import", ROOT / "scripts/check-dynamic-import-evidence.py")
_INDIRECT = load_python_module("urp_external_provider_indirect_control", ROOT / "scripts/check-indirect-control-evidence.py")
_IDENTITY = load_python_module("urp_external_provider_runtime_identity", ROOT / "scripts/tls_runtime_identity.py")


def _provider_file_limit(relative: str) -> int:
    if relative == "SHA256SUMS":
        return MAX_PROVIDER_MANIFEST_BYTES
    if relative == "provider-image.so":
        return MAX_PROVIDER_BYTES
    if relative in {"runtime-files/libc.so.6", "runtime-files/ld-linux-aarch64.so.1"}:
        return MAX_RUNTIME_IMAGE_BYTES
    if relative == "build-provenance.tar.gz":
        return MAX_PROVENANCE_BYTES
    if relative in BUILD_PROVENANCE_FILES:
        return MAX_PROVENANCE_MEMBER_BYTES
    if relative.endswith((".stdout", ".stderr")):
        return MAX_STREAM_BYTES
    if relative.endswith(".json") or relative.endswith(".txt"):
        return MAX_REPORT_BYTES
    return MAX_FILE_BYTES


def _expected_root_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in files:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _new_root_snapshot(
    root: Path,
    *,
    exact_inventory: bool = False,
    optional_report: bool = True,
    optional_manifest: bool = True,
):
    expected_files = None
    optional_files: set[str] = set()
    expected_directories = None
    if exact_inventory:
        expected_files = _exact_root_files()
        if optional_report:
            expected_files.remove("external-provider-evidence.json")
            optional_files.add("external-provider-evidence.json")
        if optional_manifest:
            optional_files.add("SHA256SUMS")
        else:
            expected_files.add("SHA256SUMS")
        expected_directories = _expected_root_directories(_exact_root_files())
    return _INDIRECT.EvidenceRootSnapshot(
        root,
        max_files=MAX_PROVIDER_ROOT_FILES,
        max_directories=MAX_PROVIDER_ROOT_DIRECTORIES,
        max_total_bytes=MAX_TREE_BYTES,
        expected_files=expected_files,
        optional_files=optional_files,
        expected_directories=expected_directories,
        file_limit_resolver=_provider_file_limit,
    )


@contextmanager
def _using_root_snapshot(snapshot: Any) -> Iterator[None]:
    global _ACTIVE_ROOT_SNAPSHOT
    previous_active = _ACTIVE_ROOT_SNAPSHOT
    previous_module = sys.modules.get(_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY)
    had_module = _ACTIVE_ROOT_SNAPSHOT_MODULE_KEY in sys.modules
    _ACTIVE_ROOT_SNAPSHOT = snapshot
    sys.modules[_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY] = snapshot
    try:
        yield
    finally:
        _ACTIVE_ROOT_SNAPSHOT = previous_active
        if had_module:
            sys.modules[_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY] = previous_module
        else:
            sys.modules.pop(_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY, None)


def _write_root_file(root: Path, relative: str, data: bytes) -> None:
    parts = safe_relative(relative, "evidence output path").parts
    root_fd = -1
    directory_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_fd = root_fd
        for part in parts[:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
            | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            0o600,
            dir_fd=directory_fd,
        )
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"evidence output is not a regular file: {relative}")
        position = 0
        while position < len(data):
            written = os.write(file_fd, data[position : position + 1024 * 1024])
            if written <= 0:
                fail(f"evidence output write made no progress: {relative}")
            position += written
        os.fsync(file_fd)
    except OSError as error:
        fail(f"cannot safely write evidence output {relative}: {error}")
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0 and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def write_closed_manifest(root: Path) -> None:
    snapshot = _new_root_snapshot(root)
    snapshot.preflight()
    with _using_root_snapshot(snapshot):
        paths = sorted(snapshot.file_paths - {"SHA256SUMS"})
        rows = [
            f"{sha256_bytes(snapshot.read(relative, limit=_provider_file_limit(relative)))}  {relative}"
            for relative in paths
        ]
        if len(rows) > MAX_PROVIDER_MANIFEST_ENTRIES:
            fail("evidence root exceeds its manifest-entry bound")
        snapshot.verify_tree_unchanged()
        manifest = ("\n".join(rows) + "\n").encode("utf-8")
        if len(manifest) > MAX_PROVIDER_MANIFEST_BYTES:
            fail("SHA256SUMS exceeds its byte bound")
        _write_root_file(root, "SHA256SUMS", manifest)


def _check_closed_manifest(root: Path, snapshot: Any) -> dict[str, str]:
    try:
        manifest_data = snapshot.read("SHA256SUMS", limit=MAX_PROVIDER_MANIFEST_BYTES)
        text = manifest_data.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, SystemExit) as error:
        fail(f"cannot read SHA256SUMS safely: {error}")
    if manifest_data.count(b"\n") > MAX_PROVIDER_MANIFEST_ENTRIES:
        fail("SHA256SUMS exceeds its manifest-entry bound")
    lines = text.splitlines()
    if len(lines) > MAX_PROVIDER_MANIFEST_ENTRIES:
        fail("SHA256SUMS exceeds its manifest-entry bound")
    entries: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or not DIGEST.fullmatch(fields[0]):
            fail(f"malformed SHA256SUMS row {number}")
        relative = safe_relative(fields[1], f"SHA256SUMS row {number}").as_posix()
        if relative in entries or relative == "SHA256SUMS":
            fail(f"duplicate or self-referential manifest path: {relative}")
        actual = sha256_bytes(snapshot.read(relative, limit=_provider_file_limit(relative)))
        if actual != fields[0]:
            fail(f"SHA256SUMS digest mismatch: {relative}")
        entries[relative] = actual
    actual_files = snapshot.file_paths - {"SHA256SUMS"}
    if actual_files != set(entries):
        fail(f"SHA256SUMS is not closed (unlisted={sorted(actual_files - set(entries))}, missing={sorted(set(entries) - actual_files)})")
    snapshot.verify_tree_unchanged()
    return entries


def check_closed_manifest(root: Path, *, snapshot: Any | None = None) -> dict[str, str]:
    current = snapshot or _new_root_snapshot(root)
    if not current._preflighted:
        current.preflight()
    with _using_root_snapshot(current):
        return _check_closed_manifest(root, current)


def require_int(value: Any, label: str) -> int:
    if type(value) is not int:
        fail(f"{label} must be an exact JSON integer")
    return value


def require_version(record: dict[str, Any], field: str, expected: int, label: str) -> None:
    value = require_int(record.get(field), f"{label}.{field}")
    if value != expected:
        fail(f"{label}.{field} is unsupported")


def _gnu_provider_facts(data: bytes) -> tuple[list[dict[str, int]], dict[int, list[int]], dict[int, dict[str, Any]]]:
    segments, dynamic_header = _INDIRECT._external_load_map(data)
    tags = _INDIRECT._external_dynamic_tags(data, dynamic_header)
    symbols = _INDIRECT._external_symbols(data, segments, tags)
    return segments, tags, symbols


def _provider_build_id(data: bytes) -> str:
    if len(data) < 64:
        fail("provider ELF is truncated")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or phnum == 0 or phnum > 4096 or phoff > len(data) or phnum * phentsize > len(data) - phoff:
        fail("provider program-header table exceeds its bound")
    matches: list[str] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        kind, _flags, file_offset, _vaddr, _paddr, file_size, _mem_size, _align = struct.unpack_from("<IIQQQQQQ", data, offset)
        if kind != 4:
            continue
        if file_offset > len(data) or file_size > len(data) - file_offset:
            fail("provider PT_NOTE escapes the bounded ELF bytes")
        end = file_offset + file_size
        cursor = file_offset
        while cursor < end:
            if end - cursor < 12:
                fail("provider note header is truncated")
            name_size, desc_size, note_type = struct.unpack_from("<III", data, cursor)
            cursor += 12
            padded_name = (name_size + 3) & ~3
            padded_desc = (desc_size + 3) & ~3
            if padded_name > end - cursor:
                fail("provider note name exceeds PT_NOTE")
            name = data[cursor : cursor + name_size]
            cursor += padded_name
            if padded_desc > end - cursor:
                fail("provider note descriptor exceeds PT_NOTE")
            desc = data[cursor : cursor + desc_size]
            cursor += padded_desc
            if name == b"GNU\0" and note_type == 3:
                if desc_size != 20:
                    fail("provider GNU build-id is not the pinned 20-byte shape")
                matches.append(desc.hex())
    if len(matches) != 1:
        fail("provider must carry exactly one GNU 20-byte build-id")
    return matches[0]


def parse_provider(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_PROVIDER_BYTES:
        fail("provider DSO exceeds the exact 8 MiB provider byte bound")
    segments, tags, symbols = _gnu_provider_facts(data)
    soname_offsets = tags.get(14, [])
    needed_offsets = tags.get(1, [])
    strtab = _INDIRECT._external_one_tag(tags, 5, "DT_STRTAB")
    strsz = _INDIRECT._external_one_tag(tags, 10, "DT_STRSZ")
    if strtab is None or strsz is None:
        fail("provider dynamic string table is absent")
    string_offset, _ = _INDIRECT._external_map_virtual(segments, strtab, strsz, "provider DT_STRTAB")
    string_bytes = _INDIRECT._external_checked_range(data, string_offset, strsz, "provider DT_STRTAB")

    def string_at(offset: int, label: str) -> str:
        if type(offset) is not int or offset < 0 or offset >= len(string_bytes):
            fail(f"{label} offset is outside provider DT_STRTAB")
        end = string_bytes.find(b"\0", offset)
        if end < 0:
            fail(f"{label} is not terminated inside provider DT_STRTAB")
        try:
            return string_bytes[offset:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail(f"{label} is not valid UTF-8")

    if len(soname_offsets) != 1:
        fail("provider must have exactly one DT_SONAME")
    soname = string_at(soname_offsets[0], "provider DT_SONAME")
    needed = [string_at(offset, "provider DT_NEEDED") for offset in needed_offsets]
    if needed or any(tag in tags for tag in (15, 29)):
        fail("provider dependency/search-path graph is not self-contained")
    table_matches = [item for item in symbols.values() if item["name"] == PROVIDER_TABLE]
    if len(table_matches) != 1:
        fail("provider must define exactly one external jump-table dynamic symbol")
    table_symbol = table_matches[0]
    if (
        table_symbol["typeId"] != 1
        or table_symbol["bindingId"] != 1
        or table_symbol["visibilityId"] != 0
        or table_symbol["sectionIndex"] == 0
        or table_symbol["size"] != 16
        or table_symbol["value"] % 4 != 0
    ):
        fail("provider jump table is not one defined aligned global 16-byte STT_OBJECT")
    table_file_offset, table_segment = _INDIRECT._external_map_virtual(
        segments, int(table_symbol["value"]), 16, "provider read-only jump table", required_flags=4
    )
    if table_segment["flags"] & 2:
        fail("provider jump table resides in a writable PT_LOAD")
    table_bytes = _INDIRECT._external_checked_range(data, table_file_offset, 16, "provider table bytes")
    targets: list[dict[str, Any]] = []
    for name in TARGET_SYMBOLS:
        rows = [item for item in symbols.values() if item["name"] == name]
        if len(rows) != 1:
            fail(f"provider must define one dynamic target {name}")
        target = rows[0]
        if (
            target["typeId"] != 2
            or target["bindingId"] != 1
            or target["visibilityId"] != 3
            or target["sectionIndex"] == 0
            or target["size"] != 8
        ):
            fail(f"provider target {name} is not a defined protected global 8-byte function")
        target_file, target_segment = _INDIRECT._external_map_virtual(
            segments, int(target["value"]), int(target["size"]), f"provider target {name}", required_flags=5
        )
        target_bytes = _INDIRECT._external_checked_range(data, target_file, int(target["size"]), f"provider target {name} bytes")
        if target_segment["flags"] & 2 or target_bytes[-4:] != bytes.fromhex("c0035fd6"):
            fail(f"provider target {name} is writable or does not terminate with RET")
        targets.append({
            "symbol": name,
            "symbolIndex": int(target["symbolIndex"]),
            "virtualAddress": int(target["value"]),
            "size": int(target["size"]),
            "fileOffset": target_file,
            "returnBytesSha256": sha256_bytes(target_bytes[-4:]),
        })
    table_base = int(table_symbol["value"])
    entry_rows: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        raw_bytes = table_bytes[index * 4 : index * 4 + 4]
        raw = int.from_bytes(raw_bytes, "little")
        displacement = raw - (1 << 32) if raw & 0x80000000 else raw
        target_address = table_base + displacement
        if target_address != target["virtualAddress"]:
            fail(f"provider signed table entry {index} does not resolve to its exact provider-local target")
        entry_rows.append({
            "index": index,
            "fileOffset": table_file_offset + index * 4,
            "rawHex": raw_bytes.hex(),
            "signedDisplacement": displacement,
            "targetVirtualAddress": target_address,
            "targetSymbol": target["symbol"],
        })
    return {
        "soname": soname,
        "buildId": _provider_build_id(data),
        "sha256": sha256_bytes(data),
        "size": len(data),
        "needed": needed,
        "table": {
            "symbolIndex": int(table_symbol["symbolIndex"]),
            "virtualAddress": table_base,
            "fileOffset": table_file_offset,
            "size": 16,
            "segmentFlags": table_segment["flags"],
            "bytesHex": table_bytes.hex(),
            "entries": entry_rows,
        },
        "targets": targets,
    }


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _decode_source_provider_dispatch(data: bytes, image: Any, entry: dict[str, Any], got_va: int) -> dict[str, Any]:
    function_va = int(entry["value"])
    function_size = int(entry["size"])
    if function_size < 40 or function_size % 4 != 0 or function_size > 1024 * 1024:
        fail("source urp_entry size is outside the exact bounded provider-dispatch shape")
    function_file, _segment = image.map_va(function_va, function_size, "source urp_entry", 5)
    words = [struct.unpack_from("<I", data, function_file + offset)[0] for offset in range(0, function_size, 4)]
    if words[0] != 0xB9400820:
        fail("source entry does not load the bounded argument index from launch_args.argc")
    matches: list[dict[str, Any]] = []
    for index in range(max(0, len(words) - 6)):
        cmp_word, bhi_word, adrp_word, ldr_word, ldrsw_word, add_word, br_word = words[index : index + 7]
        is_cmp = (
            cmp_word & 0x7F00001F == 0x7100001F
            and (cmp_word >> 5) & 0x1F == 0
            and (cmp_word >> 10) & 0xFFF == 3
            and (cmp_word >> 22) & 1 == 0
        )
        is_bhi = bhi_word & 0xFF00001F == 0x54000008
        is_adrp = adrp_word & 0x9F000000 == 0x90000000 and adrp_word & 0x1F == 9
        is_got_ldr = ldr_word & 0xFFC00000 == 0xF9400000 and ldr_word & 0x1F == 9 and (ldr_word >> 5) & 0x1F == 9
        is_ldrsw = (
            ldrsw_word & 0xFFE00C00 == 0xB8A00800
            and ldrsw_word & 0x1F == 2
            and (ldrsw_word >> 5) & 0x1F == 9
            and (ldrsw_word >> 16) & 0x1F == 0
            and (ldrsw_word >> 13) & 0x7 == 2
            and (ldrsw_word >> 12) & 1 == 1
        )
        is_add = add_word & 0xFFE0FC00 == 0x8B000000 and add_word & 0x1F == 1 and (add_word >> 5) & 0x1F == 9 and (add_word >> 16) & 0x1F == 2
        is_br = br_word & 0xFFFFFC1F == 0xD61F0000 and (br_word >> 5) & 0x1F == 1
        if is_cmp and is_bhi and is_adrp and is_got_ldr and is_ldrsw and is_add and is_br:
            matches.append({"instructionIndex": index, "words": words[index : index + 7]})
    if len(matches) != 1:
        fail("source urp_entry lacks one unique guarded GOT/LDRSW/provider-relative/BR chain")
    selected = matches[0]
    start = selected["instructionIndex"]
    cmp_va = function_va + start * 4
    branch_va = cmp_va + 4
    branch_disp = _sign_extend((selected["words"][1] >> 5) & 0x7FFFF, 19) * 4
    default_va = branch_va + branch_disp
    function_end = function_va + function_size
    if default_va != function_end - 8 or default_va < cmp_va + 28:
        fail("source B.HI does not target the final bounded default-return block")
    default_offset = function_file + default_va - function_va
    default_move, default_ret = struct.unpack_from("<II", data, default_offset)
    if default_move != 0x12800000 or default_ret != 0xD65F03C0:
        fail("source B.HI target is not the exact MOV W0,#-1; RET default block")
    adrp_word, ldr_word, ldrsw_word, add_word, br_word = selected["words"][2:]
    adrp_va = cmp_va + 8
    adrp_imm = (((adrp_word >> 5) & 0x7FFFF) << 2) | ((adrp_word >> 29) & 3)
    got_page = (adrp_va & ~0xFFF) + (_sign_extend(adrp_imm, 21) << 12)
    got_offset = ((ldr_word >> 10) & 0xFFF) * 8
    computed_got = got_page + got_offset
    if computed_got != got_va:
        fail("source GOT load does not resolve to the imported object's exact GLOB_DAT slot")
    relative_base_register = (add_word >> 5) & 0x1F
    if relative_base_register != 9:
        fail("source relative target addition is not based on the provider table pointer")
    # The table uses signed 32-bit displacements indexed by W0, with scale two.
    if (ldrsw_word >> 13) & 7 != 2 or (ldrsw_word >> 12) & 1 != 1 or (ldrsw_word >> 16) & 0x1F != 0:
        fail("source LDRSW does not use [X9,W0,UXTW #2]")
    return {
        "selectedFunction": {"selector": f"dynsym:{entry['index']}", "symbolIndex": entry["index"], "name": "urp_entry", "virtualAddress": function_va, "size": function_size},
        "guard": {"cmpAddress": cmp_va, "bound": 3, "branchAddress": branch_va, "defaultAddress": default_va, "defaultBytesHex": data[default_offset : default_offset + 8].hex()},
        "dispatch": {
            "gotAddress": computed_got,
            "gotLoadInstructionAddress": adrp_va + 4,
            "indexedReadAddress": adrp_va + 8,
            "indexedReadMnemonic": "LDRSW",
            "indexRegister": "w0",
            "baseRegister": "x9",
            "extension": "UXTW",
            "scale": 4,
            "targetAddAddress": adrp_va + 12,
            "branchAddress": adrp_va + 16,
            "branchRegister": "x1",
            "instructionWords": [f"0x{word:08x}" for word in selected["words"]],
        },
    }


def parse_consumer(data: bytes, label: str, *, require_source_dispatch: bool) -> dict[str, Any]:
    image = _DYNAMIC.ElfImage(data, label)
    imported = [row for row in image.symbols if row["name"] == PROVIDER_TABLE]
    if len(imported) != 1:
        fail(f"{label} must carry one imported provider-table dynamic symbol")
    imported_symbol = imported[0]
    if (
        imported_symbol["type"] != 1
        or imported_symbol["binding"] != 1
        or imported_symbol["visibility"] != 0
        or imported_symbol["sectionIndex"] != 0
        or imported_symbol["value"] != 0
        or imported_symbol["size"] != 0
    ):
        fail(f"{label} imported table dynsym identity is not undefined global default STT_OBJECT")
    matching = [
        row for row in image.rela_rows
        if row["symbolIndex"] == imported_symbol["index"] and row["type"] == 1025 and not row["isPlt"]
    ]
    if len(matching) != 1 or len(image.rela_rows) != 1:
        fail(f"{label} must have exactly one non-PLT R_AARCH64_GLOB_DAT owner for the imported table")
    relocation = matching[0]
    if relocation["addend"] != 0 or relocation["offset"] % 8 != 0:
        fail(f"{label} imported table GLOB_DAT has an unsupported addend or alignment")
    got_file, got_segment = image.map_va(int(relocation["offset"]), 8, "provider-table GLOB_DAT GOT", 2)
    if got_segment["flags"] & 1:
        fail(f"{label} provider-table GOT slot resides in an executable PT_LOAD")
    functions: dict[str, dict[str, int]] = {}
    function_rows: dict[str, dict[str, Any]] = {}
    for name in ENTRY_SYMBOLS:
        matches = [row for row in image.symbols if row["name"] == name]
        if len(matches) != 1:
            fail(f"{label} must define one dynamic function {name}")
        row = matches[0]
        if row["type"] != 2 or row["binding"] != 1 or row["visibility"] != 0 or row["sectionIndex"] == 0 or row["size"] == 0:
            fail(f"{label} dynamic symbol {name} is not a defined global default function")
        offset, segment = image.map_va(int(row["value"]), int(row["size"]), name, 5)
        functions[name] = {
            "symbolIndex": int(row["index"]),
            "virtualAddress": int(row["value"]),
            "size": int(row["size"]),
            "fileOffset": offset,
            "segmentFlags": segment["flags"],
            "bytesSha256": sha256_bytes(data[offset : offset + int(row["size"])]),
        }
        function_rows[name] = row
    needed_offsets = image.dynamic.get(1, [])
    soname_offsets = image.dynamic.get(14, [])
    strtab = image._dynamic_value(5, "DT_STRTAB")
    strsz = image._dynamic_value(10, "DT_STRSZ")
    assert strtab is not None and strsz is not None
    string_file, _ = image.map_va(strtab, strsz, "DT_STRTAB")
    strings = data[string_file : string_file + strsz]

    def get_string(value: int, label2: str) -> str:
        if value < 0 or value >= len(strings):
            fail(f"{label} {label2} offset is outside DT_STRTAB")
        end = strings.find(b"\0", value)
        if end < 0:
            fail(f"{label} {label2} is unterminated")
        return strings[value:end].decode("utf-8", errors="strict")

    needed = [get_string(offset, "DT_NEEDED") for offset in needed_offsets]
    sonames = [get_string(offset, "DT_SONAME") for offset in soname_offsets]
    if needed != [PROVIDER_SONAME] or sonames or any(tag in image.dynamic for tag in (15, 29)):
        fail(f"{label} dependency closure is not exactly the configured provider with no search path")
    if data[got_file : got_file + 8] != b"\0" * 8:
        fail(f"{label} provider-table GLOB_DAT slot is not an unresolved zero-initialized pointer")
    facts: dict[str, Any] = {
        "sha256": sha256_bytes(data),
        "size": len(data),
        "dynamicNeeded": needed,
        "dynamicSoname": sonames,
        "importSymbol": {
            "symbolIndex": int(imported_symbol["index"]),
            "name": PROVIDER_TABLE,
            "value": 0,
            "size": 0,
            "typeId": 1,
            "bindingId": 1,
            "visibilityId": 0,
        },
        "relocation": {
            "type": int(relocation["type"]),
            "symbolIndex": int(relocation["symbolIndex"]),
            "virtualAddress": int(relocation["offset"]),
            "addend": int(relocation["addend"]),
            "isPlt": False,
        },
        "got": {
            "virtualAddress": int(relocation["offset"]),
            "fileOffset": got_file,
            "size": 8,
            "segmentFlags": got_segment["flags"],
            "initialBytesHex": data[got_file : got_file + 8].hex(),
        },
        "functions": functions,
    }
    if require_source_dispatch:
        facts["sourceDispatch"] = _decode_source_provider_dispatch(
            data, image, function_rows["urp_entry"], int(relocation["offset"])
        )
    return facts


def _checked_load_endpoint(start: int, size: int, label: str) -> int:
    address_space_end = 1 << 64
    if (
        not _INDIRECT.is_int(start)
        or not _INDIRECT.is_int(size)
        or start < 0
        or start >= address_space_end
        or size < 0
        or size > address_space_end - start
    ):
        fail(f"{label} has an overflowing PT_LOAD interval")
    return start + size


def _unique_code_load_owner(
    data: bytes,
    segments: list[dict[str, int]],
    virtual_address: int,
    size: int,
    label: str,
) -> tuple[int, dict[str, int]]:
    """Bind a bounded emitted code range to one file owner and reject all PT_LOAD overlaps."""
    virtual_end = _checked_load_endpoint(virtual_address, size, label)
    if size == 0:
        fail(f"{label} has an empty emitted-code interval")

    owners: list[dict[str, int]] = []
    intersecting: list[dict[str, int]] = []
    for segment in segments:
        segment_va = segment.get("virtualAddress")
        memory_size = segment.get("memorySize")
        file_size = segment.get("fileSize")
        file_offset = segment.get("fileOffset")
        if not all(_INDIRECT.is_int(value) for value in (segment_va, memory_size, file_size, file_offset)):
            fail(f"{label} has malformed PT_LOAD range fields")
        if segment_va < 0 or memory_size < 0 or file_size < 0 or file_offset < 0 or file_size > memory_size:
            fail(f"{label} has malformed PT_LOAD range fields")

        memory_end = _checked_load_endpoint(segment_va, memory_size, label)
        file_virtual_end = _checked_load_endpoint(segment_va, file_size, label)
        if file_offset > len(data) or file_size > len(data) - file_offset:
            fail(f"{label} has a PT_LOAD file range outside the Native Image")

        # All ranges are half-open. In particular, zero-sized PT_LOAD memory
        # ranges and segments adjacent to either boundary do not intersect.
        if memory_size > 0 and max(virtual_address, segment_va) < min(virtual_end, memory_end):
            intersecting.append(segment)
        if segment_va <= virtual_address and virtual_end <= file_virtual_end:
            owners.append(segment)

    if len(owners) != 1:
        fail(f"{label} is not uniquely backed by a file range in one PT_LOAD")
    owner = owners[0]
    if any(segment is not owner for segment in intersecting):
        fail(f"{label} intersects another PT_LOAD memory range")

    owner_va = owner["virtualAddress"]
    owner_file = owner["fileOffset"]
    file_address = owner_file + (virtual_address - owner_va)
    if file_address > len(data) or size > len(data) - file_address:
        fail(f"{label} file translation exceeds the Native Image")
    return file_address, owner


def _decode_native_provider_dispatch(
    data: bytes,
    source: dict[str, Any],
    native: dict[str, Any],
    layout: dict[str, Any],
) -> dict[str, Any]:
    """Follow the actual entry B stub, then decode only its mapped provider dispatcher."""
    source_entry = source["functions"]["urp_entry"]
    native_entry = native["functions"]["urp_entry"]
    source_start = source_entry["virtualAddress"]
    if any(
        not same_json(source_entry.get(field), native_entry.get(field))
        for field in ("symbolIndex", "virtualAddress", "size", "fileOffset", "segmentFlags")
    ):
        fail("selected urp_entry output symbol identity/range changed")

    source_range_expected = (
        source_entry["fileOffset"], source_entry["virtualAddress"], source_entry["size"]
    )
    address_map = layout.get("addressMap")
    if not isinstance(address_map, list):
        fail("rehydration layout has no selected-function output map")
    matching_maps: list[tuple[dict[str, Any], tuple[int, int, int]]] = []
    for row in address_map:
        if not isinstance(row, dict):
            fail("rehydration address-map row is malformed")
        candidate = _INDIRECT.semantic_range_values(row.get("sourceRange"), "selected source mapping")
        if candidate == source_range_expected:
            output_range = _INDIRECT.semantic_range_values(row.get("outputRange"), "selected output mapping")
            matching_maps.append((row, output_range))
    if len(matching_maps) != 1:
        fail("rehydration does not retain one exact selected urp_entry output mapping")
    mapping, output_range = matching_maps[0]
    output_file, output_va, output_size = output_range
    if output_size != 92:
        fail("selected urp_entry output mapping has an unexpected transformed fixture extent")

    placements = layout.get("placements")
    if not isinstance(placements, list):
        fail("rehydration layout has no physical output placements")
    placement_matches: list[dict[str, Any]] = []
    for placement in placements:
        if not isinstance(placement, dict):
            fail("rehydration physical placement row is malformed")
        placement_range = _INDIRECT.semantic_range_values(placement.get("range"), "selected physical placement")
        if (
            placement.get("identity") == mapping.get("identity")
            and placement.get("sourceIdentity") == mapping.get("sourceIdentity")
            and placement_range == output_range
        ):
            placement_matches.append(placement)
    if len(placement_matches) != 1:
        fail("selected logical output mapping has no unique matching physical placement")
    placement = placement_matches[0]
    if require_int(placement.get("permissions"), "selected output permissions") != 5:
        fail("selected physical output placement is not read-only executable")

    segments = _INDIRECT.parse_load_segments(data, "Native Image")
    if output_size % 4 != 0:
        fail("selected emitted urp_entry output range is not a whole number of AArch64 instructions")
    mapped_output_file, output_segment = _unique_code_load_owner(
        data, segments, output_va, output_size, "complete emitted Native Image urp_entry output range"
    )
    if mapped_output_file != output_file or output_segment["flags"] != 5:
        fail("selected rehydration output map does not identify the complete physical read-only executable range")

    def verify_output_instruction_mapping(offset: int, label: str) -> int:
        if offset < 0 or offset > output_size - 4:
            fail(f"{label} exceeds the emitted Native Image urp_entry output range")
        address = output_va + offset
        if address > (1 << 64) - 4:
            fail(f"{label} address overflows the AArch64 virtual-address domain")
        file_offset, segment = _INDIRECT.mapped_file_offset(segments, address, 4, label)
        if (
            file_offset != output_file + offset
            or segment["flags"] & 1 == 0
            or segment != output_segment
        ):
            fail(f"{label} is not executable file-backed output at the exact emitted file/VA mapping")
        return file_offset

    output_end = _checked_load_endpoint(output_va, output_size, "complete emitted Native Image urp_entry output range")

    def verify_output_branch_target(address: int, label: str) -> None:
        if address < output_va or address > output_end - 4:
            fail(f"{label} leaves the emitted Native Image urp_entry output range")
        file_offset, segment = _INDIRECT.mapped_file_offset(segments, address, 4, label)
        expected_file = output_file + address - output_va
        if file_offset != expected_file or segment["flags"] & 1 == 0 or segment != output_segment:
            fail(f"{label} is not executable file-backed output at the exact emitted file/VA mapping")

    # Validate every emitted word, not just the source symbol-sized prefix or
    # instructions subsequently selected by the semantic decoder below.
    for instruction_offset in range(0, output_size, 4):
        verify_output_instruction_mapping(
            instruction_offset,
            f"Native Image urp_entry emitted instruction at +0x{instruction_offset:x}",
        )
    entry_file, entry_segment = _unique_code_load_owner(
        data,
        segments,
        native_entry["virtualAddress"],
        4,
        "Native Image urp_entry branch stub",
    )
    if entry_file != native_entry["fileOffset"] or entry_segment["flags"] & 1 == 0:
        fail("Native Image urp_entry entry stub is not mapped to executable output bytes")
    branch_word = struct.unpack_from("<I", data, entry_file)[0]
    if branch_word & 0xFC000000 != 0x14000000:
        fail("selected Native Image urp_entry does not begin with the expected live B stub")
    branch_target = native_entry["virtualAddress"] + _sign_extend(branch_word & 0x03FFFFFF, 26) * 4
    verify_output_branch_target(branch_target, "Native Image urp_entry entry B target")
    if branch_target != output_va:
        fail("selected Native Image entry B stub bypasses the retained mapped output function")

    image = _DYNAMIC.ElfImage(data, "mapped Native Image urp_entry")
    def word_at(offset: int) -> int:
        if offset < 0 or offset > output_size - 4:
            fail("selected transformed dispatcher instruction exceeds its mapped output region")
        return struct.unpack_from("<I", data, output_file + offset)[0]

    def branch_target_at(offset: int, word: int, *, conditional: bool = False) -> int:
        verify_output_instruction_mapping(
            offset,
            f"Native Image urp_entry branch instruction at +0x{offset:x}",
        )
        if conditional:
            displacement = _sign_extend((word >> 5) & 0x7FFFF, 19) * 4
        else:
            if word & 0xFC000000 != 0x14000000:
                fail("selected transformed live path contains a non-B unconditional transition")
            displacement = _sign_extend(word & 0x03FFFFFF, 26) * 4
        target = output_va + offset + displacement
        verify_output_branch_target(target, f"Native Image urp_entry branch target from +0x{offset:x}")
        return target

    # This is the bounded exact output shape of the current control-flow-flattening
    # fixture. Verify its state machine edges, not merely the existence of a dead chain.
    if word_at(0) != 0x52800010 or branch_target_at(4, word_at(4)) != output_va + 64:
        fail("selected transformed urp_entry does not enter its retained live dispatcher")
    if word_at(8) != 0xB9400820 or word_at(12) != 0x71000C1F:
        fail("selected transformed live path does not load and compare the bounded input index")
    guard_branch = word_at(16)
    if guard_branch & 0xFF00001F != 0x54000008 or branch_target_at(16, guard_branch, conditional=True) != output_va + 28:
        fail("selected transformed B.HI does not route an out-of-range index to its safe default state")
    if word_at(20) != 0x52800030 or branch_target_at(24, word_at(24)) != output_va + 64:
        fail("selected transformed valid-index path does not enter provider-dispatch state 1")
    if word_at(28) != 0x52800050 or branch_target_at(32, word_at(32)) != output_va + 64:
        fail("selected transformed out-of-range path does not enter default state 2")
    default_bytes = data[output_file + 56 : output_file + 64]
    if default_bytes != bytes.fromhex("00008012c0035fd6"):
        fail("selected transformed state 2 is not the exact MOV W0,#-1; RET default block")
    if word_at(88) != 0xD65F03C0:
        fail("selected transformed dispatcher has no bounded terminal RET")

    state_transitions = []
    for offset, state, target_offset in ((64, 0, 8), (72, 1, 36), (80, 2, 56)):
        expected_cmp = 0x7100021F | (state << 10)
        if word_at(offset) != expected_cmp:
            fail(f"selected transformed dispatcher state {state} comparison changed")
        state_branch = word_at(offset + 4)
        if state_branch & 0xFF00001F != 0x54000000:
            fail(f"selected transformed dispatcher state {state} has no B.EQ edge")
        actual_target = branch_target_at(offset + 4, state_branch, conditional=True)
        if actual_target != output_va + target_offset:
            fail(f"selected transformed live dispatcher state {state} bypasses its mapped semantic block")
        state_transitions.append({"state": state, "branchAddress": output_va + offset + 4, "targetAddress": actual_target})

    chain_words = [word_at(offset) for offset in range(36, 56, 4)]
    adrp_word, ldr_word, ldrsw_word, add_word, br_word = chain_words
    is_adrp = adrp_word & 0x9F000000 == 0x90000000 and adrp_word & 0x1F == 9
    is_got_ldr = ldr_word & 0xFFC00000 == 0xF9400000 and ldr_word & 0x1F == 9 and (ldr_word >> 5) & 0x1F == 9
    is_ldrsw = (
        ldrsw_word & 0xFFE00C00 == 0xB8A00800
        and ldrsw_word & 0x1F == 2
        and (ldrsw_word >> 5) & 0x1F == 9
        and (ldrsw_word >> 16) & 0x1F == 0
        and (ldrsw_word >> 13) & 0x7 == 2
        and (ldrsw_word >> 12) & 1 == 1
    )
    is_add = add_word & 0xFFE0FC00 == 0x8B000000 and add_word & 0x1F == 1 and (add_word >> 5) & 0x1F == 9 and (add_word >> 16) & 0x1F == 2
    is_br = br_word & 0xFFFFFC1F == 0xD61F0000 and (br_word >> 5) & 0x1F == 1
    if not (is_adrp and is_got_ldr and is_ldrsw and is_add and is_br):
        fail("selected transformed live state 1 lacks the complete GOT/LDRSW/provider-relative/BR chain")
    adrp_va = output_va + 36
    adrp_imm = (((adrp_word >> 5) & 0x7FFFF) << 2) | ((adrp_word >> 29) & 3)
    got_page = (adrp_va & ~0xFFF) + (_sign_extend(adrp_imm, 21) << 12)
    computed_got = got_page + ((ldr_word >> 10) & 0xFFF) * 8
    if computed_got != native["got"]["virtualAddress"]:
        fail("selected transformed live GOT load does not resolve to the Native Image provider GLOB_DAT slot")
    if (add_word >> 5) & 0x1F != 9 or (ldrsw_word >> 13) & 7 != 2 or (ldrsw_word >> 12) & 1 != 1:
        fail("selected transformed live target chain does not use the provider pointer and signed W0-scaled displacement")
    source_dispatch = source["sourceDispatch"]
    if source_dispatch["guard"]["bound"] != 3 or source_dispatch["guard"]["defaultBytesHex"] != default_bytes.hex():
        fail("mapped Native Image live bounds/default differ from the proven source function")
    source_chain = source_dispatch["dispatch"]
    if (
        computed_got != source_chain["gotAddress"]
        or source_chain["indexRegister"] != "w0"
        or source_chain["baseRegister"] != "x9"
        or source_chain["branchRegister"] != "x1"
    ):
        fail("mapped Native Image live provider dispatcher changes the source GOT/index/base/target contract")
    dispatch = {
        "selectedFunction": {
            "selector": f"dynsym:{native_entry['symbolIndex']}",
            "symbolIndex": native_entry["symbolIndex"],
            "name": "urp_entry",
            "virtualAddress": output_va,
            "size": output_size,
        },
        "guard": {
            "cmpAddress": output_va + 12,
            "bound": 3,
            "branchAddress": output_va + 16,
            "defaultAddress": output_va + 56,
            "defaultBytesHex": default_bytes.hex(),
        },
        "dispatch": {
            "gotAddress": computed_got,
            "gotLoadInstructionAddress": output_va + 40,
            "indexedReadAddress": output_va + 44,
            "indexedReadMnemonic": "LDRSW",
            "indexRegister": "w0",
            "baseRegister": "x9",
            "extension": "UXTW",
            "scale": 4,
            "targetAddAddress": output_va + 48,
            "branchAddress": output_va + 52,
            "branchRegister": "x1",
            "instructionWords": [f"0x{word:08x}" for word in chain_words],
        },
        "stateTransitions": state_transitions,
    }
    return {
        "entryStub": {
            "virtualAddress": native_entry["virtualAddress"],
            "fileOffset": entry_file,
            "instructionWord": f"0x{branch_word:08x}",
            "branchTarget": branch_target,
        },
        "outputMapping": {
            "sourceRange": {"fileOffset": source_entry["fileOffset"], "virtualAddress": source_start, "size": source_entry["size"]},
            "outputRange": {"fileOffset": output_file, "virtualAddress": output_va, "size": output_size},
            "segmentFlags": output_segment["flags"],
            "placementPermissions": placement["permissions"],
            "identity": mapping.get("identity"),
        },
        "dispatch": dispatch,
    }


def verify_runtime(root: Path) -> dict[str, Any]:
    identity = read_json(root, "runtime-identity.json")
    required = {
        "runtime", "architecture", "version", "libcPath", "libcSha256", "libcElfClass", "libcElfData",
        "libcMachine", "loaderPath", "loaderSha256", "loaderElfClass", "loaderElfData", "loaderMachine",
        "identitySha256",
    }
    if set(identity) != required:
        fail("runtime identity fields are not the exact bounded glibc identity schema")
    if identity["runtime"] != "glibc" or identity["architecture"] not in {"aarch64", "arm64"}:
        fail("runtime evidence is not native AArch64/glibc")
    if not isinstance(identity["version"], str) or not re.fullmatch(r"glibc [0-9][A-Za-z0-9.+_-]{0,63}", identity["version"]):
        fail("runtime identity glibc version is malformed")
    for field, expected_name in (("libcPath", "libc.so.6"), ("loaderPath", "ld-linux-aarch64.so.1")):
        path_text = identity[field]
        if (
            not isinstance(path_text, str)
            or len(path_text.encode("utf-8")) > 4096
            or not Path(path_text).is_absolute()
            or Path(path_text).name != expected_name
            or ".." in Path(path_text).parts
        ):
            fail(f"runtime identity {field} is not a normalized absolute producer path")
    for field in ("libcSha256", "loaderSha256", "identitySha256"):
        if not isinstance(identity[field], str) or not DIGEST.fullmatch(identity[field]):
            fail(f"runtime identity {field} is not normalized SHA-256")
    if _IDENTITY.canonical_identity_digest(identity) != identity["identitySha256"]:
        fail("runtime identity digest does not bind its exact fields")
    for prefix in ("libc", "loader"):
        if (
            type(identity[f"{prefix}ElfClass"]) is not int or identity[f"{prefix}ElfClass"] != 64
            or identity[f"{prefix}ElfData"] != "little"
            or type(identity[f"{prefix}Machine"]) is not int or identity[f"{prefix}Machine"] != 183
        ):
            fail(f"retained runtime {prefix} identity facts are not exact AArch64 ELF values")
    for relative, prefix in (("runtime-files/libc.so.6", "libc"), ("runtime-files/ld-linux-aarch64.so.1", "loader")):
        data = read_file(root, relative, limit=256 * 1024 * 1024)
        if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01" or data[6] != 1:
            fail(f"retained runtime image {relative} is not bounded little-endian ELF64")
        elf_type, machine = struct.unpack_from("<HH", data, 16)
        if machine != 183 or elf_type not in {2, 3}:
            fail(f"retained runtime image {relative} is not native AArch64 ET_EXEC/ET_DYN")
        if (
            sha256_bytes(data) != identity[f"{prefix}Sha256"]
            or identity[f"{prefix}ElfClass"] != 64
            or identity[f"{prefix}ElfData"] != "little"
            or identity[f"{prefix}Machine"] != machine
        ):
            fail(f"root-contained runtime image {relative} differs from its retained identity facts")
    machine = platform.machine().lower()
    libc_version = os.confstr("CS_GNU_LIBC_VERSION") or ""
    if machine not in {"aarch64", "arm64"} or libc_version != identity["version"]:
        fail("retained AArch64/glibc identity differs from the directly executing current process")
    return identity


def _read_mapping(value: Any, address: int, size: int, label: str, *, executable: bool, writable: bool | None) -> dict[str, Any]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
        fail(f"{label} mapping line is malformed")
    fields = value.split(maxsplit=5)
    if len(fields) < 5 or not re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", fields[0]) or not re.fullmatch(r"[r-][w-][x-][ps]", fields[1]):
        fail(f"{label} mapping line does not match /proc/self/maps syntax")
    start_text, end_text = fields[0].split("-", 1)
    start, end = int(start_text, 16), int(end_text, 16)
    if start >= end or address < start or size <= 0 or size > end - address:
        fail(f"{label} address range is not covered by its retained mapping")
    permissions = fields[1]
    if permissions[0] != "r" or (permissions[2] == "x") != executable:
        fail(f"{label} mapping permissions differ from the required loader protection")
    if writable is not None and (permissions[1] == "w") != writable:
        fail(f"{label} mapping writable bit differs from the required loader protection")
    return {"start": start, "end": end, "permissions": permissions, "path": fields[5] if len(fields) == 6 else ""}


def validate_handoff_record(
    record: dict[str, Any],
    *,
    image_sha256: str,
    provider: dict[str, Any],
    consumer: dict[str, Any],
    entry_symbol: str,
    index: int,
) -> dict[str, Any]:
    if entry_symbol not in ENTRY_SYMBOLS or index not in INDICES:
        fail("handoff validator was given an unsupported entry/index")
    exact = {
        "schemaVersion": 1,
        "status": "passed",
        "loaderId": "host-context.sealed-memfd.dlmopen-provider",
        "nativeImageSha256": image_sha256,
        "entrySymbol": entry_symbol,
        "argumentIndex": index,
        "entryStatus": ENTRY_STATUSES[index],
        "processStatus": PROCESS_STATUSES[index],
        "releaseStatus": "passed",
        "releaseStatusCode": 0,
        "releaseOrder": "dispatch-before-release-image",
        "providerSoname": provider["soname"],
        "providerBuildId": provider["buildId"],
        "providerSha256": provider["sha256"],
    }
    for field, expected in exact.items():
        value = record.get(field)
        if type(expected) is int:
            require_int(value, f"handoff {field}")
        if not same_json(value, expected):
            fail(f"handoff {field} does not match the independently derived expectation")
    provider_bias = require_int(record.get("providerLoadBias"), "providerLoadBias")
    consumer_bias = require_int(record.get("consumerLoadBias"), "consumerLoadBias")
    table_address = require_int(record.get("providerTableAddress"), "providerTableAddress")
    table_va = require_int(record.get("providerTableVirtualAddress"), "providerTableVirtualAddress")
    if table_va != provider["table"]["virtualAddress"] or table_address != provider_bias + table_va:
        fail("runtime provider mapping does not bind the exact provider table VA")
    if record.get("providerTableBytes") != provider["table"]["bytesHex"]:
        fail("runtime provider table bytes differ from the pinned read-only DSO")
    entry_address = require_int(record.get("entryAddress"), "entryAddress")
    if entry_address != consumer_bias + consumer["functions"][entry_symbol]["virtualAddress"]:
        fail("loaded entry address does not bind the selected consumer dynamic symbol")
    got_va = require_int(record.get("gotVirtualAddress"), "gotVirtualAddress")
    got_address = require_int(record.get("gotAddress"), "gotAddress")
    got_value = require_int(record.get("gotValue"), "gotValue")
    if got_va != consumer["got"]["virtualAddress"] or got_address != consumer_bias + got_va or got_value != table_address:
        fail("runtime GLOB_DAT GOT address/value is not bound to the loaded provider table")
    target_addresses = record.get("providerTargetAddresses")
    if not isinstance(target_addresses, list) or len(target_addresses) != 4:
        fail("providerTargetAddresses must contain exactly four runtime targets")
    expected_targets = [provider_bias + row["virtualAddress"] for row in provider["targets"]]
    for position, (actual, expected) in enumerate(zip(target_addresses, expected_targets, strict=True)):
        if type(actual) is not int or actual != expected:
            fail(f"provider target runtime address {position} is not bound to its pinned symbol")
    table_permissions = record.get("providerTablePermissions")
    got_permissions = record.get("gotPermissions")
    if table_permissions != "r--p" or got_permissions not in {"r--p", "rw-p"}:
        fail("provider table/GOT reported unexpected final mapping permissions")
    table_map = _read_mapping(record.get("providerTableMapping"), table_address, 16, "provider table", executable=False, writable=False)
    got_map = _read_mapping(record.get("gotMapping"), got_address, 8, "consumer GOT", executable=False, writable=(got_permissions == "rw-p"))
    if table_map["permissions"] != table_permissions or got_map["permissions"] != got_permissions:
        fail("reported mapping permission strings disagree with /proc/self/maps")
    if "/memfd:urprotect-trusted-provider (deleted)" not in table_map["path"] or "/memfd:urprotect-host-image (deleted)" not in got_map["path"]:
        fail("provider and consumer mappings are not the sealed memfd images")
    if record.get("providerMappedPath") != "/proc/self/fd/3" or record.get("consumerMappedPath") != "/proc/self/fd/4":
        fail("loader mappings were not created from the configured provider/consumer file descriptors")
    if type(record.get("dependencyCount")) is not int or record["dependencyCount"] != 1:
        fail("consumer dependency count is not exactly one")
    for field in (
        "usesConfiguredProvider", "imageSealed", "providerTableFileBytesMatch",
        "providerTableUnchangedAfterDispatch", "providerConsumerMapsIsolated", "providerReleasedAfterConsumer",
    ):
        if type(record.get(field)) is not bool or record[field] is not True:
            fail(f"handoff {field} is not the exact observed true boolean")
    if record.get("firstFailureStage") is not None:
        fail("successful handoff carries a failure stage")
    return {
        "argumentIndex": index,
        "entryStatus": ENTRY_STATUSES[index],
        "processStatus": PROCESS_STATUSES[index],
        "providerTargetAddress": expected_targets[index] if index < 4 else None,
        "defaultTarget": index == 4,
    }


def _require_role(root: Path, relative: str, expected_stage: str, expected_unit: str) -> dict[str, Any]:
    record = read_json(root, relative)
    require_version(record, "schemaVersion", 1, relative)
    if "abiVersion" in record:
        require_version(record, "abiVersion", 1, relative)
    if record.get("status") != "passed" or record.get("stage") != expected_stage:
        fail(f"{relative} does not report successful {expected_stage}")
    if record.get("unitId") != expected_unit:
        fail(f"{relative} unit id is not the exact fixture unit")
    return record


def _check_producer_manifest(root: Path, protected_sha: str) -> None:
    raw = read_file(root, "producer-manifest.txt", limit=4096)
    try:
        lines = raw.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        fail(f"producer raw manifest is not ASCII: {error}")
    observed: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or not DIGEST.fullmatch(fields[0]):
            fail(f"producer raw manifest row {number} is malformed")
        relative = safe_relative(fields[1], f"producer manifest row {number}").as_posix()
        if relative in observed:
            fail(f"producer raw manifest duplicates {relative}")
        observed[relative] = fields[0]
    expected = {
        "protected-image.bin": protected_sha,
        "protected-image.json": sha256_bytes(read_file(root, "protected-image.json")),
        "stage.json": sha256_bytes(read_file(root, "stage.json")),
    }
    if observed != expected:
        fail("producer raw manifest does not hash-bind exactly the Protected Image, role, and stage")


def _check_commands(root: Path, commands: dict[str, Any], provider: dict[str, Any], runtime: dict[str, Any], source_sha: str) -> None:
    require_version(commands, "schemaVersion", 1, "commands.json")
    if commands.get("unitId") != UNIT_ID or commands.get("producerId") != PRODUCER_ID:
        fail("commands.json schema/unit/producer identity is unsupported")
    if commands.get("execution") != {"architecture": runtime["architecture"], "runtime": "glibc", "emulated": False, "invocation": "direct-native-exec"}:
        fail("command provenance is not strict direct native AArch64/glibc execution")
    if commands.get("provider") != {"file": "provider-image.so", "soname": provider["soname"], "buildId": provider["buildId"], "sha256": provider["sha256"]}:
        fail("command provenance does not bind the exact provider artifact and pins")
    if commands.get("sourceSha256") != source_sha:
        fail("command provenance source digest differs from retained source bytes")
    selected = commands.get("selectedFunction")
    expected_commands = {
        "producer": [
            "dotnet", "urprotect.dll", "protect-image", "source-image.bin",
            "--artifact", "protected-image.bin", "--role", "protected-image.json",
            "--manifest", "producer-manifest.txt", "--stage", "stage.json",
            "--unit", UNIT_ID, "--profile", "host-context-entry", "--producer-id", PRODUCER_ID,
            "--rehydrator", "urprotect.rehydrator.v1", "--source-sha256", source_sha,
            "--function-id", selected, "--pass", "control-flow-flattening",
            "--provider-file", "provider-image.so", "--provider-soname", provider["soname"],
            "--provider-build-id", provider["buildId"], "--provider-sha256", provider["sha256"], "--json", "-",
        ],
        "rehydration": [
            "dotnet", "urprotect.dll", "rehydrate-image", "source-image.bin",
            "--artifact", "protected-image.bin", "--native-image", "native-image.bin",
            "--role", "native-image.json", "--record", "rehydration.json",
            "--unit", UNIT_ID, "--profile", "host-context-entry", "--source-sha256", source_sha,
            "--request-sha256", commands.get("requestSha256"), "--producer-id", commands.get("actualProducerId"),
            "--producer-build-sha256", commands.get("producerBuildSha256"), "--consumer-id", "urprotect.rehydrator.v1",
            "--consumer-build-sha256", commands.get("consumerBuildSha256"),
            "--provider-file", "provider-image.so", "--provider-soname", provider["soname"],
            "--provider-build-id", provider["buildId"], "--provider-sha256", provider["sha256"], "--json", "-",
        ],
        "wrongProviderSha256Rollback": [
            "dotnet", "urprotect.dll", "rehydrate-image", "source-image.bin",
            "--artifact", "protected-image.bin", "--native-image", "negative-native-image.bin",
            "--role", "negative-native-image.json", "--record", "negative-rehydration.json",
            "--unit", UNIT_ID, "--profile", "host-context-entry", "--source-sha256", source_sha,
            "--request-sha256", commands.get("requestSha256"), "--producer-id", commands.get("actualProducerId"),
            "--producer-build-sha256", commands.get("producerBuildSha256"), "--consumer-id", "urprotect.rehydrator.v1",
            "--consumer-build-sha256", commands.get("consumerBuildSha256"),
            "--provider-file", "provider-image.so", "--provider-soname", provider["soname"],
            "--provider-build-id", provider["buildId"], "--provider-sha256", commands.get("wrongProviderSha256"), "--json", "-",
        ],
        "transformedNativeRollback": [
            "host-context-external-provider-rollback-self-test",
            "--native-image-provider-loaded-rollback", "provider-image.so", "native-image.bin",
            "runtime-identity.json:libcPath", "runtime-identity.json:loaderPath",
        ],
    }
    for name, expected_argv in expected_commands.items():
        command = commands.get(name)
        if not isinstance(command, dict) or not same_json(command.get("argv"), expected_argv):
            fail(f"{name} command arguments do not contain the exact required all-or-none provider configuration")
        require_int(command.get("exitStatus"), f"{name}.exitStatus")
    if commands["producer"]["exitStatus"] != 0 or commands["rehydration"]["exitStatus"] != 0:
        fail("positive producer/rehydration command did not exit successfully")
    wrong = commands["wrongProviderSha256Rollback"]
    if wrong["exitStatus"] == 0 or commands.get("wrongProviderSha256") == provider["sha256"]:
        fail("wrong-provider-SHA rollback did not exercise a real mismatch")
    rollback = commands["transformedNativeRollback"]
    if rollback["exitStatus"] != 0:
        fail("transformed Native Image same-process rollback oracle did not pass")
    expected_rollback_bindings = {
        "recordSha256": sha256_bytes(read_file(root, "transformed-native-rollback.json", limit=MAX_REPORT_BYTES)),
        "stderrSha256": sha256_bytes(read_file(root, "transformed-native-rollback.stderr", allow_empty=True, limit=MAX_STREAM_BYTES)),
        "sourceImageSha256": source_sha,
        "protectedImageSha256": sha256_bytes(read_file(root, "protected-image.bin")),
        "nativeImageSha256": sha256_bytes(read_file(root, "native-image.bin")),
        "runtimeIdentitySha256": runtime["identitySha256"],
    }
    if any(rollback.get(field) != expected for field, expected in expected_rollback_bindings.items()):
        fail("transformed Native Image rollback command does not bind exact source/protected/native/runtime evidence bytes")
    for name, argv in (("nativeBuild", NATIVE_BUILD_COMMAND), ("managedBuild", MANAGED_BUILD_COMMAND)): 
        row = commands.get(name)
        if not isinstance(row, dict) or not same_json(row.get("argv"), argv):
            fail(f"{name} command does not bind the exact retained build invocation")
        if require_int(row.get("exitStatus"), f"{name}.exitStatus") != 0:
            fail(f"{name} command did not complete successfully")
        for field in ("stdoutSha256", "stderrSha256"):
            if not isinstance(row.get(field), str) or not DIGEST.fullmatch(row[field]):
                fail(f"{name}.{field} is not a normalized retained stream digest")
    if not isinstance(commands.get("managedCliSha256"), str) or not DIGEST.fullmatch(commands["managedCliSha256"]):
        fail("commands.json managed CLI executable identity is malformed")
    handoff_commands = commands.get("handoffs")
    if not isinstance(handoff_commands, list) or len(handoff_commands) != 20:
        fail("command provenance must retain all twenty source/transformed handoff invocations")


def _check_negative(root: Path, commands: dict[str, Any], provider: dict[str, Any]) -> dict[str, Any]:
    negative = read_json(root, "negative-provider-sha256.json")
    record = read_json(root, "negative-rehydration.json")
    stderr = read_file(root, "negative-provider-sha256.stderr", allow_empty=True, limit=MAX_STREAM_BYTES)
    stdout = read_file(root, "negative-provider-sha256.stdout", allow_empty=True, limit=MAX_STREAM_BYTES)
    status_bytes = read_file(root, "negative-provider-sha256.exit-status", limit=32)
    try:
        observed_status = int(status_bytes.decode("ascii").strip(), 10)
    except (UnicodeDecodeError, ValueError):
        fail("wrong-provider-SHA exit-status file is malformed")
    if commands["wrongProviderSha256Rollback"]["exitStatus"] == 0:
        fail("wrong-provider-SHA rehydration unexpectedly succeeded")
    if observed_status != commands["wrongProviderSha256Rollback"]["exitStatus"]:
        fail("wrong-provider-SHA exit-status file differs from command provenance")
    if not any(token in (stdout + stderr).lower() for token in (b"sha-256", b"sha256", b"provider")):
        fail("wrong-provider-SHA negative has no observed provider/hash diagnostic")
    if record.get("status") != "failed" or record.get("unitId") != UNIT_ID:
        fail("wrong-provider-SHA rehydration record has the wrong failure identity")
    try:
        command_output = json.loads(stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"wrong-provider-SHA command stdout is not JSON: {error}")
    if not isinstance(command_output, dict) or command_output.get("success") is not False or not same_json(command_output.get("record"), record):
        fail("wrong-provider-SHA command stdout does not bind the actual failed record")
    first_failure = record.get("firstFailureStage")
    if first_failure not in {"rehydration", "provider-preflight", "provider-input"}:
        fail("wrong-provider-SHA negative did not fail before publication")
    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, list) or not diagnostics:
        fail("wrong-provider-SHA rehydration failure has no actual diagnostic")
    provider_diagnostics = [
        item for item in diagnostics
        if isinstance(item, dict)
        and isinstance(item.get("code"), str)
        and (
            "provider" in item["code"].lower()
            or ("provider" in str(item.get("message", "")).lower() and "sha-256" in str(item.get("message", "")).lower())
        )
    ]
    if len(provider_diagnostics) != 1:
        fail("wrong-provider-SHA negative lacks one actual provider/hash-specific fail-closed diagnostic")
    provider_code = provider_diagnostics[0]["code"]
    require_version(negative, "schemaVersion", 1, "negative-provider-sha256.json")
    if negative.get("stage") != first_failure or negative.get("firstFailureStage") != first_failure or negative.get("status") != "failed":
        fail("wrong-provider-SHA evidence witness does not bind the actual failure stage/status")
    if negative.get("failureClass") != provider_code:
        fail("wrong-provider-SHA witness failure class differs from the actual diagnostic")
    if type(negative.get("exitStatus")) is not int or negative["exitStatus"] != observed_status:
        fail("wrong-provider-SHA witness exit status differs from the actual process")
    for forbidden in ("negative-native-image.bin", "negative-native-image.json", "negative-loader.json", "negative-handoff.json"):
        if (root / forbidden).exists() or (root / forbidden).is_symlink():
            fail(f"failed provider rehydration published forbidden output: {forbidden}")
    if negative.get("nativeImagePublished") is not False or negative.get("loaderInvoked") is not False:
        fail("wrong-provider-SHA rollback does not prove no Native Image/loader publication")
    if negative.get("providerSha256") != provider["sha256"] or negative.get("suppliedProviderSha256") != commands.get("wrongProviderSha256"):
        fail("wrong-provider-SHA negative is not bound to the measured and mismatched pins")
    if negative.get("stdoutSha256") != sha256_bytes(stdout) or negative.get("stderrSha256") != sha256_bytes(stderr):
        fail("wrong-provider-SHA negative stream hashes do not bind retained process output")
    if negative.get("negativeRecordSha256") != sha256_bytes(read_file(root, "negative-rehydration.json")):
        fail("wrong-provider-SHA witness does not bind the actual failed rehydration record")
    return {
        "kind": "wrong-provider-sha256",
        "status": "failed-before-publication",
        "failureClass": provider_code,
        "firstFailureStage": first_failure,
        "exitStatus": observed_status,
        "nativeImagePublished": False,
        "loaderInvoked": False,
        "stdoutSha256": negative["stdoutSha256"],
        "stderrSha256": negative["stderrSha256"],
    }


def _parse_mapped_elf_loads(
    data: bytes,
    label: str,
    *,
    maximum_size: int = MAX_FILE_BYTES,
) -> list[dict[str, int]]:
    if len(data) < 64 or len(data) > maximum_size or data[:6] != b"\x7fELF\x02\x01" or data[6] != 1:
        fail(f"{label} is not a bounded little-endian ELF64 image")
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    except struct.error:
        fail(f"{label} ELF header is truncated")
    _ident, elf_type, machine, version, _entry, phoff, _shoff, _flags, ehsize, phentsize, phnum, _shentsize, _shnum, _shstrndx = header
    if (elf_type not in {2, 3} or machine != 183 or version != 1 or ehsize != 64
        or phentsize != 56 or phnum == 0 or phnum > 256
        or phoff > len(data) or phnum > (len(data) - phoff) // phentsize):
        fail(f"{label} program-header table is malformed or not AArch64")
    loads: list[dict[str, int]] = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize
        )
        if kind != 1:
            continue
        if (filesz > memsz or offset > len(data) or filesz > len(data) - offset
            or vaddr > (1 << 64) - 1 - memsz or offset > (1 << 64) - 1 - filesz):
            fail(f"{label} PT_LOAD {index} has an invalid half-open file or memory extent")
        loads.append({"index": index, "flags": flags, "offset": offset,
            "vaddr": vaddr, "filesz": filesz, "memsz": memsz, "align": align})
    if not loads:
        fail(f"{label} has no PT_LOAD ranges")
    ordered = sorted(loads, key=lambda row: (row["vaddr"], row["index"]))
    previous_end = 0
    for index, segment in enumerate(ordered):
        end = segment["vaddr"] + segment["memsz"]
        if index and segment["vaddr"] < previous_end:
            fail(f"{label} PT_LOAD memory extents overlap and do not have unique byte owners")
        previous_end = end
    return loads


def _parse_map_rows(value: Any, label: str, *, allow_empty: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 256 or (not allow_empty and not value):
        fail(f"{label} must be a bounded nonempty mapping list")
    expected_keys = {"deviceMajor", "deviceMinor", "end", "inode", "offset", "permissions", "start"}
    rows: list[dict[str, Any]] = []
    previous_end = 0
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            fail(f"{label}[{index}] mapping row fields are malformed")
        row = dict(raw)
        for field in ("deviceMajor", "deviceMinor", "end", "inode", "offset", "start"):
            number = require_int(row[field], f"{label}[{index}].{field}")
            if number < 0 or number > (1 << 64) - 1:
                fail(f"{label}[{index}].{field} is outside uint64")
        if row["deviceMajor"] > 0xffffffff or row["deviceMinor"] > 0xffffffff:
            fail(f"{label}[{index}] device id exceeds uint32")
        if row["start"] >= row["end"] or row["offset"] > (1 << 64) - 1 - (row["end"] - row["start"]):
            fail(f"{label}[{index}] mapping interval overflows or is empty")
        permissions = row["permissions"]
        if not isinstance(permissions, str) or not re.fullmatch(r"[r-][w-][x-][ps]", permissions):
            fail(f"{label}[{index}] mapping permissions are malformed")
        if index and row["start"] < previous_end:
            fail(f"{label} contains overlapping or unsorted half-open mapping rows")
        previous_end = row["end"]
        rows.append(row)
    return rows


def _parse_map_identity(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {"deviceMajor", "deviceMinor", "inode"}:
        fail(f"{label} backing identity fields are malformed")
    identity = {field: require_int(value.get(field), f"{label}.{field}")
        for field in ("deviceMajor", "deviceMinor", "inode")}
    if (identity["deviceMajor"] < 0 or identity["deviceMajor"] > 0xffffffff
        or identity["deviceMinor"] < 0 or identity["deviceMinor"] > 0xffffffff
        or identity["inode"] <= 0 or identity["inode"] > (1 << 64) - 1):
        fail(f"{label} backing identity is outside its strict range")
    return identity


def _maps_for_identity(rows: list[dict[str, Any]], identity: dict[str, int]) -> list[dict[str, Any]]:
    return [row for row in rows if row["deviceMajor"] == identity["deviceMajor"]
        and row["deviceMinor"] == identity["deviceMinor"] and row["inode"] == identity["inode"]]


def _check_load_mappings(
    data: bytes,
    label: str,
    load_bias: Any,
    identity_value: Any,
    process_rows_value: Any,
    recorded_rows_value: Any,
    *,
    maximum_size: int = MAX_FILE_BYTES,
) -> dict[str, Any]:
    bias = require_int(load_bias, f"{label}.loadBias")
    if bias < 0 or bias > (1 << 64) - 1:
        fail(f"{label} load bias is outside uint64")
    identity = _parse_map_identity(identity_value, f"{label}.identity")
    process_rows = _parse_map_rows(process_rows_value, f"{label}.processMaps")
    recorded_rows = _parse_map_rows(recorded_rows_value, f"{label}.recordedMappings")
    expected_rows = _maps_for_identity(process_rows, identity)
    if recorded_rows != expected_rows or not recorded_rows:
        fail(f"{label} recorded mapping rows do not exactly cover the process snapshot for its backing identity")
    loads = _parse_mapped_elf_loads(data, label, maximum_size=maximum_size)
    ranges: list[dict[str, int]] = []
    for segment in loads:
        if bias > (1 << 64) - 1 - segment["vaddr"]:
            fail(f"{label} load bias plus PT_LOAD start overflows")
        start = bias + segment["vaddr"]
        if start > (1 << 64) - 1 - segment["memsz"]:
            fail(f"{label} PT_LOAD runtime memory extent overflows")
        end = start + segment["memsz"]
        file_end = start + segment["filesz"]
        ranges.append({"start": start, "end": end, "fileEnd": file_end,
            "fileOffset": segment["offset"], "flags": segment["flags"], "index": segment["index"]})
        cursor = start
        while cursor < end:
            owners = [row for row in process_rows if row["start"] <= cursor < row["end"]]
            if len(owners) != 1:
                fail(f"{label} PT_LOAD {segment['index']} byte has no unique live mapping owner")
            owner = owners[0]
            next_cursor = min(end, owner["end"])
            flags = segment["flags"]
            permissions = owner["permissions"]
            if ((flags & 4 and permissions[0] != "r")
                or (flags & 1 and permissions[2] != "x")
                or (not flags & 1 and permissions[2] == "x")
                or (not flags & 2 and permissions[1] == "w")):
                fail(f"{label} PT_LOAD {segment['index']} live mapping permissions violate its ELF flags")
            if cursor < file_end:
                file_cursor_end = min(next_cursor, file_end)
                if (owner["deviceMajor"] != identity["deviceMajor"]
                    or owner["deviceMinor"] != identity["deviceMinor"]
                    or owner["inode"] != identity["inode"]):
                    fail(f"{label} PT_LOAD {segment['index']} file-backed bytes map to a different backing identity")
                actual_offset = owner["offset"] + (cursor - owner["start"])
                expected_offset = segment["offset"] + (cursor - start)
                if actual_offset != expected_offset:
                    fail(f"{label} PT_LOAD {segment['index']} file-backed byte offset mapping is inconsistent")
                if file_cursor_end <= cursor:
                    fail(f"{label} PT_LOAD {segment['index']} file mapping made no progress")
            if next_cursor <= cursor:
                fail(f"{label} PT_LOAD {segment['index']} live mapping made no progress")
            cursor = next_cursor
    return {"identity": identity, "loadBias": bias, "mappings": recorded_rows, "loadRanges": ranges}


def _require_load_ranges_unmapped(
    data: bytes,
    label: str,
    load_bias: Any,
    identity: dict[str, int],
    process_rows_value: Any,
    recorded_rows_value: Any,
) -> dict[str, Any]:
    bias = require_int(load_bias, f"{label}.loadBias")
    process_rows = _parse_map_rows(process_rows_value, f"{label}.processMaps")
    recorded_rows = _parse_map_rows(recorded_rows_value, f"{label}.recordedMappings", allow_empty=True)
    if recorded_rows or _maps_for_identity(process_rows, identity):
        fail(f"{label} backing identity remains mapped after rollback/release")
    for segment in _parse_mapped_elf_loads(data, label):
        if bias > (1 << 64) - 1 - segment["vaddr"]:
            fail(f"{label} unmapped PT_LOAD start overflows")
        start = bias + segment["vaddr"]
        if start > (1 << 64) - 1 - segment["memsz"]:
            fail(f"{label} unmapped PT_LOAD end overflows")
        end = start + segment["memsz"]
        if any(row["start"] < end and start < row["end"] for row in process_rows):
            fail(f"{label} PT_LOAD range still intersects a live process mapping after rollback/release")
    return {"identity": identity, "loadBias": bias, "remainingMappings": []}


def _check_rollback_state(value: Any, label: str, *, failure_descriptors: bool) -> dict[str, Any]:
    fields = {
        "activeProviderDescriptorOpen", "activeProviderPresent", "activeProviderReferences",
        "failureConsumerDescriptorOpen", "failureProviderDescriptorOpen", "nextImageHandle",
        "openDescriptorCount", "registeredImageCount", "registeredImageDescriptorCount",
    }
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} lifecycle resource state fields are malformed")
    for field in ("activeProviderReferences", "nextImageHandle", "openDescriptorCount", "registeredImageCount", "registeredImageDescriptorCount"):
        number = require_int(value[field], f"{label}.{field}")
        if number < 0 or number > (1 << 64) - 1:
            fail(f"{label}.{field} is outside uint64")
    for field in ("activeProviderDescriptorOpen", "activeProviderPresent"):
        if type(value[field]) is not bool:
            fail(f"{label}.{field} must be an exact JSON boolean")
    for field in ("failureConsumerDescriptorOpen", "failureProviderDescriptorOpen"):
        if failure_descriptors:
            if type(value[field]) is not bool:
                fail(f"{label}.{field} must be an exact JSON boolean")
        elif value[field] is not None:
            fail(f"{label}.{field} must be null outside the failpoint cleanup state")
    return value


def _check_transformed_native_rollback(
    root: Path,
    commands: dict[str, Any],
    provider: dict[str, Any],
    source_facts: dict[str, Any],
    native_facts: dict[str, Any],
    source_sha: str,
    protected_sha: str,
    native_sha: str,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    record = read_json(root, "transformed-native-rollback.json")
    command = commands["transformedNativeRollback"]
    status_bytes = read_file(root, "transformed-native-rollback.exit-status", limit=32)
    stderr = read_file(root, "transformed-native-rollback.stderr", allow_empty=True, limit=MAX_STREAM_BYTES)
    try:
        status = int(status_bytes.decode("ascii", errors="strict").strip(), 10)
    except (UnicodeDecodeError, ValueError):
        fail("transformed Native Image rollback exit-status file is malformed")
    if status != command["exitStatus"] or status != 0:
        fail("transformed Native Image rollback helper did not exit successfully")
    if command.get("recordSha256") != sha256_bytes(read_file(root, "transformed-native-rollback.json", limit=MAX_REPORT_BYTES)):
        fail("transformed Native Image rollback command does not hash-bind its actual record bytes")
    if command.get("stderrSha256") != sha256_bytes(stderr) or stderr:
        fail("transformed Native Image rollback helper emitted unbound stderr")
    if command.get("sourceImageSha256") != source_sha or command.get("protectedImageSha256") != protected_sha or command.get("nativeImageSha256") != native_sha:
        fail("transformed Native Image rollback input is detached from the exact Source/Protected/Native Image chain")
    if command.get("runtimeIdentitySha256") != runtime["identitySha256"]:
        fail("transformed Native Image rollback command does not bind the measured libc/loader runtime identity")
    require_version(record, "schemaVersion", 2, "transformed-native-rollback.json")
    if set(record) != {
        "schemaVersion", "oracle", "architecture", "runtime", "glibcVersion", "provider", "input",
        "baseline", "failpoint", "firstLoad", "cleanup", "retry", "release", "counters", "events",
        "eventOverflow", "oraclePassed", "mappingEvidence",
    }:
        fail("transformed Native Image rollback record fields are not the exact schema")
    if (record.get("oracle") != "transformed-native-image-provider-loaded-consumer-binding-failure-rollback"
        or record.get("architecture") != "aarch64" or record.get("runtime") != "glibc"
        or record.get("glibcVersion") != runtime["version"].removeprefix("glibc ") or record.get("oraclePassed") is not True
        or record.get("eventOverflow") is not False):
        fail("transformed Native Image rollback record has the wrong schema, execution identity, or result")
    if record.get("provider") != {"soname": provider["soname"], "buildId": provider["buildId"],
        "sha256": provider["sha256"], "size": provider["size"], "tableBytesHex": provider["table"]["bytesHex"]}:
        fail("transformed Native Image rollback record does not bind the parsed provider ELF identity/table bytes")
    require_int(record["provider"]["size"], "provider.size")
    failpoint_record = record.get("failpoint")
    if (not isinstance(failpoint_record, dict) or set(failpoint_record) != {
        "oneShot", "placement", "providerAcquisitions", "consumerDlmopenSuccesses", "bindingVerifications", "reached"}
        or type(failpoint_record.get("oneShot")) is not bool or failpoint_record.get("oneShot") is not True
        or failpoint_record.get("placement") != "after-provider-consumer-GOT-binding-verification-before-image-handle-publication"):
        fail("transformed Native Image rollback failpoint claim is malformed")
    for field in ("providerAcquisitions", "consumerDlmopenSuccesses", "bindingVerifications", "reached"):
        require_int(failpoint_record[field], f"failpoint.{field}")
    if [failpoint_record[field] for field in ("providerAcquisitions", "consumerDlmopenSuccesses", "bindingVerifications", "reached")] != [1, 1, 1, 1]:
        fail("one-shot rollback failpoint was not reached after actual provider/consumer binding")
    input_record = record.get("input")
    if not isinstance(input_record, dict) or input_record != {"nativeImageSha256": native_sha,
        "nativeImageSize": len(read_file(root, "native-image.bin"))}:
        fail("provider-loaded rollback oracle did not consume the exact retained transformed Native Image bytes")
    if not native_facts.get("liveDispatch") or source_facts.get("sourceDispatch") is None:
        fail("rollback evidence is not connected to the independent source/native provider dispatch proofs")
    mapping = record.get("mappingEvidence")
    if not isinstance(mapping, dict) or set(mapping) != {"failpoint", "retry", "runtimeLibraries"}:
        fail("rollback mapping evidence fields are not exact")
    failpoint = mapping["failpoint"]
    retry = mapping["retry"]
    runtime_maps = mapping["runtimeLibraries"]
    if not isinstance(failpoint, dict) or set(failpoint) != {"provider", "consumer", "processMapsBeforeCleanup", "processMapsAfterCleanup"}:
        fail("failpoint map observation schema is malformed")
    if not isinstance(retry, dict) or set(retry) != {"provider", "consumer", "processMapsActive", "processMapsAfterRelease"}:
        fail("retry map observation schema is malformed")
    if not isinstance(runtime_maps, dict) or set(runtime_maps) != {"processMapsBaseline", "libc", "loader"}:
        fail("runtime mapping observation schema is malformed")

    provider_elf = read_file(root, "provider-image.so", limit=MAX_PROVIDER_BYTES)
    consumer_elf = read_file(root, "native-image.bin")
    provider_table_va = provider["table"]["virtualAddress"]
    consumer_got_va = native_facts["got"]["virtualAddress"]
    first = record.get("firstLoad")
    retry_result = record.get("retry")
    release = record.get("release")
    if not isinstance(first, dict) or set(first) != {
        "statusCode", "expectedFailureStatusCode", "publishedHandle", "memfdAttemptsDelta", "loaderAttemptsDelta",
        "providerTableAddress", "providerLoadBias", "consumerGotSlotAddress", "consumerGotValue", "consumerLoadBias",
        "providerMappingPresentAfterCleanup", "consumerMappingPresentAfterCleanup", "postCleanupState"}:
        fail("rollback first-load lifecycle record fields are malformed")
    if not isinstance(retry_result, dict) or set(retry_result) != {
        "loadStatusCode", "handlePublished", "memfdAttemptsDelta", "loaderAttemptsDelta", "providerTableAddress",
        "providerLoadBias", "providerMappingPermissions", "consumerGotSlotAddress", "consumerGotPermissions",
        "consumerGotValue", "consumerLoadBias", "providerTableBytesHex", "entryLookupStatus", "observerLookupStatus",
        "entryStatus", "observerStatus", "stdoutHex", "stdoutSha256", "stderrHex", "stderrSha256", "activeState"}:
        fail("rollback retry lifecycle record fields are malformed")
    if not isinstance(release, dict) or set(release) != {
        "statusCode", "providerMappingAbsent", "consumerMappingAbsent", "finalState"}:
        fail("rollback release lifecycle record fields are malformed")
    for field in ("statusCode", "expectedFailureStatusCode", "publishedHandle", "memfdAttemptsDelta", "loaderAttemptsDelta",
        "providerTableAddress", "providerLoadBias", "consumerGotSlotAddress", "consumerGotValue", "consumerLoadBias"):
        require_int(first[field], f"firstLoad.{field}")
    for field in ("loadStatusCode", "memfdAttemptsDelta", "loaderAttemptsDelta", "providerTableAddress", "providerLoadBias",
        "consumerGotSlotAddress", "consumerGotValue", "consumerLoadBias", "entryLookupStatus", "observerLookupStatus",
        "entryStatus", "observerStatus"):
        require_int(retry_result[field], f"retry.{field}")
    require_int(release["statusCode"], "release.statusCode")
    if (type(first["providerMappingPresentAfterCleanup"]) is not bool
        or type(first["consumerMappingPresentAfterCleanup"]) is not bool
        or type(retry_result["handlePublished"]) is not bool
        or type(release["providerMappingAbsent"]) is not bool or type(release["consumerMappingAbsent"]) is not bool):
        fail("rollback mapping/publication claims must be exact JSON booleans")
    first_provider_bias = require_int(first.get("providerLoadBias"), "firstLoad.providerLoadBias")
    first_consumer_bias = require_int(first.get("consumerLoadBias"), "firstLoad.consumerLoadBias")
    retry_provider_bias = require_int(retry_result.get("providerLoadBias"), "retry.providerLoadBias")
    retry_consumer_bias = require_int(retry_result.get("consumerLoadBias"), "retry.consumerLoadBias")
    for label, value, bias, va in (
        ("first provider table", first.get("providerTableAddress"), first_provider_bias, provider_table_va),
        ("first consumer GOT slot", first.get("consumerGotSlotAddress"), first_consumer_bias, consumer_got_va),
        ("retry provider table", retry_result.get("providerTableAddress"), retry_provider_bias, provider_table_va),
        ("retry consumer GOT slot", retry_result.get("consumerGotSlotAddress"), retry_consumer_bias, consumer_got_va),
    ):
        address = require_int(value, f"{label}.address")
        if bias > (1 << 64) - 1 - va or address != bias + va:
            fail(f"{label} is not derived from its source PT_LOAD identity and loader bias")
    if first.get("consumerGotValue") != first.get("providerTableAddress") or retry_result.get("consumerGotValue") != retry_result.get("providerTableAddress"):
        fail("rollback consumer GOT values do not point to the exact provider-owned table")
    if retry_result.get("providerTableBytesHex") != provider["table"]["bytesHex"]:
        fail("live provider table bytes do not match the independently parsed provider ELF")
    if (retry_result["providerMappingPermissions"] != "r--p"
        or retry_result["consumerGotPermissions"] != "r--p"
        or release["providerMappingAbsent"] is not True or release["consumerMappingAbsent"] is not True):
        fail("provider table/GOT read-only mapping or post-release absence claims are false")
    if (first["statusCode"] != -2 or first["expectedFailureStatusCode"] != -2
        or first["publishedHandle"] != 0 or first["providerMappingPresentAfterCleanup"] is not False
        or first["consumerMappingPresentAfterCleanup"] is not False
        or first["memfdAttemptsDelta"] != 2 or first["loaderAttemptsDelta"] != 2
        or retry_result["loadStatusCode"] != 0 or retry_result["handlePublished"] is not True
        or retry_result["memfdAttemptsDelta"] != 2 or retry_result["loaderAttemptsDelta"] != 2
        or retry_result["entryLookupStatus"] != 0 or retry_result["observerLookupStatus"] != 0):
        fail("rollback did not demonstrate a failed first load followed by a genuine successful retry")
    baseline = record.get("baseline")
    if not isinstance(baseline, dict) or set(baseline) != {
        "nextImageHandle", "openDescriptorCount", "registeredImageCount", "activeProviderPresent"}:
        fail("rollback baseline state fields are malformed")
    baseline_next = require_int(baseline["nextImageHandle"], "baseline.nextImageHandle")
    baseline_descriptors = require_int(baseline["openDescriptorCount"], "baseline.openDescriptorCount")
    baseline_registered = require_int(baseline["registeredImageCount"], "baseline.registeredImageCount")
    if type(baseline["activeProviderPresent"]) is not bool:
        fail("baseline.activeProviderPresent must be an exact JSON boolean")
    if baseline["activeProviderPresent"] is not False or baseline_registered != 0:
        fail("rollback baseline is not an empty provider/image registry")
    failure_state = _check_rollback_state(first["postCleanupState"], "firstLoad.postCleanupState", failure_descriptors=True)
    retry_state = _check_rollback_state(retry_result["activeState"], "retry.activeState", failure_descriptors=False)
    final_state = _check_rollback_state(release["finalState"], "release.finalState", failure_descriptors=False)
    if (failure_state["nextImageHandle"] != baseline_next or failure_state["openDescriptorCount"] != baseline_descriptors
        or failure_state["registeredImageCount"] != 0 or failure_state["registeredImageDescriptorCount"] != 0
        or failure_state["activeProviderPresent"] is not False or failure_state["activeProviderReferences"] != 0
        or failure_state["activeProviderDescriptorOpen"] is not False
        or failure_state["failureProviderDescriptorOpen"] is not False
        or failure_state["failureConsumerDescriptorOpen"] is not False):
        fail("failed provider-loaded rollback leaked an image handle, descriptor, provider, or mapping owner")
    if (retry_state["nextImageHandle"] != baseline_next + 1 or retry_state["openDescriptorCount"] != baseline_descriptors + 2
        or retry_state["registeredImageCount"] != 1 or retry_state["registeredImageDescriptorCount"] != 1
        or retry_state["activeProviderPresent"] is not True or retry_state["activeProviderReferences"] != 1
        or retry_state["activeProviderDescriptorOpen"] is not True):
        fail("successful rollback retry did not publish exactly one live image/provider and two descriptors")
    if (final_state["nextImageHandle"] != baseline_next + 1 or final_state["openDescriptorCount"] != baseline_descriptors
        or final_state["registeredImageCount"] != 0 or final_state["registeredImageDescriptorCount"] != 0
        or final_state["activeProviderPresent"] is not False or final_state["activeProviderReferences"] != 0
        or final_state["activeProviderDescriptorOpen"] is not False):
        fail("successful retry release did not return resources to the exact baseline state")
    counters = record.get("counters")
    if not isinstance(counters, dict) or set(counters) != {
        "memfdAttemptsBefore", "memfdAttemptsAfter", "loaderAttemptsBefore", "loaderAttemptsAfter"}:
        fail("rollback attempt counters fields are malformed")
    for field, value in counters.items():
        require_int(value, f"counters.{field}")
    if (counters["memfdAttemptsAfter"] - counters["memfdAttemptsBefore"] != 4
        or counters["loaderAttemptsAfter"] - counters["loaderAttemptsBefore"] != 4):
        fail("rollback/retry counters do not show exactly two provider+consumer load attempts")

    failure_provider = failpoint.get("provider")
    failure_consumer = failpoint.get("consumer")
    retry_provider = retry.get("provider")
    retry_consumer = retry.get("consumer")
    for value, label in ((failure_provider, "failure provider"), (failure_consumer, "failure consumer"),
        (retry_provider, "retry provider"), (retry_consumer, "retry consumer")):
        if not isinstance(value, dict) or set(value) != {"identity", "beforeCleanup", "afterCleanup"} and label.startswith("failure"):
            fail(f"{label} mapping record is malformed")
        if not isinstance(value, dict) or set(value) != {"identity", "active", "afterRelease"} and label.startswith("retry"):
            fail(f"{label} mapping record is malformed")

    fail_before = _parse_map_rows(failpoint["processMapsBeforeCleanup"], "failpoint.processMapsBeforeCleanup")
    fail_after = _parse_map_rows(failpoint["processMapsAfterCleanup"], "failpoint.processMapsAfterCleanup")
    active_rows = _parse_map_rows(retry["processMapsActive"], "retry.processMapsActive")
    released_rows = _parse_map_rows(retry["processMapsAfterRelease"], "retry.processMapsAfterRelease")
    failure_provider_id = _parse_map_identity(failure_provider.get("identity"), "failpoint.provider.identity")
    failure_consumer_id = _parse_map_identity(failure_consumer.get("identity"), "failpoint.consumer.identity")
    retry_provider_id = _parse_map_identity(retry_provider.get("identity"), "retry.provider.identity")
    retry_consumer_id = _parse_map_identity(retry_consumer.get("identity"), "retry.consumer.identity")
    if (failure_provider_id["inode"] == failure_consumer_id["inode"]
        and failure_provider_id["deviceMajor"] == failure_consumer_id["deviceMajor"]
        and failure_provider_id["deviceMinor"] == failure_consumer_id["deviceMinor"]
        or retry_provider_id["inode"] == retry_consumer_id["inode"]
        and retry_provider_id["deviceMajor"] == retry_consumer_id["deviceMajor"]
        and retry_provider_id["deviceMinor"] == retry_consumer_id["deviceMinor"]):
        fail("provider and Native Image consumer mappings do not have distinct sealed-memfd owners")
    failure_provider_maps = _check_load_mappings(provider_elf, "failpoint provider", first_provider_bias,
        failure_provider_id, fail_before, failure_provider.get("beforeCleanup"))
    failure_consumer_maps = _check_load_mappings(consumer_elf, "failpoint Native Image consumer", first_consumer_bias,
        failure_consumer_id, fail_before, failure_consumer.get("beforeCleanup"))
    failure_provider_unmapped = _require_load_ranges_unmapped(provider_elf, "failed provider", first_provider_bias,
        failure_provider_id, fail_after, failure_provider.get("afterCleanup"))
    failure_consumer_unmapped = _require_load_ranges_unmapped(consumer_elf, "failed Native Image consumer", first_consumer_bias,
        failure_consumer_id, fail_after, failure_consumer.get("afterCleanup"))
    retry_provider_maps = _check_load_mappings(provider_elf, "retry provider", retry_provider_bias,
        retry_provider_id, active_rows, retry_provider.get("active"))
    retry_consumer_maps = _check_load_mappings(consumer_elf, "retry Native Image consumer", retry_consumer_bias,
        retry_consumer_id, active_rows, retry_consumer.get("active"))
    retry_provider_unmapped = _require_load_ranges_unmapped(provider_elf, "released provider", retry_provider_bias,
        retry_provider_id, released_rows, retry_provider.get("afterRelease"))
    retry_consumer_unmapped = _require_load_ranges_unmapped(consumer_elf, "released Native Image consumer", retry_consumer_bias,
        retry_consumer_id, released_rows, retry_consumer.get("afterRelease"))

    baseline_rows = _parse_map_rows(runtime_maps["processMapsBaseline"], "runtimeLibraries.processMapsBaseline")
    runtime_checks: dict[str, Any] = {}
    for key, filename, path_field, sha_field in (
        ("libc", "libc.so.6", "libcPath", "libcSha256"),
        ("loader", "ld-linux-aarch64.so.1", "loaderPath", "loaderSha256"),
    ):
        row = runtime_maps.get(key)
        if not isinstance(row, dict) or set(row) != {"identity", "loadBias", "mappings"}:
            fail(f"runtime {key} loaded mapping identity schema is malformed")
        identity = _parse_map_identity(row["identity"], f"runtime {key}.identity")
        st = os.stat(runtime[path_field])
        if identity != {"deviceMajor": os.major(st.st_dev), "deviceMinor": os.minor(st.st_dev), "inode": st.st_ino}:
            fail(f"runtime {key} mapping identity is not the actual loaded libc/loader backing file")
        if sha256_bytes(read_file(root, f"runtime-files/{filename}", limit=256 * 1024 * 1024)) != runtime[sha_field]:
            fail(f"runtime {key} loaded identity differs from the bound runtime file digest")
        mapped = _check_load_mappings(read_file(root, f"runtime-files/{filename}", limit=MAX_RUNTIME_IMAGE_BYTES),
            f"runtime {key}", row["loadBias"], identity, baseline_rows, row["mappings"],
            maximum_size=MAX_RUNTIME_IMAGE_BYTES)
        runtime_checks[key] = mapped
    live_dispatch = native_facts["liveDispatch"].get("dispatch")
    source_dispatch = source_facts["sourceDispatch"]
    if (not isinstance(live_dispatch, dict) or not isinstance(source_dispatch, dict)
        or live_dispatch.get("dispatch", {}).get("gotAddress") != source_dispatch.get("dispatch", {}).get("gotAddress")
        or live_dispatch.get("guard", {}).get("bound") != source_dispatch.get("guard", {}).get("bound")
        or native_facts["liveDispatch"].get("outputMapping", {}).get("sourceRange", {}).get("virtualAddress")
            != source_dispatch.get("selectedFunction", {}).get("virtualAddress")):
        fail("rollback input dispatch proof is not source-image-derived through the re-decoded Native Image live entry chain")
    if (record.get("firstLoad", {}).get("statusCode") != record.get("firstLoad", {}).get("expectedFailureStatusCode")
        or require_int(first.get("publishedHandle"), "firstLoad.publishedHandle") != 0
        or require_int(retry_result.get("loadStatusCode"), "retry.loadStatusCode") != 0
        or retry_result.get("handlePublished") is not True
        or require_int(release.get("statusCode"), "release.statusCode") != 0
        or require_int(retry_result.get("entryStatus"), "retry.entryStatus") != 17
        or require_int(retry_result.get("observerStatus"), "retry.observerStatus") != 17
        or retry_result.get("stdoutHex") != "" or retry_result.get("stderrHex") != ""
        or retry_result.get("stdoutSha256") != sha256_bytes(b"") or retry_result.get("stderrSha256") != sha256_bytes(b"")):
        fail("transformed Native Image rollback/retry execution did not preserve the expected status/stream contract")
    expected_events = ["provider-acquired", "consumer-dlmopen-succeeded", "provider-binding-verified",
        "binding-failpoint-reached", "failure-consumer-dlclose-returned", "failure-consumer-fd-close-returned",
        "provider-dlclose-returned", "provider-fd-close-returned", "provider-release-returned", "first-load-rejected",
        "provider-acquired", "consumer-dlmopen-succeeded", "provider-binding-verified", "image-handle-published",
        "image-release-started", "image-dlclose-returned", "image-fd-close-returned", "provider-dlclose-returned",
        "provider-fd-close-returned", "provider-release-returned", "image-release-returned"]
    if record.get("events") != expected_events:
        fail("transformed Native Image rollback lifecycle event order is incomplete or incorrect")
    cleanup = record.get("cleanup")
    if not isinstance(cleanup, dict) or set(cleanup) != {
        "consumerDlcloseResult", "consumerFdCloseResult", "providerReleaseStatus", "providerDlcloseResult",
        "providerFdCloseResult", "providerReleaseCallsAfterFailure", "consumerDlcloseCalls", "consumerFdCloseCalls",
    }:
        fail("transformed Native Image failure cleanup record schema is malformed")
    for field in ("consumerDlcloseResult", "consumerFdCloseResult", "providerReleaseStatus", "providerDlcloseResult",
        "providerFdCloseResult", "providerReleaseCallsAfterFailure", "consumerDlcloseCalls", "consumerFdCloseCalls"):
        require_int(cleanup[field], f"cleanup.{field}")
    if (cleanup["consumerDlcloseResult"] != 0 or cleanup["consumerFdCloseResult"] != 0
        or cleanup["providerReleaseStatus"] != 0 or cleanup["providerDlcloseResult"] != 0
        or cleanup["providerFdCloseResult"] != 0 or cleanup["providerReleaseCallsAfterFailure"] != 1
        or cleanup["consumerDlcloseCalls"] != 1 or cleanup["consumerFdCloseCalls"] != 1):
        fail("transformed Native Image failure cleanup did not actually close/release every resource")
    return {
        "kind": "transformed-native-image-provider-loaded-rollback",
        "sourceImageSha256": source_sha,
        "protectedImageSha256": protected_sha,
        "nativeImageSha256": native_sha,
        "runtimeIdentitySha256": runtime["identitySha256"],
        "failureProviderLoadRanges": failure_provider_maps["loadRanges"],
        "failureConsumerLoadRanges": failure_consumer_maps["loadRanges"],
        "failureProviderCleanup": failure_provider_unmapped,
        "failureConsumerCleanup": failure_consumer_unmapped,
        "retryProviderLoadRanges": retry_provider_maps["loadRanges"],
        "retryConsumerLoadRanges": retry_consumer_maps["loadRanges"],
        "retryProviderRelease": retry_provider_unmapped,
        "retryConsumerRelease": retry_consumer_unmapped,
        "runtimeLibraries": runtime_checks,
        "sourceDispatchSha256": sha256_bytes(canonical(source_facts["sourceDispatch"])),
        "nativeLiveDispatch": native_facts["liveDispatch"],
        "exitStatus": status,
        "oraclePassed": True,
    }


def _walk_handoffs(root: Path, commands: dict[str, Any], provider: dict[str, Any], source_facts: dict[str, Any], native_facts: dict[str, Any], source_sha: str, native_sha: str) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    command_by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    for command in commands["handoffs"]:
        if not isinstance(command, dict):
            fail("handoff command row is malformed")
        index = require_int(command.get("argumentIndex"), "handoff command argumentIndex")
        key = (command.get("lane"), command.get("entrySymbol"), index)
        if key in command_by_key:
            fail("duplicate handoff command row")
        command_by_key[key] = command
    if len(command_by_key) != 20:
        fail("handoff command table does not cover every entry/index pair exactly once")
    for lane, image_sha, facts in (("source", source_sha, source_facts), ("transformed", native_sha, native_facts)):
        rows[lane] = {}
        for symbol in ENTRY_SYMBOLS:
            rows[lane][symbol] = []
            for index in INDICES:
                key = (lane, symbol, index)
                command = command_by_key.get(key)
                if command is None:
                    fail(f"missing {lane}/{symbol}/{index} handoff command")
                expected_argv = [
                    "host-context-external-provider-image-handoff", "provider-image.so", PROVIDER_SONAME,
                    provider["buildId"], provider["sha256"], f"{lane}-image.bin", symbol, str(index),
                    f"handoffs/{lane}/{symbol}/index-{index}.json",
                ]
                if not same_json(command.get("argv"), expected_argv) or type(command.get("exitStatus")) is not int:
                    fail(f"{lane}/{symbol}/{index} handoff command arguments/status are malformed")
                record_rel = expected_argv[-1]
                record = read_json(root, record_rel)
                validated = validate_handoff_record(record, image_sha256=image_sha, provider=provider, consumer=facts, entry_symbol=symbol, index=index)
                out = read_file(root, f"handoffs/{lane}/{symbol}/index-{index}.stdout", allow_empty=True, limit=MAX_STREAM_BYTES)
                err = read_file(root, f"handoffs/{lane}/{symbol}/index-{index}.stderr", allow_empty=True, limit=MAX_STREAM_BYTES)
                status_file = read_file(root, f"handoffs/{lane}/{symbol}/index-{index}.exit-status", limit=32)
                try:
                    actual_status = int(status_file.decode("ascii").strip(), 10)
                except (UnicodeDecodeError, ValueError):
                    fail(f"{lane}/{symbol}/{index} process exit-status file is malformed")
                if actual_status != command["exitStatus"] or actual_status != PROCESS_STATUSES[index]:
                    fail(f"{lane}/{symbol}/{index} observed process status is not the exact expected target result")
                if record["processStatus"] != actual_status:
                    fail(f"{lane}/{symbol}/{index} handoff record/process status mismatch")
                if out or err:
                    fail(f"{lane}/{symbol}/{index} unexpectedly emitted stdout/stderr")
                validated["stdoutSha256"] = sha256_bytes(out)
                validated["stderrSha256"] = sha256_bytes(err)
                validated["handoffSha256"] = sha256_bytes(read_file(root, record_rel, limit=MAX_REPORT_BYTES))
                rows[lane][symbol].append(validated)
                command_stream_hashes = {"stdoutSha256": validated["stdoutSha256"], "stderrSha256": validated["stderrSha256"]}
                if not same_json(command.get("streams"), command_stream_hashes):
                    fail(f"{lane}/{symbol}/{index} command stream hashes differ from retained bytes")
    for symbol in ENTRY_SYMBOLS:
        for index in INDICES:
            source = rows["source"][symbol][index]
            transformed = rows["transformed"][symbol][index]
            if source["entryStatus"] != transformed["entryStatus"] or source["processStatus"] != transformed["processStatus"]:
                fail(f"source/transformed {symbol}/{index} behavior differs")
            if source["stdoutSha256"] != transformed["stdoutSha256"] or source["stderrSha256"] != transformed["stderrSha256"]:
                fail(f"source/transformed {symbol}/{index} streams differ")
    return rows


def _exact_root_files() -> set[str]:
    required = {
        "provider-image.so", "provider-fixture.S", "provider-object.o", "source-fixture.S", "consumer-object.o",
        "source-image.bin", "protected-image.bin", "protected-image.json", "producer-manifest.txt", "stage.json",
        "build-provenance.tar.gz", "host-context-external-provider-image-handoff",
        "host-context-external-provider-rollback-self-test", "producer.json", "producer.stderr", "native-image.bin", "native-image.json", "rehydration.json",
        "rehydration-command.json", "rehydration-command.stderr", "commands.json", "negative-provider-sha256.json",
        "negative-provider-sha256.stdout", "negative-provider-sha256.stderr", "negative-provider-sha256.exit-status",
        "negative-rehydration.json", "native-build.json", "runtime-identity.json",
        "runtime-files/libc.so.6", "runtime-files/ld-linux-aarch64.so.1", "provider-readelf.txt",
        "source-readelf.txt", "native-readelf.txt", "transformed-native-rollback.json",
        "transformed-native-rollback.stderr", "transformed-native-rollback.exit-status",
        "external-provider-evidence.json",
    }
    for lane in ("source", "transformed"):
        for symbol in ENTRY_SYMBOLS:
            for index in INDICES:
                base = f"handoffs/{lane}/{symbol}/index-{index}"
                required.update({f"{base}.json", f"{base}.stdout", f"{base}.stderr", f"{base}.exit-status"})
    return required


def _validate_root_integer_schemas(root: Path) -> None:
    versioned = (
        ("commands.json", "schemaVersion", 1),
        ("stage.json", "schemaVersion", 1),
        ("stage.json", "abiVersion", 1),
        ("protected-image.json", "schemaVersion", 1),
        ("protected-image.json", "abiVersion", 1),
        ("native-image.json", "schemaVersion", 1),
        ("native-image.json", "abiVersion", 1),
        ("rehydration.json", "schemaVersion", 1),
        ("rehydration.json", "abiVersion", 1),
        ("native-build.json", "schemaVersion", 1),
        ("negative-provider-sha256.json", "schemaVersion", 1),
        ("negative-rehydration.json", "schemaVersion", 1),
        ("negative-rehydration.json", "abiVersion", 1),
        ("transformed-native-rollback.json", "schemaVersion", 2),
    )
    for relative, field, expected in versioned:
        require_version(read_json(root, relative), field, expected, relative)

    commands = read_json(root, "commands.json")
    for command_name in ("producer", "rehydration", "wrongProviderSha256Rollback", "transformedNativeRollback"):
        command = commands.get(command_name)
        if not isinstance(command, dict):
            fail(f"commands.{command_name} must be an object")
        require_int(command.get("exitStatus"), f"commands.{command_name}.exitStatus")
    handoff_commands = commands.get("handoffs")
    if not isinstance(handoff_commands, list):
        fail("commands.handoffs must be a list")
    for command in handoff_commands:
        if not isinstance(command, dict):
            fail("commands.handoffs row must be an object")
        require_int(command.get("argumentIndex"), "commands.handoffs.argumentIndex")
        require_int(command.get("exitStatus"), "commands.handoffs.exitStatus")

    rehydration = read_json(root, "rehydration.json")
    require_int(rehydration.get("nativeImageSize"), "rehydration.nativeImageSize")
    require_int(rehydration.get("hostContextAbiVersion"), "rehydration.hostContextAbiVersion")
    require_int(rehydration.get("requiredCapabilities"), "rehydration.requiredCapabilities")
    layout = rehydration.get("layoutEvidence")
    if not isinstance(layout, dict):
        fail("rehydration record has no layout schema object")
    require_version(layout, "schemaVersion", 3, "rehydration.layoutEvidence")
    if require_int(layout.get("strategy"), "rehydration.layoutEvidence.strategy") != 3:
        fail("rehydration layout strategy ordinal differs from the fixture contract")
    require_int(layout.get("outputLength"), "rehydration.layoutEvidence.outputLength")
    for relative in ("native-image.json", "negative-rehydration.json"):
        record = read_json(root, relative)
        if require_int(record.get("requiredCapabilities"), f"{relative}.requiredCapabilities") != 11:
            fail(f"{relative}.requiredCapabilities ordinal differs from the HostContext fixture contract")
        if require_int(record.get("hostContextAbiVersion"), f"{relative}.hostContextAbiVersion") != 1:
            fail(f"{relative}.hostContextAbiVersion ordinal differs from the HostContext fixture contract")
    protected_role = read_json(root, "protected-image.json")
    require_int(protected_role.get("artifactSize"), "protected-image.json.artifactSize")
    native_role = read_json(root, "native-image.json")
    require_int(native_role.get("nativeImageSize"), "native-image.json.nativeImageSize")
    negative_witness = read_json(root, "negative-provider-sha256.json")
    require_int(negative_witness.get("exitStatus"), "negative-provider-sha256.exitStatus")
    transformed = read_json(root, "transformed-native-rollback.json")
    provider = transformed.get("provider")
    input_record = transformed.get("input")
    if not isinstance(provider, dict) or not isinstance(input_record, dict):
        fail("transformed-native-rollback provider/input integer schemas are malformed")
    require_int(provider.get("size"), "transformed-native-rollback.provider.size")
    require_int(input_record.get("nativeImageSize"), "transformed-native-rollback.input.nativeImageSize")
    baseline = transformed.get("baseline")
    if not isinstance(baseline, dict):
        fail("transformed-native-rollback.baseline must be an object")
    for field in ("nextImageHandle", "openDescriptorCount", "registeredImageCount"):
        require_int(baseline.get(field), f"transformed-native-rollback.baseline.{field}")
    failpoint = transformed.get("failpoint")
    if not isinstance(failpoint, dict):
        fail("transformed-native-rollback.failpoint must be an object")
    for field in ("providerAcquisitions", "consumerDlmopenSuccesses", "bindingVerifications", "reached"):
        require_int(failpoint.get(field), f"transformed-native-rollback.failpoint.{field}")
    for container_name, fields in (
        ("firstLoad", ("statusCode", "expectedFailureStatusCode", "publishedHandle", "memfdAttemptsDelta", "loaderAttemptsDelta",
            "providerTableAddress", "providerLoadBias", "consumerGotSlotAddress", "consumerGotValue", "consumerLoadBias")),
        ("retry", ("loadStatusCode", "memfdAttemptsDelta", "loaderAttemptsDelta", "providerTableAddress", "providerLoadBias",
            "consumerGotSlotAddress", "consumerGotValue", "consumerLoadBias", "entryLookupStatus", "observerLookupStatus", "entryStatus", "observerStatus")),
        ("release", ("statusCode",)),
    ):
        container = transformed.get(container_name)
        if not isinstance(container, dict):
            fail(f"transformed-native-rollback.{container_name} must be an object")
        for field in fields:
            require_int(container.get(field), f"transformed-native-rollback.{container_name}.{field}")
    for container_name in ("firstLoad.postCleanupState", "retry.activeState", "release.finalState"):
        first, second = container_name.split(".")
        state = transformed.get(first)
        if not isinstance(state, dict) or not isinstance(state.get(second), dict):
            fail(f"transformed-native-rollback.{container_name} must be an object")
        for field in ("activeProviderReferences", "nextImageHandle", "openDescriptorCount", "registeredImageCount", "registeredImageDescriptorCount"):
            require_int(state[second].get(field), f"transformed-native-rollback.{container_name}.{field}")
    counters = transformed.get("counters")
    if not isinstance(counters, dict):
        fail("transformed-native-rollback.counters must be an object")
    for field in ("memfdAttemptsBefore", "memfdAttemptsAfter", "loaderAttemptsBefore", "loaderAttemptsAfter"):
        require_int(counters.get(field), f"transformed-native-rollback.counters.{field}")
    cleanup = transformed.get("cleanup")
    if not isinstance(cleanup, dict):
        fail("transformed-native-rollback.cleanup must be an object")
    for field in ("consumerDlcloseResult", "consumerFdCloseResult", "providerReleaseStatus", "providerDlcloseResult",
        "providerFdCloseResult", "providerReleaseCallsAfterFailure", "consumerDlcloseCalls", "consumerFdCloseCalls"):
        require_int(cleanup.get(field), f"transformed-native-rollback.cleanup.{field}")
    for relative in ("producer.json", "rehydration-command.json"): 
        require_version(read_json(root, relative), "schemaVersion", 1, relative)
    for lane in ("source", "transformed"):
        for symbol in ENTRY_SYMBOLS:
            for index in INDICES:
                relative = f"handoffs/{lane}/{symbol}/index-{index}.json"
                require_version(read_json(root, relative), "schemaVersion", 1, relative)


def _decompress_provenance_gzip(raw: bytes) -> bytes:
    """Return one gzip member under a strict expanded-byte bound."""
    if not raw or len(raw) > MAX_PROVENANCE_BYTES:
        fail("retained build provenance compressed stream is empty or oversized")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = bytearray()
    try:
        for start in range(0, len(raw), 64 * 1024):
            pending = raw[start : start + 64 * 1024]
            while pending:
                if decoder.eof:
                    fail("retained build provenance gzip has trailing bytes or concatenated members")
                remaining = MAX_PROVENANCE_EXPANDED_BYTES + 1 - len(expanded)
                if remaining <= 0:
                    fail(f"retained build provenance expanded tar exceeds its {MAX_PROVENANCE_EXPANDED_BYTES}-byte bound")
                before = len(pending)
                chunk = decoder.decompress(pending, min(remaining, 64 * 1024))
                expanded.extend(chunk)
                if len(expanded) > MAX_PROVENANCE_EXPANDED_BYTES:
                    fail(f"retained build provenance expanded tar exceeds its {MAX_PROVENANCE_EXPANDED_BYTES}-byte bound")
                if decoder.unused_data:
                    fail("retained build provenance gzip has trailing bytes or concatenated members")
                pending = decoder.unconsumed_tail
                if pending and len(pending) == before and not chunk:
                    fail("retained build provenance gzip decoder made no bounded progress")
            if decoder.eof and start + 64 * 1024 < len(raw):
                fail("retained build provenance gzip has trailing bytes or concatenated members")
    except zlib.error as error:
        fail(f"retained build provenance gzip is malformed: {error}")
    if not decoder.eof:
        fail("retained build provenance gzip is truncated or malformed")
    if decoder.unused_data:
        fail("retained build provenance gzip has trailing bytes or concatenated members")
    return bytes(expanded)


def _parse_tar_octal(field: bytes, label: str) -> int:
    if field and field[0] & 0x80:
        fail(f"retained build provenance has unsupported base-256 {label}")
    digits = field.strip(b"\0 ")
    if not digits:
        return 0
    if any(value < ord("0") or value > ord("7") for value in digits):
        fail(f"retained build provenance has malformed octal {label}")
    return int(digits, 8)


def _scan_provenance_pax(payload: bytes, label: str) -> int:
    if len(payload) > MAX_PROVENANCE_PAX_HEADER_BYTES:
        fail(f"retained build provenance {label} exceeds the per-header metadata bound")
    offset = 0
    count = 0
    seen: set[bytes] = set()
    while offset < len(payload):
        separator = payload.find(b" ", offset)
        if separator <= offset:
            fail(f"retained build provenance {label} has malformed PAX record length")
        length_bytes = payload[offset:separator]
        if not length_bytes.isdigit() or len(length_bytes) > 5:
            fail(f"retained build provenance {label} has malformed PAX record length")
        record_length = int(length_bytes)
        record_end = offset + record_length
        if record_length <= separator - offset + 2 or record_end > len(payload) or payload[record_end - 1] != 0x0A:
            fail(f"retained build provenance {label} has a truncated PAX record")
        record = payload[separator + 1 : record_end - 1]
        equals = record.find(b"=")
        if equals <= 0:
            fail(f"retained build provenance {label} has a malformed PAX key/value")
        key = record[:equals]
        value = record[equals + 1 :]
        if key not in {b"mtime", b"atime", b"ctime"} or key in seen:
            fail(f"retained build provenance {label} has an unsupported or duplicate PAX key")
        if not value or re.fullmatch(rb"-?[0-9]+(?:\.[0-9]+)?", value) is None:
            fail(f"retained build provenance {label} has a malformed PAX timestamp")
        seen.add(key)
        count += 1
        if count > MAX_PROVENANCE_PAX_RECORDS_PER_HEADER:
            fail(f"retained build provenance {label} has too many PAX metadata records")
        offset = record_end
    return count


def _scan_provenance_tar(data: bytes) -> None:
    """Bound every tar header/extension before tarfile parses or materializes it."""
    if not data or len(data) > MAX_PROVENANCE_EXPANDED_BYTES:
        fail("retained build provenance expanded tar is empty or oversized")
    offset = 0
    header_count = 0
    member_count = 0
    extension_count = 0
    metadata_total = 0
    pending_pax = False
    zero_block = bytes(512)
    while offset <= len(data) - 512:
        header = data[offset : offset + 512]
        if header == zero_block:
            end_mark = offset + 1024
            if end_mark > len(data) or data[offset + 512 : end_mark] != zero_block:
                fail("retained build provenance tar has a truncated end marker")
            if any(data[end_mark:]):
                fail("retained build provenance tar has nonzero bytes after its end marker")
            if pending_pax:
                fail("retained build provenance tar ends with an unpaired PAX extension header")
            if member_count != MAX_PROVENANCE_MEMBERS:
                fail("retained build provenance tar has an unexpected member count")
            return

        header_count += 1
        if header_count > MAX_PROVENANCE_TAR_HEADERS:
            fail("retained build provenance tar has too many header records")
        size = _parse_tar_octal(header[124:136], "member size")
        payload_start = offset + 512
        payload_end = payload_start + size
        padded_end = payload_start + ((size + 511) // 512) * 512
        if payload_end > len(data) or padded_end > len(data):
            fail("retained build provenance tar has a truncated member payload")
        member_type = header[156:157]
        if member_type == b"x":
            if pending_pax:
                fail("retained build provenance tar has repeated hidden PAX extension headers")
            extension_count += 1
            if extension_count > MAX_PROVENANCE_EXTENSION_HEADERS:
                fail("retained build provenance tar has too many extension headers")
            metadata_total += size
            if size > MAX_PROVENANCE_PAX_HEADER_BYTES or metadata_total > MAX_PROVENANCE_PAX_TOTAL_BYTES:
                fail("retained build provenance tar exceeds its PAX metadata byte bound")
            _scan_provenance_pax(data[payload_start:payload_end], "PAX header")
            pending_pax = True
        elif member_type in (b"0", b"\0"):
            pending_pax = False
            member_count += 1
            if member_count > MAX_PROVENANCE_MEMBERS:
                fail("retained build provenance tar has too many members")
            if size > MAX_PROVENANCE_MEMBER_BYTES:
                fail("retained build provenance tar member exceeds its byte bound")
        else:
            fail("retained build provenance tar contains a non-regular or unsupported header type")
        offset = padded_end
    fail("retained build provenance tar is truncated or has no bounded end marker")


def _read_build_provenance_bundle(root: Path) -> dict[str, bytes]:
    raw = read_file(root, "build-provenance.tar.gz", limit=MAX_PROVENANCE_BYTES)
    expanded = _decompress_provenance_gzip(raw)
    _scan_provenance_tar(expanded)
    retained: dict[str, bytes] = {}
    total = 0
    try:
        # The gzip stream has already been fully snapshotted and bounded; do not
        # let tarfile decompress or buffer an extension before our header scan.
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_PROVENANCE_MEMBERS:
                    fail("retained build provenance bundle has too many members")
                name = safe_relative(member.name, "build provenance member").as_posix()
                if name not in BUILD_PROVENANCE_FILES or name in retained:
                    fail(f"retained build provenance bundle has an unexpected/duplicate member: {name}")
                if not member.isfile() or member.size < 0 or member.size > MAX_PROVENANCE_MEMBER_BYTES:
                    fail(f"retained build provenance member is not a bounded regular file: {name}")
                total += member.size
                if total > MAX_PROVENANCE_EXPANDED_BYTES:
                    fail("retained build provenance bundle exceeds its aggregate member-byte bound")
                stream = archive.extractfile(member)
                if stream is None:
                    fail(f"retained build provenance member cannot be read: {name}")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    fail(f"retained build provenance member changed size or is truncated: {name}")
                retained[name] = data
    except (tarfile.TarError, OSError, EOFError, ValueError) as error:
        fail(f"cannot safely read retained build provenance bundle: {error}")
    if set(retained) != BUILD_PROVENANCE_FILES:
        fail(f"retained build provenance bundle is not closed (missing={sorted(BUILD_PROVENANCE_FILES - set(retained))})")
    return retained


def _check_build_provenance(root: Path, build_record: dict[str, Any], commands: dict[str, Any], provider: dict[str, Any], source_sha: str) -> dict[str, Any]:
    require_version(build_record, "schemaVersion", 1, "native-build.json")
    retained = _read_build_provenance_bundle(root)
    if build_record.get("buildCommand") != NATIVE_BUILD_COMMAND:
        fail("native build record does not bind the exact forced provider-fixture build command")
    if build_record.get("managedBuildCommand") != MANAGED_BUILD_COMMAND:
        fail("managed build record does not bind the exact Release solution build command")
    bindings = {
        "makefileSha256": "build-inputs/Makefile",
        "providerAssemblySha256": "provider-fixture.S",
        "providerObjectSha256": "provider-object.o",
        "consumerAssemblySha256": "source-fixture.S",
        "consumerObjectSha256": "consumer-object.o",
        "helperSourceSha256": "build-inputs/host_context_external_provider_image_handoff.c",
        "helperBinarySha256": "host-context-external-provider-image-handoff",
        "rollbackHelperSourceSha256": "build-inputs/host_context_external_provider_self_test.c",
        "rollbackTestHeaderSha256": "build-inputs/host_adapter_provider_rollback_test.h",
        "rollbackHelperBinarySha256": "host-context-external-provider-rollback-self-test",
        "rollbackAdapterObjectSha256": "rollback-host-adapter.o",
        "rollbackHostImageValidationTestObjectSha256": "rollback-host-image-validation-test.o",
        "hostAdapterSourceSha256": "build-inputs/host_adapter.c",
        "hostImageValidationSourceSha256": "build-inputs/host_image_validation.c",
        "hostImageValidationHeaderSha256": "build-inputs/host_image_validation.h",
        "androidPackedRelocationTagsSha256": "build-inputs/android_packed_relocation_tags.h",
        "hostAdapterHeaderSha256": "build-inputs/include/urp/host_adapter.h",
        "hostContextHeaderSha256": "build-inputs/include/urp/host_context.h",
        "sha256SourceSha256": "build-inputs/sha256.c",
        "sha256HeaderSha256": "build-inputs/sha256.h",
        "hostAdapterObjectSha256": "host-adapter.o",
        "hostImageValidationObjectSha256": "host-image-validation.o",
        "sha256ObjectSha256": "sha256.o",
    }
    for field, relative in bindings.items():
        data = retained[relative] if relative in retained else read_file(root, relative)
        actual = sha256_bytes(data)
        if build_record.get(field) != actual:
            fail(f"native build {field} does not bind retained bytes for {relative}")
    evidence_tools = build_record.get("evidenceTools")
    if not isinstance(evidence_tools, dict) or set(evidence_tools) != set(EVIDENCE_TOOL_FILES):
        fail("native build record does not bind the exact provider/rollback evidence tool inventory")
    for field, relative in EVIDENCE_TOOL_FILES.items():
        if evidence_tools.get(field) != sha256_bytes(retained[relative]):
            fail(f"native build {field} does not bind retained evidence tool source {relative}")
    if build_record.get("providerImageSha256") != provider["sha256"] or build_record.get("sourceConsumerSha256") != source_sha:
        fail("native build record does not bind measured provider/source ELF outputs")
    if build_record.get("providerImageSha256") != provider["sha256"]:
        fail("native build provider output identity differs from parsed provider bytes")

    native_stdout = retained["native-build.stdout"]
    native_stderr = retained["native-build.stderr"]
    managed_stdout = retained["managed-build.stdout"]
    managed_stderr = retained["managed-build.stderr"]
    if any(len(stream) > MAX_REPORT_BYTES for stream in (native_stdout, native_stderr, managed_stdout, managed_stderr)):
        fail("retained native/managed build output exceeds its parser bound")
    if build_record.get("nativeBuildStdoutSha256") != sha256_bytes(native_stdout) or build_record.get("nativeBuildStderrSha256") != sha256_bytes(native_stderr):
        fail("native build record does not bind the retained actual make command output")
    if build_record.get("managedBuildStdoutSha256") != sha256_bytes(managed_stdout) or build_record.get("managedBuildStderrSha256") != sha256_bytes(managed_stderr):
        fail("managed build record does not bind the retained Release build output")
    for name, stdout, stderr in (("nativeBuild", native_stdout, native_stderr), ("managedBuild", managed_stdout, managed_stderr)):
        command = commands[name]
        if command.get("stdoutSha256") != sha256_bytes(stdout) or command.get("stderrSha256") != sha256_bytes(stderr):
            fail(f"{name} command record does not bind its retained stdout/stderr bytes")

    toolchain = build_record.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("native build record has no retained toolchain identity")
    version_paths = {
        "ccVersionLine": "toolchain/cc-version.txt",
        "assemblerVersionLine": "toolchain/as-version.txt",
        "linkerVersionLine": "toolchain/ld-version.txt",
    }
    version_lines: dict[str, str] = {}
    for field, relative in version_paths.items():
        raw = retained[relative]
        if len(raw) > 64 * 1024:
            fail(f"retained tool version output exceeds its parser bound: {relative}")
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            fail(f"retained tool version output is not UTF-8: {relative}")
        if not lines or not lines[0]:
            fail(f"retained tool version output is empty: {relative}")
        version_lines[field] = lines[0]
        if toolchain.get(field) != lines[0]:
            fail(f"native tool identity claim {field} differs from its retained version bytes")
    tool_binaries = {
        "ccDriverSha256": "toolchain/cc-driver",
        "cc1Sha256": "toolchain/cc1",
        "assemblerSha256": "toolchain/as",
        "linkerSha256": "toolchain/ld",
    }
    for field, relative in tool_binaries.items():
        if toolchain.get(field) != sha256_bytes(retained[relative]):
            fail(f"native tool identity claim {field} does not bind retained executable bytes")
    target_raw = retained["toolchain/target-triple.txt"]
    if len(target_raw) > 4096:
        fail("retained compiler target triple exceeds its parser bound")
    try:
        target_triple = target_raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        fail("retained compiler target triple is not ASCII")
    if target_triple != "aarch64-linux-gnu" or toolchain.get("targetTriple") != target_triple:
        fail("retained C compiler target identity is not native AArch64 GNU/Linux")
    if toolchain.get("cppFlags") != CPP_FLAGS or toolchain.get("cFlags") != C_FLAGS:
        fail("native C compiler flags differ from the bounded provider-helper contract")

    try:
        rows = native_stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        fail("retained native build command log is not UTF-8")
    parsed_rows: list[list[str]] = []
    for row in rows:
        try:
            parsed_rows.append(shlex.split(row))
        except ValueError:
            continue
    def one_command(predicate, expected: list[str], label: str) -> None:
        matches = [row for row in parsed_rows if predicate(row)]
        if matches != [expected]:
            fail(f"retained make output does not bind the exact {label} compiler/linker command and flags")
    one_command(lambda row: "host_context_external_provider_image_handoff.c" in row, [
        "cc", *CPP_FLAGS, *C_FLAGS, "host_context_external_provider_image_handoff.c",
        "build/host_adapter.o", "build/host_image_validation.o", "build/sha256.o", "-ldl", "-pthread",
        "-o", "build/host-context-external-provider-image-handoff",
    ], "provider handoff C")
    one_command(lambda row: row and row[-1] == "host_context_external_provider_fixture.S" and "build/host-context-external-provider-fixture.S.o" in row,
        ["as", "-o", "build/host-context-external-provider-fixture.S.o", "host_context_external_provider_fixture.S"],
        "provider fixture assembler")
    one_command(lambda row: row and row[-1] == "host_context_external_provider_consumer_fixture.S",
        ["as", "-o", "build/host-context-external-provider-consumer-fixture.S.o", "host_context_external_provider_consumer_fixture.S"],
        "consumer fixture assembler")
    one_command(lambda row: "host_adapter.c" in row and "-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1" in row and "-DURP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT=1" not in row,
        ["cc", *CPP_FLAGS, *C_FLAGS, "-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1", "-c", "host_adapter.c", "-o", "build/host_adapter.o"],
        "production host adapter compiler")
    one_command(lambda row: "host_adapter.c" in row and "-DURP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT=1" in row,
        ["cc", *CPP_FLAGS, *C_FLAGS, "-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1", "-DURP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT=1", "-c", "host_adapter.c", "-o", "build/host_adapter_provider_rollback_test.o"],
        "test-only rollback host adapter compiler")
    one_command(lambda row: "host_image_validation.c" in row and "-c" in row and "-o" in row and "-DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1" not in row,
        ["cc", *CPP_FLAGS, *C_FLAGS, "-c", "host_image_validation.c", "-o", "build/host_image_validation.o"],
        "ELF/provider parser compiler")
    one_command(lambda row: "host_image_validation.c" in row and "-DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1" in row,
        ["cc", *CPP_FLAGS, *C_FLAGS, "-DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1", "-c", "host_image_validation.c", "-o", "build/host_image_validation_test.o"],
        "test-only provider parser compiler")
    one_command(lambda row: "host_context_external_provider_self_test.c" in row,
        ["cc", *CPP_FLAGS, *C_FLAGS, "-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1", "-DURP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT=1", "-DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1", "host_context_external_provider_self_test.c", "build/host_adapter_provider_rollback_test.o", "build/host_image_validation_test.o", "build/sha256.o", "-ldl", "-pthread", "-o", "build/host-context-external-provider-rollback-self-test"],
        "transformed Native Image rollback oracle linker")
    one_command(lambda row: "../urprotect-launcher/sha256.c" in row and "build/sha256.o" in row,
        ["cc", *CPP_FLAGS, *C_FLAGS, "-c", "../urprotect-launcher/sha256.c", "-o", "build/sha256.o"],
        "SHA-256 object compiler")
    one_command(lambda row: "-soname" in row and "liburprotect-jump-table-provider.so.1" in row and "build/liburprotect-jump-table-provider.so.1" in row,
        ["ld", "-shared", "-z", "separate-code", "--build-id=sha1", "--hash-style=gnu", "-soname",
         "liburprotect-jump-table-provider.so.1", "build/host-context-external-provider-fixture.S.o", "-o",
         "build/liburprotect-jump-table-provider.so.1"], "provider linker")
    one_command(lambda row: "-l:liburprotect-jump-table-provider.so.1" in row and "build/host-context-external-provider-consumer.so" in row,
        ["ld", "-shared", "--build-id=none", "--hash-style=gnu", "--no-undefined", "-z", "now",
         "build/host-context-external-provider-consumer-fixture.S.o", "-Lbuild", "-l:liburprotect-jump-table-provider.so.1",
         "-o", "build/host-context-external-provider-consumer.so"], "consumer linker")

    managed = build_record.get("managedBuild")
    if not isinstance(managed, dict):
        fail("native build record does not retain managed CLI/Core assembly identities")
    cli_sha = sha256_bytes(retained["managed-build/urprotect.dll"])
    core_sha = sha256_bytes(retained["managed-build/UrProtect.Core.dll"])
    if managed.get("cliAssemblySha256") != cli_sha or managed.get("coreAssemblySha256") != core_sha:
        fail("managed executable identity claim does not bind retained CLI/Core assembly bytes")
    if (
        commands.get("managedCliSha256") != cli_sha
        or commands.get("producerBuildSha256") != core_sha
        or commands.get("consumerBuildSha256") != core_sha
        or managed.get("producerBuildSha256") != core_sha
        or managed.get("consumerBuildSha256") != core_sha
    ):
        fail("producer/rehydrator executable identities do not match retained managed CLI/Core bytes")
    dotnet_version = retained["managed-build/dotnet-version.txt"]
    if len(dotnet_version) > 4096:
        fail("retained managed tool version output exceeds its parser bound")
    try:
        dotnet_version_text = dotnet_version.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        fail("retained managed tool identity is not ASCII")
    if not dotnet_version_text or managed.get("dotnetVersion") != dotnet_version_text:
        fail("managed build identity does not match the retained dotnet --version output")
    return {
        "nativeBuildCommand": NATIVE_BUILD_COMMAND,
        "managedBuildCommand": MANAGED_BUILD_COMMAND,
        "makefileSha256": bindings["makefileSha256"],
        "retainedBundleSha256": sha256_bytes(read_file(root, "build-provenance.tar.gz", limit=MAX_PROVENANCE_BYTES)),
        "helperSourceSha256": build_record["helperSourceSha256"],
        "helperBinarySha256": build_record["helperBinarySha256"],
        "adapterParserSourceSha256": build_record["hostAdapterSourceSha256"],
        "nativeBuildLogSha256": sha256_bytes(native_stdout),
        "cCompilerVersion": version_lines["ccVersionLine"],
        "assemblerVersion": version_lines["assemblerVersionLine"],
        "linkerVersion": version_lines["linkerVersionLine"],
        "targetTriple": target_triple,
        "cFlags": C_FLAGS,
        "cppFlags": CPP_FLAGS,
        "evidenceTools": {
            field: sha256_bytes(retained[relative])
            for field, relative in EVIDENCE_TOOL_FILES.items()
        },
        "managedCliAssemblySha256": cli_sha,
        "managedCoreAssemblySha256": core_sha,
        "provenanceTrustBoundary": "retained-byte hashes bind recorded identities; they are not a cryptographic build attestation",
    }


def _matching_root_snapshot(root: Path) -> Any | None:
    snapshot = _ACTIVE_ROOT_SNAPSHOT or sys.modules.get(_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY)
    if snapshot is not None and Path(os.path.abspath(snapshot.root)) == Path(os.path.abspath(root)):
        return snapshot
    return None


def _build_report_from_snapshot(root: Path) -> dict[str, Any]:
    if root.name != UNIT_ID:
        fail(f"evidence root basename must be exact unit id {UNIT_ID}")
    snapshot = _matching_root_snapshot(root)
    if snapshot is None or not snapshot._preflighted:
        fail("external-provider report requires a bounded root snapshot")
    actual_files = snapshot.file_paths - {"SHA256SUMS", "external-provider-evidence.json"}
    required = _exact_root_files()
    # The report is an output of this recomputation and is excluded from the
    # semantic input comparison whether absent (sealing) or already retained.
    required.remove("external-provider-evidence.json")
    expected_directories = _expected_root_directories(_exact_root_files())
    actual_directories = snapshot.directory_paths
    if actual_directories != expected_directories:
        fail(f"evidence directory set is not exact (missing={sorted(expected_directories - actual_directories)}, extra={sorted(actual_directories - expected_directories)})")
    if actual_files != required:
        fail(f"evidence root file set is not exact (missing={sorted(required - actual_files)}, extra={sorted(actual_files - required)})")
    _validate_root_integer_schemas(root)

    provider_data = read_file(root, "provider-image.so", limit=MAX_PROVIDER_BYTES)
    source_data = read_file(root, "source-image.bin")
    protected_data = read_file(root, "protected-image.bin")
    native_data = read_file(root, "native-image.bin")
    provider = parse_provider(provider_data)
    source_sha = sha256_bytes(source_data)
    protected_sha = sha256_bytes(protected_data)
    native_sha = sha256_bytes(native_data)
    if provider["soname"] != PROVIDER_SONAME or not HEX_BUILD_ID.fullmatch(provider["buildId"]):
        fail("provider identity is not the configured fixture")
    source_facts = parse_consumer(source_data, "source consumer", require_source_dispatch=True)
    native_facts = parse_consumer(native_data, "Native Image consumer", require_source_dispatch=False)
    rehydration = read_json(root, "rehydration.json")
    layout = rehydration.get("layoutEvidence")
    if not isinstance(layout, dict):
        fail("rehydration record has no physical selected-function output mapping")
    native_facts["liveDispatch"] = _decode_native_provider_dispatch(native_data, source_facts, native_facts, layout)
    if (
        not same_json(source_facts["dynamicNeeded"], native_facts["dynamicNeeded"])
        or not same_json(source_facts["importSymbol"], native_facts["importSymbol"])
        or not same_json(source_facts["relocation"], native_facts["relocation"])
        or not same_json(source_facts["got"], native_facts["got"])
    ):
        fail("Native Image changed the exact external provider dynsym/GLOB_DAT/GOT source binding")
    if not same_json(source_facts["functions"]["urp_observer"], native_facts["functions"]["urp_observer"]):
        fail("unselected urp_observer dynamic symbol identity/address/size changed in Native Image")
    observer_source = source_data[source_facts["functions"]["urp_observer"]["fileOffset"] : source_facts["functions"]["urp_observer"]["fileOffset"] + source_facts["functions"]["urp_observer"]["size"]]
    observer_native = native_data[native_facts["functions"]["urp_observer"]["fileOffset"] : native_facts["functions"]["urp_observer"]["fileOffset"] + native_facts["functions"]["urp_observer"]["size"]]
    if observer_source != observer_native:
        fail("unselected urp_observer instruction bytes no longer preserve the source provider dispatch")
    if source_sha == native_sha or protected_sha in {source_sha, native_sha}:
        fail("source, Protected Image, and Native Image do not have distinct expected identities")

    runtime = verify_runtime(root)
    commands = read_json(root, "commands.json")
    _check_commands(root, commands, provider, runtime, source_sha)
    selected_function = commands.get("selectedFunction")
    if selected_function != source_facts["sourceDispatch"]["selectedFunction"]["selector"]:
        fail("producer selector does not match independently parsed selected urp_entry dynsym")
    if not isinstance(commands.get("requestSha256"), str) or not DIGEST.fullmatch(commands["requestSha256"]):
        fail("producer request SHA-256 is malformed")
    for field in ("producerBuildSha256", "consumerBuildSha256"):
        if not isinstance(commands.get(field), str) or not DIGEST.fullmatch(commands[field]):
            fail(f"commands.json {field} is malformed")
    if commands.get("actualProducerId") != PRODUCER_ID:
        fail("actual producer role does not name the expected producer")
    if commands.get("wrongProviderSha256") == provider["sha256"] or not isinstance(commands.get("wrongProviderSha256"), str) or not DIGEST.fullmatch(commands["wrongProviderSha256"]):
        fail("negative provider pin is not a distinct normalized SHA-256")

    stage = _require_role(root, "stage.json", "protected-image-producer", UNIT_ID)
    protected_role = read_json(root, "protected-image.json")
    native_role = read_json(root, "native-image.json")
    producer_output = read_json(root, "producer.json")
    rehydration_output = read_json(root, "rehydration-command.json")
    for output_name, output_record in (("producer.json", producer_output), ("rehydration-command.json", rehydration_output)):
        if "schemaVersion" in output_record:
            require_version(output_record, "schemaVersion", 1, output_name)
    if producer_output.get("success") is not True or not same_json(producer_output.get("role"), protected_role) or not same_json(producer_output.get("stage"), stage):
        fail("protect-image command stdout does not bind the retained Protected Image role/stage")
    if rehydration_output.get("success") is not True or not same_json(rehydration_output.get("record"), rehydration):
        fail("rehydrate-image command stdout does not bind the retained successful record")
    if (
        stage.get("producerId") != PRODUCER_ID
        or stage.get("sourceSha256") != source_sha
        or stage.get("requestSha256") != commands["requestSha256"]
        or stage.get("artifactSha256") != protected_sha
        or stage.get("rehydratorConsumerId") != "urprotect.rehydrator.v1"
        or type(stage.get("publicationComplete")) is not bool
        or stage["publicationComplete"] is not True
    ):
        fail("producer stage does not bind the retained source/request/artifact and completed publication")
    require_version(protected_role, "schemaVersion", 1, "protected-image.json")
    require_version(protected_role, "abiVersion", 1, "protected-image.json")
    if (
        protected_role.get("artifactRole") != "protected-image"
        or protected_role.get("unitId") != UNIT_ID
        or protected_role.get("profile") != "host-context-entry"
        or protected_role.get("sourceSha256") != source_sha
        or protected_role.get("artifactSha256") != protected_sha
        or require_int(protected_role.get("artifactSize"), "Protected Image artifactSize") != len(protected_data)
        or protected_role.get("requestSha256") != commands["requestSha256"]
        or protected_role.get("producerId") != PRODUCER_ID
        or protected_role.get("producerBuildSha256") != commands["producerBuildSha256"]
        or protected_role.get("rehydratorConsumerId") != "urprotect.rehydrator.v1"
        or protected_role.get("selectors") != [f"table=dynsym, index={source_facts['sourceDispatch']['selectedFunction']['symbolIndex']}"]
        or protected_role.get("passes") != ["control-flow-flattening"]
    ):
        fail("Protected Image role does not bind the retained source/request/provider-selected producer artifact")
    require_version(native_role, "schemaVersion", 1, "native-image.json")
    require_version(native_role, "abiVersion", 1, "native-image.json")
    if require_int(native_role.get("requiredCapabilities"), "Native Image requiredCapabilities") != 11:
        fail("Native Image requiredCapabilities ordinal differs from the HostContext fixture contract")
    if (
        native_role.get("artifactRole") != "native-image"
        or native_role.get("unitId") != UNIT_ID
        or native_role.get("profile") != "host-context-entry"
        or native_role.get("sourceSha256") != source_sha
        or native_role.get("protectedImageSha256") != protected_sha
        or native_role.get("nativeImageSha256") != native_sha
        or require_int(native_role.get("nativeImageSize"), "Native Image nativeImageSize") != len(native_data)
        or native_role.get("producerId") != PRODUCER_ID
        or native_role.get("producerBuildSha256") != commands["producerBuildSha256"]
        or native_role.get("consumerId") != "urprotect.rehydrator.v1"
        or native_role.get("consumerBuildSha256") != commands["consumerBuildSha256"]
        or native_role.get("rehydrationRecordSha256") != sha256_bytes(read_file(root, "rehydration.json"))
    ):
        fail("Native Image role does not bind the retained source/Protected Image/rehydration/build identities")
    require_version(rehydration, "schemaVersion", 1, "rehydration.json")
    require_version(rehydration, "abiVersion", 1, "rehydration.json")
    if require_int(rehydration.get("hostContextAbiVersion"), "rehydration hostContextAbiVersion") != 1:
        fail("rehydration HostContext ABI ordinal differs from the fixture contract")
    if require_int(rehydration.get("requiredCapabilities"), "rehydration requiredCapabilities") != 11:
        fail("rehydration requiredCapabilities ordinal differs from the fixture contract")
    layout = rehydration.get("layoutEvidence")
    if (
        rehydration.get("status") != "passed"
        or rehydration.get("stage") != "rehydration"
        or rehydration.get("unitId") != UNIT_ID
        or rehydration.get("profile") != "host-context-entry"
        or rehydration.get("sourceSha256") != source_sha
        or rehydration.get("protectedImageSha256") != protected_sha
        or rehydration.get("nativeImageSha256") != native_sha
        or require_int(rehydration.get("nativeImageSize"), "rehydration nativeImageSize") != len(native_data)
        or rehydration.get("requestSha256") != commands["requestSha256"]
        or rehydration.get("producerId") != PRODUCER_ID
        or rehydration.get("producerBuildSha256") != commands["producerBuildSha256"]
        or rehydration.get("consumerId") != "urprotect.rehydrator.v1"
        or rehydration.get("consumerBuildSha256") != commands["consumerBuildSha256"]
        or not isinstance(layout, dict)
        or require_int(layout.get("schemaVersion"), "layoutEvidence.schemaVersion") != 3
        or layout.get("outputSha256") != native_sha
        or layout.get("sourceSha256") != source_sha
        or require_int(layout.get("outputLength"), "layout outputLength") != len(native_data)
    ):
        fail("rehydration record/layout does not bind the retained source/Protected/Native Image chain")
    _check_producer_manifest(root, protected_sha)
    provider_path = str((root / "provider-image.so").resolve())
    for record_name, record in (("protected-image.json", protected_role), ("native-image.json", native_role), ("rehydration.json", rehydration)):
        encoded = canonical(record).lower()
        if (
            b"provider-file" in encoded
            or b"providerpath" in encoded
            or b"provider-path" in encoded
            or provider_path.encode("utf-8").lower() in encoded
        ):
            fail(f"{record_name} serializes host provider-path configuration")
    provider_path = str((root / "provider-image.so").resolve())
    if provider_path.encode() in protected_data or str(root.resolve()).encode() in protected_data:
        fail("Protected Image bytes serialize an absolute provider or evidence-root path")
    if b"provider-file" in protected_data or provider_path.encode() in native_data:
        fail("Protected/Native Image bytes serialize provider host configuration")
    for relative in ("provider-readelf.txt", "source-readelf.txt", "native-readelf.txt"):
        read_file(root, relative, limit=MAX_REPORT_BYTES)
    build_record = read_json(root, "native-build.json")
    build_provenance = _check_build_provenance(root, build_record, commands, provider, source_sha)

    handoffs = _walk_handoffs(root, commands, provider, source_facts, native_facts, source_sha, native_sha)
    rollback = _check_negative(root, commands, provider)
    transformed_rollback = _check_transformed_native_rollback(
        root, commands, provider, source_facts, native_facts, source_sha, protected_sha, native_sha, runtime)
    return {
        "schemaVersion": 1,
        "unitId": UNIT_ID,
        "acceptanceState": "scoped-observation-not-promoted",
        "producerId": PRODUCER_ID,
        "execution": {
            "architecture": runtime["architecture"],
            "runtime": runtime["runtime"],
            "glibcVersion": runtime["version"],
            "emulated": False,
            "invocation": "direct-native-exec",
            "runtimeIdentitySha256": runtime["identitySha256"],
        },
        "artifacts": {
            "sourceSha256": source_sha,
            "protectedImageSha256": protected_sha,
            "nativeImageSha256": native_sha,
            "providerSha256": provider["sha256"],
            "providerBuildId": provider["buildId"],
        },
        "providerFacts": provider,
        "sourceElfFacts": source_facts,
        "nativeElfFacts": native_facts,
        "buildProvenance": build_provenance,
        "observerSourceBinding": {
            "symbol": "urp_observer",
            "symbolIdentity": source_facts["functions"]["urp_observer"],
            "instructionBytesSha256": source_facts["functions"]["urp_observer"]["bytesSha256"],
            "providerImport": source_facts["importSymbol"],
            "providerRelocation": source_facts["relocation"],
            "got": source_facts["got"],
            "sourceNativeBytesEqual": True,
        },
        "selectedFunction": selected_function,
        "producerRequestSha256": commands["requestSha256"],
        "producerBuildSha256": commands["producerBuildSha256"],
        "consumerBuildSha256": commands["consumerBuildSha256"],
        "handoffs": handoffs,
        "rollbackNegative": rollback,
        "transformedNativeRollback": transformed_rollback,
    }


def build_report(root: Path) -> dict[str, Any]:
    snapshot = _matching_root_snapshot(root)
    if snapshot is not None:
        return _build_report_from_snapshot(root)
    snapshot = _precheck_tree_bounds(root)
    with _using_root_snapshot(snapshot):
        return _build_report_from_snapshot(root)


def _precheck_tree_bounds(root: Path):
    snapshot = _new_root_snapshot(root, exact_inventory=True)
    snapshot.preflight()
    return snapshot


def validate_root(root: Path, *, write_report: bool) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        fail("evidence root is missing, unsafe, or not a directory")
    snapshot = _precheck_tree_bounds(root)
    with _using_root_snapshot(snapshot):
        report = build_report(root)
        if write_report:
            snapshot.verify_tree_unchanged()
            report_bytes = (json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            if len(report_bytes) > MAX_REPORT_BYTES:
                fail("external-provider report exceeds its byte bound")
            _write_root_file(root, "external-provider-evidence.json", report_bytes)
            write_closed_manifest(root)
        else:
            check_closed_manifest(root, snapshot=snapshot)
            claim = read_json(root, "external-provider-evidence.json")
            if not same_json(claim, report):
                fail("external-provider-evidence.json differs from independently recomputed facts")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write-report", action="store_true", help="write recomputed report and closed SHA256SUMS")
    args = parser.parse_args()
    report = validate_root(args.root, write_report=args.write_report)
    print(f"external-provider evidence: PASS ({report['unitId']}; {report['execution']['architecture']} {report['execution']['glibcVersion']}; acceptance not promoted)")


if __name__ == "__main__":
    main()
