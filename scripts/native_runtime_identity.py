"""Strict evidence-only validation for the native HostContext runtime carrier.

This module reads only fixed relative files beneath a closed evidence root. It
is deliberately not an attestation mechanism: it checks that native self-
reported mappings agree with the retained ELF and proc-maps bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
from pathlib import Path, PurePosixPath
from typing import Any

DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_MAPS_BYTES = 1024 * 1024
MAX_MAP_LINE_BYTES = 8192
MAX_RUNTIME_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
MAX_IDENTITY_BYTES = 16 * 1024
MAX_ELF_PROGRAM_HEADERS = 4096
MAX_U64 = (1 << 64) - 1


def _fail(message: str) -> None:
    raise ValueError(message)


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail(f"{label} is not a safe relative path")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or len(candidate.parts) > 8
    ):
        _fail(f"{label} is not a safe relative path")
    return value


def _read_root_file(root: Path, relative: str, maximum: int) -> bytes:
    _safe_relative(relative, "runtime identity file")
    absolute = Path(os.path.abspath(root))
    try:
        if absolute.resolve(strict=True) != absolute:
            _fail("runtime identity root is not a real isolated directory")
    except (OSError, RuntimeError) as error:
        raise ValueError("runtime identity root cannot be resolved") from error
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _fail("runtime identity reads require no-follow directory flags")
    root_fd = -1
    current_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(absolute, os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow)
        current_fd = root_fd
        parts = PurePosixPath(relative).parts
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
                dir_fd=current_fd,
            )
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                _fail("runtime identity path contains a non-directory")
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=current_fd,
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            _fail("runtime identity file exceeds its regular-file bound")
        content = bytearray(before.st_size)
        offset = 0
        while offset < before.st_size:
            chunk = os.read(file_fd, min(1024 * 1024, before.st_size - offset))
            if not chunk:
                _fail("runtime identity file was truncated while reading")
            content[offset : offset + len(chunk)] = chunk
            offset += len(chunk)
        if os.read(file_fd, 1):
            _fail("runtime identity file grew while reading")
        after = os.fstat(file_fd)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or not stat.S_ISREG(after.st_mode):
            _fail("runtime identity file changed while reading")
        return bytes(content)
    except OSError as error:
        raise ValueError("runtime identity file cannot be read safely") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if current_fd >= 0 and current_fd != root_fd:
            os.close(current_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(f"{label} schema has missing or unexpected fields")
    return value


def _integer(value: Any, label: str, *, maximum: int = MAX_U64) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        _fail(f"{label} is not a bounded integer")
    return value


def _mapped_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\\" in value
        or '"' in value
        or " (deleted)" in value
        or any(ord(character) < 0x20 or ord(character) > 0x7e for character in value)
    ):
        _fail(f"{label} is not a canonical printable mapped path")
    return value


def _maps_path(value: str, label: str) -> str:
    if value.startswith("/"):
        return _mapped_path(value, label)
    if (
        re.fullmatch(r"\[[A-Za-z0-9_.:+ -]{1,256}\]", value) is None
        or any(ord(character) < 0x20 or ord(character) > 0x7e for character in value)
    ):
        _fail(f"{label} is not a canonical mapped path or kernel region label")
    return value


def _elf(data: bytes, label: str, *, require_interpreter: bool) -> dict[str, Any]:
    if (
        len(data) < 64
        or data[:4] != b"\x7fELF"
        or data[4] != 2
        or data[5] != 1
        or data[6] != 1
        or struct.unpack_from("<I", data, 20)[0] != 1
    ):
        _fail(f"{label} is not a bounded ELF64 little-endian image")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if machine != 183 or elf_type not in {2, 3}:
        _fail(f"{label} has an unsupported ELF machine or type")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if (
        phentsize < 56
        or phnum == 0
        or phnum > MAX_ELF_PROGRAM_HEADERS
        or phoff > len(data)
        or phnum > (len(data) - phoff) // phentsize
    ):
        _fail(f"{label} has malformed program headers")
    loads: list[dict[str, int]] = []
    interpreters: list[str] = []
    for index in range(phnum):
        header = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        segment_type, flags, file_offset, virtual_address, _physical, file_size, memory_size, _alignment = header
        if segment_type == 1:
            if (
                file_size > memory_size
                or file_offset > len(data)
                or file_size > len(data) - file_offset
                or virtual_address > MAX_U64 - memory_size
                or file_offset > MAX_U64 - file_size
            ):
                _fail(f"{label} has an invalid PT_LOAD range")
            loads.append({
                "fileOffset": file_offset,
                "virtualAddress": virtual_address,
                "fileSize": file_size,
                "memorySize": memory_size,
                "flags": flags,
            })
        elif segment_type == 3:
            if file_size < 2 or file_size > 4096 or file_offset > len(data) or file_size > len(data) - file_offset:
                _fail(f"{label} has an invalid PT_INTERP range")
            raw = data[file_offset : file_offset + file_size]
            if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
                _fail(f"{label} PT_INTERP is not uniquely terminated")
            try:
                path = raw[:-1].decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise ValueError(f"{label} PT_INTERP is not ASCII") from error
            if not path.startswith("/") or "\\" in path or any(ord(ch) < 0x20 for ch in path):
                _fail(f"{label} PT_INTERP is not an absolute validated path")
            interpreters.append(path)
    if not loads or (require_interpreter and len(interpreters) != 1):
        _fail(f"{label} has no unique PT_LOAD/interpreter contract")
    return {"type": elf_type, "loads": loads, "interpreter": interpreters[0] if interpreters else None}


def _maps_rows(data: bytes) -> list[dict[str, Any]]:
    if len(data) > MAX_MAPS_BYTES:
        _fail("retained process maps exceed their bound")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("retained process maps are not ASCII") from error
    rows = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or len(line.encode("ascii")) > MAX_MAP_LINE_BYTES:
            _fail(f"retained process maps line {line_number} is malformed or too long")
        fields = line.split(None, 5)
        if len(fields) < 5:
            _fail(f"retained process maps line {line_number} has too few fields")
        match = re.fullmatch(r"([0-9a-fA-F]+)-([0-9a-fA-F]+)", fields[0])
        device = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+)", fields[3])
        if (
            match is None
            or device is None
            or re.fullmatch(r"[r-][w-][x-][ps]", fields[1]) is None
            or re.fullmatch(r"[0-9a-fA-F]+", fields[2]) is None
            or re.fullmatch(r"[0-9]+", fields[4]) is None
        ):
            _fail(f"retained process maps line {line_number} fields are malformed")
        start, end = int(match.group(1), 16), int(match.group(2), 16)
        if start >= end or end > MAX_U64:
            _fail(f"retained process maps line {line_number} interval is invalid")
        path = fields[5] if len(fields) == 6 else ""
        if path:
            _maps_path(path, f"retained process maps line {line_number} path")
        rows.append({
            "start": start,
            "end": end,
            "permissions": fields[1],
            "offset": int(fields[2], 16),
            "major": int(device.group(1), 16),
            "minor": int(device.group(2), 16),
            "inode": int(fields[4]),
            "path": path,
        })
    if not rows:
        _fail("retained process maps are empty")
    return rows


def _checked_add(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or left > MAX_U64 - right:
        _fail(f"{label} overflows its bounded address domain")
    return left + right


def _align_up(value: int, alignment: int, label: str) -> int:
    adjustment = alignment - 1
    if value < 0 or value > MAX_U64 - adjustment:
        _fail(f"{label} page rounding overflows")
    return (value + adjustment) & ~(alignment - 1)


def _page_file_range(segment: dict[str, int], page_size: int, label: str) -> tuple[int, int] | None:
    if segment["fileSize"] == 0:
        return None
    start = segment["fileOffset"] & ~(page_size - 1)
    end = _checked_add(segment["fileOffset"], segment["fileSize"], label)
    return start, _align_up(end, page_size, label)


def _page_memory_range(segment: dict[str, int], page_size: int, label: str) -> tuple[int, int] | None:
    if segment["memorySize"] == 0:
        return None
    start = segment["virtualAddress"] & ~(page_size - 1)
    end = _checked_add(segment["virtualAddress"], segment["memorySize"], label)
    return start, _align_up(end, page_size, label)


def _intersects(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def _verify_unique_virtual_memory_owner(
    loads: list[dict[str, int]],
    page_size: int,
    load_bias: int,
    map_start: int,
    map_end: int,
    file_owner_index: int,
    label: str,
) -> None:
    if map_start < load_bias or map_end < load_bias or map_start >= map_end:
        _fail(f"{label} mapped VMA is outside its checked load-bias domain")
    virtual_start = map_start - load_bias
    virtual_end = map_end - load_bias
    owner_count = 0
    owner_index: int | None = None
    for index, segment in enumerate(loads):
        memory_range = _page_memory_range(segment, page_size, f"{label} PT_LOAD memory interval")
        if memory_range is None or not _intersects(virtual_start, virtual_end, *memory_range):
            continue
        if virtual_start < memory_range[0] or virtual_end > memory_range[1]:
            _fail(f"{label} map partially intersects a PT_LOAD virtual-memory interval")
        if index != file_owner_index:
            _fail(f"{label} map has a conflicting PT_LOAD virtual-memory owner")
        owner_count += 1
        owner_index = index
    if owner_count != 1 or owner_index != file_owner_index:
        _fail(f"{label} map requires exactly one consistent PT_LOAD virtual-memory owner")


def _verify_maps_file(
    rows: list[dict[str, Any]],
    file_record: dict[str, Any],
    elf_data: bytes,
    label: str,
    *,
    require_executable: bool = True,
) -> None:
    info = _exact_keys(
        file_record,
        {"mappedPath", "deviceMajor", "deviceMinor", "inode", "size", "sha256", "retainedPath"},
        label,
    )
    path = _mapped_path(info["mappedPath"], f"{label} mappedPath")
    major = _integer(info["deviceMajor"], f"{label} deviceMajor", maximum=(1 << 32) - 1)
    minor = _integer(info["deviceMinor"], f"{label} deviceMinor", maximum=(1 << 32) - 1)
    inode = _integer(info["inode"], f"{label} inode")
    file_size = _integer(info["size"], f"{label} size", maximum=MAX_RUNTIME_FILE_BYTES)
    if file_size != len(elf_data) or file_size == 0:
        _fail(f"{label} retained size differs from its ELF bytes")
    if not isinstance(info["sha256"], str) or not DIGEST.fullmatch(info["sha256"]):
        _fail(f"{label} SHA-256 is malformed")
    if hashlib.sha256(elf_data).hexdigest() != info["sha256"]:
        _fail(f"{label} retained ELF digest does not match its native identity")
    elf = _elf(elf_data, label, require_interpreter=False)
    if elf["type"] != 3:
        _fail(f"{label} mapped runtime is not ET_DYN")

    matching = [row for row in rows if row["major"] == major and row["minor"] == minor and row["inode"] == inode]
    if not matching or any(row["path"] != path for row in matching):
        _fail(f"{label} device/inode does not identify one exact retained maps path")
    if any(row["path"] == path and (row["major"], row["minor"], row["inode"]) != (major, minor, inode) for row in rows):
        _fail(f"{label} mapped path has an ambiguous device/inode owner")

    page_size = os.sysconf("SC_PAGE_SIZE")
    if page_size <= 0 or page_size & (page_size - 1) or page_size > MAX_U64:
        _fail("host page size is unsupported")
    page_mask = ~(page_size - 1)
    file_page_limit = _align_up(len(elf_data), page_size, f"{label} file")

    def map_flags(row: dict[str, Any]) -> int:
        permissions = row["permissions"]
        return (4 if permissions[0] == "r" else 0) | (2 if permissions[1] == "w" else 0) | (1 if permissions[2] == "x" else 0)

    def mapping_file_range(row: dict[str, Any]) -> tuple[int, int]:
        end = _checked_add(row["offset"], row["end"] - row["start"], f"{label} maps file range")
        return row["offset"], end

    # Every mapped VMA must have one and only one page-rounded PT_LOAD memory
    # owner as well as one file-offset owner. Disjoint file ranges do not excuse
    # a second PT_LOAD whose p_memsz claims the same runtime pages.
    load_biases: set[int] = set()
    for row in matching:
        flags = map_flags(row)
        if not flags & 1:
            continue
        map_start, map_end = mapping_file_range(row)
        owner_count = 0
        row_bias: int | None = None
        row_owner_index: int | None = None
        for segment_index, segment in enumerate(elf["loads"]):
            page_range = _page_file_range(segment, page_size, f"{label} PT_LOAD")
            if page_range is None or not _intersects(map_start, map_end, *page_range):
                continue
            page_start, page_end = page_range
            if map_start < page_start or map_end > page_end:
                _fail(f"{label} executable map partially intersects a PT_LOAD page range")
            if not segment["flags"] & 1 or flags & ~segment["flags"]:
                _fail(f"{label} executable map intersects an incompatible PT_LOAD owner")
            virtual_page_start = segment["virtualAddress"] & page_mask
            segment_delta = map_start - page_start
            expected_virtual = _checked_add(virtual_page_start, segment_delta, f"{label} PT_LOAD virtual page")
            if row["start"] < expected_virtual:
                _fail(f"{label} executable map precedes its PT_LOAD virtual page")
            candidate_bias = row["start"] - expected_virtual
            if row_bias is not None and row_bias != candidate_bias:
                _fail(f"{label} executable map has conflicting PT_LOAD load biases")
            row_bias = candidate_bias
            row_owner_index = segment_index
            owner_count += 1
        if owner_count != 1 or row_bias is None or row_owner_index is None:
            _fail(f"{label} executable map requires exactly one fully-containing PT_LOAD owner")
        _verify_unique_virtual_memory_owner(
            elf["loads"], page_size, row_bias, row["start"], row["end"], row_owner_index, label
        )
        load_biases.add(row_bias)
    if len(load_biases) != 1:
        _fail(f"{label} executable map does not establish one ELF load bias")
    load_bias = next(iter(load_biases))
    executable_seen = False

    # Kernel RELRO/protection splits remain valid: each split VMA is independently
    # contained by the same PT_LOAD. No map may be partially covered or multiply owned.
    for row in matching:
        flags = map_flags(row)
        map_size = row["end"] - row["start"]
        map_file_start, map_file_end = mapping_file_range(row)
        if row["start"] < load_bias or (map_file_end > file_page_limit and flags != 0):
            _fail(f"{label} mapped range exceeds its file or load-bias bound")
        owner_count = 0
        owner_index: int | None = None
        if flags != 0:
            for segment_index, segment in enumerate(elf["loads"]):
                page_range = _page_file_range(segment, page_size, f"{label} PT_LOAD")
                if page_range is None or not _intersects(map_file_start, map_file_end, *page_range):
                    continue
                page_start, page_end = page_range
                if map_file_start < page_start or map_file_end > page_end:
                    _fail(f"{label} map partially intersects a PT_LOAD page range")
                if flags & ~segment["flags"]:
                    _fail(f"{label} map permissions exceed its PT_LOAD owner")
                virtual_page_start = segment["virtualAddress"] & page_mask
                expected_start = _checked_add(load_bias, virtual_page_start, f"{label} PT_LOAD load bias")
                expected_start = _checked_add(expected_start, map_file_start - page_start, f"{label} PT_LOAD mapping address")
                if row["start"] != expected_start:
                    _fail(f"{label} map intersects a PT_LOAD at a conflicting virtual address")
                owner_index = segment_index
                owner_count += 1
        if owner_count > 1:
            _fail(f"{label} map has multiple fully-containing PT_LOAD owners")
        if owner_count == 1:
            if owner_index is None:
                _fail(f"{label} map has no stable PT_LOAD file owner")
            _verify_unique_virtual_memory_owner(
                elf["loads"], page_size, load_bias, row["start"], row["end"], owner_index, label
            )
        if owner_count == 0:
            if flags != 0 or map_size > MAX_RUNTIME_FILE_BYTES:
                _fail(f"{label} has a file-backed maps range outside its ELF PT_LOAD layout")
            gap_count = 0
            memory_ranges: list[tuple[int, int]] = []
            for segment in elf["loads"]:
                memory_range = _page_memory_range(segment, page_size, f"{label} PT_LOAD memory interval")
                if memory_range is not None:
                    memory_ranges.append(memory_range)
            memory_ranges.sort()
            merged_ranges: list[tuple[int, int]] = []
            for memory_start, memory_end in memory_ranges:
                if not merged_ranges or memory_start > merged_ranges[-1][1]:
                    merged_ranges.append((memory_start, memory_end))
                else:
                    merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], memory_end))
            for (_left_start, left_end), (right_start, _right_end) in zip(merged_ranges, merged_ranges[1:]):
                gap_start = _checked_add(load_bias, left_end, f"{label} PT_LOAD memory gap")
                gap_end = _checked_add(load_bias, right_start, f"{label} PT_LOAD memory gap")
                if _intersects(row["start"], row["end"], gap_start, gap_end):
                    if row["start"] < gap_start or row["end"] > gap_end:
                        _fail(f"{label} map partially intersects a PT_LOAD memory gap")
                    gap_count += 1
            if gap_count != 1:
                _fail(f"{label} has a non-unique or uncovered PT_LOAD memory gap mapping")
        if flags & 1:
            executable_seen = True
    if require_executable and not executable_seen:
        _fail(f"{label} has no executable mapped PT_LOAD range")


def _version_from_bytes(data: bytes, runtime: str) -> str:
    marker = b"Version " if runtime == "musl" else b"release version "
    occurrences = [match.start() for match in re.finditer(re.escape(marker), data)]
    if len(occurrences) != 1:
        _fail("runtime ELF has missing or conflicting version markers")
    start = occurrences[0] + len(marker)
    match = re.match(rb"[0-9]+\.[0-9]+(?:\.[0-9]+)?", data[start : start + 64])
    if match is None:
        _fail("runtime ELF version marker has no strict numeric version")
    version = match.group(0).decode("ascii")
    expected_parts = 3 if runtime == "musl" else 2
    if version.count(".") != expected_parts - 1:
        _fail("runtime ELF version has the wrong component count")
    if runtime == "glibc" and data[start + len(version) : start + len(version) + 1] not in {b"", b"."}:
        _fail("glibc version marker has an unexpected suffix")
    return version


def validate_handoff_runtime_identity(
    root: Path,
    handoff: dict[str, Any],
    *,
    expected_runtime: str,
    expected_role: str,
    expected_image_sha256: str,
    required: bool = False,
) -> dict[str, Any] | None:
    if expected_runtime not in {"glibc", "musl"} or expected_role not in {"source", "target"}:
        _fail("runtime identity request has an unsupported runtime or role")
    carrier = handoff.get("runtimeIdentity")
    if carrier is None:
        if required or expected_runtime == "musl":
            _fail("HostContext handoff is missing its required native runtime identity")
        return None
    carrier = _exact_keys(carrier, {"schemaVersion", "path", "sha256"}, "runtimeIdentity carrier")
    if type(carrier["schemaVersion"]) is not int or carrier["schemaVersion"] != 1:
        _fail("runtime identity carrier schemaVersion must be the exact integer 1")
    identity_path = _safe_relative(carrier["path"], "runtime identity carrier path")
    if not isinstance(carrier["sha256"], str) or not DIGEST.fullmatch(carrier["sha256"]):
        _fail("runtime identity carrier digest is malformed")
    identity_bytes = _read_root_file(root, identity_path, MAX_IDENTITY_BYTES)
    if hashlib.sha256(identity_bytes).hexdigest() != carrier["sha256"]:
        _fail("runtime identity carrier digest differs from its retained record")
    try:
        identity = json.loads(identity_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("native runtime identity record is malformed") from error
    identity = _exact_keys(
        identity,
        {
            "schemaVersion", "runtime", "architecture", "role", "processId", "imageSha256",
            "runtimeVersion", "runtimeVersionSource", "interpreter", "maps", "helper", "libc", "loader",
        },
        "native runtime identity",
    )
    if type(identity["schemaVersion"]) is not int:
        _fail("native runtime identity schemaVersion must be an exact integer")
    if identity["schemaVersion"] != 1:
        _fail("native runtime identity schemaVersion is unsupported")
    if (
        identity["runtime"] != expected_runtime
        or identity["architecture"] != "aarch64"
        or identity["role"] != expected_role
        or identity["imageSha256"] != expected_image_sha256
    ):
        _fail("native runtime identity does not bind the expected family, role, architecture, or image")
    _integer(identity["processId"], "runtime identity processId", maximum=(1 << 31) - 1)
    version = identity["runtimeVersion"]
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", version) is None:
        _fail("native runtime identity version is malformed")
    expected_version_source = "musl-loader-version-marker" if expected_runtime == "musl" else "glibc-libc-release-version-marker"
    if identity["runtimeVersionSource"] != expected_version_source:
        _fail("native runtime identity version source is unsupported")

    maps_record = _exact_keys(identity["maps"], {"retainedPath", "sha256"}, "runtime maps record")
    maps_path = _safe_relative(maps_record["retainedPath"], "runtime maps path")
    if not isinstance(maps_record["sha256"], str) or not DIGEST.fullmatch(maps_record["sha256"]):
        _fail("runtime maps digest is malformed")
    maps_bytes = _read_root_file(root, maps_path, MAX_MAPS_BYTES)
    if hashlib.sha256(maps_bytes).hexdigest() != maps_record["sha256"]:
        _fail("retained process maps do not match the native identity digest")
    rows = _maps_rows(maps_bytes)

    total_bytes = len(identity_bytes) + len(maps_bytes)
    retained: dict[str, bytes] = {}
    for label in ("helper", "libc", "loader"):
        info = _exact_keys(
            identity[label],
            {"mappedPath", "deviceMajor", "deviceMinor", "inode", "size", "sha256", "retainedPath"},
            f"runtime {label} record",
        )
        relative = _safe_relative(info["retainedPath"], f"runtime {label} retained path")
        size = _integer(info["size"], f"runtime {label} size", maximum=MAX_RUNTIME_FILE_BYTES)
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            _fail("runtime identity retained aggregate exceeds its configured bound")
        data = _read_root_file(root, relative, MAX_RUNTIME_FILE_BYTES)
        if len(data) != size:
            _fail(f"runtime {label} retained byte count differs from its native record")
        retained[label] = data
        _verify_maps_file(rows, info, data, f"runtime {label}")

    helper_elf = _elf(retained["helper"], "runtime helper", require_interpreter=True)
    interpreter = _exact_keys(
        identity["interpreter"],
        {"declaredPath", "resolvedPath", "deviceMajor", "deviceMinor", "inode"},
        "runtime interpreter record",
    )
    declared = interpreter["declaredPath"]
    resolved = _mapped_path(interpreter["resolvedPath"], "runtime interpreter resolvedPath")
    if declared != helper_elf["interpreter"]:
        _fail("runtime identity PT_INTERP differs from the retained helper ELF")
    expected_interpreter = "ld-musl-aarch64.so.1" if expected_runtime == "musl" else "ld-linux-aarch64.so.1"
    if PurePosixPath(declared).name != expected_interpreter:
        _fail("runtime helper PT_INTERP names the wrong loader family")
    loader = identity["loader"]
    if resolved != loader["mappedPath"]:
        _fail("resolved PT_INTERP does not identify the mapped loader path")
    if (
        _integer(interpreter["deviceMajor"], "interpreter deviceMajor", maximum=(1 << 32) - 1) != loader["deviceMajor"]
        or _integer(interpreter["deviceMinor"], "interpreter deviceMinor", maximum=(1 << 32) - 1) != loader["deviceMinor"]
        or _integer(interpreter["inode"], "interpreter inode") != loader["inode"]
    ):
        _fail("PT_INTERP resolved device/inode differs from the actual mapped loader")

    libc = identity["libc"]
    if expected_runtime == "musl":
        if any(libc[key] != loader[key] for key in ("mappedPath", "deviceMajor", "deviceMinor", "inode", "size", "sha256")):
            _fail("musl loader and combined libc identities disagree")
        if identity["runtimeVersion"] != _version_from_bytes(retained["libc"], "musl"):
            _fail("musl runtime version differs from the retained mapped libc/loader bytes")
    else:
        if PurePosixPath(libc["mappedPath"]).name != "libc.so.6":
            _fail("glibc identity does not name the actual mapped libc")
        if PurePosixPath(loader["mappedPath"]).name != "ld-linux-aarch64.so.1":
            _fail("glibc identity does not name the actual mapped loader")
        if identity["runtimeVersion"] != _version_from_bytes(retained["libc"], "glibc"):
            _fail("glibc runtime version differs from the retained mapped libc bytes")
    return identity


def require_same_runtime_identity(source: dict[str, Any] | None, target: dict[str, Any] | None) -> None:
    if source is None or target is None:
        if source is not target:
            _fail("source and target runtime identity presence differs")
        return
    if source["runtime"] != target["runtime"] or source["runtimeVersion"] != target["runtimeVersion"]:
        _fail("source and transformed execution used different runtime families or versions")
    shared_file_fields = ("mappedPath", "deviceMajor", "deviceMinor", "inode", "size", "sha256")
    for label in ("helper", "libc", "loader"):
        if any(source[label].get(field) != target[label].get(field) for field in shared_file_fields):
            _fail(f"source and transformed native {label} identities disagree")
    if source["interpreter"] != target["interpreter"]:
        _fail("source and transformed native interpreter identities disagree")
