"""Strict, byte-backed PT_LOAD mapping for evidence validators.

This helper intentionally validates only caller-selected ranges. It does not
impose a disjointness policy on unrelated ELF segments.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_U64_ENDPOINT = 1 << 64


def resolve_isolated_evidence_root(path: Path, label: str) -> Path:
    """Resolve a real artifact directory and reject symlinks/special files.

    Evidence roots are closed snapshots, not aliases into another tree. Walk
    without following links so an unlisted link directory cannot hide files
    or redirect later evidence reads.
    """
    try:
        candidate = Path(os.path.abspath(path))
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"{label} is not a resolvable artifact directory") from error
    if candidate != root or not root.is_dir():
        raise ValueError(f"{label} must be an isolated non-symlink directory")

    def raise_walk_error(error: OSError) -> None:
        raise error

    try:
        for directory, subdirectories, filenames in os.walk(
            root, topdown=True, onerror=raise_walk_error, followlinks=False
        ):
            for name in (*subdirectories, *filenames):
                entry = Path(directory) / name
                mode = entry.lstat().st_mode
                if stat.S_ISLNK(mode):
                    raise ValueError(f"{label} contains a symlink: {entry.relative_to(root).as_posix()}")
                if name in subdirectories:
                    if not stat.S_ISDIR(mode):
                        raise ValueError(f"{label} contains a non-directory tree entry")
                elif not stat.S_ISREG(mode):
                    raise ValueError(f"{label} contains a non-regular evidence file")
    except OSError as error:
        raise ValueError(f"{label} tree cannot be inspected safely") from error
    return root


def unique_file_backed_pt_load(
    image: bytes,
    segments: list[dict[str, int]],
    address: int,
    size: int,
    label: str,
    *,
    virtual_address_key: str,
    file_offset_key: str,
    file_size_key: str,
    memory_size_key: str,
) -> tuple[int, dict[str, int]]:
    """Return the exact file mapping if one PT_LOAD uniquely owns the range.

    All intervals are half-open. Every PT_LOAD intersecting the requested
    memory interval is considered, including non-file-backed tails; a partial
    or duplicate memory overlap is rejected even when one segment fully backs
    the requested bytes.
    """
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError(f"{label} has a malformed or empty virtual interval")
    if address >= MAX_U64_ENDPOINT or size > MAX_U64_ENDPOINT - address:
        raise ValueError(f"{label} virtual interval overflows ELF64")
    end = address + size

    owners: list[tuple[int, dict[str, int]]] = []
    intersections: list[tuple[int, dict[str, int]]] = []
    for index, segment in enumerate(segments):
        values = (
            segment.get(virtual_address_key),
            segment.get(file_offset_key),
            segment.get(file_size_key),
            segment.get(memory_size_key),
        )
        if any(type(value) is not int for value in values):
            raise ValueError(f"{label} intersects a PT_LOAD with malformed range fields")
        segment_va, file_offset, file_size, memory_size = values
        if (
            segment_va < 0
            or segment_va >= MAX_U64_ENDPOINT
            or file_offset < 0
            or file_offset > len(image)
            or file_size < 0
            or memory_size < 0
            or file_size > memory_size
            or file_size > len(image) - file_offset
            or memory_size > MAX_U64_ENDPOINT - segment_va
        ):
            raise ValueError(f"{label} intersects a PT_LOAD with an invalid file or memory range")
        memory_end = segment_va + memory_size
        file_end = segment_va + file_size
        if memory_size > 0 and max(address, segment_va) < min(end, memory_end):
            intersections.append((index, segment))
        if segment_va <= address and end <= file_end:
            owners.append((index, segment))

    if len(owners) != 1:
        raise ValueError(
            f"{label} does not have exactly one fully containing file-backed PT_LOAD owner"
        )
    owner_index, owner = owners[0]
    if len(intersections) != 1 or intersections[0][0] != owner_index:
        raise ValueError(f"{label} partially intersects another PT_LOAD memory interval")

    owner_va = owner[virtual_address_key]
    owner_offset = owner[file_offset_key]
    translated = owner_offset + address - owner_va
    if translated > len(image) or size > len(image) - translated:
        raise ValueError(f"{label} file translation exceeds the retained image")
    return translated, owner
