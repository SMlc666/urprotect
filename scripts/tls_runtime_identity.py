#!/usr/bin/env python3
"""Identify and verify the native AArch64 glibc image/loader used by TLS evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_RUNTIME_IMAGE_BYTES = 256 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def file_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"runtime identity path is not a regular file: {path}")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_RUNTIME_IMAGE_BYTES:
        fail(f"runtime identity file exceeds its bound: {path}")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def canonical_identity_digest(identity: dict[str, Any]) -> str:
    payload = {key: value for key, value in identity.items() if key != "identitySha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapped_files() -> dict[str, set[Path]]:
    maps = Path("/proc/self/maps")
    if not maps.is_file():
        fail("native glibc identity requires /proc/self/maps")
    found: dict[str, set[Path]] = {"libc.so.6": set(), "ld-linux-aarch64.so.1": set()}
    for line in maps.read_text(encoding="utf-8", errors="strict").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            continue
        mapped_name = fields[5]
        if mapped_name.endswith(" (deleted)"):
            continue
        base = Path(mapped_name).name
        if base not in found:
            continue
        try:
            resolved = Path(mapped_name).resolve(strict=True)
        except OSError:
            continue
        found[base].add(resolved)
    return found


def _elf_identity(path: Path, label: str) -> dict[str, Any]:
    with path.open("rb") as stream:
        header = stream.read(20)
    if (
        len(header) < 20
        or header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != 183
    ):
        fail(f"resolved {label} is not an ELF64 little-endian AArch64 image: {path}")
    return {"class": 64, "data": "little", "machine": 183}


def _valid_canonical_path(value: Any, expected_name: str, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        fail(f"retained runtime {label} is outside its bound")
    path = Path(value)
    if (
        not path.is_absolute()
        or path.name != expected_name
        or ".." in path.parts
        or str(path) != value
    ):
        fail(f"retained runtime {label} is not a canonical absolute {expected_name} identity")
    return value


def identify_native_glibc() -> dict[str, Any]:
    machine = platform.machine().lower()
    if machine not in {"aarch64", "arm64"}:
        fail(f"glibc TLS promotion requires native AArch64; found {machine}")
    try:
        version = os.confstr("CS_GNU_LIBC_VERSION")
    except (AttributeError, OSError, ValueError):
        version = None
    if not isinstance(version, str) or not re.fullmatch(r"glibc [0-9][A-Za-z0-9.+_-]{0,63}", version):
        fail(f"requested glibc runtime does not match the executing libc: {version!r}")
    mapped = _mapped_files()
    if len(mapped["libc.so.6"]) != 1 or len(mapped["ld-linux-aarch64.so.1"]) != 1:
        fail("could not uniquely resolve the running AArch64 glibc libc and loader")
    libc_path = next(iter(mapped["libc.so.6"]))
    loader_path = next(iter(mapped["ld-linux-aarch64.so.1"]))
    libc_elf = _elf_identity(libc_path, "libc")
    loader_elf = _elf_identity(loader_path, "glibc loader")
    identity: dict[str, Any] = {
        "runtime": "glibc",
        "architecture": machine,
        "version": version,
        "libcPath": str(libc_path),
        "libcSha256": file_digest(libc_path),
        "libcElfClass": libc_elf["class"],
        "libcElfData": libc_elf["data"],
        "libcMachine": libc_elf["machine"],
        "loaderPath": str(loader_path),
        "loaderSha256": file_digest(loader_path),
        "loaderElfClass": loader_elf["class"],
        "loaderElfData": loader_elf["data"],
        "loaderMachine": loader_elf["machine"],
    }
    identity["identitySha256"] = canonical_identity_digest(identity)
    return identity


def verify_artifact_identity(value: Any) -> dict[str, Any]:
    """Validate portable producer facts without touching producer paths or this host's libc."""
    required = {
        "runtime",
        "architecture",
        "version",
        "libcPath",
        "libcSha256",
        "libcElfClass",
        "libcElfData",
        "libcMachine",
        "loaderPath",
        "loaderSha256",
        "loaderElfClass",
        "loaderElfData",
        "loaderMachine",
        "identitySha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail("retained glibc runtime identity fields are malformed")
    if value["runtime"] != "glibc" or value["architecture"] not in {"aarch64", "arm64"}:
        fail("retained runtime identity is not native AArch64 glibc")
    if not isinstance(value["version"], str) or not re.fullmatch(
        r"glibc [0-9][A-Za-z0-9.+_-]{0,63}", value["version"]
    ):
        fail("retained glibc version is malformed")
    _valid_canonical_path(value["libcPath"], "libc.so.6", "libcPath")
    _valid_canonical_path(value["loaderPath"], "ld-linux-aarch64.so.1", "loaderPath")
    for field in ("libcSha256", "loaderSha256", "identitySha256"):
        if not isinstance(value[field], str) or not DIGEST.fullmatch(value[field]):
            fail(f"retained runtime {field} is malformed")
    for prefix in ("libc", "loader"):
        if (
            type(value[f"{prefix}ElfClass"]) is not int
            or value[f"{prefix}ElfClass"] != 64
            or value[f"{prefix}ElfData"] != "little"
            or type(value[f"{prefix}Machine"]) is not int
            or value[f"{prefix}Machine"] != 183
        ):
            fail(f"retained runtime {prefix} ELF identity facts are unsupported")
    if canonical_identity_digest(value) != value["identitySha256"]:
        fail("retained runtime identity digest does not match its facts")
    return value


def verify_identity(value: Any, *, verify_current_process: bool = True) -> dict[str, Any]:
    """Producer-local verification of retained facts against mapped runtime files."""
    value = verify_artifact_identity(value)
    for path_key, hash_key, expected_name in (
        ("libcPath", "libcSha256", "libc.so.6"),
        ("loaderPath", "loaderSha256", "ld-linux-aarch64.so.1"),
    ):
        path = Path(value[path_key])
        if path.is_symlink():
            fail(f"producer runtime {path_key} must already be resolved")
        resolved = path.resolve(strict=True)
        if str(resolved) != value[path_key] or path.name != expected_name:
            fail(f"producer runtime {path_key} does not name resolved {expected_name}")
        facts = _elf_identity(path, expected_name)
        if (
            facts["class"] != value[f"{hash_key.removesuffix('Sha256')}ElfClass"]
            or facts["data"] != value[f"{hash_key.removesuffix('Sha256')}ElfData"]
            or facts["machine"] != value[f"{hash_key.removesuffix('Sha256')}Machine"]
        ):
            fail(f"producer runtime {path_key} ELF facts differ from retained identity")
        if file_digest(path) != value[hash_key]:
            fail(f"producer runtime {hash_key} does not match {value[path_key]}")
    if verify_current_process:
        actual = identify_native_glibc()
        if actual != value:
            fail("retained glibc identity does not match the producer process runtime")
    return value


def main() -> None:
    identity = identify_native_glibc()
    print(json.dumps(identity, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
