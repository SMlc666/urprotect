#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import struct
import sys
import types
from pathlib import Path
from typing import Any, Callable

_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY = "_urprotect_active_evidence_root_snapshot"
_RANGE_MODULE_SOURCE_DIGEST = "_urprotect_range_module_source_sha256"
MAX_PRIVATE_HELPER_SOURCE_BYTES = 16 * 1024 * 1024


def _read_bounded_root_relative_source(root: Path, relative: str, limit: int) -> bytes:
    """Read one fixed checker dependency through no-follow descriptors."""
    path = Path(relative)
    if (
        not relative or "\\" in relative or path.is_absolute()
        or path.as_posix() != relative or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ImportError("checker helper source path is unsafe")
    root_path = Path(os.path.abspath(root))
    try:
        if root_path.resolve(strict=True) != root_path:
            raise ImportError("checker helper root is not an isolated directory")
    except (OSError, RuntimeError) as error:
        raise ImportError("checker helper root cannot be resolved safely") from error
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise ImportError("checker helper reads require no-follow directory flags")
    root_fd = -1
    directory_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(root_path, os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow)
        directory_metadata = os.fstat(root_fd)
        directory_fd = root_fd
        for part in path.parts[:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
                dir_fd=directory_fd,
            )
            next_metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(next_metadata.st_mode):
                os.close(next_fd)
                raise ImportError("checker helper path contains a non-directory")
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            path.parts[-1], os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > limit:
            raise ImportError("checker helper source exceeds its bounded regular-file contract")
        result = bytearray(before.st_size)
        position = 0
        while position < before.st_size:
            chunk = os.read(file_fd, min(1024 * 1024, before.st_size - position))
            if not chunk:
                raise ImportError("checker helper source was truncated while reading")
            result[position : position + len(chunk)] = chunk
            position += len(chunk)
        growth_probe = os.read(file_fd, 1)
        after = os.fstat(file_fd)
        identity = lambda metadata: (
            metadata.st_size, metadata.st_dev, metadata.st_ino,
            metadata.st_mtime_ns, metadata.st_ctime_ns,
        )
        if growth_probe or identity(after) != identity(before) or not stat.S_ISREG(after.st_mode):
            raise ImportError("checker helper source grew or changed while reading")
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise ImportError("checker helper root is not a directory")
        return bytes(result)
    except OSError as error:
        raise ImportError("checker helper source cannot be read safely") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0 and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _read_sibling_helper_source(helper_path: Path) -> bytes:
    root = helper_path.parent
    relative = helper_path.name
    snapshot = sys.modules.get(_ACTIVE_ROOT_SNAPSHOT_MODULE_KEY)
    if (
        snapshot is not None
        and Path(os.path.abspath(snapshot.root)) == Path(os.path.abspath(root.parent))
    ):
        return snapshot.read(f"scripts/{relative}", limit=MAX_PRIVATE_HELPER_SOURCE_BYTES)
    return _read_bounded_root_relative_source(root, relative, MAX_PRIVATE_HELPER_SOURCE_BYTES)


def _range_helper_module_name(helper_path: Path) -> str:
    """Separate this checker instance's cache namespace from path collisions."""
    owner_nonce = f"{id(globals()):x}"
    module_key = hashlib.sha256(f"{helper_path}\0{owner_nonce}".encode("utf-8")).hexdigest()[:16]
    return f"_urprotect_evidence_load_range_{module_key}"


def _load_sibling_evidence_range_helper() -> Any:
    """Load the range owner from this checker directory, never ambient sys.path."""
    helper_path = Path(__file__).resolve().with_name("evidence_load_range.py")
    module_name = _range_helper_module_name(helper_path)
    existing = sys.modules.get(module_name)
    if existing is not None:
        if existing is not globals().get("_RANGE_HELPER"):
            raise ImportError("preloaded evidence range cache entry is not checker-owned")
        if not isinstance(existing, types.ModuleType):
            raise ImportError("preloaded evidence range cache entry is not a module")
        namespace = types.ModuleType.__getattribute__(existing, "__dict__")
        source_file = namespace.get("__file__")
        if not isinstance(source_file, str):
            raise ImportError("preloaded evidence range module has no owned source file")
        try:
            existing_path = Path(source_file).resolve(strict=True)
        except (OSError, RuntimeError):
            raise ImportError("preloaded evidence range module has no owned source file")
        if existing_path != helper_path:
            raise ImportError("preloaded evidence range module is not the checker sibling")
        source = _read_sibling_helper_source(helper_path)
        if namespace.get(_RANGE_MODULE_SOURCE_DIGEST) != hashlib.sha256(source).hexdigest():
            raise ImportError("preloaded evidence range cache does not bind the checker sibling source")
        return existing

    source = _read_sibling_helper_source(helper_path)
    module = types.ModuleType(module_name)
    namespace = types.ModuleType.__getattribute__(module, "__dict__")
    namespace["__file__"] = str(helper_path)
    namespace["__package__"] = ""
    namespace[_RANGE_MODULE_SOURCE_DIGEST] = hashlib.sha256(source).hexdigest()
    sys.modules[module_name] = module
    try:
        exec(compile(source, str(helper_path), "exec"), namespace)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_RANGE_HELPER = _load_sibling_evidence_range_helper()
resolve_isolated_evidence_root = _RANGE_HELPER.resolve_isolated_evidence_root
unique_file_backed_pt_load = _RANGE_HELPER.unique_file_backed_pt_load

DIGEST = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_CASE_INDICES = [0, 1, 2, 3]
EXPECTED_CASE_RESULTS = [17, 103, -7, 91]
EXPECTED_CASE_SYMBOLS = [f"urp_jump_table_case{index}" for index in EXPECTED_CASE_INDICES]
EXPECTED_TRACE = "0x1167f95b"
EXPECTED_ENTRY_STATUS = 91
EXPECTED_FAILURE_STAGE = "protected-image-producer"
ELF_LAYOUT_EVIDENCE_SCHEMA_VERSION = 3
LAYOUT_PERMISSION_READ = 4
LAYOUT_OWNERSHIP_AMBIGUOUS = 0
LAYOUT_REWRITE_COPIED_AND_RETARGETED = 1
SEMANTIC_ENTITY_KIND_BASIC_BLOCK = 1
SEMANTIC_ENTITY_KIND_TABLE = 5
SEMANTIC_ENTITY_KIND_TABLE_ENTRY = 6
EXPECTED_NEGATIVES = {
    "negative-malformed-table": (
        "A signed relative jump-table entry resolves outside the selected function closure.",
    ),
    "negative-out-of-range-target": (
        "A signed relative jump-table entry resolves outside an executable PT_LOAD range.",
    ),
    "negative-index-clobber": (
        "The checked jump-table index register W0/X0 is overwritten between B.HI and the indexed LDRSW.",
    ),
    "negative-external-table": (
        "The selected instruction does not match the promoted relative jump-table family.",
    ),
}
EXPECTED_MUTATION_KINDS = {
    "negative-malformed-table": "out-of-closure-executable-target",
    "negative-out-of-range-target": "outside-executable-load-range",
}
TRACE_OBSERVATION = (
    "urp_entry returns 91 only after the in-function 0,1,2,3 table walk "
    "matches all four exact result bytes"
)
MAX_EVIDENCE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_IMAGE_BYTES = 128 * 1024 * 1024
MAX_EVIDENCE_JSON_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_STREAM_BYTES = 1024 * 1024
MAX_EVIDENCE_LOG_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_TEXT_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_OTHER_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_FILES = 4096
MAX_EVIDENCE_DIRECTORIES = 512
EVIDENCE_IMAGE_NAMES = {
    "source-image.bin", "native-image.bin", "protected-image.bin",
    "input-image.bin", "provider-image.so",
}
EVIDENCE_STREAM_NAMES = {
    "baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr",
}
_ACTIVE_EVIDENCE_SNAPSHOT: EvidenceRootSnapshot | None = None


def fail(message: str) -> None:
    raise SystemExit(message)


def _safe_relative(relative: str) -> tuple[str, ...]:
    path = Path(relative)
    if (
        not relative or "\\" in relative or path.is_absolute()
        or path.as_posix() != relative or any(part in {"", ".", ".."} for part in path.parts)
    ):
        fail("indirect-control evidence path is not a safe relative path")
    return path.parts


def _file_limit(relative: str) -> int:
    name = Path(relative).name
    if relative == "SHA256SUMS":
        return MAX_EVIDENCE_MANIFEST_BYTES
    if name in EVIDENCE_IMAGE_NAMES or name.endswith(".elf"):
        return MAX_EVIDENCE_IMAGE_BYTES
    if name in EVIDENCE_STREAM_NAMES:
        return MAX_EVIDENCE_STREAM_BYTES
    if name.endswith((".stdout", ".stderr", ".log")):
        return MAX_EVIDENCE_LOG_BYTES
    if name.endswith(".json"):
        return MAX_EVIDENCE_JSON_BYTES
    if name.endswith(".txt"):
        return MAX_EVIDENCE_TEXT_BYTES
    return MAX_EVIDENCE_OTHER_BYTES


class EvidenceRootSnapshot:
    """Metadata-gated, no-follow bounded snapshot of a closed evidence tree."""

    def __init__(
        self,
        root: Path,
        *,
        max_files: int | None = None,
        max_directories: int | None = None,
        max_total_bytes: int | None = None,
        expected_files: set[str] | None = None,
        optional_files: set[str] | None = None,
        expected_directories: set[str] | None = None,
        file_limit_resolver: Callable[[str], int] | None = None,
    ) -> None:
        self.root = Path(root)
        self._root_path = Path(os.path.abspath(self.root))
        self._max_files = MAX_EVIDENCE_FILES if max_files is None else max_files
        self._max_directories = MAX_EVIDENCE_DIRECTORIES if max_directories is None else max_directories
        self._max_total_bytes = MAX_EVIDENCE_TOTAL_BYTES if max_total_bytes is None else max_total_bytes
        self._expected_files = None if expected_files is None else frozenset(expected_files)
        self._optional_files = frozenset(optional_files or ())
        self._expected_directories = None if expected_directories is None else frozenset(expected_directories)
        self._file_limit_resolver = file_limit_resolver or _file_limit
        if (
            type(self._max_files) is not int or self._max_files < 0
            or type(self._max_directories) is not int or self._max_directories < 1
            or type(self._max_total_bytes) is not int or self._max_total_bytes < 0
        ):
            raise ValueError("evidence root limits must be nonnegative exact integers")
        if self._expected_files is None and self._optional_files:
            raise ValueError("optional evidence paths require an expected-file contract")
        self._allowed_files = (
            None if self._expected_files is None
            else self._expected_files | self._optional_files
        )
        self._facts: dict[str, tuple[int, int, int, int, int]] = {}
        self._directory_facts: dict[str, tuple[int, int, int, int]] = {}
        self._root_identity: tuple[int, int, int, int] | None = None
        self._bytes: dict[str, bytes] = {}
        self._preflighted = False
        self._manifest_verified = False

    @staticmethod
    def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    @staticmethod
    def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            metadata.st_size,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _scan_tree(
        self,
    ) -> tuple[
        dict[str, tuple[int, int, int, int, int]],
        dict[str, tuple[int, int, int, int]],
        tuple[int, int, int, int],
    ]:
        facts: dict[str, tuple[int, int, int, int, int]] = {}
        directory_facts: dict[str, tuple[int, int, int, int]] = {}
        total = 0
        files_seen = 0
        directories_seen = 1  # The evidence root itself counts toward the cap.
        pending: list[tuple[tuple[str, ...], str, tuple[int, int, int, int] | None]] = [((), "", None)]
        root_fd = -1
        directory_flag = getattr(os, "O_DIRECTORY", None)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if directory_flag is None or nofollow is None:
            fail("indirect-control evidence scans require no-follow directory flags")
        allowed_nodes = None
        if self._allowed_files is not None:
            allowed_nodes = set(self._allowed_files) | set(self._expected_directories or ())
        try:
            try:
                resolved_root = self._root_path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                fail(f"indirect-control evidence root cannot be resolved safely: {error}")
            if resolved_root != self._root_path:
                fail("indirect-control evidence root must be an isolated non-symlink directory")
            root_fd = os.open(
                self._root_path,
                os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
            )
            root_metadata = os.fstat(root_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                fail("indirect-control evidence root must be a non-symlink directory")
            root_identity = self._directory_identity(root_metadata)
            if self._root_identity is not None and root_identity != self._root_identity:
                fail("indirect-control evidence root changed after bounded tree preflight")

            while pending:
                parts, relative_directory, expected_directory_identity = pending.pop()
                directory_fd = os.dup(root_fd)
                opened_relative = ""
                try:
                    for part in parts:
                        next_fd = os.open(
                            part,
                            os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
                            dir_fd=directory_fd,
                        )
                        os.close(directory_fd)
                        directory_fd = next_fd
                        opened_relative = f"{opened_relative}/{part}".lstrip("/")
                        opened_metadata = os.fstat(directory_fd)
                        opened_identity = self._directory_identity(opened_metadata)
                        if (
                            not stat.S_ISDIR(opened_metadata.st_mode)
                            or opened_identity != directory_facts.get(opened_relative)
                        ):
                            fail("indirect-control evidence directory changed during bounded tree scan")
                    if relative_directory and expected_directory_identity != directory_facts.get(relative_directory):
                        fail("indirect-control evidence directory changed during bounded tree scan")
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            name = entry.name
                            relative = f"{relative_directory}/{name}".lstrip("/")
                            _safe_relative(relative)
                            if allowed_nodes is not None and relative not in allowed_nodes:
                                fail(f"indirect-control evidence root contains an unexpected path: {relative}")
                            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            if stat.S_ISLNK(metadata.st_mode):
                                fail(f"indirect-control evidence tree contains a symlink: {relative}")
                            if stat.S_ISDIR(metadata.st_mode):
                                if self._expected_directories is not None and relative not in self._expected_directories:
                                    fail(f"indirect-control evidence root contains an unexpected directory: {relative}")
                                if directories_seen >= self._max_directories:
                                    fail("indirect-control evidence root exceeds its directory-count bound")
                                directories_seen += 1
                                identity = self._directory_identity(metadata)
                                child_fd = os.open(
                                    name,
                                    os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
                                    dir_fd=directory_fd,
                                )
                                try:
                                    child_metadata = os.fstat(child_fd)
                                    if (
                                        not stat.S_ISDIR(child_metadata.st_mode)
                                        or self._directory_identity(child_metadata) != identity
                                    ):
                                        fail("indirect-control evidence directory changed during bounded tree scan")
                                finally:
                                    os.close(child_fd)
                                directory_facts[relative] = identity
                                pending.append(((*parts, name), relative, identity))
                                continue
                            if not stat.S_ISREG(metadata.st_mode):
                                fail(f"indirect-control evidence tree contains a non-regular evidence file: {relative}")
                            if self._allowed_files is not None and relative not in self._allowed_files:
                                fail(f"indirect-control evidence root contains an unexpected path: {relative}")
                            if files_seen >= self._max_files:
                                fail("indirect-control evidence root exceeds its file-count bound")
                            files_seen += 1
                            limit = self._file_limit_resolver(relative)
                            if type(limit) is not int or limit < 0:
                                fail("indirect-control evidence file-limit policy is invalid")
                            if metadata.st_size < 0 or metadata.st_size > limit:
                                fail(f"indirect-control evidence file exceeds its per-file byte limit: {relative}")
                            total += metadata.st_size
                            if total > self._max_total_bytes:
                                fail("indirect-control evidence root exceeds its aggregate byte limit")
                            facts[relative] = self._file_identity(metadata)
                finally:
                    os.close(directory_fd)

            if self._expected_files is not None:
                missing_files = self._expected_files - facts.keys()
                if missing_files:
                    fail(f"indirect-control evidence root is missing required file: {min(missing_files)}")
            if self._expected_directories is not None:
                missing_directories = self._expected_directories - directory_facts.keys()
                if missing_directories:
                    fail(f"indirect-control evidence root is missing required directory: {min(missing_directories)}")
            if self._directory_identity(os.fstat(root_fd)) != root_identity:
                fail("indirect-control evidence root changed during bounded tree scan")
            return facts, directory_facts, root_identity
        except OSError as error:
            fail(f"indirect-control evidence tree cannot be inspected safely: {error}")
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    def preflight(self) -> None:
        self._facts, self._directory_facts, self._root_identity = self._scan_tree()
        self._preflighted = True

    def _open_relative(self, relative: str) -> int:
        parts = _safe_relative(relative)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory_flag is None:
            fail("indirect-control evidence reads require audited no-follow directory flags")
        root_fd = -1
        directory_fd = -1
        try:
            root_fd = os.open(
                self._root_path,
                os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
            )
            root_metadata = os.fstat(root_fd)
            if self._root_identity != self._directory_identity(root_metadata):
                fail("indirect-control evidence root changed after bounded tree preflight")
            directory_fd = root_fd
            parent = ""
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow,
                    dir_fd=directory_fd,
                )
                next_relative = f"{parent}/{part}".lstrip("/")
                next_metadata = os.fstat(next_fd)
                if (
                    not stat.S_ISDIR(next_metadata.st_mode)
                    or self._directory_identity(next_metadata) != self._directory_facts.get(next_relative)
                ):
                    os.close(next_fd)
                    fail(f"indirect-control evidence directory changed after bounded tree preflight: {next_relative}")
                if directory_fd != root_fd:
                    os.close(directory_fd)
                directory_fd = next_fd
                parent = next_relative
            file_fd = os.open(
                parts[-1],
                os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            return file_fd
        except OSError as error:
            fail(f"indirect-control evidence file cannot be opened safely: {relative}: {error}")
        finally:
            if directory_fd >= 0 and directory_fd != root_fd:
                os.close(directory_fd)
            if root_fd >= 0:
                os.close(root_fd)

    def read(
        self,
        relative: str,
        *,
        limit: int | None = None,
        after_initial_size_validation: Callable[[], None] | None = None,
    ) -> bytes:
        if not self._preflighted:
            fail("indirect-control evidence root was not byte-budgeted before reads")
        _safe_relative(relative)
        fact = self._facts.get(relative)
        if fact is None:
            fail(f"indirect-control evidence file is not in the preflighted tree: {relative}")
        expected_size, expected_device, expected_inode, expected_mtime, expected_ctime = fact
        effective_limit = self._file_limit_resolver(relative)
        if limit is not None:
            if type(limit) is not int or limit < 0:
                fail("indirect-control evidence read limit is invalid")
            effective_limit = min(effective_limit, limit)
        if expected_size > effective_limit:
            fail(f"indirect-control evidence file exceeds its per-file byte limit: {relative}")
        cached = self._bytes.get(relative)
        if cached is not None:
            return cached
        file_fd = self._open_relative(relative)
        try:
            before = os.fstat(file_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size != expected_size
                or before.st_size > effective_limit
                or self._file_identity(before) != fact
            ):
                fail(f"indirect-control evidence file changed after bounded tree preflight: {relative}")
            if after_initial_size_validation is not None:
                after_initial_size_validation()

            # Allocate only after the aggregate preflight and the same open
            # descriptor's type, identity, size and per-file limit are checked.
            result = bytearray(expected_size)
            position = 0
            while position < expected_size:
                chunk = os.read(file_fd, min(1024 * 1024, expected_size - position))
                if not chunk:
                    fail(f"indirect-control evidence file was truncated while reading: {relative}")
                result[position : position + len(chunk)] = chunk
                position += len(chunk)
            growth_probe = os.read(file_fd, 1)
            after = os.fstat(file_fd)
            if growth_probe or self._file_identity(after) != fact or not stat.S_ISREG(after.st_mode):
                fail(f"indirect-control evidence file grew or changed while reading: {relative}")
            data = bytes(result)
            self._bytes[relative] = data
            return data
        except OSError as error:
            fail(f"indirect-control evidence file read failed: {relative}: {error}")
        finally:
            os.close(file_fd)

    def read_path(self, path: Path) -> bytes:
        try:
            relative = path.relative_to(self.root).as_posix()
        except ValueError:
            fail("indirect-control evidence read escaped the active root")
        return self.read(relative)

    @property
    def file_paths(self) -> set[str]:
        if not self._preflighted:
            fail("indirect-control evidence paths were requested before bounded tree preflight")
        return set(self._facts)

    @property
    def directory_paths(self) -> set[str]:
        if not self._preflighted:
            fail("indirect-control evidence directories were requested before bounded tree preflight")
        return set(self._directory_facts)

    def verify_tree_unchanged(self) -> None:
        facts, directory_facts, root_identity = self._scan_tree()
        if (
            self._root_identity != root_identity
            or facts != self._facts
            or directory_facts != self._directory_facts
        ):
            fail("indirect-control evidence tree changed after bounded snapshot validation")

    def verify_manifest(self) -> None:
        manifest_data = self.read("SHA256SUMS")
        try:
            lines = manifest_data.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            fail(f"indirect-control SHA256SUMS is not UTF-8: {error}")
        entries: dict[str, str] = {}
        for line_number, line in enumerate(lines, 1):
            parts = line.split("  ", 1)
            if len(parts) != 2:
                fail(f"indirect-control SHA256SUMS line {line_number} is malformed")
            expected, relative = parts
            require_digest(expected, f"indirect-control SHA256SUMS line {line_number}")
            _safe_relative(relative)
            if relative == "SHA256SUMS" or relative in entries:
                fail("indirect-control SHA256SUMS contains a duplicate or self-referential path")
            data = self.read(relative)
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                fail(f"indirect-control SHA256SUMS hash mismatch: {relative}")
            entries[relative] = expected
        # A nested positive child owns its own SHA256SUMS; like the outer
        # runner, the outer manifest closes all payload files while each
        # directory-level manifest remains an independent closure boundary.
        actual_files = {
            relative for relative in self._facts
            if Path(relative).name != "SHA256SUMS"
        }
        if actual_files != set(entries):
            fail("indirect-control SHA256SUMS is not closed")
        self.verify_tree_unchanged()
        self._manifest_verified = True


def _active_snapshot(root: Path) -> EvidenceRootSnapshot:
    snapshot = _ACTIVE_EVIDENCE_SNAPSHOT
    if snapshot is None or snapshot.root != root or not snapshot._manifest_verified:
        fail("indirect-control evidence bytes were requested before closed-root validation")
    return snapshot


def read_evidence_file(root: Path, relative: str) -> bytes:
    return _active_snapshot(root).read(relative)


def digest(path: Path) -> str:
    if _ACTIVE_EVIDENCE_SNAPSHOT is None:
        fail("indirect-control evidence digest requested outside a validated root")
    return hashlib.sha256(_ACTIVE_EVIDENCE_SNAPSHOT.read_path(path)).hexdigest()


def require_file(root: Path, relative: str) -> Path:
    _safe_relative(relative)
    candidate = root / relative
    if candidate.is_symlink() or not candidate.is_file():
        fail(f"missing indirect-control evidence: {relative}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"path escapes indirect-control root: {relative}")
    return resolved


def read_json(root: Path, relative: str) -> dict[str, Any]:
    try:
        value = json.loads(read_evidence_file(root, relative).decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON evidence {relative}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON evidence is not an object: {relative}")
    return value


def is_int(value: object) -> bool:
    return type(value) is int


def require_int(value: object, label: str) -> int:
    if not is_int(value):
        fail(f"{label} is not an integer")
    return value


def require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def host_status(entry_status: int) -> int:
    return 1 if entry_status < 0 else 255 if entry_status > 255 else entry_status


def check_handoff(
    root: Path,
    relative: str,
    expected_image_hash: str,
) -> dict[str, Any]:
    handoff = read_json(root, relative)
    if (
        handoff.get("schemaVersion") != 1
        or handoff.get("stage") != "host-context-handoff"
        or handoff.get("status") != "passed"
        or handoff.get("loaderId") != "host-context.sealed-memfd.dlopen"
        or handoff.get("nativeImageSha256") != expected_image_hash
        or handoff.get("entrySymbol") != "urp_entry"
        or not is_int(handoff.get("entryStatus"))
        or not is_int(handoff.get("processStatus"))
        or handoff["processStatus"] != host_status(handoff["entryStatus"])
        or handoff.get("releaseStatus") != "passed"
        or handoff.get("releaseOrder") != "entry-dispatch-before-release-image"
        or handoff.get("firstFailureStage") is not None
    ):
        fail(f"HostContext handoff is incomplete or mismatched: {relative}")
    return handoff


def parse_dynamic_symbols(data: bytes, label: str) -> dict[int, tuple[str, int, int, int, int, int, int]]:
    if len(data) < 64:
        fail(f"{label} is truncated before ELF section metadata")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_entry_size, section_count, _section_name_index = struct.unpack_from("<HHH", data, 58)
    if (
        section_entry_size < 64
        or section_count == 0
        or section_count > 4096
        or section_offset > len(data)
        or section_count * section_entry_size > len(data) - section_offset
    ):
        fail(f"{label} has invalid or out-of-bounds section metadata for its fixture dynsym")

    sections: list[tuple[int, ...]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        sections.append(struct.unpack_from("<IIQQQQIIQQ", data, offset))
    dynamic_indexes = [index for index, section in enumerate(sections) if section[1] == 11]
    if len(dynamic_indexes) != 1:
        fail(f"{label} does not contain one unique dynamic symbol table")
    dynamic_index = dynamic_indexes[0]
    dynamic_section = sections[dynamic_index]
    string_index = dynamic_section[6]
    if string_index >= len(sections) or sections[string_index][1] != 3:
        fail(f"{label} dynamic symbol table has no linked string table")
    string_section = sections[string_index]
    string_offset, string_size = string_section[4], string_section[5]
    symbol_offset, symbol_size, symbol_entry_size = dynamic_section[4], dynamic_section[5], dynamic_section[9]
    if (
        symbol_entry_size < 24
        or symbol_size % symbol_entry_size != 0
        or symbol_size // symbol_entry_size > 1_048_576
        or string_offset > len(data)
        or string_size > len(data) - string_offset
        or symbol_offset > len(data)
        or symbol_size > len(data) - symbol_offset
    ):
        fail(f"{label} dynamic symbol or string table is malformed or out of bounds")

    strings = data[string_offset : string_offset + string_size]
    symbols: dict[int, tuple[str, int, int, int, int, int, int]] = {}
    for index in range(symbol_size // symbol_entry_size):
        offset = symbol_offset + index * symbol_entry_size
        name_offset, info, other, section_index, value, size = struct.unpack_from("<IBBHQQ", data, offset)
        if name_offset >= len(strings):
            fail(f"{label} dynamic symbol name offset is outside its string table")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            fail(f"{label} dynamic symbol name is not terminated")
        try:
            name = strings[name_offset:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail(f"{label} dynamic symbol name is not valid UTF-8")
        symbols[index] = (name, value, size, info & 0xF, info >> 4, other & 0x3, section_index)
    return symbols


def _external_checked_range(data: bytes, offset: int, size: int, label: str) -> bytes:
    if (
        not is_int(offset)
        or not is_int(size)
        or offset < 0
        or size <= 0
        or offset > len(data)
        or size > len(data) - offset
    ):
        fail(f"{label} is outside the retained ELF bytes")
    return data[offset : offset + size]


def _external_load_map(data: bytes) -> tuple[list[dict[str, int]], dict[str, int]]:
    if (
        len(data) < 64
        or data[:4] != b"\x7fELF"
        or data[4:7] != b"\x02\x01\x01"
    ):
        fail("external-table source is not ELF64 little-endian version 1")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 3 or machine != 183:
        fail("external-table source is not an AArch64 ET_DYN image")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    ehsize, phentsize, phnum = struct.unpack_from("<HHH", data, 52)
    if (
        ehsize != 64
        or phentsize < 56
        or phnum == 0
        or phnum > 4096
        or phoff > len(data)
        or phnum * phentsize > len(data) - phoff
    ):
        fail("external-table source has an invalid or out-of-bounds program-header table")
    segments: list[dict[str, int]] = []
    dynamic_headers: list[dict[str, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_offset > len(data) or p_filesz > len(data) - p_offset or p_filesz > p_memsz:
            fail("external-table source has an invalid program-header file range")
        if p_vaddr + p_memsz > (1 << 64):
            fail("external-table source has an overflowing program-header memory range")
        header = {
            "type": p_type,
            "flags": p_flags,
            "fileOffset": p_offset,
            "virtualAddress": p_vaddr,
            "fileSize": p_filesz,
            "memorySize": p_memsz,
            "alignment": p_align,
        }
        if p_type == 1:
            segments.append(header)
        elif p_type == 2:
            dynamic_headers.append(header)
    if not segments or len(dynamic_headers) != 1:
        fail("external-table source needs PT_LOAD mappings and one bounded PT_DYNAMIC")
    return segments, dynamic_headers[0]


def _external_map_virtual(
    segments: list[dict[str, int]],
    address: int,
    size: int,
    label: str,
    *,
    required_flags: int = 0,
) -> tuple[int, dict[str, int]]:
    if (
        not is_int(address)
        or not is_int(size)
        or address < 0
        or size <= 0
        or address + size > (1 << 64)
    ):
        fail(f"{label} has an invalid ELF64 virtual range")
    matches = [
        segment
        for segment in segments
        if address >= segment["virtualAddress"]
        and address + size <= segment["virtualAddress"] + segment["fileSize"]
        and segment["flags"] & required_flags == required_flags
    ]
    if len(matches) != 1:
        fail(f"{label} is not uniquely file-backed by the required PT_LOAD permissions")
    segment = matches[0]
    file_offset = segment["fileOffset"] + address - segment["virtualAddress"]
    if file_offset > (1 << 64) - size:
        fail(f"{label} file mapping overflows ELF64")
    return file_offset, segment


def _external_dynamic_tags(data: bytes, dynamic_header: dict[str, int]) -> dict[int, list[int]]:
    size = dynamic_header["fileSize"]
    if size == 0 or size % 16 != 0 or size // 16 > 65536:
        fail("external-table PT_DYNAMIC has an invalid bounded entry count")
    raw = _external_checked_range(data, dynamic_header["fileOffset"], size, "PT_DYNAMIC")
    tags: dict[int, list[int]] = {}
    terminated = False
    for offset in range(0, len(raw), 16):
        tag, value = struct.unpack_from("<qQ", raw, offset)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    if not terminated:
        fail("external-table PT_DYNAMIC has no bounded DT_NULL terminator")
    return tags


def _external_one_tag(tags: dict[int, list[int]], tag: int, label: str, *, required: bool = True) -> int | None:
    values = tags.get(tag, [])
    if len(values) > 1 or (required and len(values) != 1):
        fail(f"external-table dynamic metadata has a missing or duplicate {label}")
    return values[0] if values else None


def _external_symbol_count(
    data: bytes,
    segments: list[dict[str, int]],
    gnu_hash_address: int,
) -> int:
    header_offset, _ = _external_map_virtual(segments, gnu_hash_address, 16, "DT_GNU_HASH header")
    nbuckets, symbol_offset, bloom_size, _bloom_shift = struct.unpack_from("<IIII", data, header_offset)
    if (
        nbuckets == 0
        or nbuckets > 1_048_576
        or symbol_offset == 0
        or symbol_offset > 1_048_576
        or bloom_size == 0
        or bloom_size > 1_048_576
    ):
        fail("external-table DT_GNU_HASH dimensions exceed bounded symbol limits")
    prefix_size = 16 + bloom_size * 8 + nbuckets * 4
    if prefix_size > 16 * 1024 * 1024:
        fail("external-table DT_GNU_HASH header tables exceed the bounded byte limit")
    prefix_offset, _ = _external_map_virtual(
        segments, gnu_hash_address, prefix_size, "DT_GNU_HASH bloom and bucket tables"
    )
    bucket_start = prefix_offset + 16 + bloom_size * 8
    chain_address = gnu_hash_address + prefix_size
    buckets = struct.unpack_from(f"<{nbuckets}I", data, bucket_start)
    symbol_count = symbol_offset
    for bucket in buckets:
        if bucket == 0:
            continue
        if bucket < symbol_offset or bucket >= 1_048_576:
            fail("external-table DT_GNU_HASH bucket has an invalid symbol index")
        symbol_index = bucket
        for _ in range(1_048_576):
            chain_index = symbol_index - symbol_offset
            chain_va = chain_address + chain_index * 4
            chain_file_offset, _ = _external_map_virtual(
                segments, chain_va, 4, "DT_GNU_HASH symbol chain"
            )
            chain_word = struct.unpack_from("<I", data, chain_file_offset)[0]
            symbol_count = max(symbol_count, symbol_index + 1)
            if chain_word & 1:
                break
            symbol_index += 1
            if symbol_index >= 1_048_576:
                fail("external-table DT_GNU_HASH symbol chain exceeds the bounded symbol limit")
        else:
            fail("external-table DT_GNU_HASH symbol chain is unterminated")
    if symbol_count == 0 or symbol_count > 1_048_576:
        fail("external-table DT_GNU_HASH produced an invalid dynamic symbol count")
    return symbol_count


def _external_symbols(
    data: bytes,
    segments: list[dict[str, int]],
    tags: dict[int, list[int]],
) -> dict[int, dict[str, int | str]]:
    symtab = _external_one_tag(tags, 6, "DT_SYMTAB")
    syment = _external_one_tag(tags, 11, "DT_SYMENT")
    strtab = _external_one_tag(tags, 5, "DT_STRTAB")
    strsz = _external_one_tag(tags, 10, "DT_STRSZ")
    gnu_hash = _external_one_tag(tags, 0x6FFFFEF5, "DT_GNU_HASH")
    if syment != 24 or strsz is None or strsz == 0 or strsz > 16 * 1024 * 1024:
        fail("external-table dynamic symbol/string table dimensions are unsupported or unbounded")
    assert symtab is not None and strtab is not None and gnu_hash is not None
    symbol_count = _external_symbol_count(data, segments, gnu_hash)
    symbol_offset, _ = _external_map_virtual(
        segments, symtab, symbol_count * syment, "DT_SYMTAB"
    )
    string_offset, _ = _external_map_virtual(segments, strtab, strsz, "DT_STRTAB")
    strings = _external_checked_range(data, string_offset, strsz, "DT_STRTAB")
    names = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 6: "TLS"}
    bindings = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
    visibility_names = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}
    symbols: dict[int, dict[str, int | str]] = {}
    for index in range(symbol_count):
        entry_offset = symbol_offset + index * syment
        name_offset, info, other, section_index, value, size = struct.unpack_from(
            "<IBBHQQ", data, entry_offset
        )
        if name_offset >= len(strings):
            fail("external-table dynamic symbol has a name offset outside DT_STRTAB")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            fail("external-table dynamic symbol name is not terminated")
        try:
            name = strings[name_offset:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("external-table dynamic symbol name is not valid UTF-8")
        symbol_type = info & 0xF
        binding = info >> 4
        visibility = other & 0x3
        symbols[index] = {
            "symbolIndex": index,
            "name": name,
            "value": value,
            "size": size,
            "typeId": symbol_type,
            "type": names.get(symbol_type, f"UNKNOWN_{symbol_type}"),
            "bindingId": binding,
            "binding": bindings.get(binding, f"UNKNOWN_{binding}"),
            "other": other,
            "visibilityId": visibility,
            "visibility": visibility_names.get(visibility, f"UNKNOWN_{visibility}"),
            "sectionIndex": section_index,
        }
    return symbols


def _external_relocations(
    data: bytes,
    segments: list[dict[str, int]],
    tags: dict[int, list[int]],
) -> tuple[list[dict[str, int | bool]], list[dict[str, int | bool]]]:
    rela_address = _external_one_tag(tags, 7, "DT_RELA")
    rela_size = _external_one_tag(tags, 8, "DT_RELASZ")
    rela_entry_size = _external_one_tag(tags, 9, "DT_RELAENT")
    if (
        rela_address is None
        or rela_size is None
        or rela_entry_size != 24
        or rela_size == 0
        or rela_size % 24 != 0
        or rela_size // 24 > 1_048_576
    ):
        fail("external-table DT_RELA tuple is incomplete or outside bounded RELA limits")
    rela_file_offset, _ = _external_map_virtual(segments, rela_address, rela_size, "DT_RELA")

    def decode_table(address: int, size: int, label: str, is_plt: bool) -> list[dict[str, int | bool]]:
        if size == 0 or size % 24 != 0 or size // 24 > 1_048_576:
            fail(f"{label} has an invalid bounded RELA size")
        file_offset, _ = _external_map_virtual(segments, address, size, label)
        rows: list[dict[str, int | bool]] = []
        for index in range(size // 24):
            row_offset = file_offset + index * 24
            relocation_offset, info, addend = struct.unpack_from("<QQq", data, row_offset)
            rows.append({
                "offset": relocation_offset,
                "info": info,
                "symbolIndex": info >> 32,
                "type": info & 0xFFFFFFFF,
                "addend": addend,
                "fileOffset": row_offset,
                "isPlt": is_plt,
            })
        return rows

    regular = decode_table(rela_address, rela_size, "non-PLT DT_RELA", False)
    plt_rows: list[dict[str, int | bool]] = []
    plt_address = _external_one_tag(tags, 23, "DT_JMPREL", required=False)
    plt_size = _external_one_tag(tags, 2, "DT_PLTRELSZ", required=False)
    plt_kind = _external_one_tag(tags, 20, "DT_PLTREL", required=False)
    if any(value is not None for value in (plt_address, plt_size, plt_kind)):
        if plt_address is None or plt_size is None or plt_kind != 7:
            fail("external-table PLT relocation tuple is incomplete or is not DT_RELA")
        plt_rows = decode_table(plt_address, plt_size, "DT_JMPREL", True)
    return regular, plt_rows


def _external_sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _external_adrp_target(word: int, address: int) -> int:
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    target = (address & ~0xFFF) + (_external_sign_extend(immediate, 21) << 12)
    if target < 0 or target >= (1 << 64):
        fail("external-table ADRP page calculation overflows ELF64")
    return target


def _external_adr_target(word: int, address: int) -> int:
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    target = address + _external_sign_extend(immediate, 21)
    if target < 0 or target >= (1 << 64):
        fail("external-table ADR target calculation overflows ELF64")
    return target


def inspect_external_table_image(data: bytes, selected_function: str) -> dict[str, Any]:
    segments, dynamic_header = _external_load_map(data)
    dynamic_file_offset, _ = _external_map_virtual(
        segments,
        dynamic_header["virtualAddress"],
        dynamic_header["fileSize"],
        "PT_DYNAMIC runtime mapping",
        required_flags=4,
    )
    if dynamic_file_offset != dynamic_header["fileOffset"]:
        fail("external-table PT_DYNAMIC file and virtual mappings disagree")
    tags = _external_dynamic_tags(data, dynamic_header)
    symbols = _external_symbols(data, segments, tags)
    selected_match = re.fullmatch(r"dynsym:([0-9]+)", selected_function)
    if selected_match is None:
        fail("external-table producer selector is not a dynamic-symbol identity")
    selected_index = int(selected_match.group(1), 10)
    entry_indexes = [index for index, symbol in symbols.items() if symbol["name"] == "urp_entry"]
    if len(entry_indexes) != 1 or selected_index != entry_indexes[0]:
        fail("external-table source does not bind the selected dynsym identity to one urp_entry")
    entry = symbols[selected_index]
    if (
        entry["typeId"] != 2
        or entry["bindingId"] != 1
        or entry["visibilityId"] != 0
        or entry["other"] != 0
        or entry["sectionIndex"] == 0
        or entry["value"] == 0
        or entry["size"] == 0
        or entry["size"] % 4 != 0
    ):
        fail("external-table selected dynamic function is not one defined global default-visible STT_FUNC")
    function_file_offset, function_segment = _external_map_virtual(
        segments, int(entry["value"]), int(entry["size"]), "selected urp_entry", required_flags=1
    )

    imported_indexes = [
        index for index, symbol in symbols.items() if symbol["name"] == "urp_external_jump_table"
    ]
    if len(imported_indexes) != 1:
        fail("external-table source does not contain one unique imported table dynsym identity")
    imported_index = imported_indexes[0]
    imported = symbols[imported_index]
    if (
        imported_index == 0
        or imported["typeId"] != 1
        or imported["bindingId"] != 1
        or imported["visibilityId"] != 0
        or imported["other"] != 0
        or imported["sectionIndex"] != 0
        or imported["value"] != 0
        or imported["size"] != 0
    ):
        fail("external-table dynsym is not a zero-sized undefined global default-visible STT_OBJECT")

    regular_relocations, plt_relocations = _external_relocations(data, segments, tags)
    matching_relocations = [
        row for row in regular_relocations
        if row["type"] == 1025 and row["symbolIndex"] == imported_index
    ]
    matching_plt = [
        row for row in plt_relocations
        if row["type"] == 1025 and row["symbolIndex"] == imported_index
    ]
    if len(matching_relocations) != 1 or matching_plt:
        fail("external-table import does not own exactly one non-PLT R_AARCH64_GLOB_DAT row")
    relocation = matching_relocations[0]
    same_slot_relocations = [
        row for row in regular_relocations + plt_relocations if row["offset"] == relocation["offset"]
    ]
    if same_slot_relocations != [relocation]:
        fail("external-table GOT pointer slot has duplicate or conflicting dynamic relocation owners")
    if relocation["addend"] != 0:
        fail("external-table R_AARCH64_GLOB_DAT addend is not zero")
    got_address = int(relocation["offset"])
    if got_address % 8 != 0:
        fail("external-table GLOB_DAT GOT slot is not 8-byte aligned")
    got_file_offset, got_segment = _external_map_virtual(
        segments, got_address, 8, "external-table GLOB_DAT GOT pointer slot", required_flags=6
    )
    got_bytes = _external_checked_range(data, got_file_offset, 8, "external-table GOT pointer slot")

    instruction_count = int(entry["size"]) // 4
    if instruction_count > 1_000_000:
        fail("external-table selected function exceeds the bounded instruction limit")
    words = [
        struct.unpack_from("<I", data, function_file_offset + index * 4)[0]
        for index in range(instruction_count)
    ]
    candidates: list[dict[str, int]] = []
    for index in range(max(0, len(words) - 7)):
        cmp_word, bhi_word, adrp_word, ldr_word, ldrsw_word, adr_word, add_word, br_word = words[index : index + 8]
        is_cmp = (
            cmp_word & 0x7F00001F == 0x7100001F
            and (cmp_word >> 5) & 0x1F == 0
            and (cmp_word >> 10) & 0xFFF == 3
            and (cmp_word >> 22) & 1 == 0
        )
        is_bhi = bhi_word & 0xFF00001F == 0x54000008
        is_adrp = adrp_word & 0x9F000000 == 0x90000000 and adrp_word & 0x1F == 9
        is_got_ldr = (
            ldr_word & 0xFFC00000 == 0xF9400000
            and ldr_word & 0x1F == 9
            and (ldr_word >> 5) & 0x1F == 9
        )
        is_ldrsw = (
            ldrsw_word & 0xFFE00C00 == 0xB8A00800
            and ldrsw_word & 0x1F == 2
            and (ldrsw_word >> 5) & 0x1F == 9
            and (ldrsw_word >> 16) & 0x1F == 0
            and (ldrsw_word >> 13) & 0x7 == 2
            and (ldrsw_word >> 12) & 1 == 1
        )
        is_adr = adr_word & 0x9F000000 == 0x10000000 and adr_word & 0x1F == 3
        is_add = (
            add_word & 0xFFE0FC00 == 0x8B000000
            and add_word & 0x1F == 1
            and (add_word >> 5) & 0x1F == 3
            and (add_word >> 16) & 0x1F == 2
        )
        is_br = br_word & 0xFFFFFC1F == 0xD61F0000 and (br_word >> 5) & 0x1F == 1
        if is_cmp and is_bhi and is_adrp and is_got_ldr and is_ldrsw and is_adr and is_add and is_br:
            candidates.append({"instructionIndex": index})
    if len(candidates) != 1:
        fail("external-table selected function does not contain one unique guarded GOT/LDRSW/relative-target/BR chain")

    start_index = candidates[0]["instructionIndex"]
    start_address = int(entry["value"]) + start_index * 4
    selected_words = words[start_index : start_index + 8]
    cmp_address, bhi_address, adrp_address, ldr_address, ldrsw_address, adr_address, add_address, br_address = (
        start_address + index * 4 for index in range(8)
    )
    branch_displacement = _external_sign_extend((selected_words[1] >> 5) & 0x7FFFF, 19) * 4
    default_target = bhi_address + branch_displacement
    function_start = int(entry["value"])
    function_end = function_start + int(entry["size"])
    default_return_size = 2 * 4
    default_return_start = function_end - default_return_size
    dispatch_chain_end = br_address + 4
    if (
        default_target < 0
        or default_target >= (1 << 64)
        or default_return_start < function_start
        or default_return_start < dispatch_chain_end
        or default_target != default_return_start
    ):
        fail("external-table B.HI taken edge is unsafe: target is not the final bounded default-return block")
    default_file_offset = function_file_offset + default_return_start - function_start
    default_bytes = _external_checked_range(
        data, default_file_offset, default_return_size, "external-table final default-return block"
    )
    default_move_word, default_return_word = struct.unpack("<II", default_bytes)
    # The retained fixture's default is MOV W0, #-1 (MOVN W0, #0), then RET.
    # These exact retained words prove the taken edge terminates before any
    # GOT/indexed-read/relative-dispatch instruction can be reached again.
    if default_move_word != 0x12800000 or default_return_word != 0xD65F03C0:
        fail("external-table B.HI final default-return block does not decode as MOV W0, #-1; RET")
    page_base = _external_adrp_target(selected_words[2], adrp_address)
    got_ldr_offset = ((selected_words[3] >> 10) & 0xFFF) * 8
    computed_got_slot = page_base + got_ldr_offset
    if computed_got_slot != got_address:
        fail("external-table GOT LDR dataflow does not resolve to the imported object's exact GLOB_DAT slot")
    relative_base = _external_adr_target(selected_words[5], adr_address)
    if relative_base != br_address + 4 or relative_base % 4 != 0:
        fail("external-table ADR relative target base does not begin the bounded in-function case body")
    if not (int(entry["value"]) <= relative_base < int(entry["value"]) + int(entry["size"])):
        fail("external-table relative target base is outside selected urp_entry")

    instruction_rows = [
        {"address": address, "word": f"0x{word:08x}"}
        for address, word in zip(
            (cmp_address, bhi_address, adrp_address, ldr_address, ldrsw_address, adr_address, add_address, br_address),
            selected_words,
            strict=True,
        )
    ]
    return {
        "schemaVersion": 1,
        "sourceSha256": hashlib.sha256(data).hexdigest(),
        "elf": {"classBits": 64, "endianness": "little", "type": "ET_DYN", "machine": "EM_AARCH64"},
        "selectedFunction": {
            "symbolIndex": selected_index,
            "name": "urp_entry",
            "binding": entry["binding"],
            "visibility": entry["visibility"],
            "type": entry["type"],
            "sectionIndex": entry["sectionIndex"],
            "value": entry["value"],
            "size": entry["size"],
            "fileOffset": function_file_offset,
            "loadSegmentFlags": function_segment["flags"],
        },
        "importedTableSymbol": {
            "symbolIndex": imported_index,
            "name": imported["name"],
            "binding": imported["binding"],
            "visibility": imported["visibility"],
            "type": imported["type"],
            "other": imported["other"],
            "sectionIndex": imported["sectionIndex"],
            "value": imported["value"],
            "size": imported["size"],
            "sourceStorageRange": None,
        },
        "relocation": {
            "source": "DT_RELA-non-PLT",
            "fileOffset": relocation["fileOffset"],
            "offset": relocation["offset"],
            "info": relocation["info"],
            "type": relocation["type"],
            "typeName": "R_AARCH64_GLOB_DAT",
            "symbolIndex": relocation["symbolIndex"],
            "symbolName": imported["name"],
            "addend": relocation["addend"],
            "isPlt": False,
        },
        "gotSlot": {
            "virtualAddress": got_address,
            "fileOffset": got_file_offset,
            "size": 8,
            "alignment": 8,
            "segmentFlags": got_segment["flags"],
            "initialBytesHex": got_bytes.hex(),
            "role": "external-object-pointer-carrier-not-table-storage",
        },
        "tablePayload": {
            "sourceImageRange": None,
            "storageOwner": "undefined-dynamic-object-import",
            "gotSlotIsTableStorage": False,
            "minimumBoundedReadBytes": 16,
            "entryWidth": 4,
            "entrySigned": True,
            "indexLowerBound": 0,
            "indexUpperBound": 3,
        },
        "instructionBinding": {
            "sequenceStart": start_address,
            "instructions": instruction_rows,
            "guard": {
                "compareAddress": cmp_address,
                "indexRegister": "w0",
                "unsignedUpperBound": 3,
                "branchAddress": bhi_address,
                "branchMnemonic": "B.HI",
                "defaultTarget": default_target,
            },
            "gotAddressProducer": {
                "adrpAddress": adrp_address,
                "destinationRegister": "x9",
                "computedPageBase": page_base,
                "ldrAddress": ldr_address,
                "baseRegister": "x9",
                "destinationRegisterAfterLoad": "x9",
                "unsignedOffset": got_ldr_offset,
                "resolvedSlotAddress": computed_got_slot,
                "relocationSlotAddress": got_address,
            },
            "indexedRead": {
                "address": ldrsw_address,
                "mnemonic": "LDRSW",
                "baseRegister": "x9",
                "indexRegister": "w0",
                "extension": "UXTW",
                "scaleShift": 2,
                "entryWidth": 4,
                "signed": True,
                "destinationRegister": "x2",
            },
            "relativeTarget": {
                "baseAddressInstruction": adr_address,
                "baseRegister": "x3",
                "baseAddress": relative_base,
                "addAddress": add_address,
                "leftRegister": "x3",
                "signedOffsetRegister": "x2",
                "destinationRegister": "x1",
            },
            "indirectBranch": {"address": br_address, "mnemonic": "BR", "targetRegister": "x1"},
        },
    }


def parse_fixture_symbols(
    path: Path,
    selected_function: str,
    source_bytes: bytes,
) -> tuple[dict[str, int], int, int, int]:
    table_pattern = re.compile(r"^Symbol table '([^']+)' contains ")
    row_pattern = re.compile(
        r"^\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$"
    )
    readelf_symbols: dict[int, tuple[str, int, int, str, str, str, str]] = {}
    in_dynamic_symbols = False
    snapshot = _ACTIVE_EVIDENCE_SNAPSHOT
    if snapshot is None:
        fail("source readelf evidence was requested outside a validated root")
    try:
        relative_path = path.relative_to(snapshot.root).as_posix()
    except ValueError:
        fail("source readelf evidence path escaped the validated root")
    try:
        text = read_evidence_file(snapshot.root, relative_path).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"source readelf evidence is not UTF-8: {error}")
    for line in text.splitlines():
        table_match = table_pattern.match(line)
        if table_match:
            in_dynamic_symbols = table_match.group(1) == ".dynsym"
            continue
        if not in_dynamic_symbols:
            continue
        match = row_pattern.match(line)
        if not match:
            continue
        index = int(match.group(1), 10)
        value = (
            match.group(8),
            int(match.group(2), 16),
            int(match.group(3), 10),
            match.group(4),
            match.group(5),
            match.group(6),
            match.group(7),
        )
        if index in readelf_symbols and readelf_symbols[index] != value:
            fail(f"source dynamic symbol index has conflicting rows: {index}")
        readelf_symbols[index] = value

    raw_symbols = parse_dynamic_symbols(source_bytes, "source-image.bin")
    selected_match = re.fullmatch(r"dynsym:([0-9]+)", selected_function)
    if selected_match is None:
        fail("jump-table selected function is not a dynamic-symbol identity")
    selected_index = int(selected_match.group(1), 10)
    selected_readelf = readelf_symbols.get(selected_index)
    selected_raw = raw_symbols.get(selected_index)
    if (
        selected_readelf is None
        or selected_raw is None
        or selected_readelf[0] != "urp_entry"
        or selected_readelf[3] != "FUNC"
        or selected_readelf[1:3] != selected_raw[1:3]
        or selected_readelf[4] != "GLOBAL"
        or selected_readelf[5] != "DEFAULT"
        or selected_readelf[6] != str(selected_raw[6])
        or selected_raw[0] != "urp_entry"
        or selected_raw[3] != 2
        or selected_raw[4] != 1
        or selected_raw[5] != 0
        or selected_raw[6] == 0
        or selected_raw[2] <= 0
    ):
        fail("selected dynamic-symbol identity does not bind the bounded urp_entry function in source ELF bytes")

    symbols_by_name: dict[str, tuple[int, int, str]] = {}
    for index, row in readelf_symbols.items():
        name, value, size, symbol_type, binding, visibility, section = row
        if name not in EXPECTED_CASE_SYMBOLS and name != "urp_jump_table":
            continue
        raw = raw_symbols.get(index)
        type_id = 0 if symbol_type == "NOTYPE" else 2 if symbol_type == "FUNC" else -1
        if (
            raw is None
            or raw[0] != name
            or raw[1:3] != (value, size)
            or raw[3] != type_id
            or raw[4] != 1
            or raw[5] != 0
            or raw[6] == 0
            or binding != "GLOBAL"
            or visibility != "DEFAULT"
            or section != str(raw[6])
        ):
            fail(f"retained source symbol does not match its ELF dynamic symbol entry: {name}")
        current = (value, size, symbol_type)
        if name in symbols_by_name and symbols_by_name[name] != current:
            fail(f"source dynamic symbol has conflicting rows: {name}")
        symbols_by_name[name] = current

    cases = {
        name: symbols_by_name[name][0]
        for name in EXPECTED_CASE_SYMBOLS
        if name in symbols_by_name and symbols_by_name[name][2] == "NOTYPE"
    }
    table = symbols_by_name.get("urp_jump_table")
    if (
        set(cases) != set(EXPECTED_CASE_SYMBOLS)
        or table is None
        or table[1] != 0
        or table[2] != "NOTYPE"
    ):
        fail("retained source dynamic symbols do not identify the bounded table and all four targets")
    return cases, table[0], selected_raw[1], selected_raw[2]


def parse_load_segments(data: bytes, label: str) -> list[dict[str, int]]:
    if (
        len(data) < 64
        or data[:4] != b"\x7fELF"
        or data[4] != 2
        or data[5] != 1
        or data[6] != 1
    ):
        fail(f"{label} is not a bounded ELF64 little-endian image")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 3 or machine != 183:
        fail(f"{label} is not an AArch64 ET_DYN image")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    ehsize, phentsize, phnum = struct.unpack_from("<HHH", data, 52)
    if (
        ehsize != 64
        or phentsize < 56
        or phnum == 0
        or phnum > 4096
        or phoff > len(data)
        or phnum * phentsize > len(data) - phoff
    ):
        fail(f"{label} has an invalid or out-of-bounds program-header table")

    segments: list[dict[str, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_type != 1:
            continue
        if (
            p_offset > len(data)
            or p_filesz > len(data) - p_offset
            or p_filesz > p_memsz
            or p_vaddr + p_memsz > (1 << 64)
        ):
            fail(f"{label} has an invalid PT_LOAD range")
        segments.append(
            {
                "flags": p_flags,
                "fileOffset": p_offset,
                "virtualAddress": p_vaddr,
                "fileSize": p_filesz,
                "memorySize": p_memsz,
            }
        )
    if not segments:
        fail(f"{label} has no PT_LOAD segment")
    return segments


def mapped_file_offset(
    segments: list[dict[str, int]],
    virtual_address: int,
    size: int,
    label: str,
) -> tuple[int, dict[str, int]]:
    if not is_int(virtual_address) or not is_int(size) or size <= 0 or virtual_address + size > (1 << 64):
        fail(f"{label} virtual range is malformed")
    matches = [
        segment
        for segment in segments
        if virtual_address >= segment["virtualAddress"]
        and virtual_address + size <= segment["virtualAddress"] + segment["fileSize"]
    ]
    if len(matches) != 1:
        fail(f"{label} is not uniquely backed by a file range in one PT_LOAD")
    segment = matches[0]
    return segment["fileOffset"] + virtual_address - segment["virtualAddress"], segment


def map_range_values(value: object, label: str) -> tuple[int, int, int]:
    if not isinstance(value, dict) or value.get("hasVirtualAddress") is not True:
        fail(f"{label} does not retain a virtual address")
    file_offset = value.get("fileOffset")
    virtual_address = value.get("virtualAddress")
    size = value.get("size")
    if (
        not isinstance(file_offset, dict)
        or not isinstance(virtual_address, dict)
        or not is_int(file_offset.get("value"))
        or not is_int(virtual_address.get("value"))
        or not is_int(size)
        or size <= 0
    ):
        fail(f"{label} is malformed")
    return file_offset["value"], virtual_address["value"], size


def semantic_range_values(value: object, label: str) -> tuple[int, int, int]:
    if not isinstance(value, dict):
        fail(f"{label} is malformed")
    file_offset = value.get("fileOffset")
    virtual_address = value.get("virtualAddress")
    size = value.get("size")
    if (
        not isinstance(file_offset, dict)
        or not isinstance(virtual_address, dict)
        or not is_int(file_offset.get("value"))
        or not is_int(virtual_address.get("value"))
        or not is_int(size)
        or size <= 0
    ):
        fail(f"{label} is malformed")
    return file_offset["value"], virtual_address["value"], size


def semantic_address(value: object, label: str) -> int:
    if not isinstance(value, dict) or not is_int(value.get("value")):
        fail(f"{label} is malformed")
    address = value["value"]
    if address < 0 or address >= (1 << 64):
        fail(f"{label} is outside the ELF64 address domain")
    return address


def validate_source_output_map(
    layout: dict[str, Any],
    source_bytes: bytes,
    source_segments: list[dict[str, int]],
    native_segments: list[dict[str, int]],
    native_bytes: bytes,
    source_entry: int,
    source_entry_size: int,
    source_targets: list[int],
) -> tuple[int, int, int]:
    address_map = layout.get("addressMap")
    if not isinstance(address_map, list) or not address_map:
        fail("jump-table layout has no address-map bindings")
    matching_output_ranges: list[tuple[int, int, int]] = []
    for binding in address_map:
        if not isinstance(binding, dict):
            continue
        source_file_offset, source_va, source_size = map_range_values(
            binding.get("sourceRange"), "address-map source range"
        )
        output_file_offset, output_va, output_size = map_range_values(
            binding.get("outputRange"), "address-map output range"
        )
        if (
            source_va > source_entry
            or source_entry + source_entry_size > source_va + source_size
            or any(target < source_va or target + 4 > source_va + source_size for target in source_targets)
        ):
            continue
        try:
            mapped_source_offset, source_segment = unique_file_backed_pt_load(
                source_bytes,
                source_segments,
                source_va,
                source_size,
                "selected source address-map complete function range",
                virtual_address_key="virtualAddress",
                file_offset_key="fileOffset",
                file_size_key="fileSize",
                memory_size_key="memorySize",
            )
        except ValueError as error:
            fail(str(error))
        if mapped_source_offset != source_file_offset or source_segment["flags"] & 0x7 != 0x5:
            fail("address-map source range is not complete read-only executable source bytes")
        try:
            mapped_output_offset, output_segment = unique_file_backed_pt_load(
                native_bytes,
                native_segments,
                output_va,
                output_size,
                "selected address-map complete Native Image output range",
                virtual_address_key="virtualAddress",
                file_offset_key="fileOffset",
                file_size_key="fileSize",
                memory_size_key="memorySize",
            )
        except ValueError as error:
            fail(str(error))
        if mapped_output_offset != output_file_offset or output_segment["flags"] & 0x7 != 0x5:
            fail("address-map output range does not bind to complete read-only executable Native Image bytes")
        identity = binding.get("identity")
        source_identity = binding.get("sourceIdentity")
        placements = layout.get("placements")
        if not isinstance(identity, str) or not isinstance(source_identity, str) or not isinstance(placements, list):
            fail("address-map binding has no typed layout placement identity")
        matching_placements = [
            placement
            for placement in placements
            if isinstance(placement, dict)
            and placement.get("identity") == identity
            and placement.get("sourceIdentity") == source_identity
            and placement.get("range") == binding.get("outputRange")
        ]
        if len(matching_placements) != 1:
            fail("address-map output range does not match one unique layout placement")
        matching_output_ranges.append((output_file_offset, output_va, output_size))
    if len(matching_output_ranges) != 1:
        fail("source function and all target symbols are not bound by one unique address-map range")
    return matching_output_ranges[0]


def validate_mapping_placement(
    layout: dict[str, Any],
    binding: dict[str, Any],
    source_range: tuple[int, int, int],
    output_range: tuple[int, int, int],
    label: str,
) -> None:
    placements = layout.get("placements")
    address_map = layout.get("addressMap")
    identity = binding.get("identity")
    source_identity = binding.get("sourceIdentity")
    if (
        not isinstance(placements, list)
        or not isinstance(address_map, list)
        or not isinstance(identity, str)
        or not isinstance(source_identity, str)
    ):
        fail(f"{label} address-map record has no typed placement identity")

    exact_placements = [
        placement
        for placement in placements
        if isinstance(placement, dict)
        and placement.get("identity") == identity
        and placement.get("sourceIdentity") == source_identity
        and placement.get("range") == binding.get("outputRange")
    ]
    if len(exact_placements) == 1:
        return
    if exact_placements:
        fail(f"{label} address-map record matches multiple exact layout placements")

    covering_placements: list[dict[str, Any]] = []
    for placement in placements:
        if not isinstance(placement, dict):
            continue
        parent_output = placement.get("range")
        parent_identity = placement.get("identity")
        parent_source_identity = placement.get("sourceIdentity")
        if not isinstance(parent_identity, str) or not isinstance(parent_source_identity, str):
            continue
        parent_rows = [
            row
            for row in address_map
            if isinstance(row, dict)
            and row.get("identity") == parent_identity
            and row.get("sourceIdentity") == parent_source_identity
            and row.get("outputRange") == parent_output
        ]
        if len(parent_rows) != 1:
            continue
        parent = parent_rows[0]
        parent_source = map_range_values(parent.get("sourceRange"), f"{label} parent source range")
        parent_output_values = map_range_values(parent_output, f"{label} parent output range")
        if (
            source_range[1] < parent_source[1]
            or source_range[1] + source_range[2] > parent_source[1] + parent_source[2]
            or output_range[1] < parent_output_values[1]
            or output_range[1] + output_range[2] > parent_output_values[1] + parent_output_values[2]
        ):
            continue
        covering_placements.append(placement)
    if len(covering_placements) != 1:
        fail(f"{label} address-map record does not bind one unique layout placement")


def validate_jump_table_clone(
    layout: dict[str, Any],
    source_bytes: bytes,
    native_bytes: bytes,
    source_segments: list[dict[str, int]],
    native_segments: list[dict[str, int]],
    source_table_address: int,
    source_table_file_offset: int,
) -> tuple[int, int, str]:
    clones = layout.get("jumpTableClones")
    if not isinstance(clones, list) or len(clones) != 1 or not isinstance(clones[0], dict):
        fail("layout evidence does not retain one unique copied-and-retargeted jump-table clone")
    clone = clones[0]
    table_size = 4 * len(EXPECTED_CASE_INDICES)
    expected_identity = f"0x{source_table_address:X}:4:0:3"
    identity = clone.get("tableIdentity")
    if (
        not isinstance(identity, dict)
        or not is_int(identity.get("kind"))
        or identity.get("kind") != SEMANTIC_ENTITY_KIND_TABLE
        or identity.get("value") != expected_identity
    ):
        fail("jump-table clone identity does not bind the source table symbol and bounded entry shape")

    source_range = semantic_range_values(clone.get("sourceTableRange"), "jump-table clone source range")
    requested_range = semantic_range_values(
        clone.get("requestedOutputRange"), "jump-table clone requested output range"
    )
    output_range = map_range_values(clone.get("outputRange"), "jump-table clone physical output range")
    if (
        source_range != (source_table_file_offset, source_table_address, table_size)
        or requested_range[2] != table_size
        or output_range[2] != table_size
        or min(*source_range[:2], *requested_range[:2], *output_range[:2]) < 0
        or any(value >= (1 << 64) for value in (*source_range, *requested_range, *output_range))
    ):
        fail("jump-table clone ranges do not bind the bounded source table and complete output clone")

    permissions = require_int(clone.get("permissions"), "jump-table clone permissions")
    ownership = require_int(clone.get("ownership"), "jump-table layout ownership ordinal")
    rewrite_policy = require_int(clone.get("rewritePolicy"), "jump-table rewrite-policy ordinal")
    if (
        permissions != LAYOUT_PERMISSION_READ
        or ownership != LAYOUT_OWNERSHIP_AMBIGUOUS
        or rewrite_policy != LAYOUT_REWRITE_COPIED_AND_RETARGETED
        or clone.get("ownerInventoryComplete") is not False
        or clone.get("ownerReferences") != []
    ):
        fail("jump-table clone does not retain the current ambiguous-owner PF_R copy-and-retarget policy")

    try:
        parsed_source_offset, _ = unique_file_backed_pt_load(
            source_bytes,
            source_segments,
            source_table_address,
            table_size,
            "source jump-table symbol range",
            virtual_address_key="virtualAddress",
            file_offset_key="fileOffset",
            file_size_key="fileSize",
            memory_size_key="memorySize",
        )
    except ValueError as error:
        fail(str(error))
    if parsed_source_offset != source_table_file_offset:
        fail("source table symbol range differs from its independent PT_LOAD file mapping")
    source_table = source_bytes[source_table_file_offset:source_table_file_offset + table_size]
    if len(source_table) != table_size:
        fail("source jump-table bytes are truncated")

    try:
        clone_file_offset, clone_segment = unique_file_backed_pt_load(
            native_bytes,
            native_segments,
            output_range[1],
            table_size,
            "Native Image jump-table clone",
            virtual_address_key="virtualAddress",
            file_offset_key="fileOffset",
            file_size_key="fileSize",
            memory_size_key="memorySize",
        )
    except ValueError as error:
        fail(str(error))
    if clone_file_offset != output_range[0] or clone_segment["flags"] != LAYOUT_PERMISSION_READ:
        fail("jump-table clone is not uniquely file-backed by a PF_R-only PT_LOAD range")
    if output_range[1] < source_table_address + table_size and source_table_address < output_range[1] + table_size:
        fail("jump-table output clone overlaps the preserved source-table virtual range")

    try:
        original_file_offset, _ = unique_file_backed_pt_load(
            native_bytes,
            native_segments,
            source_table_address,
            table_size,
            "Native Image preserved original jump table",
            virtual_address_key="virtualAddress",
            file_offset_key="fileOffset",
            file_size_key="fileSize",
            memory_size_key="memorySize",
        )
    except ValueError as error:
        fail(str(error))
    if (
        original_file_offset < clone_file_offset + table_size
        and clone_file_offset < original_file_offset + table_size
    ):
        fail("jump-table output clone overlaps the original table's Native Image bytes")
    if native_bytes[original_file_offset:original_file_offset + table_size] != source_table:
        fail("copy-and-retarget changed the original source jump-table bytes")

    address_map = layout.get("addressMap")
    if not isinstance(address_map, list):
        fail("jump-table clone has no typed layout address-map evidence")
    table_maps = [row for row in address_map if isinstance(row, dict) and row.get("identity") == expected_identity]
    if len(table_maps) != 1:
        fail("jump-table source identity does not have one unique clone address-map row")
    table_map = table_maps[0]
    if (
        table_map.get("sourceIdentity") != expected_identity
        or map_range_values(table_map.get("sourceRange"), "jump-table address-map source range") != source_range
        or map_range_values(table_map.get("outputRange"), "jump-table address-map output range") != output_range
    ):
        fail("jump-table address-map row does not bind the parsed source range to its PF_R clone")
    return clone_file_offset, output_range[1], expected_identity


def sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def decode_adrp(word: int, address: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    target = (address & ~0xFFF) + (sign_extend(immediate, 21) << 12)
    if target < 0 or target >= (1 << 64):
        return None
    return target, word & 0x1F


def decode_add_immediate(word: int) -> tuple[int, int, int] | None:
    # Bit 23 distinguishes ordinary ADD-immediate from tagged ADDG encodings.
    if word & 0xFF800000 != 0x91000000:
        return None
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return word & 0x1F, (word >> 5) & 0x1F, immediate


def decode_adr(word: int, address: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x10000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    target = address + sign_extend(immediate, 21)
    if target < 0 or target >= (1 << 64):
        return None
    return target, word & 0x1F


def validate_live_entry_b_stub(
    image: bytes,
    segments: list[dict[str, int]],
    entry_address: int,
    output_file_offset: int,
    output_address: int,
    output_size: int,
) -> None:
    label = "Native Image urp_entry entry B stub"
    try:
        stub_file_offset, stub_segment = unique_file_backed_pt_load(
            image,
            segments,
            entry_address,
            4,
            label,
            virtual_address_key="virtualAddress",
            file_offset_key="fileOffset",
            file_size_key="fileSize",
            memory_size_key="memorySize",
        )
    except ValueError as error:
        fail(str(error))
    if stub_segment["flags"] & 0x7 != 0x5:
        fail(f"{label} is not file-backed read-only executable output")
    branch_word = struct.unpack_from("<I", image, stub_file_offset)[0]
    if branch_word & 0xFC000000 != 0x14000000:
        fail(f"{label} does not begin with one live unconditional B instruction")
    immediate = branch_word & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    target = entry_address + immediate * 4
    if target < 0 or target >= (1 << 64) - 3:
        fail(f"{label} branch target overflows ELF64")
    if target < output_address or target + 4 > output_address + output_size:
        fail(f"{label} branch target leaves the complete mapped selected-function output range")
    try:
        target_file_offset, target_segment = unique_file_backed_pt_load(
            image,
            segments,
            target,
            4,
            "Native Image urp_entry entry B target",
            virtual_address_key="virtualAddress",
            file_offset_key="fileOffset",
            file_size_key="fileSize",
            memory_size_key="memorySize",
        )
    except ValueError as error:
        fail(str(error))
    if (
        target != output_address
        or target_file_offset != output_file_offset
        or target_segment["flags"] & 0x7 != 0x5
    ):
        fail("Native Image urp_entry entry B target bypasses the exact mapped output function entry")


def validate_relative_table_reference_chain(
    image: bytes,
    segments: list[dict[str, int]],
    code_address: int,
    code_size: int,
    table_address: int,
    target_base_address: int,
    label: str,
) -> tuple[int, int]:
    try:
        code_file_offset, code_segment = unique_file_backed_pt_load(
            image,
            segments,
            code_address,
            code_size,
            f"{label} complete code range",
            virtual_address_key="virtualAddress",
            file_offset_key="fileOffset",
            file_size_key="fileSize",
            memory_size_key="memorySize",
        )
    except ValueError as error:
        fail(str(error))
    if code_segment["flags"] & 0x7 != 0x5 or code_size % 4 != 0:
        fail(f"{label} is not an aligned read-only executable instruction range")
    if code_file_offset > len(image) or code_size > len(image) - code_file_offset:
        fail(f"{label} exceeds its retained image bytes")
    words = struct.unpack_from(f"<{code_size // 4}I", image, code_file_offset)
    matches: list[tuple[int, int]] = []
    for index in range(max(0, len(words) - 5)):
        instruction_address = code_address + index * 4
        page = decode_adrp(words[index], instruction_address)
        low = decode_add_immediate(words[index + 1])
        if page is None or low is None:
            continue
        page_address, page_register = page
        low_destination, low_base, low_immediate = low
        if (
            page_register != 1
            or low_destination != page_register
            or low_base != page_register
            or page_address + low_immediate != table_address
        ):
            continue
        adr = decode_adr(words[index + 3], instruction_address + 12)
        if (
            words[index + 2] != 0xB8A05822
            or adr is None
            or adr != (target_base_address, 3)
            or words[index + 4] != 0x8B020061
            or words[index + 5] != 0xD61F0020
        ):
            continue
        matches.append((instruction_address, instruction_address + 4))
    if len(matches) != 1:
        fail(f"{label} does not contain one exact ADRP/ADD/LDRSW/ADR/ADD/BR dispatch chain")
    return matches[0]


def map_layout_source_address(
    layout: dict[str, Any],
    source_segments: list[dict[str, int]],
    native_segments: list[dict[str, int]],
    native_bytes: bytes,
    source_address: int,
    size: int,
    label: str,
) -> int:
    address_map = layout.get("addressMap")
    placements = layout.get("placements")
    if not isinstance(address_map, list) or not isinstance(placements, list):
        fail("jump-table layout address map or placements are malformed")

    covering_sizes: list[int] = []
    for candidate in address_map:
        if not isinstance(candidate, dict):
            continue
        _candidate_file, candidate_va, candidate_size = map_range_values(
            candidate.get("sourceRange"), f"{label} address-map source range"
        )
        if (
            source_address >= candidate_va
            and source_address + size <= candidate_va + candidate_size
            and source_address + size <= (1 << 64)
        ):
            covering_sizes.append(candidate_size)
    if not covering_sizes:
        fail(f"{label} has no unique retained source-to-output address-map decision")
    most_specific_size = min(covering_sizes)

    matches: list[int] = []
    for binding in address_map:
        if not isinstance(binding, dict):
            continue
        source_file_offset, source_va, source_size = map_range_values(
            binding.get("sourceRange"), f"{label} address-map source range"
        )
        output_file_offset, output_va, output_size = map_range_values(
            binding.get("outputRange"), f"{label} address-map output range"
        )
        if (
            source_address < source_va
            or source_address + size > source_va + source_size
            or source_address + size > (1 << 64)
            or source_size != most_specific_size
        ):
            continue

        source_file, _ = mapped_file_offset(source_segments, source_va, source_size, f"{label} source map")
        if source_file != source_file_offset:
            fail(f"{label} address-map source range disagrees with its source PT_LOAD mapping")
        try:
            mapped_output_file, output_segment = unique_file_backed_pt_load(
                native_bytes,
                native_segments,
                output_va,
                output_size,
                f"{label} complete Native Image output map",
                virtual_address_key="virtualAddress",
                file_offset_key="fileOffset",
                file_size_key="fileSize",
                memory_size_key="memorySize",
            )
        except ValueError as error:
            fail(str(error))
        if mapped_output_file != output_file_offset or output_segment["flags"] & 0x7 != 0x5:
            fail(f"{label} address-map range is not complete read-only executable output")

        validate_mapping_placement(
            layout,
            binding,
            (source_file_offset, source_va, source_size),
            (output_file_offset, output_va, output_size),
            label,
        )

        delta = source_address - source_va
        if delta >= output_size or output_va + delta + size > (1 << 64):
            fail(f"{label} output address is outside the retained layout placement")
        output_address = output_va + delta
        try:
            output_file, output_segment = unique_file_backed_pt_load(
                native_bytes,
                native_segments,
                output_address,
                size,
                f"{label} Native Image output target",
                virtual_address_key="virtualAddress",
                file_offset_key="fileOffset",
                file_size_key="fileSize",
                memory_size_key="memorySize",
            )
        except ValueError as error:
            fail(str(error))
        if output_file != output_file_offset + delta or output_segment["flags"] & 0x7 != 0x5:
            fail(f"{label} output target is not read-only executable file-backed output")
        matches.append(output_address)

    if len(matches) != 1:
        fail(f"{label} has no unique retained source-to-output address-map decision")
    return matches[0]


def validate_jump_table_target_bindings(
    layout: dict[str, Any],
    source_bytes: bytes,
    native_bytes: bytes,
    source_segments: list[dict[str, int]],
    native_segments: list[dict[str, int]],
    source_table_address: int,
    source_table_file_offset: int,
    clone_file_offset: int,
    clone_virtual_address: int,
    source_target_addresses: list[int],
    source_table_values: list[int],
) -> int:
    bindings = layout.get("jumpTableTargetBindings")
    if not isinstance(bindings, list) or len(bindings) != len(EXPECTED_CASE_INDICES):
        fail("layout evidence is missing one unique output target binding per jump-table entry")

    expected_table_identity = f"0x{source_table_address:X}:4:0:3"
    table_size = 4 * len(EXPECTED_CASE_INDICES)
    expected_source_table_range = (source_table_file_offset, source_table_address, table_size)
    if source_table_file_offset > len(source_bytes) or table_size > len(source_bytes) - source_table_file_offset:
        fail("source jump-table bytes are truncated for per-entry target binding")
    source_values_from_bytes = [
        struct.unpack_from("<i", source_bytes, source_table_file_offset + index * 4)[0]
        for index in EXPECTED_CASE_INDICES
    ]
    if source_values_from_bytes != source_table_values:
        fail("per-entry source table values differ from retained source ELF table bytes")
    if not all(isinstance(binding, dict) and is_int(binding.get("entryIndex")) for binding in bindings):
        fail("jump-table target binding has a non-integer entry index")
    ordered = sorted(bindings, key=lambda binding: binding["entryIndex"])
    if [binding["entryIndex"] for binding in ordered] != EXPECTED_CASE_INDICES:
        fail("layout evidence has missing, duplicate, or unknown jump-table entry bindings")

    output_base_addresses: list[int] = []
    for index, binding in enumerate(ordered):
        table_identity = binding.get("tableIdentity")
        entry_identity = binding.get("entryIdentity")
        target_identity = binding.get("targetIdentity")
        target_base_identity = binding.get("targetBaseIdentity")
        if (
            not isinstance(table_identity, dict)
            or not is_int(table_identity.get("kind"))
            or table_identity.get("kind") != SEMANTIC_ENTITY_KIND_TABLE
            or table_identity.get("value") != expected_table_identity
            or not isinstance(entry_identity, dict)
            or not is_int(entry_identity.get("kind"))
            or entry_identity.get("kind") != SEMANTIC_ENTITY_KIND_TABLE_ENTRY
            or entry_identity.get("value") != f"{expected_table_identity}:{index}"
            or not isinstance(target_identity, dict)
            or not is_int(target_identity.get("kind"))
            or target_identity.get("kind") != SEMANTIC_ENTITY_KIND_BASIC_BLOCK
            or target_identity.get("value") != f"0x{source_target_addresses[index]:X}"
            or not isinstance(target_base_identity, dict)
            or not is_int(target_base_identity.get("kind"))
            or target_base_identity.get("kind") != SEMANTIC_ENTITY_KIND_BASIC_BLOCK
            or target_base_identity.get("value") != f"0x{source_target_addresses[0]:X}"
        ):
            fail("jump-table target/entry/base identity differs from the source table and target symbols")

        if semantic_range_values(binding.get("sourceTableRange"), "jump-table source table range") != expected_source_table_range:
            fail("jump-table target binding source table range differs from the source ELF table symbol")
        expected_source_entry_range = (
            source_table_file_offset + index * 4,
            source_table_address + index * 4,
            4,
        )
        if semantic_range_values(binding.get("sourceEntryRange"), "jump-table source entry range") != expected_source_entry_range:
            fail("jump-table target binding entry index/offset does not identify its source ELF table row")
        expected_output_entry_range = (
            clone_file_offset + index * 4,
            clone_virtual_address + index * 4,
            4,
        )
        if semantic_range_values(binding.get("outputEntryRange"), "jump-table output entry range") != expected_output_entry_range:
            fail("jump-table target binding output entry does not identify its unique cloned table row")

        source_target = semantic_address(binding.get("sourceTargetAddress"), "jump-table source target VA")
        source_base = semantic_address(binding.get("sourceTargetBaseAddress"), "jump-table source target base VA")
        output_target = semantic_address(binding.get("outputTargetAddress"), "jump-table output target VA")
        output_base = semantic_address(binding.get("outputTargetBaseAddress"), "jump-table output target base VA")
        entry_width = require_int(binding.get("entryWidth"), "jump-table entry width")
        scale = require_int(binding.get("scale"), "jump-table entry scale")
        addend = require_int(binding.get("addend"), "jump-table entry addend")
        source_encoded = require_int(binding.get("sourceEncodedValue"), "jump-table source entry value")
        output_encoded = require_int(binding.get("outputEncodedValue"), "jump-table output entry value")
        if (
            source_target != source_target_addresses[index]
            or source_base != source_target_addresses[0]
            or entry_width != 4
            or binding.get("isSigned") is not True
            or scale != 1
            or addend != 0
            or source_encoded != source_table_values[index]
            or source_base + source_encoded != source_target
        ):
            fail("jump-table target binding does not reproduce the signed source table target/base facts")

        mapped_target = map_layout_source_address(
            layout, source_segments, native_segments, native_bytes, source_target, 4, f"jump-table target {index}"
        )
        mapped_base = map_layout_source_address(
            layout, source_segments, native_segments, native_bytes, source_base, 4, "jump-table target base"
        )
        if output_target != mapped_target or output_base != mapped_base:
            fail("jump-table output target/base VA differs from the retained layout address-map decision")
        output_base_addresses.append(output_base)

        encoded_delta = output_target - output_base
        encoded_adjusted = encoded_delta - addend
        if encoded_adjusted % scale != 0:
            fail("jump-table output target/base cannot be represented by the retained relative scale")
        expected_output_encoded = encoded_adjusted // scale
        if not (-(1 << 31) <= expected_output_encoded < (1 << 31)):
            fail("jump-table output target/base is outside the signed-32-bit entry range")
        if output_encoded != expected_output_encoded:
            fail("jump-table target binding output VA does not reproduce its encoded value")

        output_entry_offset = clone_file_offset + index * 4
        edit_offset, edit_encoded = table_entry_offsets_for_binding(layout, output_entry_offset)
        if edit_offset != output_entry_offset or edit_encoded != expected_output_encoded:
            fail("jump-table target binding differs from the corresponding cloned-table edit")
        native_entry_file_offset, _ = mapped_file_offset(
            native_segments, clone_virtual_address + index * 4, 4, "Native Image cloned jump-table entry"
        )
        if (
            native_entry_file_offset != output_entry_offset
            or struct.unpack_from("<i", native_bytes, native_entry_file_offset)[0] != expected_output_encoded
        ):
            fail("jump-table output target binding differs from the rewritten clone bytes in the Native Image")

    if len(set(output_base_addresses)) != 1:
        fail("jump-table entries do not retain one common mapped output target base")
    return output_base_addresses[0]


def table_entry_offsets_for_binding(layout: dict[str, Any], expected_offset: int) -> tuple[int, int]:
    edits = layout.get("jumpTableEdits")
    if not isinstance(edits, list):
        fail("layout evidence has no jump-table byte edits")
    matches: list[tuple[int, int]] = []
    for edit in edits:
        if not isinstance(edit, dict) or not is_int(edit.get("kind")) or edit.get("kind") != 8:
            continue
        offset = edit.get("offset")
        if not isinstance(offset, dict) or not is_int(offset.get("value")):
            fail("jump-table edit source offset is malformed")
        if offset["value"] != expected_offset:
            continue
        try:
            encoded = base64.b64decode(edit.get("bytes", ""), validate=True)
        except (ValueError, TypeError):
            fail("jump-table edit bytes are malformed")
        if len(encoded) != 4:
            fail("jump-table edit is not one signed 32-bit entry")
        matches.append((offset["value"], int.from_bytes(encoded, "little", signed=True)))
    if len(matches) != 1:
        fail("jump-table cloned entry has no unique corresponding rewrite edit")
    return matches[0]


def table_entry_offsets(layout: dict[str, Any]) -> tuple[list[int], list[int]]:
    edits = layout.get("jumpTableEdits")
    if not isinstance(edits, list) or len(edits) != len(EXPECTED_CASE_INDICES):
        fail("layout evidence does not retain one rewritten table entry for every case")
    source_offsets: list[int] = []
    target_offsets: list[int] = []
    for edit in edits:
        if not isinstance(edit, dict) or not is_int(edit.get("kind")) or edit.get("kind") != 8:
            fail("layout evidence contains a non-table edit in the jump-table edit set")
        offset = edit.get("offset")
        if not isinstance(offset, dict) or not is_int(offset.get("value")):
            fail("jump-table edit source offset is malformed")
        try:
            encoded = base64.b64decode(edit.get("bytes", ""), validate=True)
        except (ValueError, TypeError):
            fail("jump-table edit bytes are malformed")
        if len(encoded) != 4:
            fail("jump-table edit is not one signed 32-bit entry")
        source_offsets.append(offset["value"])
        target_offsets.append(int.from_bytes(encoded, "little", signed=True))
    if (
        len(set(source_offsets)) != len(source_offsets)
        or sorted(source_offsets) != list(range(min(source_offsets), min(source_offsets) + 4 * len(source_offsets), 4))
        or len(set(target_offsets)) != len(target_offsets)
        or target_offsets[0] != 0
        or target_offsets != sorted(target_offsets)
    ):
        fail("jump-table entry edits do not retain four ordered, distinct target bindings")
    return source_offsets, target_offsets


def check_positive(root: Path, unit: str) -> None:
    positive = root / unit
    try:
        positive.resolve().relative_to(root.resolve())
    except ValueError:
        fail("positive unit path escapes indirect-control root")

    behavior = read_json(root, f"{unit}/jump-table-behavior.json")
    if (
        behavior.get("schemaVersion") != 2
        or behavior.get("unitId") != unit
        or not isinstance(behavior.get("selectedFunction"), str)
        or not re.fullmatch(r"dynsym:[0-9]+", behavior["selectedFunction"])
    ):
        fail("jump-table behavior identity is invalid")

    stage = read_json(root, f"{unit}/stage.json")
    native_metadata = read_json(root, f"{unit}/native-image.json")
    if (
        stage.get("unitId") != unit
        or stage.get("profile") != "host-context-entry"
        or stage.get("status") != "passed"
        or native_metadata.get("unitId") != unit
        or native_metadata.get("artifactRole") != "native-image"
        or native_metadata.get("profile") != "host-context-entry"
        or native_metadata.get("entrySymbol") != "urp_entry"
    ):
        fail("jump-table stage/native-image metadata does not bind the selected entry and host-context-entry profile")

    source_path = require_file(root, f"{unit}/source-image.bin")
    native_path = require_file(root, f"{unit}/native-image.bin")
    source_bytes = read_evidence_file(root, f"{unit}/source-image.bin")
    native_bytes = read_evidence_file(root, f"{unit}/native-image.bin")
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    protected_hash = digest(require_file(root, f"{unit}/protected-image.bin"))
    native_hash = hashlib.sha256(native_bytes).hexdigest()
    for key, expected in (
        ("sourceSha256", source_hash),
        ("protectedSha256", protected_hash),
        ("nativeSha256", native_hash),
    ):
        if require_digest(behavior.get(key), key) != expected:
            fail(f"jump-table behavior {key} does not bind its retained image")

    source_handoff_path = require_file(root, f"{unit}/source-handoff.json")
    target_handoff_path = require_file(root, f"{unit}/handoff.json")
    source_handoff = check_handoff(root, f"{unit}/source-handoff.json", source_hash)
    target_handoff = check_handoff(root, f"{unit}/handoff.json", native_hash)
    if (
        source_handoff["entryStatus"] != EXPECTED_ENTRY_STATUS
        or target_handoff["entryStatus"] != EXPECTED_ENTRY_STATUS
        or source_handoff["processStatus"] != EXPECTED_ENTRY_STATUS
        or target_handoff["processStatus"] != EXPECTED_ENTRY_STATUS
    ):
        fail("source/transformed handoff did not return the complete-table execution oracle status")
    if behavior.get("sourceHandoffSha256") != digest(source_handoff_path):
        fail("jump-table behavior does not bind the measured source handoff record")
    if behavior.get("targetHandoffSha256") != digest(target_handoff_path):
        fail("jump-table behavior does not bind the measured transformed handoff record")

    rehydration = read_json(root, f"{unit}/rehydration.json")
    layout = rehydration.get("layoutEvidence")
    if (
        rehydration.get("schemaVersion") != 1
        or rehydration.get("stage") != "rehydration"
        or rehydration.get("status") != "passed"
        or rehydration.get("sourceSha256") != source_hash
        or rehydration.get("protectedImageSha256") != protected_hash
        or rehydration.get("nativeImageSha256") != native_hash
        or rehydration.get("profile") != "host-context-entry"
        or rehydration.get("entrySymbol") != "urp_entry"
        or not isinstance(layout, dict)
    ):
        fail("jump-table rehydration record does not bind the retained images/profile/selected entry")
    if (
        native_metadata.get("sourceSha256") != source_hash
        or native_metadata.get("nativeImageSha256") != native_hash
        or native_metadata.get("nativeImageSize") != len(native_bytes)
    ):
        fail("Native Image metadata does not bind the exact retained Source/Native bytes")
    if (
        not is_int(layout.get("schemaVersion"))
        or layout.get("schemaVersion") != ELF_LAYOUT_EVIDENCE_SCHEMA_VERSION
    ):
        fail("jump-table layout evidence lacks the current schema v3 clone-preserving contract")
    if layout.get("sourceSha256") != source_hash or layout.get("outputSha256") != native_hash:
        fail("jump-table layout evidence does not bind the retained source and Native Image")
    edit_offsets, output_target_offsets = table_entry_offsets(layout)
    if (
        not is_int(behavior.get("jumpTableEditCount"))
        or behavior.get("jumpTableEditCount") != len(EXPECTED_CASE_INDICES)
    ):
        fail("jump-table behavior does not retain all four table edits")
    if not isinstance(layout.get("addressMap"), list):
        fail("jump-table layout has no address-map bindings")
    if (
        not is_int(behavior.get("addressMapBindings"))
        or behavior.get("addressMapBindings") != len(layout["addressMap"])
    ):
        fail("jump-table behavior address-map count differs from rehydration evidence")
    if behavior.get("targetResolutionMode") != "bounded-relative-table":
        fail("jump-table target-resolution mode is not the promoted bounded relative table")

    source_symbols, source_table_address, source_entry_address, source_entry_size = parse_fixture_symbols(
        require_file(root, f"{unit}/source-readelf.txt"), behavior["selectedFunction"], source_bytes
    )
    selected_index = int(behavior["selectedFunction"].split(":", 1)[1])
    source_entry_record = parse_dynamic_symbols(source_bytes, "source-image.bin").get(selected_index)
    native_entry_record = parse_dynamic_symbols(native_bytes, "native-image.bin").get(selected_index)
    if (
        source_entry_record is None
        or native_entry_record != source_entry_record
        or source_entry_record[0] != "urp_entry"
        or source_entry_record[1] != source_entry_address
        or source_entry_record[2] != source_entry_size
        or source_entry_record[3] != 2
        or source_entry_record[4] != 1
        or source_entry_record[5] != 0
        or source_entry_record[6] == 0
    ):
        fail("selected Native Image dynsym identity does not exactly match source urp_entry and requested profile")
    source_target_addresses = [source_symbols[name] for name in EXPECTED_CASE_SYMBOLS]
    if (
        source_entry_size <= 0
        or any(address < source_entry_address or address + 4 > source_entry_address + source_entry_size for address in source_target_addresses)
        or any(address % 4 != 0 for address in source_target_addresses)
    ):
        fail("source jump-table targets are outside the selected, instruction-aligned urp_entry range")

    source_segments = parse_load_segments(source_bytes, "source-image.bin")
    native_segments = parse_load_segments(native_bytes, "native-image.bin")
    _, source_entry_segment = mapped_file_offset(
        source_segments, source_entry_address, source_entry_size, "selected urp_entry function"
    )
    if source_entry_segment["flags"] & 1 == 0:
        fail("selected urp_entry source range is not in an executable PT_LOAD")
    table_size = 4 * len(EXPECTED_CASE_INDICES)
    source_table_file_offset, _ = mapped_file_offset(
        source_segments, source_table_address, table_size, "source jump-table symbol range"
    )
    source_table_values = [
        struct.unpack_from("<i", source_bytes, source_table_file_offset + index * 4)[0]
        for index in EXPECTED_CASE_INDICES
    ]
    expected_source_values = [
        address - source_target_addresses[0]
        for address in source_target_addresses
    ]
    if source_table_values != expected_source_values:
        fail("source jump-table bytes do not encode the retained source target-symbol deltas")

    source_producers = validate_relative_table_reference_chain(
        source_bytes,
        source_segments,
        source_entry_address,
        source_entry_size,
        source_table_address,
        source_target_addresses[0],
        "source urp_entry",
    )
    clone_file_offset, clone_virtual_address, table_identity = validate_jump_table_clone(
        layout,
        source_bytes,
        native_bytes,
        source_segments,
        native_segments,
        source_table_address,
        source_table_file_offset,
    )
    expected_edit_offsets = [clone_file_offset + index * 4 for index in EXPECTED_CASE_INDICES]
    if edit_offsets != expected_edit_offsets:
        fail("jump-table edits are not confined to the four entries in the distinct output clone")

    clone_rows = layout["jumpTableClones"]
    producer_rows = clone_rows[0].get("tableReferenceProducers")
    if (
        not isinstance(producer_rows, list)
        or len(producer_rows) != 2
        or any(not isinstance(row, dict) for row in producer_rows)
        or any(not is_int(row.get("instructionAddress")) or not is_int(row.get("kind")) for row in producer_rows)
    ):
        fail("jump-table clone does not retain its exact selected consumer producer chain")
    producer_rows = sorted(producer_rows, key=lambda row: row["instructionAddress"])
    if [
        (row["instructionAddress"], row["kind"])
        for row in producer_rows
    ] != [(source_producers[0], 1), (source_producers[1], 2)]:
        fail("jump-table clone producer facts differ from the independently decoded source reference chain")

    output_code_file_offset, output_code_address, output_code_size = validate_source_output_map(
        layout,
        source_bytes,
        source_segments,
        native_segments,
        native_bytes,
        source_entry_address,
        source_entry_size,
        source_target_addresses,
    )
    output_target_base = validate_jump_table_target_bindings(
        layout,
        source_bytes,
        native_bytes,
        source_segments,
        native_segments,
        source_table_address,
        source_table_file_offset,
        clone_file_offset,
        clone_virtual_address,
        source_target_addresses,
        source_table_values,
    )
    if output_code_file_offset > len(native_bytes) or output_code_size > len(native_bytes) - output_code_file_offset:
        fail("selected generated code range exceeds its Native Image bytes")
    validate_live_entry_b_stub(
        native_bytes,
        native_segments,
        source_entry_address,
        output_code_file_offset,
        output_code_address,
        output_code_size,
    )
    validate_relative_table_reference_chain(
        native_bytes,
        native_segments,
        output_code_address,
        output_code_size,
        clone_virtual_address,
        output_target_base,
        "transformed urp_entry",
    )
    if table_identity != f"0x{source_table_address:X}:4:0:3":
        fail("jump-table clone identity differs from the independently parsed source table symbol")

    facts = behavior.get("targetSelectionFacts")
    expected_facts = {
        "caseIndices": EXPECTED_CASE_INDICES,
        "caseResults": EXPECTED_CASE_RESULTS,
        "caseTargetSymbols": EXPECTED_CASE_SYMBOLS,
        "sourceTargetAddresses": source_target_addresses,
        "rewrittenTargetOffsets": output_target_offsets,
        "expectedTraceValue": EXPECTED_TRACE,
        "traceAcceptanceEntryStatus": EXPECTED_ENTRY_STATUS,
        "observation": TRACE_OBSERVATION,
    }
    if facts != expected_facts:
        fail("jump-table target-selection facts differ from retained source symbols and rewritten table entries")
    if len(edit_offsets) != len(facts["caseIndices"]):
        fail("jump-table clone edits do not bind every declared target index")

    streams = {
        name: read_evidence_file(root, f"{unit}/{name}")
        for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr")
    }
    if max(map(len, streams.values())) > 1024 * 1024:
        fail("jump-table retained behavior streams exceed the evidence bound")
    stream_hashes = {
        "baselineStdoutSha256": hashlib.sha256(streams["baseline.stdout"]).hexdigest(),
        "baselineStderrSha256": hashlib.sha256(streams["baseline.stderr"]).hexdigest(),
        "transformedStdoutSha256": hashlib.sha256(streams["target.stdout"]).hexdigest(),
        "transformedStderrSha256": hashlib.sha256(streams["target.stderr"]).hexdigest(),
    }
    status_equal = (
        source_handoff["status"] == target_handoff["status"] == "passed"
        and source_handoff["entryStatus"] == target_handoff["entryStatus"]
        and source_handoff["processStatus"] == target_handoff["processStatus"]
        and source_handoff["releaseStatus"] == target_handoff["releaseStatus"] == "passed"
    )
    stdout_equal = streams["baseline.stdout"] == streams["target.stdout"]
    stderr_equal = streams["baseline.stderr"] == streams["target.stderr"]
    recomputed = {
        "baselineStatus": source_handoff["processStatus"],
        "transformedStatus": target_handoff["processStatus"],
        "baselineEntryStatus": source_handoff["entryStatus"],
        "transformedEntryStatus": target_handoff["entryStatus"],
        **stream_hashes,
        "statusEqual": status_equal,
        "stdoutEqual": stdout_equal,
        "stderrEqual": stderr_equal,
    }
    for key, expected in recomputed.items():
        if behavior.get(key) != expected:
            fail(f"jump-table behavior {key} differs from recomputed handoff/stream evidence")
    if not (status_equal and stdout_equal and stderr_equal):
        fail("jump-table source/transformed handoff or byte-stream comparison failed")
    if behavior.get("firstFailureStage") is not None:
        fail("successful jump-table evidence records a failure stage")


def dynamic_symbol_by_name(data: bytes, symbol_name: str, label: str) -> tuple[str, int, int, int, int, int, int]:
    symbols = parse_dynamic_symbols(data, label)
    matches = [symbol for symbol in symbols.values() if symbol[0] == symbol_name]
    if len(matches) != 1:
        fail(f"{label} does not contain one defined dynamic symbol {symbol_name}")
    symbol = matches[0]
    if symbol[6] == 0:
        fail(f"{label} dynamic symbol {symbol_name} is undefined")
    return symbol


def in_load_memory_range(segment: dict[str, int], address: int, size: int) -> bool:
    return (
        address >= segment["virtualAddress"]
        and size <= segment["memorySize"]
        and address - segment["virtualAddress"] <= segment["memorySize"] - size
    )


def in_executable_file_range(segments: list[dict[str, int]], address: int, size: int) -> bool:
    return any(
        segment["flags"] & 1 != 0
        and address >= segment["virtualAddress"]
        and size <= segment["fileSize"]
        and address - segment["virtualAddress"] <= segment["fileSize"] - size
        for segment in segments
    )


def validate_relative_table_negative(root: Path, negative_name: str) -> dict[str, str]:
    input_path = require_file(root, f"{negative_name}/input-image.bin")
    source_path = require_file(root, f"{negative_name}/source-image.bin")
    mutation_path = require_file(root, f"{negative_name}/mutation.json")
    input_bytes = read_evidence_file(root, f"{negative_name}/input-image.bin")
    source_bytes = read_evidence_file(root, f"{negative_name}/source-image.bin")
    mutation = read_json(root, f"{negative_name}/mutation.json")
    input_segments = parse_load_segments(input_bytes, f"{negative_name}/input-image.bin")
    source_segments = parse_load_segments(source_bytes, f"{negative_name}/source-image.bin")
    if len(input_bytes) != len(source_bytes):
        fail(f"{negative_name} mutation changed the source image length")

    table_symbol = dynamic_symbol_by_name(input_bytes, "urp_jump_table", f"{negative_name}/input-image.bin")
    base_symbol = dynamic_symbol_by_name(input_bytes, "urp_jump_table_case0", f"{negative_name}/input-image.bin")
    function_symbol = dynamic_symbol_by_name(input_bytes, "urp_entry", f"{negative_name}/input-image.bin")
    if function_symbol[3] != 2 or function_symbol[2] <= 0:
        fail(f"{negative_name} source urp_entry symbol is not a bounded function")
    case_symbols = [
        dynamic_symbol_by_name(input_bytes, f"urp_jump_table_case{index}", f"{negative_name}/input-image.bin")
        for index in EXPECTED_CASE_INDICES
    ]
    table_address = table_symbol[1]
    target_base = base_symbol[1]
    table_size = len(EXPECTED_CASE_INDICES) * 4
    table_file_offset, _ = mapped_file_offset(input_segments, table_address, table_size, "negative source jump table")
    source_table_file_offset, _ = mapped_file_offset(source_segments, table_address, table_size, "mutated source jump table")
    if source_table_file_offset != table_file_offset:
        fail(f"{negative_name} mutation changed the table's PT_LOAD file mapping")

    expected_input_values = [symbol[1] - target_base for symbol in case_symbols]
    input_values = [
        struct.unpack_from("<i", input_bytes, table_file_offset + index * 4)[0]
        for index in EXPECTED_CASE_INDICES
    ]
    if input_values != expected_input_values:
        fail(f"{negative_name} exact input bytes do not encode the four bounded case targets")
    function_start = function_symbol[1]
    function_end = function_start + function_symbol[2]
    if function_end > (1 << 64) or any(
        target < function_start
        or target + 4 > function_end
        or not in_executable_file_range(input_segments, target, 4)
        for target in (symbol[1] for symbol in case_symbols)
    ):
        fail(f"{negative_name} input table does not begin with four executable in-function targets")

    entry_index = mutation.get("entryIndex")
    if not is_int(entry_index) or entry_index != 0:
        fail(f"{negative_name} mutation does not identify the bounded first table entry")
    entry_address = table_address + entry_index * 4
    entry_file_offset = table_file_offset + entry_index * 4
    original_value = input_values[entry_index]
    mutated_value = struct.unpack_from("<i", source_bytes, source_table_file_offset + entry_index * 4)[0]
    computed_target = target_base + mutated_value
    if computed_target < 0 or computed_target + 4 > (1 << 64):
        fail(f"{negative_name} recomputed table target overflows the ELF64 address range")
    reconstructed_source = bytearray(input_bytes)
    struct.pack_into("<i", reconstructed_source, entry_file_offset, mutated_value)
    if bytes(reconstructed_source) != source_bytes or mutated_value == original_value:
        fail(f"{negative_name} source bytes are not exactly the declared one-entry mutation")
    if source_bytes[entry_file_offset + 4 : table_file_offset + table_size] != input_bytes[entry_file_offset + 4 : table_file_offset + table_size]:
        fail(f"{negative_name} mutation changed another relative jump-table entry")

    target_symbol_name: str | None = None
    mutation_kind = EXPECTED_MUTATION_KINDS[negative_name]
    if mutation_kind == "out-of-closure-executable-target":
        target_symbol_name = "urp_jump_table_outside_closure"
        outside_symbol = dynamic_symbol_by_name(
            input_bytes, target_symbol_name, f"{negative_name}/input-image.bin"
        )
        if (
            outside_symbol[3] != 2
            or computed_target != outside_symbol[1]
            or not in_executable_file_range(input_segments, computed_target, 4)
            or not any(in_load_memory_range(segment, computed_target, 4) for segment in input_segments)
            or function_start <= computed_target < function_end
            or computed_target % 4 != 0
        ):
            fail(f"{negative_name} target is not a distinct in-image executable address outside urp_entry")
    else:
        if (
            mutated_value != 0x7FFFFFE0
            or in_executable_file_range(input_segments, computed_target, 4)
            or any(in_load_memory_range(segment, computed_target, 4) for segment in input_segments)
        ):
            fail(f"{negative_name} computed target is not genuinely outside every executable/load image range")

    expected_mutation = {
        "schemaVersion": 1,
        "mutationKind": mutation_kind,
        "inputSha256": digest(input_path),
        "sourceSha256": digest(source_path),
        "tableSymbol": "urp_jump_table",
        "tableAddress": table_address,
        "tableFileOffset": table_file_offset,
        "tableSize": table_size,
        "entryIndex": entry_index,
        "entryAddress": entry_address,
        "entryFileOffset": entry_file_offset,
        "entryWidth": 4,
        "isSigned": True,
        "targetBaseSymbol": "urp_jump_table_case0",
        "targetBaseAddress": target_base,
        "originalEncodedValue": original_value,
        "mutatedEncodedValue": mutated_value,
        "computedTargetAddress": computed_target,
        "targetSymbol": target_symbol_name,
    }
    if mutation != expected_mutation:
        fail(f"{negative_name} mutation facts differ from independently parsed source/table bytes and load ranges")
    return {
        "inputSourceSha256": digest(input_path),
        "mutationSha256": digest(mutation_path),
    }


def check_positive_reuse(root: Path, unit: str) -> None:
    reuse = read_json(root, "positive-reuse.json")
    if (
        reuse.get("schemaVersion") != 1
        or reuse.get("unitId") != unit
        or reuse.get("reuseMode") != "existing-schema-2-positive-evidence-copy"
        or reuse.get("positiveExecutionRerun") is not False
        or not isinstance(reuse.get("sourceEvidenceRoot"), str)
        or not reuse["sourceEvidenceRoot"]
    ):
        fail("positive reuse record does not identify a non-rerun accepted schema-2 evidence copy")
    require_digest(reuse.get("sourceEvidenceManifestSha256"), "positive reuse source manifest digest")
    claimed_files = reuse.get("positiveFiles")
    if not isinstance(claimed_files, dict):
        fail("positive reuse record has no copied-file hash inventory")
    prefix = f"{unit}/"
    actual_files = {
        relative[len(prefix):]
        for relative in _active_snapshot(root).file_paths
        if relative.startswith(prefix)
    }
    if actual_files != set(claimed_files):
        fail("positive reuse inventory does not match the copied schema-2 positive evidence")
    for relative, expected in claimed_files.items():
        require_digest(expected, f"positive reuse file hash {relative}")
        if digest(require_file(root, f"{unit}/{relative}")) != expected:
            fail(f"positive reuse copied-file hash mismatch: {relative}")


def validate_producer_command(root: Path, negative_name: str, negative_unit: str, source_path: Path) -> str:
    command_path = require_file(root, f"{negative_name}/producer-command.json")
    command = read_json(root, f"{negative_name}/producer-command.json")
    source_bytes = read_evidence_file(root, f"{negative_name}/source-image.bin")
    if negative_name == "negative-external-table":
        claimed_selection = command.get("selectedFunction")
        if not isinstance(claimed_selection, str):
            fail("negative-external-table producer command omits its selected dynsym identity")
        external_facts = inspect_external_table_image(source_bytes, claimed_selection)
        selected_function = f"dynsym:{external_facts['selectedFunction']['symbolIndex']}"
    else:
        source_symbols = parse_dynamic_symbols(source_bytes, f"{negative_name}/source-image.bin")
        function_indexes = [index for index, symbol in source_symbols.items() if symbol[0] == "urp_entry"]
        if len(function_indexes) != 1:
            fail(f"{negative_name} command source does not have one selected urp_entry dynamic symbol")
        selected_function = f"dynsym:{function_indexes[0]}"
    argv = command.get("argv")
    if not isinstance(argv, list) or not all(isinstance(argument, str) for argument in argv) or len(argv) != 28:
        fail(f"{negative_name} retained producer command has a malformed argument vector")
    assembly_path = argv[1]
    expected_values = {
        0: "dotnet",
        2: "protect-image",
        4: "--artifact",
        6: "--role",
        8: "--manifest",
        10: "--stage",
        12: "--unit",
        13: negative_unit,
        14: "--profile",
        15: "host-context-entry",
        16: "--producer-id",
        17: f"gcc-aarch64-jump-table-{negative_name}",
        18: "--rehydrator",
        19: "urprotect.rehydrator.v1",
        20: "--source-sha256",
        21: digest(source_path),
        22: "--function-id",
        23: selected_function,
        24: "--pass",
        25: "control-flow-flattening",
        26: "--json",
        27: "-",
    }
    path_suffixes = {
        3: f"/{negative_name}/source-image.bin",
        5: f"/{negative_name}/protected-image.bin",
        7: f"/{negative_name}/protected-image.json",
        9: f"/{negative_name}/producer-manifest.txt",
        11: f"/{negative_name}/stage.json",
    }
    if (
        not Path(assembly_path).is_absolute()
        or Path(assembly_path).name != "urprotect.dll"
        or "src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll" not in assembly_path
        or any(argv[index] != expected for index, expected in expected_values.items())
        or any(not Path(argv[index]).is_absolute() or not argv[index].replace("\\\\", "/").endswith(suffix)
               for index, suffix in path_suffixes.items())
        or command != {
            "schemaVersion": 1,
            "workingDirectory": command.get("workingDirectory"),
            "sourceSha256": digest(source_path),
            "selectedFunction": selected_function,
            "unitId": negative_unit,
            "argv": argv,
        }
        or not isinstance(command.get("workingDirectory"), str)
        or not Path(command["workingDirectory"]).is_absolute()
    ):
        fail(f"{negative_name} retained producer command does not bind the exact source and producer invocation")
    return digest(command_path)


def check_negative(root: Path, negative_name: str, parent_unit: str) -> None:
    expected_message = EXPECTED_NEGATIVES[negative_name][0]
    negative_unit = f"{parent_unit}.{negative_name}"
    required = (
        "source-image.bin",
        "producer.stdout",
        "producer.stderr",
        "producer-command.json",
        "producer-exit-status.txt",
        "stage.json",
        "negative-result.json",
    )
    if negative_name in EXPECTED_MUTATION_KINDS:
        required += ("input-image.bin", "mutation.json")
    if negative_name == "negative-external-table":
        required += ("external-table-facts.json",)
    for name in required:
        require_file(root, f"{negative_name}/{name}")

    result = read_json(root, f"{negative_name}/negative-result.json")
    producer_output_path = require_file(root, f"{negative_name}/producer.stdout")
    producer_stderr_path = require_file(root, f"{negative_name}/producer.stderr")
    source_path = require_file(root, f"{negative_name}/source-image.bin")
    stage_path = require_file(root, f"{negative_name}/stage.json")
    producer = read_json(root, f"{negative_name}/producer.stdout")
    stage = read_json(root, f"{negative_name}/stage.json")
    actual_stage = producer.get("stage")
    if (
        producer.get("success") is not False
        or not isinstance(actual_stage, dict)
        or actual_stage != stage
        or actual_stage.get("stage") != "protected-image-producer"
        or actual_stage.get("status") != "failed"
        or actual_stage.get("firstFailureStage") != EXPECTED_FAILURE_STAGE
        or actual_stage.get("publicationComplete") is not False
        or actual_stage.get("transformationStatus") != "failed"
        or actual_stage.get("sourceSha256") != digest(source_path)
    ):
        fail(f"{negative_name} producer output does not prove a failed Protected Image producer stage")

    def has_diagnostic(items: object) -> bool:
        return isinstance(items, list) and any(
            isinstance(item, dict)
            and item.get("severity") == "Error"
            and item.get("code") == "IndirectTargetUnresolved"
            and item.get("message") == expected_message
            for item in items
        )

    if not has_diagnostic(producer.get("diagnostics")) or not has_diagnostic(actual_stage.get("diagnostics")):
        fail(f"{negative_name} producer did not emit its declared stable diagnostic family and message")

    try:
        exit_text = read_evidence_file(root, f"{negative_name}/producer-exit-status.txt").decode("ascii", errors="strict").strip()
        exit_status = int(exit_text, 10)
    except (UnicodeDecodeError, ValueError):
        fail(f"{negative_name} producer exit status is malformed")
    if exit_status == 0 or not is_int(result.get("producerExitStatus")) or result["producerExitStatus"] != exit_status:
        fail(f"{negative_name} producer exit status does not bind the observed failure")

    command_sha256 = validate_producer_command(root, negative_name, negative_unit, source_path)
    expected_record = {
        "schemaVersion": 1,
        "unitId": negative_unit,
        "status": "passed",
        "producerExitStatus": exit_status,
        "producerStdoutSha256": digest(producer_output_path),
        "producerStderrSha256": digest(producer_stderr_path),
        "producerCommandSha256": command_sha256,
        "sourceSha256": digest(source_path),
        "protectedImagePublished": False,
        "nativeImagePublished": False,
        "loaderInvoked": False,
        "expectedDiagnosticFamily": "IndirectTargetUnresolved",
        "expectedDiagnosticMessage": expected_message,
        "firstFailureStage": EXPECTED_FAILURE_STAGE,
    }
    if negative_name in EXPECTED_MUTATION_KINDS:
        expected_record.update(validate_relative_table_negative(root, negative_name))
    elif negative_name == "negative-external-table":
        command = read_json(root, f"{negative_name}/producer-command.json")
        selected_function = command.get("selectedFunction")
        if not isinstance(selected_function, str):
            fail("negative-external-table producer command has no selected function")
        expected_facts = inspect_external_table_image(read_evidence_file(root, f"{negative_name}/source-image.bin"), selected_function)
        facts_path = require_file(root, f"{negative_name}/external-table-facts.json")
        if read_json(root, f"{negative_name}/external-table-facts.json") != expected_facts:
            fail("negative-external-table ELF owner/link facts differ from independent retained-source parsing")
        expected_record["externalTableFactsSha256"] = digest(facts_path)
        if (root / negative_name / "mutation.json").exists() or (root / negative_name / "input-image.bin").exists():
            fail("negative-external-table unexpectedly carries table-mutation artifacts")
    elif (root / negative_name / "mutation.json").exists() or (root / negative_name / "input-image.bin").exists() \
        or (root / negative_name / "external-table-facts.json").exists():
        fail(f"{negative_name} unexpectedly carries table-mutation or external-owner artifacts")
    if result != expected_record:
        fail(f"{negative_name} negative-result.json claims differ from producer output and retained files")

    forbidden_publications = (
        "protected-image.bin",
        "protected-image.json",
        "native-image.bin",
        "native-image.json",
        "rehydration.json",
        "handoff.json",
        "source-handoff.json",
        "target-loader.json",
        "loader-invocation.json",
    )
    for name in forbidden_publications:
        if (root / negative_name / name).exists() or (root / negative_name / name).is_symlink():
            fail(f"{negative_name} published or invoked a downstream image/loader artifact: {name}")


def check_closed_manifest(root: Path) -> None:
    global _ACTIVE_EVIDENCE_SNAPSHOT
    snapshot = EvidenceRootSnapshot(root)
    # Account for every file and reject special entries before reading the
    # manifest, hashing a file, allocating image bytes, or parsing evidence.
    snapshot.preflight()
    snapshot.verify_manifest()
    _ACTIVE_EVIDENCE_SNAPSHOT = snapshot


def read_bounded_external_file(path: Path, limit: int, label: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail(f"{label} requires an audited no-follow file open")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > limit:
            fail(f"{label} is not a bounded regular file")
        data = bytearray(before.st_size)
        position = 0
        while position < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - position))
            if not chunk:
                fail(f"{label} was truncated while reading")
            data[position : position + len(chunk)] = chunk
            position += len(chunk)
        growth_probe = os.read(descriptor, 1)
        after = os.fstat(descriptor)
        if (
            growth_probe or not stat.S_ISREG(after.st_mode)
            or after.st_size != before.st_size or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            fail(f"{label} grew or changed while reading")
        return bytes(data)
    except OSError as error:
        fail(f"{label} cannot be read safely: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?")
    parser.add_argument("--tier", choices=("pr", "nightly", "release"))
    parser.add_argument("--unit")
    parser.add_argument("--inspect-external-table", type=Path)
    parser.add_argument("--selected-function")
    args = parser.parse_args()
    if args.inspect_external_table is not None:
        if args.root is not None or args.tier is not None or args.unit is not None or not args.selected_function:
            parser.error("--inspect-external-table requires only --selected-function and no evidence-root arguments")
        source = read_bounded_external_file(
            args.inspect_external_table,
            MAX_EVIDENCE_IMAGE_BYTES,
            "external-table source ELF",
        )
        facts = inspect_external_table_image(source, args.selected_function)
        print(json.dumps(facts, sort_keys=True, indent=2))
        return
    if args.root is None or args.tier is None or not args.unit:
        parser.error("evidence checking requires ROOT --tier TIER --unit UNIT")
    try:
        root = resolve_isolated_evidence_root(args.root, "indirect-control evidence root")
    except ValueError as error:
        fail(str(error))
    check_closed_manifest(root)
    check_positive(root, args.unit)
    if (root / "positive-reuse.json").exists():
        check_positive_reuse(root, args.unit)
    for negative_name in EXPECTED_NEGATIVES:
        check_negative(root, negative_name, args.unit)
    _active_snapshot(root).verify_tree_unchanged()
    print("Indirect-control evidence valid: all table cases, measured handoff/streams, and four fail-closed negatives")


if __name__ == "__main__":
    main()
