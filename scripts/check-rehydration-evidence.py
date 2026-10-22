#!/usr/bin/env python3
"""Validate hash-bound Protected Image -> Native Image -> execveat evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import types
sys.dont_write_bytecode = True
from pathlib import Path, PureWindowsPath
from typing import Any

DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_FILES = 1000
MAX_DIRECTORIES = 512  # Includes the evidence root.
MAX_ENTRIES = 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_SOURCE_IMAGE_BYTES = 128 * 1024 * 1024
MAX_NATIVE_IMAGE_BYTES = 128 * 1024 * 1024
MAX_PROTECTED_IMAGE_BYTES = 16 * 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
UNIT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
LAYOUT_STRATEGIES = frozenset({
    "existing-rx-load-extension",
    "available-program-header-slot",
    "relocated-program-header-table",
})
LAYOUT_DEFAULT = "generic-elf-layout-v1"


def _load_native_runtime_identity_helper() -> Any:
    helper_path = Path(__file__).resolve(strict=True).with_name("native_runtime_identity.py")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ImportError("runtime identity helper load requires O_NOFOLLOW")
    descriptor = os.open(helper_path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > 1024 * 1024:
            raise ImportError("runtime identity helper exceeds its bounded regular-file contract")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ImportError("runtime identity helper was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ImportError("runtime identity helper grew while reading")
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after) or not stat.S_ISREG(after.st_mode):
            raise ImportError("runtime identity helper changed while reading")
    finally:
        os.close(descriptor)
    source = b"".join(chunks)
    module_name = f"_urprotect_rehydration_runtime_identity_{hashlib.sha256(source).hexdigest()[:16]}"
    module = types.ModuleType(module_name)
    namespace = types.ModuleType.__getattribute__(module, "__dict__")
    namespace["__file__"] = str(helper_path)
    namespace["__package__"] = ""
    exec(compile(source, str(helper_path), "exec"), namespace)
    return module


_RUNTIME_IDENTITY_HELPER = _load_native_runtime_identity_helper()


def fail(message: str) -> None:
    raise SystemExit(message)


def _file_limit(relative: str) -> int:
    name = PureWindowsPath(relative).name
    if name == "SHA256SUMS":
        return MAX_MANIFEST_BYTES
    if name == "source-image.bin":
        return MAX_SOURCE_IMAGE_BYTES
    if name == "native-image.bin":
        return MAX_NATIVE_IMAGE_BYTES
    if name == "protected-image.bin":
        return MAX_PROTECTED_IMAGE_BYTES
    if name.endswith((".stdout", ".stderr")):
        return MAX_STREAM_BYTES
    if name.endswith(".json"):
        return MAX_RECORD_BYTES
    return MAX_FILE_BYTES


class BoundedEvidenceTree:
    """No-follow bounded snapshot for a standalone rehydration evidence root."""

    @staticmethod
    def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
        return metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns

    @staticmethod
    def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return metadata.st_size, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns

    def __init__(self, root: Path) -> None:
        self.root = Path(os.path.abspath(root))
        self.files: dict[str, tuple[int, int, int, int, int]] = {}
        self.directories: dict[str, tuple[int, int, int, int]] = {}
        self.root_identity: tuple[int, int, int, int] | None = None
        self.preflighted = False

    def _scan(self) -> tuple[dict[str, tuple[int, int, int, int, int]], dict[str, tuple[int, int, int, int]], tuple[int, int, int, int]]:
        directory_flag = getattr(os, "O_DIRECTORY", None)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if directory_flag is None or nofollow is None:
            fail("rehydration evidence scans require no-follow directory flags")
        try:
            resolved_root = self.root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            fail(f"rehydration evidence root cannot be resolved safely: {error}")
        if resolved_root != self.root:
            fail("rehydration evidence root must not contain symlink path components")
        files: dict[str, tuple[int, int, int, int, int]] = {}
        directories: dict[str, tuple[int, int, int, int]] = {}
        total_bytes = 0
        entries_seen = 0
        files_seen = 0
        directories_seen = 1
        root_fd = -1
        pending: list[tuple[tuple[str, ...], str, tuple[int, int, int, int] | None]] = [((), "", None)]
        try:
            root_fd = os.open(self.root, os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow)
            root_metadata = os.fstat(root_fd)
            if not stat.S_ISDIR(root_metadata.st_mode):
                fail("rehydration evidence root is not a non-symlink directory")
            root_identity = self._directory_identity(root_metadata)
            if self.root_identity is not None and root_identity != self.root_identity:
                fail("rehydration evidence root changed after bounded tree preflight")
            directories[""] = root_identity

            while pending:
                parts, relative_directory, expected_identity = pending.pop()
                directory_fd = os.dup(root_fd)
                opened_relative = ""
                try:
                    directory_identity = self._directory_identity(os.fstat(directory_fd))
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
                            or opened_identity != directories.get(opened_relative)
                        ):
                            fail("rehydration evidence directory changed during bounded tree scan")
                        directory_identity = opened_identity
                    if relative_directory and expected_identity != directories.get(relative_directory):
                        fail("rehydration evidence directory changed during bounded tree scan")
                    with os.scandir(directory_fd) as children:
                        for child in children:
                            name = child.name
                            relative = f"{relative_directory}/{name}".lstrip("/")
                            safe_relative(relative, "rehydration evidence tree path")
                            entries_seen += 1
                            if entries_seen > MAX_ENTRIES:
                                fail("rehydration evidence entry count exceeds its configured bound")
                            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            if stat.S_ISLNK(metadata.st_mode):
                                fail(f"rehydration evidence tree contains a symlink: {relative}")
                            if stat.S_ISDIR(metadata.st_mode):
                                if directories_seen >= MAX_DIRECTORIES:
                                    fail("rehydration evidence directory count exceeds its configured bound")
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
                                        fail("rehydration evidence directory changed during bounded tree scan")
                                finally:
                                    os.close(child_fd)
                                directories[relative] = identity
                                pending.append(((*parts, name), relative, identity))
                                continue
                            if not stat.S_ISREG(metadata.st_mode):
                                fail(f"rehydration evidence tree contains a non-regular file: {relative}")
                            if files_seen >= MAX_FILES:
                                fail("rehydration evidence file count exceeds its configured bound")
                            files_seen += 1
                            limit = _file_limit(relative)
                            if metadata.st_size < 0 or metadata.st_size > limit:
                                fail(f"rehydration evidence file exceeds its per-file byte bound: {relative}")
                            total_bytes += metadata.st_size
                            if total_bytes > MAX_TREE_BYTES:
                                fail("rehydration evidence exceeds the bounded tree size")
                            files[relative] = self._file_identity(metadata)
                    if self._directory_identity(os.fstat(directory_fd)) != directory_identity:
                        fail("rehydration evidence directory changed while scanning")
                finally:
                    os.close(directory_fd)
            if self._directory_identity(os.fstat(root_fd)) != root_identity:
                fail("rehydration evidence root changed during bounded tree scan")
            return files, directories, root_identity
        except OSError as error:
            fail(f"rehydration evidence tree cannot be inspected safely: {error}")
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    def preflight(self) -> None:
        self.files, self.directories, self.root_identity = self._scan()
        self.preflighted = True

    def file_size(self, relative: str) -> int | None:
        fact = self.files.get(relative)
        return fact[0] if fact is not None else None

    def read(self, relative: str, limit: int | None = None) -> bytes:
        if not self.preflighted or self.root_identity is None:
            fail("rehydration evidence root was not bounded before reads")
        safe_relative(relative, "rehydration evidence path")
        fact = self.files.get(relative)
        if fact is None:
            fail(f"rehydration evidence file is outside the preflighted tree: {relative}")
        file_limit = _file_limit(relative)
        if limit is not None:
            file_limit = min(file_limit, limit)
        if fact[0] < 0 or fact[0] > file_limit:
            fail(f"rehydration evidence file exceeds its read bound: {relative}")
        directory_flag = getattr(os, "O_DIRECTORY", None)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        root_fd = -1
        directory_fd = -1
        file_fd = -1
        parts = Path(relative).parts
        try:
            root_fd = os.open(self.root, os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow)
            if self._directory_identity(os.fstat(root_fd)) != self.root_identity:
                fail("rehydration evidence root changed after bounded tree preflight")
            directory_fd = root_fd
            parent = ""
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow, dir_fd=directory_fd)
                next_relative = f"{parent}/{part}".lstrip("/")
                next_metadata = os.fstat(next_fd)
                if (
                    not stat.S_ISDIR(next_metadata.st_mode)
                    or self._directory_identity(next_metadata) != self.directories.get(next_relative)
                ):
                    os.close(next_fd)
                    fail(f"rehydration evidence directory changed after preflight: {next_relative}")
                if directory_fd != root_fd:
                    os.close(directory_fd)
                directory_fd = next_fd
                parent = next_relative
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
            before = os.fstat(file_fd)
            before_identity = self._file_identity(before)
            if not stat.S_ISREG(before.st_mode) or before_identity != fact:
                fail(f"rehydration evidence file changed after preflight: {relative}")
            chunks: list[bytes] = []
            remaining = fact[0]
            while remaining:
                chunk = os.read(file_fd, min(1024 * 1024, remaining))
                if not chunk:
                    fail(f"rehydration evidence file was truncated while reading: {relative}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(file_fd, 1):
                fail(f"rehydration evidence file grew while reading: {relative}")
            after = os.fstat(file_fd)
            if not stat.S_ISREG(after.st_mode) or self._file_identity(after) != before_identity:
                fail(f"rehydration evidence file changed while reading: {relative}")
            return b"".join(chunks)
        except OSError as error:
            fail(f"rehydration evidence file cannot be read safely: {relative}: {error}")
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0 and directory_fd != root_fd:
                os.close(directory_fd)
            if root_fd >= 0:
                os.close(root_fd)

    def verify_unchanged(self) -> None:
        if not self.preflighted:
            fail("rehydration evidence tree was not preflighted")
        files, directories, root_identity = self._scan()
        if files != self.files or directories != self.directories or root_identity != self.root_identity:
            fail("rehydration evidence tree changed after bounded preflight")


_ACTIVE_EVIDENCE_TREE: BoundedEvidenceTree | None = None


def read_evidence_file(path: Path, limit: int) -> bytes:
    if _ACTIVE_EVIDENCE_TREE is not None:
        try:
            relative = path.relative_to(_ACTIVE_EVIDENCE_TREE.root).as_posix()
        except ValueError:
            fail("rehydration evidence read escaped its root")
        return _ACTIVE_EVIDENCE_TREE.read(relative, limit)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        fail("rehydration evidence reads require no-follow file opens")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow | getattr(os, "O_NONBLOCK", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > limit:
            fail(f"rehydration evidence file is not bounded: {path.name}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"rehydration evidence file was truncated: {path.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"rehydration evidence file grew: {path.name}")
        after = os.fstat(descriptor)
        if BoundedEvidenceTree._file_identity(before) != BoundedEvidenceTree._file_identity(after):
            fail(f"rehydration evidence file changed while reading: {path.name}")
        return b"".join(chunks)
    except OSError as error:
        fail(f"rehydration evidence file cannot be read safely: {path.name}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def digest(path: Path) -> str:
    return hashlib.sha256(read_evidence_file(path, MAX_TREE_BYTES)).hexdigest()


def require_file(
    root: Path,
    name: str,
    *,
    allow_empty: bool = False,
    max_bytes: int | None = None,
) -> Path:
    path = root / name
    if _ACTIVE_EVIDENCE_TREE is not None:
        try:
            relative = path.relative_to(_ACTIVE_EVIDENCE_TREE.root).as_posix()
        except ValueError:
            fail("rehydration evidence path escaped its root")
        size = _ACTIVE_EVIDENCE_TREE.file_size(relative)
        if size is None or (not allow_empty and size == 0):
            fail(f"missing or invalid rehydration evidence file: {name}")
        if max_bytes is not None and size > max_bytes:
            fail(f"rehydration evidence file exceeds its bound: {name}")
        return path
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"missing or invalid rehydration evidence file: {name}")
    if not stat.S_ISREG(metadata.st_mode) or (not allow_empty and metadata.st_size == 0):
        fail(f"missing or invalid rehydration evidence file: {name}")
    if max_bytes is not None and metadata.st_size > max_bytes:
        fail(f"rehydration evidence file exceeds its bound: {name}")
    return path


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_evidence_file(path, MAX_RECORD_BYTES).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid evidence JSON {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"evidence record is not an object: {path.name}")
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
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(part in {"", ".", ".."} for part in windows.parts)
    ):
        fail(f"{label} is not a safe relative evidence path: {value!r}")
    return candidate


def check_closed_manifest(root: Path) -> dict[str, str]:
    global _ACTIVE_EVIDENCE_TREE
    snapshot = BoundedEvidenceTree(root)
    snapshot.preflight()
    _ACTIVE_EVIDENCE_TREE = snapshot
    manifest = require_file(snapshot.root, "SHA256SUMS")
    manifest_bytes = snapshot.read("SHA256SUMS", MAX_MANIFEST_BYTES)
    entries: dict[str, str] = {}
    try:
        manifest_text = manifest_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"SHA256SUMS is not UTF-8: {error}")
    for line_number, line in enumerate(manifest_text.splitlines(), 1):
        fields = line.split("  ", 1)
        if len(fields) != 2 or not DIGEST.fullmatch(fields[0]):
            fail(f"invalid SHA256SUMS entry at line {line_number}")
        relative = safe_relative(fields[1], f"SHA256SUMS:{line_number}").as_posix()
        if relative in entries:
            fail(f"duplicate SHA256SUMS path: {relative}")
        if relative not in snapshot.files:
            fail(f"SHA256SUMS references a missing, symlink, or non-file path: {relative}")
        actual = hashlib.sha256(snapshot.read(relative)).hexdigest()
        if actual != fields[0]:
            fail(f"SHA256SUMS digest mismatch: {relative}")
        entries[relative] = actual

    files = set(snapshot.files) - {"SHA256SUMS"}
    for relative in files:
        if relative.endswith(".tmp") or ".tmp." in relative:
            fail(f"evidence tree retains a temporary file: {relative}")
    if files != set(entries):
        fail(f"SHA256SUMS is not closed (missing={sorted(files - set(entries))}, extra={sorted(set(entries) - files)})")
    snapshot.verify_unchanged()
    return entries


def require_digest(value: Any, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{label} is not a normalized SHA-256 digest")


def check_diagnostics(record: dict[str, Any], status: str) -> None:
    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, list) or len(diagnostics) > 128:
        fail("rehydration diagnostics are outside the bounded schema")
    if status == "failed" and not diagnostics:
        fail("failed rehydration stage has no diagnostic")
    for item in diagnostics:
        if not isinstance(item, dict):
            fail("rehydration diagnostic is malformed")
        for field, maximum in (("severity", 16), ("code", 128), ("message", 4096)):
            value = item.get(field)
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
                fail(f"rehydration diagnostic {field} is outside its bound")


def check_producer(root: Path, unit: str) -> tuple[dict[str, Any], dict[str, Any], bytes | None, bytes | None]:
    stage = read_json(require_file(root, "stage.json"))
    if stage.get("schemaVersion") != 1 or stage.get("stage") != "protected-image-producer":
        fail("producer stage schema or identity is unsupported")
    if stage.get("status") not in {"passed", "failed"}:
        fail("producer stage has an unsupported status")
    if stage.get("unitId") != unit:
        fail("producer stage unit does not match the requested unit")
    if stage.get("status") == "failed":
        if (root / "protected-image.bin").exists() or (root / "protected-image.json").exists():
            fail("failed producer stage retained a Protected Image success artifact")
        return stage, {}, None, None

    role = read_json(require_file(root, "protected-image.json"))
    artifact = require_file(root, "protected-image.bin", max_bytes=16 * 1024 * 1024)
    source_path = require_file(root, "source-image.bin", max_bytes=MAX_SOURCE_IMAGE_BYTES)
    source_bytes = read_evidence_file(source_path, MAX_SOURCE_IMAGE_BYTES)
    artifact_bytes = read_evidence_file(artifact, MAX_PROTECTED_IMAGE_BYTES)
    if role.get("schemaVersion") != 1 or role.get("artifactRole") != "protected-image":
        fail("producer role is not a Protected Image v1 role record")
    if role.get("abiId") != "urprotect.protected-image.v1" or role.get("abiVersion") != 1:
        fail("producer role ABI identity is unsupported")
    if role.get("unitId") != unit or stage.get("unitId") != role.get("unitId"):
        fail("producer stage/role unit binding mismatch")
    if role.get("profile") not in {"outer-execveat", "host-context-entry"} or stage.get("profile") != role.get("profile"):
        fail("producer stage/role profile binding mismatch")
    for field in ("sourceSha256", "requestSha256", "producerBuildSha256", "artifactSha256"):
        require_digest(role.get(field), f"producer role {field}")
    for field in ("sourceSha256", "requestSha256", "producerBuildSha256", "artifactSha256"):
        if role.get(field) != stage.get(field):
            fail(f"producer role/stage {field} binding mismatch")
    if digest(source_path) != role["sourceSha256"]:
        fail("retained Source Image hash does not match the producer record")
    if digest(artifact) != role["artifactSha256"] or role.get("artifactSize") != len(artifact_bytes):
        fail("Protected Image bytes do not match the producer role")
    if role.get("rehydratorConsumerId") != stage.get("rehydratorConsumerId"):
        fail("producer consumer binding mismatch")
    if artifact_bytes[:4] != b"UPPI" or len(artifact_bytes) < 52:
        fail("Protected Image is not a bounded ABI v1 artifact")
    if int.from_bytes(artifact_bytes[12:16], "little") != len(artifact_bytes):
        fail("Protected Image declared size does not match the retained artifact")
    if hashlib.sha256(artifact_bytes[:-32]).digest() != artifact_bytes[-32:]:
        fail("Protected Image canonical integrity digest mismatch")
    return stage, role, source_bytes, artifact_bytes


def check_rehydration(
    root: Path,
    unit: str,
    producer_stage: dict[str, Any],
    role: dict[str, Any],
    source: bytes | None,
    protected: bytes | None,
) -> tuple[dict[str, Any], str | None]:
    record = read_json(require_file(root, "rehydration.json"))
    if record.get("schemaVersion") != 1 or record.get("stage") != "rehydration":
        fail("rehydration stage schema or identity is unsupported")
    if record.get("status") not in {"passed", "failed"}:
        fail("rehydration stage has an unsupported status")
    if record.get("unitId") != unit:
        fail("rehydration unit binding mismatch")
    if (
        record.get("abiId") != "urprotect.protected-image.v1"
        or record.get("abiVersion") != 1
        or record.get("architecture") != "AArch64"
        or record.get("layoutStrategy") not in LAYOUT_STRATEGIES | {LAYOUT_DEFAULT}
    ):
        fail("rehydration ABI, architecture, or layout binding is unsupported")
    check_diagnostics(record, record["status"])
    if record["status"] == "passed":
        if record.get("layoutStrategy") not in LAYOUT_STRATEGIES:
            fail("passed rehydration stage does not bind a selected generic ELF layout strategy")
        evidence = record.get("layoutEvidence")
        if not isinstance(evidence, dict):
            fail("passed rehydration stage does not retain bounded layout evidence")
        if evidence.get("strategyValue") != record.get("layoutStrategy"):
            fail("rehydration layout evidence strategy does not match the record")
        for field in ("sourceSha256", "outputSha256", "preservedMetadataSha256"):
            require_digest(evidence.get(field), f"rehydration layoutEvidence.{field}")
        if evidence.get("sourceSha256") != record.get("sourceSha256") or evidence.get("outputSha256") != record.get("nativeImageSha256"):
            fail("rehydration layout evidence digest bindings do not match the record")
        if evidence.get("outputLength") != record.get("nativeImageSize"):
            fail("rehydration layout evidence size does not match the record")
        for field in ("placements", "addressMap", "branchDecisions"):
            value = evidence.get(field)
            if not isinstance(value, list) or len(value) > 4096:
                fail(f"rehydration layout evidence {field} is outside its bound")
        if producer_stage.get("status") != "passed" or role == {} or source is None or protected is None:
            fail("rehydration passed without a passed producer and retained inputs")
        if record.get("firstFailureStage") is not None or record.get("materializationStatus") != "passed":
            fail("passed rehydration stage contains failure state")
        if record.get("handoffRecordPath") != "handoff.json" or record.get("rawEvidenceManifestPath") != "SHA256SUMS":
            fail("rehydration stage does not bind the handoff record and closed evidence manifest")
        handoff = read_json(require_file(root, "handoff.json"))
        require_digest(record.get("handoffRecordSha256"), "rehydration handoff record")
        require_digest(record.get("preHandoffRecordSha256"), "rehydration pre-handoff record")
        if record.get("handoffRecordSha256") != digest(root / "handoff.json"):
            fail("rehydration record does not bind the retained handoff record")
        if record.get("handoffStatus") != handoff.get("status"):
            fail("rehydration record handoff status differs from the handoff record")
        if handoff.get("rehydrationRecordSha256") != record.get("preHandoffRecordSha256"):
            fail("handoff record does not bind the pre-handoff rehydration record")
        bindings = {
            "profile": role["profile"],
            "sourceSha256": role["sourceSha256"],
            "requestSha256": role["requestSha256"],
            "protectedImageSha256": role["artifactSha256"],
            "protectedImageSize": role["artifactSize"],
            "producerId": role["producerId"],
            "producerBuildSha256": role["producerBuildSha256"],
            "consumerId": role["rehydratorConsumerId"],
        }
        for field, expected in bindings.items():
            if record.get(field) != expected:
                fail(f"rehydration {field} binding does not match the producer")
        for field in ("sourceSha256", "requestSha256", "protectedImageSha256", "producerBuildSha256", "consumerBuildSha256", "nativeImageSha256"):
            require_digest(record.get(field), f"rehydration {field}")
        native_path = require_file(root, "native-image.bin", max_bytes=MAX_NATIVE_IMAGE_BYTES)
        native_bytes = read_evidence_file(native_path, MAX_NATIVE_IMAGE_BYTES)
        if len(native_bytes) > MAX_NATIVE_IMAGE_BYTES or len(native_bytes) != record.get("nativeImageSize"):
            fail("Native Image size is outside the bound or differs from the rehydration record")
        if digest(native_path) != record["nativeImageSha256"]:
            fail("Native Image hash differs from the rehydration record")
        if record["nativeImageSha256"] in {role["sourceSha256"], role["artifactSha256"]}:
            fail("Native Image aliases the Source or Protected Image")
        if native_bytes[:6] != b"\x7fELF\x02\x01" or len(native_bytes) < 64:
            fail("Native Image is not ELF64 little-endian")
        if int.from_bytes(native_bytes[18:20], "little") != 183:
            fail("Native Image is not AArch64")
        if native_bytes[16:18] not in {b"\x02\x00", b"\x03\x00"}:
            fail("Native Image type is not ET_EXEC or ET_DYN")
        native_role = read_json(require_file(root, "native-image.json"))
        if native_role.get("schemaVersion") != 1 or native_role.get("artifactRole") != "native-image":
            fail("Native Image role record is unsupported")
        if native_role.get("abiId") != "urprotect.native-image.v1" or native_role.get("abiVersion") != 1:
            fail("Native Image ABI identity is unsupported")
        if native_role.get("nativeImageSha256") != record["nativeImageSha256"] or native_role.get("nativeImageSize") != len(native_bytes):
            fail("Native Image role bytes do not match its rehydration record")
        if native_role.get("rehydrationRecordSha256") != digest(root / "rehydration.json"):
            fail("Native Image role does not bind the retained rehydration record")
        for field, expected in {
            "unitId": record["unitId"],
            "profile": record["profile"],
            "sourceSha256": record["sourceSha256"],
            "protectedImageSha256": record["protectedImageSha256"],
            "producerId": record["producerId"],
            "producerBuildSha256": record["producerBuildSha256"],
            "consumerId": record["consumerId"],
            "consumerBuildSha256": record["consumerBuildSha256"],
        }.items():
            if native_role.get(field) != expected:
                fail(f"Native Image role {field} binding mismatch")
        return record, record["nativeImageSha256"]

    if (root / "native-image.bin").exists() or (root / "native-image.json").exists():
        fail("failed rehydration stage retained a successful Native Image or role record")
    if producer_stage.get("status") == "passed" and role:
        bindings = {
            "profile": role["profile"],
            "sourceSha256": role["sourceSha256"],
            "requestSha256": role["requestSha256"],
            "protectedImageSha256": role["artifactSha256"],
            "protectedImageSize": role["artifactSize"],
            "producerId": role["producerId"],
            "producerBuildSha256": role["producerBuildSha256"],
            "consumerId": role["rehydratorConsumerId"],
        }
        for field, expected in bindings.items():
            if record.get(field) != expected:
                fail(f"failed rehydration {field} does not retain the producer binding")
    if record.get("nativeImageSha256") is not None or record.get("nativeImageSize") is not None:
        fail("failed rehydration record claims Native Image bytes")
    return record, None


def host_context_exit_status(entry_status: int) -> int:
    return 1 if entry_status < 0 else 255 if entry_status > 255 else entry_status


def check_handoff(
    root: Path,
    rehydration: dict[str, Any],
    native_hash: str | None,
    expected_runtime: str,
    require_runtime_identity: bool,
) -> tuple[dict[str, Any], str | None]:
    record = read_json(require_file(root, "handoff.json"))
    if record.get("schemaVersion") == 1 and record.get("stage") == "host-context-handoff":
        if record.get("status") != "passed" or rehydration.get("status") != "passed" or native_hash is None:
            fail("HostContext handoff did not pass after Native Image materialization")
        if record.get("loaderId") != "host-context.sealed-memfd.dlopen":
            fail("HostContext handoff used an unsupported loader identity")
        if record.get("nativeImageSha256") != native_hash:
            fail("HostContext handoff image hash does not match the Native Image")
        if type(record.get("entryStatus")) is not int:
            fail("HostContext handoff entry status is malformed")
        if (
            type(record.get("processStatus")) is not int
            or not 0 <= record["processStatus"] <= 255
            or record["processStatus"] != host_context_exit_status(record["entryStatus"])
            or rehydration.get("processStatus") != record.get("processStatus")
        ):
            fail("HostContext handoff process status does not bind the observed entry status")
        if record.get("releaseStatus") != "passed" or record.get("releaseOrder") != "entry-dispatch-before-release-image":
            fail("HostContext handoff release order did not pass")
        if record.get("rehydrationRecordSha256") != rehydration.get("preHandoffRecordSha256"):
            fail("HostContext handoff does not bind the pre-handoff rehydration record")
        try:
            _RUNTIME_IDENTITY_HELPER.validate_handoff_runtime_identity(
                root,
                record,
                expected_runtime=expected_runtime,
                expected_role="target",
                expected_image_sha256=native_hash,
                required=require_runtime_identity,
            )
        except ValueError as error:
            fail(f"native runtime identity invalid: {error}")
        return record, native_hash
    if record.get("schemaVersion") != 1 or record.get("stage") != "native-handoff":
        fail("native handoff record schema or stage is unsupported")
    if record.get("status") not in {"passed", "failed", "not-run"}:
        fail("native handoff record status is unsupported")
    if record["status"] == "passed":
        if rehydration.get("status") != "passed" or native_hash is None:
            fail("native handoff passed without a passed Native Image stage")
        for field in ("helperStatus", "loaderId", "fchmodStatus", "fsyncStatus", "execveatStatus"):
            if not isinstance(record.get(field), str):
                fail(f"native handoff is missing {field}")
        if record.get("helperStatus") != "passed" or record.get("helperExitCode") != 0:
            fail("native handoff helper status is not a successful helper result")
        if record.get("loaderId") != "kernel.execveat-at-empty-path":
            fail("strict native handoff used an unsupported loader boundary")
        if record.get("nativeImageSha256") != native_hash:
            fail("native handoff image hash does not match the Native Image")
        expected_rehydration_hash = rehydration.get("preHandoffRecordSha256") or digest(root / "rehydration.json")
        if record.get("rehydrationRecordSha256") != expected_rehydration_hash:
            fail("native handoff does not bind the retained rehydration record")
        for field in ("memfdCreated", "sealsSupported", "sealsApplied", "execveatInvoked"):
            if record.get(field) is not True:
                fail(f"strict native handoff did not prove {field}")
        if record.get("fchmodStatus") != "passed" or record.get("fsyncStatus") != "passed" or record.get("execveatStatus") != "passed":
            fail("strict native handoff setup or execveat failed")
        target_status = record.get("targetStatus")
        if not isinstance(target_status, int) or not 0 <= target_status <= 255 or record.get("targetSignal") is not None:
            fail("native handoff target status is malformed")
        stdout = read_evidence_file(require_file(root, "target.stdout", allow_empty=True, max_bytes=MAX_STREAM_BYTES), MAX_STREAM_BYTES)
        stderr = read_evidence_file(require_file(root, "target.stderr", allow_empty=True, max_bytes=MAX_STREAM_BYTES), MAX_STREAM_BYTES)
        if len(stdout) > MAX_STREAM_BYTES or len(stderr) > MAX_STREAM_BYTES:
            fail("native handoff captured streams exceed their output bounds")
        if record.get("stdoutBytes") != len(stdout) or record.get("stderrBytes") != len(stderr):
            fail("native handoff stream byte counts do not match retained streams")
        if record.get("stdoutTruncated") is not False or record.get("stderrTruncated") is not False:
            fail("native handoff streams were truncated on a passing target")
        return record, native_hash

    if record.get("status") == "not-run" and rehydration.get("status") == "passed":
        if record.get("execveatInvoked") is True:
            fail("not-run handoff record claims an execveat invocation")
    elif record.get("status") == "failed" and rehydration.get("status") == "failed":
        if record.get("execveatStatus") == "passed":
            fail("handoff stage passed after failed rehydration")
    if native_hash is not None and record.get("nativeImageSha256") not in {None, native_hash}:
        fail("failed handoff record is bound to a different Native Image")
    if record.get("rehydrationRecordSha256") is not None:
        final_rehydration_hash = digest(root / "rehydration.json")
        pre_handoff_hash = rehydration.get("preHandoffRecordSha256")
        if pre_handoff_hash is not None:
            require_digest(pre_handoff_hash, "rehydration pre-handoff record")
        allowed_rehydration_hashes = {final_rehydration_hash}
        if pre_handoff_hash is not None:
            allowed_rehydration_hashes.add(pre_handoff_hash)
        if record.get("rehydrationRecordSha256") not in allowed_rehydration_hashes:
            fail("handoff record is bound to a different rehydration record")
    return record, None


def check_target_loader(root: Path, handoff: dict[str, Any], handoff_hash: str | None, native_hash: str | None) -> dict[str, Any]:
    record = read_json(require_file(root, "target-loader.json"))
    if record.get("schemaVersion") != 1 or record.get("stage") != "target-loader":
        fail("target loader record schema or identity is unsupported")
    if record.get("status") not in {"passed", "failed", "not-run"}:
        fail("target loader record status is unsupported")
    if record.get("status") == "passed":
        if handoff.get("status") != "passed" or native_hash is None or handoff_hash is None:
            fail("target loader passed without a successful handoff")
        expected_loader = "host-context.sealed-memfd.dlopen" if handoff.get("stage") == "host-context-handoff" else "kernel.execveat-at-empty-path"
        if record.get("loaderId") != expected_loader:
            fail("target loader record names an unsupported loader")
        if record.get("nativeImageSha256") != native_hash or record.get("evidenceSha256") != handoff_hash:
            fail("target loader does not bind the exact Native Image and handoff record")
        expected_target_status = handoff.get("targetStatus", handoff.get("entryStatus"))
        if record.get("targetStatus") != expected_target_status or record.get("targetSignal") != handoff.get("targetSignal"):
            fail("target loader target status differs from the handoff record")
        if handoff.get("stage") == "host-context-handoff" and record.get("targetProcessStatus") != handoff.get("processStatus"):
            fail("target loader process status differs from the observed HostContext process status")
        for stream_name, field in (("target.stdout", "stdoutSha256"), ("target.stderr", "stderrSha256")):
            if record.get(field) != digest(require_file(root, stream_name, allow_empty=True, max_bytes=MAX_STREAM_BYTES)):
                fail(f"target loader {field} does not bind its retained stream")
        return record
    if record.get("status") == "not-run" and handoff.get("status") == "passed":
        fail("target loader was marked not-run after a successful handoff")
    if native_hash is not None and record.get("nativeImageSha256") not in {None, native_hash}:
        fail("target loader failure record binds a different Native Image")
    return record


def check_behavior(
    root: Path,
    record: dict[str, Any],
    target_loader: dict[str, Any],
    source_hash: str | None,
    native_hash: str | None,
    expected_entry_status: int | None = None,
    expected_runtime: str = "glibc",
    require_runtime_identity: bool = False,
) -> dict[str, Any]:
    oracle = read_json(require_file(root, "behavioral-oracle.json"))
    if oracle.get("schemaVersion") != 1 or oracle.get("stage") != "behavioral-oracle":
        fail("behavioral oracle record schema or identity is unsupported")
    if oracle.get("status") not in {"passed", "failed", "not-run"}:
        fail("behavioral oracle status is unsupported")
    if oracle.get("status") in {"passed", "failed"}:
        if oracle.get("status") == "passed" and (target_loader.get("status") != "passed" or native_hash is None):
            fail("behavior oracle passed without a target loader pass")
        if oracle.get("oracleId") == "fixture.host-context-entry.v1":
            if target_loader.get("status") != "passed" or source_hash is None or native_hash is None:
                fail("HostContext behavior oracle passed without source and transformed execution")
            source_handoff_path = require_file(root, "source-handoff.json", max_bytes=MAX_RECORD_BYTES)
            target_handoff_path = require_file(root, "handoff.json", max_bytes=MAX_RECORD_BYTES)
            comparison_path = require_file(root, "behavior-comparison.json", max_bytes=MAX_RECORD_BYTES)
            source_handoff = read_json(source_handoff_path)
            target_handoff = read_json(target_handoff_path)
            comparison = read_json(comparison_path)
            try:
                source_runtime_identity = _RUNTIME_IDENTITY_HELPER.validate_handoff_runtime_identity(
                    root,
                    source_handoff,
                    expected_runtime=expected_runtime,
                    expected_role="source",
                    expected_image_sha256=source_hash,
                    required=require_runtime_identity,
                )
                target_runtime_identity = _RUNTIME_IDENTITY_HELPER.validate_handoff_runtime_identity(
                    root,
                    target_handoff,
                    expected_runtime=expected_runtime,
                    expected_role="target",
                    expected_image_sha256=native_hash,
                    required=require_runtime_identity,
                )
                _RUNTIME_IDENTITY_HELPER.require_same_runtime_identity(source_runtime_identity, target_runtime_identity)
            except ValueError as error:
                fail(f"native runtime identity invalid: {error}")
            stream_values = {
                name: read_evidence_file(require_file(root, name, allow_empty=True, max_bytes=MAX_STREAM_BYTES), MAX_STREAM_BYTES)
                for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr")
            }
            for label, observed, expected_image in (
                ("source", source_handoff, source_hash),
                ("target", target_handoff, native_hash),
            ):
                if (
                    observed.get("schemaVersion") != 1
                    or observed.get("stage") != "host-context-handoff"
                    or observed.get("status") != "passed"
                    or observed.get("loaderId") != "host-context.sealed-memfd.dlopen"
                    or observed.get("nativeImageSha256") != expected_image
                    or observed.get("entrySymbol") != "urp_entry"
                    or type(observed.get("entryStatus")) is not int
                    or type(observed.get("processStatus")) is not int
                    or not 0 <= observed["processStatus"] <= 255
                    or observed["processStatus"] != host_context_exit_status(observed["entryStatus"])
                    or observed.get("releaseStatus") != "passed"
                    or observed.get("releaseOrder") != "entry-dispatch-before-release-image"
                    or observed.get("firstFailureStage") is not None
                ):
                    fail(f"HostContext {label} handoff lacks observed process, entry, or release evidence")
            observed_source_sha = digest(source_handoff_path)
            observed_target_sha = digest(target_handoff_path)
            source_process = source_handoff["processStatus"]
            target_process = target_handoff["processStatus"]
            source_entry = source_handoff["entryStatus"]
            target_entry = target_handoff["entryStatus"]
            expected_entry = oracle.get("expectedEntryStatus")
            if (
                type(expected_entry) is not int
                or (expected_entry_status is not None and expected_entry != expected_entry_status)
                or source_entry != expected_entry
                or target_entry != expected_entry
            ):
                fail("HostContext baseline and transformed entry statuses do not match the explicit expected status")
            source_stdout_sha = digest(require_file(root, "baseline.stdout", allow_empty=True, max_bytes=MAX_STREAM_BYTES))
            source_stderr_sha = digest(require_file(root, "baseline.stderr", allow_empty=True, max_bytes=MAX_STREAM_BYTES))
            target_stdout_sha = digest(require_file(root, "target.stdout", allow_empty=True, max_bytes=MAX_STREAM_BYTES))
            target_stderr_sha = digest(require_file(root, "target.stderr", allow_empty=True, max_bytes=MAX_STREAM_BYTES))
            status_equal = (
                source_handoff["status"] == target_handoff["status"]
                and source_process == target_process
                and source_entry == target_entry
                and source_handoff["releaseStatus"] == target_handoff["releaseStatus"]
            )
            stdout_equal = stream_values["baseline.stdout"] == stream_values["target.stdout"]
            stderr_equal = stream_values["baseline.stderr"] == stream_values["target.stderr"]
            observed_comparison = {
                "schemaVersion": 1,
                "unitId": record.get("unitId"),
                "oracleId": "fixture.host-context-entry.v1",
                "sourceSha256": source_hash,
                "protectedSha256": record.get("protectedImageSha256"),
                "nativeImageSha256": native_hash,
                "sourceHandoffSha256": observed_source_sha,
                "targetHandoffSha256": observed_target_sha,
                "sourceProcessStatus": source_process,
                "targetProcessStatus": target_process,
                "sourceEntryStatus": source_entry,
                "targetEntryStatus": target_entry,
                "sourceReleaseStatus": source_handoff["releaseStatus"],
                "targetReleaseStatus": target_handoff["releaseStatus"],
                "baselineStdoutSha256": source_stdout_sha,
                "baselineStderrSha256": source_stderr_sha,
                "targetStdoutSha256": target_stdout_sha,
                "targetStderrSha256": target_stderr_sha,
                "statusEqual": status_equal,
                "stdoutEqual": stdout_equal,
                "stderrEqual": stderr_equal,
            }
            if comparison != observed_comparison:
                fail("HostContext behavior comparison differs from recomputed source/transformed observations")
            comparison_sha = digest(comparison_path)
            all_equal = status_equal and stdout_equal and stderr_equal
            expected_oracle = {
                **observed_comparison,
                "stage": "behavioral-oracle",
                "status": "passed" if all_equal else "failed",
                "comparisonSha256": comparison_sha,
                "baselineStatus": source_process,
                "targetStatus": target_process,
                "entryStatus": target_entry,
                "expectedEntryStatus": expected_entry,
                "firstFailureStage": None if all_equal else "behavioral-oracle",
            }
            if oracle != expected_oracle:
                fail("HostContext behavioral oracle claims do not match recomputed observations")
            if oracle.get("sourceSha256") != source_hash or oracle.get("nativeImageSha256") != native_hash:
                fail("HostContext behavior oracle source or Native Image binding mismatch")
            if target_loader.get("targetStatus") != target_entry or target_loader.get("targetProcessStatus") != target_process:
                fail("HostContext behavior oracle status differs from the measured target loader result")
            return oracle
        if oracle.get("status") != "passed":
            if native_hash is not None and oracle.get("nativeImageSha256") not in {None, native_hash}:
                fail("failed behavior oracle binds a different Native Image")
            return oracle
        if oracle.get("oracleId") != "fixture.process-oracle.v1":
            fail("behavior oracle identity differs from the frozen fixture oracle")
        if oracle.get("sourceSha256") != source_hash or oracle.get("nativeImageSha256") != native_hash:
            fail("behavior oracle source or Native Image binding mismatch")
        if oracle.get("statusEqual") is False or oracle.get("stdoutEqual") is False or oracle.get("stderrEqual") is False:
            fail("behavior oracle report records a mismatch despite passing")
        if oracle.get("baselineStatus") != 0 or oracle.get("targetStatus") != 0:
            fail("behavior oracle status must match the frozen zero-exit result")
        comparison_path = require_file(root, "behavior-comparison.json")
        comparison = read_json(comparison_path)
        if digest(comparison_path) != oracle.get("comparisonSha256"):
            fail("behavior comparison digest does not match the oracle record")
        for field, value in (("sourceSha256", source_hash), ("nativeImageSha256", native_hash), ("oracleId", oracle["oracleId"])):
            if comparison.get(field) != value:
                fail(f"behavior comparison {field} binding mismatch")
        for baseline, target in (("baseline.stdout", "target.stdout"), ("baseline.stderr", "target.stderr")):
            if read_evidence_file(require_file(root, baseline, allow_empty=True, max_bytes=MAX_STREAM_BYTES), MAX_STREAM_BYTES) != read_evidence_file(require_file(root, target, allow_empty=True, max_bytes=MAX_STREAM_BYTES), MAX_STREAM_BYTES):
                fail("retained baseline and target streams differ")
        if not all(comparison.get(field) is True for field in ("statusEqual", "stdoutEqual", "stderrEqual")):
            fail("behavior comparison failed equivalence")
    elif oracle.get("status") == "not-run" and target_loader.get("status") == "passed":
        fail("behavioral oracle was not run after target loader success")
    if native_hash is not None and oracle.get("nativeImageSha256") not in {None, native_hash}:
        fail("behavior oracle failure binds a different Native Image")
    return oracle

def check_negative_witness(root: Path, unit: str) -> None:
    witness = read_json(require_file(root, "negative-rollback.json"))
    if (
        witness.get("schemaVersion") != 1
        or witness.get("kind") != "strict-chain-negative-witness"
        or witness.get("status") != "passed"
        or witness.get("unitId") != unit
        or witness.get("rollbackStatus") != "passed"
        or witness.get("nativeImagePublished") is not False
        or witness.get("loaderInvoked") is not False
        or witness.get("loaderMarkerObserved") is not False
        or witness.get("stage") not in {"protected-image", "rehydration", "native-image", "target-loader"}
        or not isinstance(witness.get("failureClass"), str)
        or not witness.get("failureClass")
    ):
        fail("negative rollback witness does not prove blocked/no-publication behavior")
    for field in ("artifactPath", "nativeImagePath", "loaderMarkerPath"):
        value = witness.get(field)
        if value is not None:
            try:
                safe_relative(value, f"negative witness {field}")
            except SystemExit:
                raise

def check_benchmark(root: Path, first_failure: str | None, native_hash: str | None) -> None:
    record = read_json(require_file(root, "benchmark.json"))
    if record.get("schemaVersion") != 1:
        fail("rehydration benchmark record schema is unsupported")
    if record.get("firstFailureStage") != first_failure:
        fail("benchmark first-failure stage differs from the observed evidence")
    for field in (
        "rehydrationCpuMilliseconds",
        "rehydrationDurationMilliseconds",
        "producerEmissionDurationMilliseconds",
        "nativeImageSize",
        "handoffDurationNanoseconds",
        "maxRssBytes",
    ):
        value = record.get(field)
        if value is not None and (not isinstance(value, int) or value < 0):
            fail(f"benchmark {field} is not a non-negative integer")
    if native_hash is None and record.get("nativeImageSize") is not None:
        fail("benchmark records a Native Image size without a Native Image")


def check_first_failure(
    producer: dict[str, Any],
    rehydration: dict[str, Any],
    handoff: dict[str, Any],
    target_loader: dict[str, Any],
    oracle: dict[str, Any],
) -> str | None:
    statuses = (
        producer.get("status"),
        rehydration.get("status"),
        handoff.get("status"),
        target_loader.get("status"),
        oracle.get("status"),
    )
    stage_names = (
        "protected-image-producer",
        "rehydration",
        "native-handoff",
        "target-loader",
        "behavioral-oracle",
    )
    first_index = next((index for index, status in enumerate(statuses) if status != "passed"), None)
    first_failure = None if first_index is None else stage_names[first_index]
    if first_index is not None and any(status == "passed" for status in statuses[first_index + 1 :]):
        fail("a later rehydration stage passed after the first failed stage")

    records = (rehydration, handoff, target_loader, oracle)
    for index, record in enumerate(records, 1):
        expected = None
        if first_index is not None and index >= first_index:
            expected = first_failure
        if record.get("firstFailureStage") != expected:
            fail(f"{stage_names[index]} first-failure binding differs from the observed stage order")
    return first_failure


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    parser.add_argument("--runtime", choices=("glibc", "musl"), required=True)
    parser.add_argument("--require-runtime-identity", action="store_true")
    parser.add_argument("--unit", required=True)
    parser.add_argument("--expect-failure", action="store_true")
    args = parser.parse_args()
    if not UNIT_PATTERN.fullmatch(args.unit):
        fail("rehydration unit is not a safe bounded identifier")
    root = Path(os.path.abspath(args.artifact_root))
    if root.name != args.unit:
        fail("rehydration evidence root does not end in the selected unit")
    manifest_entries = check_closed_manifest(root)
    producer_stage, role, source, protected = check_producer(root, args.unit)
    if producer_stage.get("status") == "passed":
        for name in ("stdout.txt", "stderr.txt"):
            require_file(root, name, allow_empty=True)
        for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr"):
            require_file(root, name, allow_empty=True)
    else:
        for name in ("baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr"):
            require_file(root, name, allow_empty=True)

    rehydration, native_hash = check_rehydration(root, args.unit, producer_stage, role, source, protected)
    handoff, passed_handoff_hash = check_handoff(
        root,
        rehydration,
        native_hash,
        args.runtime,
        args.require_runtime_identity,
    )
    handoff_hash = digest(root / "handoff.json") if handoff.get("status") == "passed" else None
    target_loader = check_target_loader(root, handoff, handoff_hash, native_hash if handoff.get("status") == "passed" else None)
    source_hash = role.get("sourceSha256") if role else rehydration.get("sourceSha256")
    tls_evidence = producer_stage.get("tlsEvidence")
    expected_tls_entry_status = tls_evidence.get("expectedEntryStatus") if isinstance(tls_evidence, dict) else None
    oracle = check_behavior(
        root,
        rehydration,
        target_loader,
        source_hash,
        native_hash if target_loader.get("status") == "passed" else None,
        expected_tls_entry_status,
        args.runtime,
        args.require_runtime_identity,
    )
    if producer_stage.get("status") == "passed" and rehydration.get("status") == "passed":
        check_negative_witness(root, args.unit)
    first_failure = check_first_failure(producer_stage, rehydration, handoff, target_loader, oracle)
    check_benchmark(root, first_failure, native_hash)

    all_passed = all(
        record.get("status") == "passed"
        for record in (producer_stage, rehydration, handoff, target_loader, oracle)
    )
    if args.expect_failure and all_passed:
        fail("evidence unexpectedly completed all rehydration and handoff stages")
    if _ACTIVE_EVIDENCE_TREE is not None:
        _ACTIVE_EVIDENCE_TREE.verify_unchanged()
    if all_passed:
        print(f"PASS rehydration evidence: root={root} unit={args.unit} stages=producer,protected-image,rehydration,native-image,target-loader,behavioral-oracle")
    else:
        print(f"PASS rehydration failure evidence: root={root} unit={args.unit} firstFailureStage={first_failure}")
    del manifest_entries, passed_handoff_hash


if __name__ == "__main__":
    main()
