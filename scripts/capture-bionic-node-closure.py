#!/usr/bin/env python3
"""Capture a manual-only Termux Node.js package-lock candidate.

This command records package metadata from a live Termux index. Its output is
always candidate-lock metadata, never runtime or compatibility evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_MANIFEST = ROOT / "fixtures/manifest.json"
DEFAULT_REAL_SAMPLE_MANIFEST = ROOT / "fixtures/real-samples/manifest.json"
CASE_ID = "c-termux-bionic-pie"
NODE_PROJECT_ID = "nodejs"
TERMUX_PREFIX = "/data/data/com.termux/files/usr"
TERMUX_SHELL = f"{TERMUX_PREFIX}/bin/sh"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_OPERATION_SECONDS = 600
# Reserve time inside the hard workflow bound for root cleanup after the
# package container is stopped.  The main capture must never consume this
# window, including when its Docker client is terminated on timeout.
CLEANUP_WINDOW_SECONDS = 30
CONTAINER_REAP_WINDOW_SECONDS = 5
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
SHA256_CHUNK_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 1024 * 1024 * 1024
MAX_CAPTURE_ENTRIES = 20_000
MAX_DEB_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_COUNT = 256
MAX_INVENTORY_COUNT = 20_000
RELATION_FIELDS = (
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Enhances",
    "Conflicts",
    "Breaks",
    "Replaces",
    "Provides",
)


def _parse_immutable_image_ref(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        return None
    repository, separator, digest = value.rpartition("@sha256:")
    if not separator or not repository or "@" in repository or SHA256_RE.fullmatch(digest) is None:
        return None
    return repository, digest


def _is_clean_https_url(value: Any) -> bool:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        return False
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.query and not parsed.fragment


def _url_path_matches_filename(value: Any, filename: str) -> bool:
    if not _is_clean_https_url(value):
        return False
    return urlsplit(value).path.rstrip("/").endswith("/" + filename)


def _image_identity_errors(
    image: Any,
    *,
    expected_ref: str | None = None,
    label: str = "candidate baseImage",
) -> list[str]:
    if not isinstance(image, dict):
        return [f"{label} identity is required"]

    errors: list[str] = []
    requested_ref = image.get("requestedRef")
    requested_parts = _parse_immutable_image_ref(requested_ref)
    if requested_parts is None:
        errors.append(f"{label} requestedRef must be a repository@sha256:<64-hex-digest> reference")
    elif expected_ref is not None and requested_ref != expected_ref:
        errors.append(f"{label} requestedRef differs from the pinned image")

    repo_digests = image.get("repoDigests")
    if not isinstance(repo_digests, list) or not repo_digests or any(
        _parse_immutable_image_ref(value) is None for value in repo_digests
    ):
        errors.append(f"{label} repoDigests must contain immutable repository digest references")
    elif requested_parts is not None and requested_ref not in repo_digests:
        errors.append(f"{label} repoDigests must contain requestedRef")
    if expected_ref is not None and isinstance(repo_digests, list) and expected_ref not in repo_digests:
        errors.append(f"{label} repoDigests must contain the pinned image digest")

    image_id = image.get("id")
    if (
        not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or SHA256_RE.fullmatch(image_id.removeprefix("sha256:")) is None
    ):
        errors.append(f"{label} id must be a SHA-256 image ID")
    if image.get("os") != "linux":
        errors.append(f"{label} os must be linux")
    if image.get("architecture") not in {"arm64", "aarch64"}:
        errors.append(f"{label} architecture must be ARM64")
    return errors


def _package_url_errors(
    url: Any,
    filename: Any,
    *,
    package_repository: Any = None,
    label: str,
) -> list[str]:
    errors: list[str] = []
    if not _is_clean_https_url(url):
        errors.append(f"{label} URL must be a clean HTTPS URL")
        return errors
    if not isinstance(filename, str) or not filename or not _url_path_matches_filename(url, filename):
        errors.append(f"{label} URL path must end with its indexed filename")
    if package_repository is not None and _is_clean_https_url(package_repository):
        expected_url = package_repository.rstrip("/") + "/" + str(filename)
        if url != expected_url:
            errors.append(f"{label} URL must match the pinned package repository and filename")
    return errors


class CaptureError(Exception):
    """A hard capture or validation failure."""


class CaptureDeadlineExceeded(CaptureError):
    """The hard workflow deadline expired during a bounded operation."""


def fail(message: str) -> None:
    raise CaptureError(message)


def _check_deadline(deadline: float | None, operation: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise CaptureDeadlineExceeded(
            f"candidate capture exceeded its total wall-time limit during {operation}"
        )


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"could not read {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def _valid_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def load_pinned_inputs(
    fixture_manifest_path: Path, real_sample_manifest_path: Path
) -> dict[str, Any]:
    fixture_manifest = read_json(fixture_manifest_path, "fixture manifest")
    real_sample_manifest = read_json(real_sample_manifest_path, "real-sample manifest")

    cases = fixture_manifest.get("cases")
    if not isinstance(cases, list):
        fail("fixture manifest cases must be a list")
    matching_cases = [
        case for case in cases if isinstance(case, dict) and case.get("id") == CASE_ID
    ]
    if len(matching_cases) != 1:
        fail(f"fixture manifest must contain exactly one {CASE_ID} case")
    host = matching_cases[0].get("host")
    if not isinstance(host, dict):
        fail(f"{CASE_ID} must declare pinned host metadata")
    image = host.get("image")
    image_parts = _parse_immutable_image_ref(image)
    if image_parts is None:
        fail(f"{CASE_ID} image must use a repository@sha256:<64-hex-digest> reference")
    image_repository, image_digest = image_parts
    repository = host.get("packageRepository")
    if not isinstance(repository, str):
        fail(f"{CASE_ID} packageRepository is required")
    repository_parts = urlsplit(repository)
    if repository_parts.scheme != "https" or not repository_parts.netloc:
        fail(f"{CASE_ID} packageRepository must be an HTTPS URL")
    if repository_parts.query or repository_parts.fragment:
        fail(f"{CASE_ID} packageRepository must not contain query or fragment data")

    projects = real_sample_manifest.get("corpus", {}).get("projects")
    if not isinstance(projects, list):
        fail("real-sample manifest corpus.projects must be a list")
    matching_projects = [
        project
        for project in projects
        if isinstance(project, dict) and project.get("projectId") == NODE_PROJECT_ID
    ]
    if len(matching_projects) != 1:
        fail("real-sample manifest must contain exactly one Node.js identity")
    provenance = matching_projects[0].get("provenance")
    if not isinstance(provenance, dict) or provenance.get("sourceKind") != "termux-package":
        fail("Node.js identity must declare Termux package provenance")
    version = provenance.get("version")
    if not isinstance(version, str) or not version or any(char.isspace() for char in version):
        fail("Node.js identity has an invalid pinned package version")
    archive_path = provenance.get("archivePath")
    if not isinstance(archive_path, str):
        fail("Node.js identity has no locked archivePath")
    archive_relative = PurePosixPath(archive_path)
    if archive_relative.is_absolute() or ".." in archive_relative.parts:
        fail("Node.js archivePath must be a safe relative path")
    archive_url = provenance.get("archiveUrl")
    archive_url_parts = urlsplit(archive_url) if isinstance(archive_url, str) else None
    if (
        archive_url_parts is None
        or archive_url_parts.scheme != "https"
        or not archive_url_parts.netloc
        or archive_url_parts.query
        or archive_url_parts.fragment
    ):
        fail("Node.js identity has no clean HTTPS source archive URL")
    if not archive_url_parts.path.rstrip("/").endswith("/" + archive_relative.as_posix()):
        fail("Node.js source archive URL does not match its locked archivePath")
    expected_sha256 = _valid_sha256(provenance.get("archiveSha256"), "Node.js archiveSha256")
    expected_size = provenance.get("archiveSizeBytes")
    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size <= 0:
        fail("Node.js archiveSizeBytes must be a positive integer")
    if expected_size > MAX_DEB_BYTES:
        fail("Node.js archive exceeds the bounded package-size limit")

    return {
        "image": image,
        "imageRepository": image_repository,
        "imageDigest": image_digest,
        "packageRepository": repository.rstrip("/"),
        "nodeVersion": version,
        "nodeArchivePath": archive_relative.as_posix(),
        "nodeArchiveUrl": archive_url,
        "nodeArchiveSha256": expected_sha256,
        "nodeArchiveSizeBytes": expected_size,
    }


def _capture_cleanup_script(host_uid: int, host_gid: int) -> str:
    """Return the bounded root cleanup command for the bind-mounted capture."""
    return (
        f"export PATH=\"{TERMUX_PREFIX}/bin:$PATH\"; "
        f"if find /capture/debs /capture/apt-lists -mindepth 1 -print "
        f"| awk -v limit={MAX_CAPTURE_ENTRIES} 'NR > limit {{ exit 1 }}'; then "
        "find /capture/debs /capture/apt-lists -type d "
        "-exec chmod 0777 {} + 2>/dev/null || true; "
        f"chown -R {host_uid}:{host_gid} /capture; "
        "else echo 'temporary capture tree exceeded its entry-count limit' >&2; exit 1; fi"
    )


def _cleanup_window_seconds(timeout_seconds: int) -> int:
    """Return a small cleanup budget that remains inside the hard timeout."""
    return min(CLEANUP_WINDOW_SECONDS, max(1, timeout_seconds - 1))


def _is_missing_container_error(error: CaptureError) -> bool:
    message = str(error).lower()
    return "no such container" in message or "is not a container" in message


def _container_name(kind: str) -> str:
    return f"urprotect-bionic-node-{kind}-{os.getpid()}-{time.monotonic_ns()}"


def _stop_and_reap_container(
    docker_command: str,
    container_name: str,
    deadline: float,
) -> None:
    """Stop, wait for, and remove a named container before its bind mount vanishes."""
    errors: list[CaptureError] = []
    running = False
    try:
        state, _ = run_bounded(
            [docker_command, "inspect", "--format", "{{.State.Running}}", container_name],
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
        )
        running = state.decode("utf-8", errors="strict").strip() == "true"
    except CaptureError as error:
        if _is_missing_container_error(error):
            return
        errors.append(error)

    if running:
        try:
            run_bounded(
                [docker_command, "stop", "--time", "1", container_name],
                timeout_seconds=_remaining_seconds(deadline),
                deadline=deadline,
            )
        except CaptureError as error:
            if not _is_missing_container_error(error):
                errors.append(error)

    try:
        run_bounded(
            [docker_command, "wait", container_name],
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
        )
    except CaptureError as error:
        if _is_missing_container_error(error):
            return
        errors.append(error)

    # Force removal is also attempted after a stop/wait failure. This keeps a
    # Docker client timeout from leaving a live container attached to /capture.
    try:
        run_bounded(
            [docker_command, "rm", "--force", container_name],
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
        )
    except CaptureError as error:
        if not _is_missing_container_error(error):
            errors.append(error)
    if errors:
        raise errors[0]


def _repair_capture_permissions(
    docker_command: str,
    image: str,
    capture_directory: Path,
    deadline: float,
) -> None:
    """Repair the bind mount as root without running a package-management command."""
    cleanup_name = _container_name("capture-cleanup")
    command = [
        docker_command,
        "run",
        "--name",
        cleanup_name,
        "--platform",
        "linux/arm64",
        "--network",
        "none",
        "--memory",
        "128m",
        "--pids-limit",
        "16",
        "--user",
        "0:0",
        "--mount",
        f"type=bind,src={capture_directory},dst=/capture",
        "--env",
        f"PREFIX={TERMUX_PREFIX}",
        "--env",
        "HOME=/tmp",
        "--env",
        f"MAX_CAPTURE_ENTRIES={MAX_CAPTURE_ENTRIES}",
        image,
        TERMUX_SHELL,
        "-c",
        _capture_cleanup_script(os.getuid(), os.getgid()),
    ]
    repair_error: CaptureError | None = None
    try:
        run_bounded(
            command,
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
        )
    except CaptureError as error:
        repair_error = error

    reap_error: CaptureError | None = None
    try:
        _stop_and_reap_container(docker_command, cleanup_name, deadline)
    except CaptureError as error:
        reap_error = error
    if repair_error is not None:
        raise repair_error
    if reap_error is not None:
        raise reap_error


def _run_capture_with_cleanup(
    command: Sequence[str],
    *,
    docker_command: str,
    image: str,
    container_name: str,
    capture_directory: Path,
    capture_deadline: float,
    cleanup_deadline: float,
) -> None:
    """Run the capture and finish all container/mount cleanup before returning."""
    capture_error: CaptureError | None = None
    try:
        run_bounded(
            command,
            timeout_seconds=_remaining_seconds(capture_deadline),
            capture_directory=capture_directory,
            deadline=capture_deadline,
        )
    except CaptureError as error:
        capture_error = error

    # A killed Docker client does not itself prove that the named container is
    # gone. Reap it before the root ownership repair and before TemporaryDirectory
    # removes the bind-mounted tree.
    reap_error: CaptureError | None = None
    reap_deadline = min(cleanup_deadline, time.monotonic() + CONTAINER_REAP_WINDOW_SECONDS)
    try:
        _stop_and_reap_container(docker_command, container_name, reap_deadline)
    except CaptureError as error:
        reap_error = error

    repair_error: CaptureError | None = None
    try:
        _repair_capture_permissions(docker_command, image, capture_directory, cleanup_deadline)
    except CaptureError as error:
        repair_error = error

    if capture_error is not None:
        raise capture_error
    if reap_error is not None:
        raise reap_error
    if repair_error is not None:
        raise repair_error


def require_native_environment(machine: str, docker_platform: str, android_context: bool) -> None:
    if machine.lower() not in {"aarch64", "arm64"}:
        fail(f"capture requires a native ARM64 host; found {machine}")
    if docker_platform != "linux/arm64":
        fail(f"capture requires a native Linux/arm64 Docker server; found {docker_platform}")
    if android_context:
        fail("capture requires a Linux host context without Android, emulator, or Waydroid markers")


def host_android_context() -> bool:
    if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"):
        return True
    return any(Path(path).exists() for path in ("/system/bin/linker64", "/dev/binder", "/dev/vndbinder"))


def _remaining_seconds(deadline: float | None) -> int:
    if deadline is None:
        return MAX_OPERATION_SECONDS
    now = time.monotonic()
    if now >= deadline:
        raise CaptureDeadlineExceeded("candidate capture exceeded its total wall-time limit")
    remaining = deadline - now
    if remaining <= 0:
        raise CaptureDeadlineExceeded("candidate capture exceeded its total wall-time limit")
    return max(1, min(MAX_OPERATION_SECONDS, int(remaining + 0.999)))


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _capture_directory_bytes(directory: Path, deadline: float | None = None) -> int:
    """Bound capture-tree inspection by both bytes and entry count."""
    _check_deadline(deadline, "capture tree traversal")
    try:
        exists = directory.exists()
    except OSError as error:
        fail(f"could not inspect temporary capture data: {error}")
    _check_deadline(deadline, "capture tree traversal")
    if not exists:
        return 0

    total = 0
    entry_count = 0
    try:
        for path in directory.rglob("*"):
            _check_deadline(deadline, "capture tree traversal")
            entry_count += 1
            if entry_count > MAX_CAPTURE_ENTRIES:
                fail("temporary capture tree exceeded its entry-count limit")
            try:
                info = path.lstat()
            except OSError as error:
                fail(f"could not inspect temporary capture data: {error}")
            _check_deadline(deadline, "capture tree traversal")
            if stat.S_ISLNK(info.st_mode):
                fail(f"unexpected symbolic link in temporary capture: {path.name}")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > MAX_CAPTURE_BYTES:
                    fail("live package capture exceeded the 1 GiB download and metadata budget")
            _check_deadline(deadline, "capture tree traversal")
    except OSError as error:
        fail(f"could not inspect temporary capture data: {error}")
    _check_deadline(deadline, "capture tree traversal")
    return total


def run_bounded(
    command: Sequence[str],
    *,
    timeout_seconds: int,
    output_limit: int = MAX_COMMAND_OUTPUT_BYTES,
    capture_directory: Path | None = None,
    deadline: float | None = None,
) -> tuple[bytes, bytes]:
    """Run one helper command with a wall-time, output, and optional disk budget."""
    import tempfile as tempfile_module

    _check_deadline(deadline, "starting a bounded command")
    with tempfile_module.TemporaryFile() as stdout_file, tempfile_module.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(command, stdout=stdout_file, stderr=stderr_file)
        except OSError as error:
            fail(f"could not start {shlex.join(command[:3])}: {error}")
        started = time.monotonic()
        command_deadline = started + timeout_seconds
        if deadline is not None:
            command_deadline = min(command_deadline, deadline)
        timed_out = False
        output_overflow = False
        disk_overflow = False
        capture_failure: CaptureError | None = None
        try:
            while process.poll() is None:
                if time.monotonic() >= command_deadline:
                    timed_out = True
                    _terminate(process)
                    break
                if stdout_file.tell() > output_limit or stderr_file.tell() > output_limit:
                    output_overflow = True
                    _terminate(process)
                    break
                if capture_directory is not None:
                    try:
                        _capture_directory_bytes(capture_directory, deadline=deadline)
                    except CaptureDeadlineExceeded:
                        timed_out = True
                        _terminate(process)
                        break
                    except CaptureError as error:
                        disk_overflow = True
                        capture_failure = error
                        _terminate(process)
                        break
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                _terminate(process)
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(output_limit + 1)
        stderr = stderr_file.read(output_limit + 1)
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
        return_code = process.returncode

    if timed_out:
        fail(f"command exceeded its {timeout_seconds}-second wall-time limit: {shlex.join(command[:3])}")
    if output_overflow or len(stdout) > output_limit or len(stderr) > output_limit:
        fail(f"command output exceeded its {output_limit}-byte limit: {shlex.join(command[:3])}")
    if disk_overflow:
        if capture_failure is not None:
            raise capture_failure
        fail("live package capture exceeded its temporary disk budget")
    if return_code != 0:
        detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
        if len(detail) > 2000:
            detail = detail[-2000:]
        fail(f"command exited with status {return_code}: {shlex.join(command[:3])}: {detail}")
    return stdout, stderr


def inspect_pinned_image(image_inspect: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    identity = {
        "requestedRef": inputs["image"],
        "id": image_inspect.get("Id"),
        "os": image_inspect.get("Os"),
        "architecture": image_inspect.get("Architecture"),
        "repoDigests": image_inspect.get("RepoDigests"),
    }
    errors = _image_identity_errors(
        identity,
        expected_ref=inputs["image"],
        label="pinned Termux image",
    )
    if errors:
        fail("; ".join(errors))
    repo_digests = identity["repoDigests"]
    assert isinstance(repo_digests, list)
    image_id = identity["id"]
    architecture = identity["architecture"]
    assert isinstance(image_id, str)
    assert isinstance(architecture, str)
    return {
        "requestedRef": inputs["image"],
        "id": image_id,
        "os": "linux",
        "architecture": architecture,
        "repoDigests": sorted(set(repo_digests)),
        "created": image_inspect.get("Created"),
    }


def parse_control_fields(
    text: str, label: str, deadline: float | None = None
) -> dict[str, str]:
    _check_deadline(deadline, f"reading {label}")
    normalized = text.replace("\r\n", "\n")
    _check_deadline(deadline, f"normalizing {label}")
    fields: dict[str, str] = {}
    current: str | None = None
    for raw_line in normalized.splitlines():
        _check_deadline(deadline, f"parsing {label}")
        if not raw_line:
            continue
        if raw_line[0] in " \t":
            if current is None:
                fail(f"{label} has a continuation line without a field")
            fields[current] += " " + raw_line.strip()
            continue
        if ":" not in raw_line:
            fail(f"{label} contains malformed control metadata")
        name, value = raw_line.split(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9-]+", name) or name in fields:
            fail(f"{label} contains an invalid or duplicate field: {name!r}")
        current = name
        fields[name] = value.lstrip()
    _check_deadline(deadline, f"parsing {label}")
    return fields


def parse_control_stanzas(
    text: str, label: str, deadline: float | None = None
) -> list[dict[str, str]]:
    _check_deadline(deadline, f"reading {label}")
    paragraphs = re.split(r"\n\s*\n", text.strip())
    _check_deadline(deadline, f"splitting {label}")
    stanzas: list[dict[str, str]] = []
    for index, paragraph in enumerate(paragraphs):
        _check_deadline(deadline, f"parsing {label}")
        if paragraph.strip():
            stanzas.append(parse_control_fields(paragraph, f"{label} stanza {index + 1}", deadline))
    if not stanzas:
        fail(f"{label} contains no metadata stanzas")
    _check_deadline(deadline, f"parsing {label}")
    return stanzas


def parse_package_inventory(
    text: str, label: str, deadline: float | None = None
) -> list[dict[str, str]]:
    _check_deadline(deadline, f"reading {label}")
    lines = text.splitlines()
    _check_deadline(deadline, f"splitting {label}")
    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        _check_deadline(deadline, f"parsing {label}")
        columns = line.split("\t")
        if len(columns) != 4 or any(not value for value in columns):
            fail(f"{label} line {line_number} is malformed")
        name, version, architecture, status = columns
        if any(ord(character) < 32 and character != "\t" for character in line):
            fail(f"{label} line {line_number} contains control characters")
        if name in seen:
            fail(f"{label} contains duplicate package name {name}")
        seen.add(name)
        packages.append(
            {"name": name, "version": version, "architecture": architecture, "status": status}
        )
        if len(packages) > MAX_INVENTORY_COUNT:
            fail(f"{label} exceeds its package-count bound")
    _check_deadline(deadline, f"sorting {label}")
    packages.sort(key=lambda package: (package["name"], package["architecture"]))
    _check_deadline(deadline, f"sorting {label}")
    return packages


def _safe_repository_filename(value: str) -> str:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        fail(f"package index filename is not a safe relative path: {value!r}")
    if "\\" in value or any(ord(character) < 32 for character in value):
        fail("package index filename contains an invalid character")
    return candidate.as_posix()


def _sha256_bytes(data: bytes, deadline: float | None, operation: str) -> str:
    _check_deadline(deadline, f"starting {operation}")
    digest = hashlib.sha256()
    for offset in range(0, len(data), SHA256_CHUNK_BYTES):
        _check_deadline(deadline, operation)
        digest.update(data[offset : offset + SHA256_CHUNK_BYTES])
        _check_deadline(deadline, operation)
    result = digest.hexdigest()
    _check_deadline(deadline, f"finishing {operation}")
    return result


def _sha256_file(path: Path, deadline: float | None, operation: str) -> str:
    _check_deadline(deadline, f"opening {operation}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as archive:
            while True:
                _check_deadline(deadline, operation)
                block = archive.read(SHA256_CHUNK_BYTES)
                _check_deadline(deadline, operation)
                if not block:
                    break
                digest.update(block)
                _check_deadline(deadline, operation)
    except OSError as error:
        fail(f"could not read {operation}: {error}")
    result = digest.hexdigest()
    _check_deadline(deadline, f"finishing {operation}")
    return result


def build_package_record(
    archive_path: Path,
    deb_fields: dict[str, str],
    apt_fields: dict[str, str],
    package_repository: str,
    deadline: float | None = None,
) -> dict[str, Any]:
    _check_deadline(deadline, f"building {archive_path.name} package metadata")
    for field in ("Package", "Version", "Architecture"):
        if not deb_fields.get(field) or deb_fields.get(field) != apt_fields.get(field):
            fail(f"downloaded package metadata does not match the package index ({field})")
    if deb_fields["Architecture"] not in {"aarch64", "all"}:
        fail(f"downloaded package is not an ARM64/architecture-independent package: {deb_fields['Package']}")
    filename = apt_fields.get("Filename")
    if not isinstance(filename, str):
        fail(f"package index has no Filename for {deb_fields['Package']}")
    filename = _safe_repository_filename(filename)
    try:
        size_bytes = archive_path.stat().st_size
    except OSError as error:
        fail(f"could not inspect downloaded package {archive_path.name}: {error}")
    _check_deadline(deadline, f"inspecting {archive_path.name}")
    if size_bytes <= 0 or size_bytes > MAX_DEB_BYTES:
        fail(f"downloaded package is empty or exceeds its size limit: {archive_path.name}")
    expected_size = apt_fields.get("Size")
    if not isinstance(expected_size, str) or not expected_size.isdigit() or int(expected_size) != size_bytes:
        fail(f"downloaded package size does not match the package index: {archive_path.name}")
    expected_sha = _valid_sha256(apt_fields.get("SHA256"), f"{archive_path.name} index SHA256")
    actual_sha = _sha256_file(archive_path, deadline, f"hashing {archive_path.name}")
    if actual_sha != expected_sha:
        fail(f"downloaded package hash does not match the package index: {archive_path.name}")

    _check_deadline(deadline, f"building {archive_path.name} package metadata")
    dependencies = {
        field: deb_fields[field]
        for field in RELATION_FIELDS
        if isinstance(deb_fields.get(field), str) and deb_fields[field]
    }
    repository_url = package_repository.rstrip("/") + "/"
    url = repository_url + filename
    if urlsplit(url).scheme != "https":
        fail(f"package URL is not HTTPS: {filename}")
    return {
        "name": deb_fields["Package"],
        "version": deb_fields["Version"],
        "architecture": deb_fields["Architecture"],
        "filename": filename,
        "localFilename": archive_path.name,
        "url": url,
        "sizeBytes": size_bytes,
        "sha256": actual_sha,
        "dependencies": dependencies,
    }


def validate_node_package_lock(
    packages: Sequence[dict[str, Any]],
    inputs: dict[str, Any],
    deadline: float | None = None,
) -> None:
    _check_deadline(deadline, "validating downloaded package identities")
    matches: list[dict[str, Any]] = []
    for package in packages:
        _check_deadline(deadline, "validating downloaded package identities")
        if package.get("name") == NODE_PROJECT_ID:
            matches.append(package)
    if len(matches) != 1:
        fail("downloaded closure must contain exactly one Node.js package archive")
    node = matches[0]
    if node.get("architecture") != "aarch64":
        fail("downloaded Node.js package is not an AArch64 package")
    expected = {
        "version": inputs["nodeVersion"],
        "filename": inputs["nodeArchivePath"],
        "localFilename": PurePosixPath(inputs["nodeArchivePath"]).name,
        "url": inputs["packageRepository"].rstrip("/") + "/" + inputs["nodeArchivePath"],
        "sizeBytes": inputs["nodeArchiveSizeBytes"],
        "sha256": inputs["nodeArchiveSha256"],
    }
    _check_deadline(deadline, "validating Node.js package identity")
    mismatches = [key for key, value in expected.items() if node.get(key) != value]
    if mismatches:
        fail("downloaded Node.js package differs from the pinned real-sample manifest: " + ", ".join(mismatches))
    _check_deadline(deadline, "validating Node.js package identity")


def build_candidate_document(
    *,
    inputs: dict[str, Any],
    image_identity: dict[str, Any],
    host_architecture: str,
    docker_server_platform: str,
    package_inventory: list[dict[str, str]],
    package_records: list[dict[str, Any]],
    captured_at: str,
    deadline: float | None = None,
) -> dict[str, Any]:
    _check_deadline(deadline, "serializing package inventory")
    inventory_lines: list[str] = []
    for package in package_inventory:
        _check_deadline(deadline, "serializing package inventory")
        inventory_lines.append(
            "\t".join(
                (package["name"], package["version"], package["architecture"], package["status"])
            )
            + "\n"
        )
    inventory_bytes = "".join(inventory_lines).encode("utf-8")
    inventory_sha256 = _sha256_bytes(inventory_bytes, deadline, "hashing package inventory")
    _check_deadline(deadline, "building candidate metadata")
    document = {
        "schemaVersion": 1,
        "status": "candidate-lock",
        "evidenceClass": "candidate-lock-only",
        "runtime": "bionic",
        "runtimeEvidence": False,
        "compatibilityStatus": "not-established",
        "capturedAtUtc": captured_at,
        "capture": {
            "trigger": "workflow_dispatch:capture_bionic_node_closure",
            "packageIndex": "live-capture-only",
            "resolver": "apt-get-update-download-only",
            "packageRepository": inputs["packageRepository"],
            "requestedPackage": f"nodejs={inputs['nodeVersion']}",
            "closureReview": "required-before-locking-or-runtime-use",
        },
        "sourceArchiveLock": {
            "projectId": NODE_PROJECT_ID,
            "version": inputs["nodeVersion"],
            "filename": inputs["nodeArchivePath"],
            "url": inputs["nodeArchiveUrl"],
            "sizeBytes": inputs["nodeArchiveSizeBytes"],
            "sha256": inputs["nodeArchiveSha256"],
        },
        "baseImage": image_identity,
        "host": {
            "architecture": host_architecture,
            "dockerServerPlatform": docker_server_platform,
            "containerPlatform": "linux/arm64",
            "loader": "/system/bin/linker64",
        },
        "basePackageInventory": {
            "count": len(package_inventory),
            "sha256": inventory_sha256,
            "packages": package_inventory,
            "unchangedAfterDownloadOnly": True,
        },
        "resolution": {
            "downloadedPackageCount": len(package_records),
            "basePackagesSatisfySomeDependencies": True,
            "allDownloadedArchivesHaveIndexAndContentHashMatch": True,
            "archivesIncludedInCandidateJson": False,
            "rawNodeBinaryIncluded": False,
        },
        "packages": package_records,
    }
    _check_deadline(deadline, "building candidate metadata")
    return document


def validate_candidate_document(document: Any, deadline: float | None = None) -> list[str]:
    _check_deadline(deadline, "validating candidate metadata")
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["candidate document must be an object"]
    if document.get("schemaVersion") != 1:
        errors.append("candidate schemaVersion must be 1")
    if document.get("status") != "candidate-lock":
        errors.append("candidate status must be candidate-lock")
    if document.get("evidenceClass") != "candidate-lock-only":
        errors.append("candidate evidenceClass must be candidate-lock-only")
    if document.get("runtime") != "bionic" or document.get("runtimeEvidence") is not False:
        errors.append("candidate must remain bionic metadata without runtime evidence")
    if document.get("compatibilityStatus") != "not-established":
        errors.append("candidate compatibilityStatus must remain not-established")
    source_lock = document.get("sourceArchiveLock")
    if not isinstance(source_lock, dict):
        errors.append("candidate sourceArchiveLock is required")
    else:
        if source_lock.get("projectId") != NODE_PROJECT_ID:
            errors.append("candidate sourceArchiveLock must identify Node.js")
        for field in ("version", "filename", "url"):
            _check_deadline(deadline, "validating candidate source metadata")
            if not isinstance(source_lock.get(field), str) or not source_lock[field]:
                errors.append(f"candidate sourceArchiveLock is missing {field}")
        if (
            isinstance(source_lock.get("sizeBytes"), bool)
            or not isinstance(source_lock.get("sizeBytes"), int)
            or source_lock["sizeBytes"] <= 0
        ):
            errors.append("candidate sourceArchiveLock sizeBytes must be a positive integer")
        if not isinstance(source_lock.get("sha256"), str) or SHA256_RE.fullmatch(source_lock["sha256"]) is None:
            errors.append("candidate sourceArchiveLock sha256 must be SHA-256")
        source_filename = source_lock.get("filename")
        if isinstance(source_filename, str):
            try:
                _safe_repository_filename(source_filename)
            except CaptureError:
                errors.append("candidate sourceArchiveLock filename is unsafe")
        if not _is_clean_https_url(source_lock.get("url")):
            errors.append("candidate sourceArchiveLock URL must be a clean HTTPS URL")
        elif isinstance(source_filename, str) and not _url_path_matches_filename(source_lock["url"], source_filename):
            errors.append("candidate sourceArchiveLock URL path must end with its filename")
    capture = document.get("capture")
    capture_repository: Any = None
    if not isinstance(capture, dict):
        errors.append("candidate capture metadata is required")
    else:
        capture_repository = capture.get("packageRepository")
        if capture.get("trigger") != "workflow_dispatch:capture_bionic_node_closure":
            errors.append("candidate capture trigger must identify the manual workflow input")
        if capture.get("packageIndex") != "live-capture-only":
            errors.append("candidate packageIndex must be live-capture-only")
        if capture.get("resolver") != "apt-get-update-download-only":
            errors.append("candidate resolver must identify download-only package resolution")
        if capture.get("closureReview") != "required-before-locking-or-runtime-use":
            errors.append("candidate closure must require review")
        if not _is_clean_https_url(capture_repository):
            errors.append("candidate packageRepository must be a clean HTTPS URL")
    image = document.get("baseImage")
    errors.extend(_image_identity_errors(image))
    host = document.get("host")
    if not isinstance(host, dict):
        errors.append("candidate host identity is required")
    else:
        if host.get("architecture") not in {"aarch64", "arm64"}:
            errors.append("candidate host architecture must be native ARM64")
        if host.get("dockerServerPlatform") != "linux/arm64":
            errors.append("candidate Docker server must be linux/arm64")
        if host.get("containerPlatform") != "linux/arm64":
            errors.append("candidate container platform must be linux/arm64")
        if host.get("loader") != "/system/bin/linker64":
            errors.append("candidate loader must be /system/bin/linker64")
    inventory = document.get("basePackageInventory")
    if not isinstance(inventory, dict):
        errors.append("candidate basePackageInventory is required")
    else:
        packages = inventory.get("packages")
        if (
            not isinstance(packages, list)
            or isinstance(inventory.get("count"), bool)
            or not isinstance(inventory.get("count"), int)
            or inventory["count"] != len(packages)
        ):
            errors.append("candidate base package inventory count does not match its records")
        if inventory.get("unchangedAfterDownloadOnly") is not True:
            errors.append("candidate capture must show that download-only left the base inventory unchanged")
        if not isinstance(inventory.get("sha256"), str) or SHA256_RE.fullmatch(inventory["sha256"]) is None:
            errors.append("candidate base package inventory hash must be SHA-256")
    records = document.get("packages")
    if not isinstance(records, list) or not records:
        errors.append("candidate must contain downloaded package metadata")
    else:
        seen: set[tuple[str, str, str]] = set()
        for index, package in enumerate(records):
            _check_deadline(deadline, "validating candidate package metadata")
            if not isinstance(package, dict):
                errors.append(f"candidate package {index} must be an object")
                continue
            for field in ("name", "version", "architecture", "filename", "localFilename", "url"):
                if not isinstance(package.get(field), str) or not package[field]:
                    errors.append(f"candidate package {index} is missing {field}")
            if isinstance(package.get("filename"), str):
                try:
                    _safe_repository_filename(package["filename"])
                except CaptureError:
                    errors.append(f"candidate package {index} has an unsafe filename")
            if isinstance(package.get("localFilename"), str) and (
                "/" in package["localFilename"] or "\\" in package["localFilename"]
            ):
                errors.append(f"candidate package {index} has an unsafe local filename")
            if isinstance(package.get("filename"), str) and isinstance(package.get("localFilename"), str):
                if package["localFilename"] != PurePosixPath(package["filename"]).name:
                    errors.append(f"candidate package {index} local filename does not match its indexed filename")
            if isinstance(package.get("url"), str) and isinstance(package.get("filename"), str):
                errors.extend(
                    _package_url_errors(
                        package["url"],
                        package["filename"],
                        package_repository=capture_repository,
                        label=f"candidate package {index}",
                    )
                )
            if isinstance(package.get("sizeBytes"), bool) or not isinstance(package.get("sizeBytes"), int) or package["sizeBytes"] <= 0:
                errors.append(f"candidate package {index} has invalid sizeBytes")
            if not isinstance(package.get("sha256"), str) or SHA256_RE.fullmatch(package["sha256"]) is None:
                errors.append(f"candidate package {index} has invalid SHA-256")
            if not isinstance(package.get("dependencies"), dict):
                errors.append(f"candidate package {index} dependency metadata is required")
            if all(isinstance(package.get(field), str) for field in ("name", "version", "architecture")):
                identity = (package["name"], package["version"], package["architecture"])
                if identity in seen:
                    errors.append(f"candidate package identity is duplicated: {identity}")
                seen.add(identity)

    node_packages = (
        [package for package in records if isinstance(package, dict) and package.get("name") == NODE_PROJECT_ID]
        if isinstance(records, list)
        else []
    )
    if isinstance(records, list) and len(node_packages) != 1:
        errors.append(
            f"candidate must contain exactly one Node.js package record; found {len(node_packages)}"
        )
    elif len(node_packages) == 1:
        node_package = node_packages[0]
        if node_package.get("name") != NODE_PROJECT_ID:
            errors.append("candidate Node.js package identity must be nodejs")
        if node_package.get("architecture") != "aarch64":
            errors.append("candidate Node.js package architecture must be aarch64")
        if isinstance(source_lock, dict):
            for field in ("version", "filename", "sizeBytes", "sha256"):
                if field in source_lock and node_package.get(field) != source_lock.get(field):
                    errors.append(f"candidate Node.js package {field} must match sourceArchiveLock")
            if (
                isinstance(source_lock.get("filename"), str)
                and isinstance(node_package.get("url"), str)
                and not _url_path_matches_filename(node_package["url"], source_lock["filename"])
            ):
                errors.append("candidate Node.js package URL must match sourceArchiveLock filename")

    resolution = document.get("resolution")
    if not isinstance(resolution, dict):
        errors.append("candidate resolution metadata is required")
    else:
        expected_record_count = len(records) if isinstance(records, list) else None
        if (
            isinstance(expected_record_count, int)
            and (
                isinstance(resolution.get("downloadedPackageCount"), bool)
                or not isinstance(resolution.get("downloadedPackageCount"), int)
                or resolution["downloadedPackageCount"] != expected_record_count
            )
        ):
            errors.append("candidate downloadedPackageCount does not match package records")
        if resolution.get("archivesIncludedInCandidateJson") is not False:
            errors.append("candidate JSON must not contain package archives")
        if resolution.get("rawNodeBinaryIncluded") is not False:
            errors.append("candidate JSON must not contain a raw Node.js executable")
        if resolution.get("allDownloadedArchivesHaveIndexAndContentHashMatch") is not True:
            errors.append("candidate must verify every downloaded archive against index and content hashes")
    _check_deadline(deadline, "validating candidate metadata")
    return errors


def validate_candidate_against_pins(
    document: Any, inputs: dict[str, Any], deadline: float | None = None
) -> list[str]:
    _check_deadline(deadline, "validating candidate pins")
    errors = validate_candidate_document(document, deadline)
    if not isinstance(document, dict):
        return errors
    source_lock = document.get("sourceArchiveLock")
    if isinstance(source_lock, dict):
        for field, input_key in (
            ("version", "nodeVersion"),
            ("filename", "nodeArchivePath"),
            ("url", "nodeArchiveUrl"),
            ("sizeBytes", "nodeArchiveSizeBytes"),
            ("sha256", "nodeArchiveSha256"),
        ):
            if source_lock.get(field) != inputs[input_key]:
                errors.append(f"candidate sourceArchiveLock {field} differs from the pinned manifest")
    image = document.get("baseImage")
    image_errors = _image_identity_errors(
        image,
        expected_ref=inputs["image"],
        label="candidate baseImage",
    )
    errors.extend(image_errors)
    host = document.get("host")
    if isinstance(host, dict) and host.get("loader") != "/system/bin/linker64":
        errors.append("candidate host loader differs from the bionic fixture contract")
    packages = document.get("packages")
    if isinstance(packages, list):
        for index, package in enumerate(packages):
            _check_deadline(deadline, "validating pinned package metadata")
            if isinstance(package, dict) and isinstance(package.get("filename"), str):
                errors.extend(
                    _package_url_errors(
                        package.get("url"),
                        package["filename"],
                        package_repository=inputs["packageRepository"],
                        label=f"candidate package {index}",
                    )
                )
        node_packages = [
            package for package in packages if isinstance(package, dict) and package.get("name") == NODE_PROJECT_ID
        ]
        if len(node_packages) != 1:
            errors.append(
                f"candidate must contain exactly one pinned Node.js package record; found {len(node_packages)}"
            )
        else:
            node = node_packages[0]
            if node.get("name") != NODE_PROJECT_ID:
                errors.append("candidate Node.js package identity must be nodejs")
            if node.get("architecture") != "aarch64":
                errors.append("candidate Node.js package architecture differs from the pinned manifest")
            expected_node_url = inputs["packageRepository"].rstrip("/") + "/" + inputs["nodeArchivePath"]
            for field, expected in (
                ("version", inputs["nodeVersion"]),
                ("filename", inputs["nodeArchivePath"]),
                ("localFilename", PurePosixPath(inputs["nodeArchivePath"]).name),
                ("url", expected_node_url),
                ("sizeBytes", inputs["nodeArchiveSizeBytes"]),
                ("sha256", inputs["nodeArchiveSha256"]),
            ):
                if node.get(field) != expected:
                    errors.append(f"candidate Node.js package {field} differs from the pinned manifest")
    _check_deadline(deadline, "validating candidate pins")
    return errors


def _container_capture_script() -> str:
    return r'''set -eu
capture_tree_within_limit() {
  find /capture/debs /capture/apt-lists -mindepth 1 -print |
    awk -v limit="${MAX_CAPTURE_ENTRIES}" 'NR > limit { exit 1 }'
}
cleanup_capture_mount() {
  # Keep the host-side TemporaryDirectory removable even when apt exits early.
  if ! capture_tree_within_limit; then
    return
  fi
  find /capture/debs /capture/apt-lists -type d -exec chmod 0777 {} + 2>/dev/null || true
}
trap cleanup_capture_mount 0
export PATH="${PREFIX}/bin:${PATH}"
export DEBIAN_FRONTEND=noninteractive
[ "$(uname -m)" = aarch64 ]
test -x /system/bin/linker64
test ! -e /system/bin/app_process
test ! -e /system/bin/app_process64
for tool in qemu-aarch64 qemu-aarch64-static qemu-system-aarch64 waydroid emulator; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "forbidden runtime tool is present: $tool" >&2
    exit 1
  fi
done
mkdir -p /capture/debs/partial /capture/apt-lists/partial
chmod 0777 /capture/debs /capture/debs/partial /capture/apt-lists /capture/apt-lists/partial
if ! capture_tree_within_limit; then
  echo 'temporary capture tree exceeded its entry-count limit' >&2
  exit 1
fi
if find /capture/debs -type f -name '*.deb' | grep -q .; then
  echo 'capture archive directory must start empty' >&2
  exit 1
fi
ulimit -f 524288
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' | sort > /capture/packages-before.tsv
apt-get -o Dir::State::lists=/capture/apt-lists \
  -o Acquire::Retries=0 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
  update > /capture/apt-update.log 2>&1
apt-get -o Dir::State::lists=/capture/apt-lists \
  -o Dir::Cache::archives=/capture/debs \
  -o Acquire::Retries=0 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
  --download-only --yes install "nodejs=${TERMUX_NODEJS_VERSION}" \
  > /capture/apt-download.log 2>&1
for log in /capture/apt-update.log /capture/apt-download.log; do
  if [ "$(wc -c < "$log")" -gt 1048576 ]; then
    echo "package-manager log exceeded its 1 MiB output limit: $log" >&2
    exit 1
  fi
done
if find /capture/debs/partial -type f -name '*.deb' -print -quit | grep -q .; then
  echo 'partial package archive remained after download-only acquisition' >&2
  exit 1
fi
find /capture/debs -maxdepth 1 -type f -name '*.deb' -printf '%f\n' | sort > /capture/downloaded-deb-paths.txt
[ -s /capture/downloaded-deb-paths.txt ]
: > /capture/apt-cache-metadata.txt
while IFS= read -r archive_name; do
  archive="/capture/debs/${archive_name}"
  package="$(dpkg-deb -f "$archive" Package)"
  version="$(dpkg-deb -f "$archive" Version)"
  [ -n "$package" ] && [ -n "$version" ]
  apt-cache -o Dir::State::lists=/capture/apt-lists show "${package}=${version}" \
    >> /capture/apt-cache-metadata.txt
  printf '\n\n' >> /capture/apt-cache-metadata.txt
done < /capture/downloaded-deb-paths.txt
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' | sort > /capture/packages-after.tsv
'''


def _check_text_file(
    path: Path, limit: int, label: str, deadline: float | None = None
) -> str:
    _check_deadline(deadline, f"reading {label}")
    try:
        size = path.stat().st_size
        _check_deadline(deadline, f"inspecting {label}")
        if size > limit:
            fail(f"{label} exceeded its {limit}-byte output limit")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"could not read {label}: {error}")
    _check_deadline(deadline, f"reading {label}")
    return text


def _load_image_identity(
    docker: str,
    image: str,
    timeout_seconds: int,
    deadline: float | None = None,
) -> dict[str, Any]:
    stdout, _ = run_bounded(
        [docker, "image", "inspect", "--format", "{{json .}}", image],
        timeout_seconds=timeout_seconds,
        deadline=deadline,
    )
    try:
        inspection = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"Docker returned malformed image identity data: {error}")
    if not isinstance(inspection, dict):
        fail("Docker image inspect result must be a JSON object")
    return inspection


def _collect_package_records(
    capture_directory: Path,
    inputs: dict[str, Any],
    deadline: float | None = None,
) -> list[dict[str, Any]]:
    _check_deadline(deadline, "collecting package records")
    metadata_path = capture_directory / "apt-cache-metadata.txt"
    apt_stanzas = parse_control_stanzas(
        _check_text_file(metadata_path, MAX_METADATA_BYTES, "apt-cache metadata", deadline),
        "apt-cache metadata",
        deadline,
    )
    apt_by_identity: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for stanza in apt_stanzas:
        _check_deadline(deadline, "indexing package metadata")
        identity = (stanza.get("Package", ""), stanza.get("Version", ""), stanza.get("Architecture", ""))
        apt_by_identity.setdefault(identity, []).append(stanza)
    _check_deadline(deadline, "indexing package metadata")

    paths_text = _check_text_file(
        capture_directory / "downloaded-deb-paths.txt", MAX_METADATA_BYTES, "downloaded package path list", deadline
    )
    _check_deadline(deadline, "parsing downloaded package paths")
    archive_names = [line for line in paths_text.splitlines() if line]
    _check_deadline(deadline, "parsing downloaded package paths")
    if not archive_names or len(archive_names) > MAX_PACKAGE_COUNT:
        fail("downloaded package count is empty or exceeds its bound")
    records: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    archive_directory = capture_directory / "debs"
    try:
        resolved_archive_directory = archive_directory.resolve()
    except OSError as error:
        fail(f"could not resolve downloaded package directory: {error}")
    _check_deadline(deadline, "inspecting downloaded package directory")
    for archive_name in archive_names:
        _check_deadline(deadline, "iterating downloaded packages")
        if (
            archive_name in {".", ".."}
            or "/" in archive_name
            or "\\" in archive_name
            or any(ord(character) < 32 for character in archive_name)
        ):
            fail(f"downloaded package name is not a safe basename: {archive_name!r}")
        archive_path = archive_directory / archive_name
        try:
            resolved_parent = archive_path.parent.resolve()
        except OSError as error:
            fail(f"could not resolve downloaded package path: {error}")
        _check_deadline(deadline, "inspecting downloaded package path")
        if resolved_parent != resolved_archive_directory:
            fail("downloaded package path escaped the dedicated archive directory")
        if archive_path.is_symlink() or not archive_path.is_file() or archive_path.suffix != ".deb":
            fail(f"downloaded package entry is not a regular .deb archive: {archive_path.name}")
        _check_deadline(deadline, "inspecting downloaded package path")
        try:
            size = archive_path.stat().st_size
        except OSError as error:
            fail(f"could not inspect downloaded package {archive_path.name}: {error}")
        _check_deadline(deadline, "inspecting downloaded package path")
        if size <= 0 or size > MAX_DEB_BYTES:
            fail(f"downloaded package exceeds the per-package size bound: {archive_path.name}")
        deb_stdout, _ = run_bounded(
            ["dpkg-deb", "--field", str(archive_path)],
            timeout_seconds=min(30, _remaining_seconds(deadline)),
            output_limit=MAX_METADATA_BYTES,
            deadline=deadline,
        )
        _check_deadline(deadline, "decoding downloaded package metadata")
        deb_fields = parse_control_fields(
            deb_stdout.decode("utf-8", errors="strict"), f"downloaded archive {archive_path.name}", deadline
        )
        _check_deadline(deadline, "validating downloaded package metadata")
        identity = (deb_fields.get("Package", ""), deb_fields.get("Version", ""), deb_fields.get("Architecture", ""))
        if identity in identities:
            fail(f"download contains a duplicate package identity: {identity}")
        identities.add(identity)
        matches = apt_by_identity.get(identity, [])
        if len(matches) != 1:
            fail(f"apt index metadata is missing or ambiguous for downloaded package {identity}")
        record = build_package_record(
            archive_path, deb_fields, matches[0], inputs["packageRepository"], deadline
        )
        records.append(record)
    _check_deadline(deadline, "sorting downloaded package records")
    records.sort(key=lambda package: (package["name"], package["version"], package["architecture"]))
    _check_deadline(deadline, "sorting downloaded package records")
    validate_node_package_lock(records, inputs, deadline)
    _check_deadline(deadline, "collecting package records")
    return records


def _serialize_candidate_document(document: dict[str, Any], deadline: float | None) -> str:
    _check_deadline(deadline, "serializing candidate metadata")
    try:
        serialized = json.dumps(document, indent=2, sort_keys=True)
    except (TypeError, ValueError) as error:
        fail(f"could not serialize candidate metadata: {error}")
    _check_deadline(deadline, "serializing candidate metadata")
    serialized += "\n"
    _check_deadline(deadline, "serializing candidate metadata")
    return serialized


def _publish_candidate_document(
    temporary_output: Path,
    output: Path,
    document: dict[str, Any],
    deadline: float | None,
) -> None:
    published = False
    try:
        serialized = _serialize_candidate_document(document, deadline)
        _check_deadline(deadline, "writing candidate metadata")
        try:
            temporary_output.write_text(serialized, encoding="utf-8")
        except OSError as error:
            fail(f"could not publish candidate metadata: {error}")
        _check_deadline(deadline, "writing candidate metadata")
        _check_deadline(deadline, "publishing candidate metadata")
        try:
            temporary_output.replace(output)
        except OSError as error:
            fail(f"could not publish candidate metadata: {error}")
        try:
            _check_deadline(deadline, "publishing candidate metadata")
        except CaptureDeadlineExceeded:
            try:
                output.unlink(missing_ok=True)
            except OSError as error:
                raise CaptureError(f"could not remove expired candidate metadata: {error}") from error
            raise
        published = True
    finally:
        if not published:
            try:
                temporary_output.unlink(missing_ok=True)
            except OSError:
                pass


def capture(
    *,
    fixture_manifest_path: Path,
    real_sample_manifest_path: Path,
    output_path: Path,
    docker_command: str = "docker",
    timeout_seconds: int = MAX_OPERATION_SECONDS,
) -> dict[str, Any]:
    if not 1 <= timeout_seconds <= MAX_OPERATION_SECONDS:
        fail(f"timeout must be between 1 and {MAX_OPERATION_SECONDS} seconds")
    workflow_deadline = time.monotonic() + timeout_seconds
    cleanup_window = _cleanup_window_seconds(timeout_seconds)
    capture_deadline = workflow_deadline - cleanup_window
    _check_deadline(capture_deadline, "loading pinned inputs")
    inputs = load_pinned_inputs(fixture_manifest_path, real_sample_manifest_path)
    _check_deadline(capture_deadline, "loading pinned inputs")
    machine = platform.machine()
    _check_deadline(capture_deadline, "checking capture environment")
    if not shutil.which(docker_command):
        fail(f"Docker runtime executable was not found: {docker_command}")
    _check_deadline(capture_deadline, "checking capture environment")
    if not shutil.which("dpkg-deb"):
        fail("dpkg-deb is required to inspect downloaded package control metadata")
    _check_deadline(capture_deadline, "checking capture environment")
    docker_version, _ = run_bounded(
        [docker_command, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"],
        timeout_seconds=min(30, _remaining_seconds(capture_deadline)),
        deadline=capture_deadline,
    )
    docker_platform = docker_version.decode("utf-8", errors="strict").strip()
    _check_deadline(capture_deadline, "checking Docker platform")
    require_native_environment(machine, docker_platform, host_android_context())

    _check_deadline(capture_deadline, "preparing candidate output")
    output = output_path.resolve()
    _check_deadline(capture_deadline, "preparing candidate output")
    if output.exists() and output.is_dir():
        fail("candidate output path must name a JSON file")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        fail(f"could not prepare candidate output directory: {error}")
    _check_deadline(capture_deadline, "preparing candidate output")
    temporary_output = output.with_name(output.name + ".tmp")
    try:
        temporary_output.unlink(missing_ok=True)
    except OSError as error:
        fail(f"could not clear temporary candidate output: {error}")
    _check_deadline(capture_deadline, "preparing candidate output")

    run_bounded(
        [docker_command, "pull", "--quiet", inputs["image"]],
        timeout_seconds=_remaining_seconds(capture_deadline),
        deadline=capture_deadline,
    )
    image_inspect = _load_image_identity(
        docker_command,
        inputs["image"],
        _remaining_seconds(capture_deadline),
        deadline=capture_deadline,
    )
    image_identity = inspect_pinned_image(image_inspect, inputs)

    runner_temp = os.environ.get("RUNNER_TEMP")
    temp_parent = Path(runner_temp) if runner_temp else None
    if temp_parent is not None:
        _check_deadline(capture_deadline, "preparing temporary capture storage")
        try:
            temp_parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            fail(f"could not prepare temporary capture storage: {error}")
        _check_deadline(capture_deadline, "preparing temporary capture storage")
    _check_deadline(capture_deadline, "preparing temporary capture storage")
    with tempfile.TemporaryDirectory(prefix="urprotect-bionic-node-capture-", dir=temp_parent) as temporary:
        capture_directory = Path(temporary).resolve()
        _check_deadline(capture_deadline, "preparing temporary capture storage")
        if output.is_relative_to(capture_directory):
            fail("candidate JSON must be outside temporary package-capture storage")
        if "," in str(capture_directory):
            fail("temporary capture path contains a Docker mount delimiter")
        try:
            os.chmod(capture_directory, 0o777)
        except OSError as error:
            fail(f"could not prepare temporary capture storage: {error}")
        _check_deadline(capture_deadline, "preparing temporary capture storage")
        shell_script = _container_capture_script()
        capture_container_name = _container_name("package-capture")
        command = [
            docker_command,
            "run",
            "--name",
            capture_container_name,
            "--platform",
            "linux/arm64",
            "--network",
            "bridge",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--pids-limit",
            "64",
            "--user",
            "1000:1000",
            "--mount",
            f"type=bind,src={capture_directory},dst=/capture",
            "--env",
            f"PREFIX={TERMUX_PREFIX}",
            "--env",
            "HOME=/tmp",
            "--env",
            f"TERMUX_PACKAGE_REPOSITORY={inputs['packageRepository']}",
            "--env",
            f"TERMUX_NODEJS_VERSION={inputs['nodeVersion']}",
            "--env",
            f"MAX_CAPTURE_ENTRIES={MAX_CAPTURE_ENTRIES}",
            inputs["image"],
            TERMUX_SHELL,
            "-c",
            shell_script,
        ]
        _run_capture_with_cleanup(
            command,
            docker_command=docker_command,
            image=inputs["image"],
            container_name=capture_container_name,
            capture_directory=capture_directory,
            capture_deadline=capture_deadline,
            cleanup_deadline=workflow_deadline,
        )
        _capture_directory_bytes(capture_directory, deadline=workflow_deadline)

        before_text = _check_text_file(
            capture_directory / "packages-before.tsv", MAX_METADATA_BYTES, "base package inventory", workflow_deadline
        )
        after_text = _check_text_file(
            capture_directory / "packages-after.tsv", MAX_METADATA_BYTES, "post-download package inventory", workflow_deadline
        )
        before_inventory = parse_package_inventory(before_text, "base package inventory", workflow_deadline)
        after_inventory = parse_package_inventory(after_text, "post-download package inventory", workflow_deadline)
        if before_inventory != after_inventory:
            fail("download-only package acquisition changed the base image's installed package inventory")
        for log_name in ("apt-update.log", "apt-download.log"):
            _check_deadline(workflow_deadline, "validating capture logs")
            _check_text_file(capture_directory / log_name, MAX_COMMAND_OUTPUT_BYTES, log_name, workflow_deadline)
        package_records = _collect_package_records(capture_directory, inputs, workflow_deadline)

    _check_deadline(workflow_deadline, "recording capture timestamp")
    captured_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    _check_deadline(workflow_deadline, "recording capture timestamp")
    document = build_candidate_document(
        inputs=inputs,
        image_identity=image_identity,
        host_architecture=machine,
        docker_server_platform=docker_platform,
        package_inventory=before_inventory,
        package_records=package_records,
        captured_at=captured_at,
        deadline=workflow_deadline,
    )
    errors = validate_candidate_against_pins(document, inputs, workflow_deadline)
    if errors:
        fail("internal candidate metadata validation failed: " + "; ".join(errors))
    _publish_candidate_document(temporary_output, output, document, workflow_deadline)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-manifest", type=Path, default=DEFAULT_FIXTURE_MANIFEST)
    parser.add_argument("--real-sample-manifest", type=Path, default=DEFAULT_REAL_SAMPLE_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-candidate", type=Path)
    parser.add_argument("--docker-command", default=os.environ.get("BIONIC_CONTAINER_RUNTIME", "docker"))
    parser.add_argument("--timeout-seconds", type=int, default=MAX_OPERATION_SECONDS)
    args = parser.parse_args()
    if (args.output is None) == (args.validate_candidate is None):
        parser.error("exactly one of --output or --validate-candidate is required")
    try:
        if args.validate_candidate is not None:
            document = read_json(args.validate_candidate, "candidate JSON")
            inputs = load_pinned_inputs(args.fixture_manifest, args.real_sample_manifest)
            errors = validate_candidate_against_pins(document, inputs)
            if errors:
                fail("; ".join(errors))
            print(f"PASS candidate-lock metadata schema: {args.validate_candidate}")
            return 0
        assert args.output is not None
        document = capture(
            fixture_manifest_path=args.fixture_manifest,
            real_sample_manifest_path=args.real_sample_manifest,
            output_path=args.output,
            docker_command=args.docker_command,
            timeout_seconds=args.timeout_seconds,
        )
    except CaptureError as error:
        print(f"candidate-lock capture failed: {error}", file=sys.stderr)
        return 1
    print(
        "candidate-lock metadata captured; runtimeEvidence=false; compatibilityStatus=not-established; "
        f"downloadedPackages={len(document['packages'])} output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
