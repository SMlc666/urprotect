#!/usr/bin/env python3
"""Safely extract one CI-only real-sample archive into a temporary directory.

The command is an implementation detail of run-real-sample-matrix.sh.  It
never writes to the repository and rejects absolute/traversal members and
links that could escape the extraction root.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile

MAX_MEMBERS = 100_000
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024


class ExtractionError(Exception):
    pass


def safe_member_name(name: str) -> Path:
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        return Path(".")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or normalized.startswith("/"):
        raise ExtractionError(f"archive member is absolute: {name}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ExtractionError(f"archive member contains traversal: {name}")
    return Path(*pure.parts)


def safe_link_target(member_name: str, link_name: str) -> None:
    """Allow links only when their normalized target stays inside the archive root."""
    target = link_name.replace("\\", "/")
    if not target or "\x00" in target or "\n" in target or "\r" in target:
        raise ExtractionError(f"archive link has an invalid target: {member_name} -> {link_name}")
    if target.startswith("/"):
        candidate = PurePosixPath(target.lstrip("/"))
    else:
        candidate = PurePosixPath(member_name).parent / target

    # Normalize lexically instead of rejecting every `..`: package archives
    # routinely use safe links such as usr/bin/tool -> ../lib/tool. Reject only
    # a traversal that escapes the archive root.
    depth = 0
    for part in candidate.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if depth == 0:
                raise ExtractionError(
                    f"archive link escapes extraction root: {member_name} -> {link_name}"
                )
            depth -= 1
        else:
            depth += 1


def ensure_destination(destination: Path) -> Path:
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ExtractionError(f"destination is a symlink: {destination}")
    return destination


def prepare_target(destination: Path, relative: Path) -> Path:
    """Create/check lexical parents without resolving through archive links."""
    if relative == Path("."):
        raise ExtractionError("root directory is not a file target")
    current = destination
    for component in relative.parts[:-1]:
        current = current / component
        if current.is_symlink():
            raise ExtractionError(f"archive path traverses a symlink: {relative}")
        if current.exists() and not current.is_dir():
            raise ExtractionError(f"archive path parent is not a directory: {current}")
        current.mkdir(exist_ok=True)
    target = destination / relative
    if os.path.lexists(target):
        raise ExtractionError(f"archive contains a duplicate target: {relative}")
    return target


def check_limits(members: list[tuple[str, int]]) -> None:
    if len(members) > MAX_MEMBERS:
        raise ExtractionError(f"archive has too many members: {len(members)}")
    total = sum(size for _, size in members)
    if total > MAX_UNCOMPRESSED_BYTES:
        raise ExtractionError(f"archive expands beyond {MAX_UNCOMPRESSED_BYTES} bytes")


def extract_tar(archive: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive, mode="r:*") as handle:
            infos = handle.getmembers()
            members: list[tuple[str, int]] = []
            safe_infos: list[tarfile.TarInfo] = []
            for info in infos:
                safe_member_name(info.name)
                if info.islnk() or not (info.isfile() or info.isdir() or info.issym()):
                    raise ExtractionError(f"archive member is not a regular file/directory/link: {info.name}")
                if info.issym():
                    safe_link_target(info.name, info.linkname)
                members.append((info.name, max(0, info.size)))
                safe_infos.append(info)
            check_limits(members)
            for info in safe_infos:
                relative = safe_member_name(info.name)
                if relative == Path("."):
                    continue
                target = prepare_target(destination, relative)
                if info.isdir():
                    target.mkdir()
                    continue
                if info.issym():
                    target.symlink_to(info.linkname)
                    continue
                source = handle.extractfile(info)
                if source is None:
                    raise ExtractionError(f"could not read archive member: {info.name}")
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                os.chmod(target, stat.S_IMODE(info.mode) or 0o600)
    except (tarfile.TarError, OSError, ValueError) as error:
        if isinstance(error, ExtractionError):
            raise
        raise ExtractionError(f"could not extract tar archive: {error}") from error


def extract_zip(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as handle:
            infos = handle.infolist()
            members: list[tuple[str, int]] = []
            for info in infos:
                safe_member_name(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode):
                    raise ExtractionError(f"archive member is a device: {info.filename}")
                if stat.S_ISLNK(mode):
                    safe_link_target(info.filename, info.comment.decode(errors="replace"))
                members.append((info.filename, info.file_size))
            check_limits(members)
            for info in infos:
                relative = safe_member_name(info.filename)
                if relative == Path("."):
                    continue
                target = prepare_target(destination, relative)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    link_name = handle.read(info).decode("utf-8", errors="strict")
                    safe_link_target(info.filename, link_name)
                    target.symlink_to(link_name)
                    continue
                if info.is_dir():
                    target.mkdir()
                    continue
                with handle.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                mode = (info.external_attr >> 16) & 0xFFFF
                os.chmod(target, stat.S_IMODE(mode) or 0o600)
    except (zipfile.BadZipFile, OSError, ValueError) as error:
        if isinstance(error, ExtractionError):
            raise
        raise ExtractionError(f"could not extract zip archive: {error}") from error


def validate_deb_members(archive: Path) -> None:
    try:
        listing = subprocess.run(
            ["dpkg-deb", "--contents", str(archive)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ExtractionError(f"could not inspect deb archive: {error}") from error
    members: list[tuple[str, int]] = []
    for line in listing.stdout.splitlines():
        if not line.strip():
            continue
        # dpkg-deb prints permissions, owner, size, timestamp, and path.  A
        # path with spaces is still accepted by taking the final columns after
        # the timestamp; package paths in the locked registry contain none.
        fields = line.split(maxsplit=5)
        if len(fields) < 6:
            raise ExtractionError(f"unparseable dpkg-deb member line: {line}")
        mode = fields[0]
        name_field = fields[5]
        name = name_field.split(" -> ", 1)[0].removeprefix("./")
        safe_member_name(name)
        if mode.startswith("l"):
            link_target = name_field.split(" -> ", 1)[1] if " -> " in name_field else ""
            safe_link_target(name, link_target)
        elif mode.startswith("c") or mode.startswith("b") or mode.startswith("p"):
            raise ExtractionError(f"deb member is a device: {name}")
        try:
            size = int(fields[2])
        except ValueError as error:
            raise ExtractionError(f"invalid deb member size: {line}") from error
        members.append((name, max(0, size)))
    check_limits(members)


def extract_deb(archive: Path, destination: Path) -> None:
    validate_deb_members(archive)
    try:
        subprocess.run(
            ["dpkg-deb", "--extract", str(archive), str(destination)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ExtractionError(f"could not extract deb archive: {error}") from error


def validate_extracted_tree(destination: Path) -> None:
    count = 0
    total = 0
    for root, directories, files in os.walk(destination, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            if path.is_symlink():
                relative = path.relative_to(destination)
                safe_link_target(str(relative), os.readlink(path))
                count += 1
                if count > MAX_MEMBERS:
                    raise ExtractionError("extracted tree has too many entries")
                continue
            count += 1
            if count > MAX_MEMBERS:
                raise ExtractionError("extracted tree has too many entries")
            try:
                stat_result = path.stat()
            except OSError as error:
                raise ExtractionError(f"cannot inspect extracted entry {path}: {error}") from error
            if stat.S_ISREG(stat_result.st_mode):
                total += stat_result.st_size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise ExtractionError("extracted tree exceeds size limit")
            elif not stat.S_ISDIR(stat_result.st_mode):
                raise ExtractionError(f"extracted tree contains a device or special file: {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--format", required=True, choices=("deb", "tar.gz", "tar", "zip"))
    parser.add_argument("--destination", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        archive = arguments.archive.resolve(strict=True)
        if not archive.is_file() or archive.is_symlink():
            raise ExtractionError("archive must be a regular non-symlink file")
        destination = ensure_destination(arguments.destination)
        if arguments.format == "deb":
            extract_deb(archive, destination)
        elif arguments.format in {"tar", "tar.gz"}:
            extract_tar(archive, destination)
        else:
            extract_zip(archive, destination)
        validate_extracted_tree(destination)
    except (ExtractionError, OSError) as error:
        print(f"FAIL archive extraction: {error}", file=sys.stderr)
        return 1
    print(f"PASS archive extraction: {arguments.format} -> {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
