#!/usr/bin/env python3
"""Create and validate narrowly declared Bionic artifact roots safely.

Every path component is opened relative to a directory descriptor with
O_NOFOLLOW. Creation (when explicitly requested) uses mkdirat-style operations
anchored to the already-open parent descriptor. The bounded tree-validation
operation also walks only through directory descriptors and never follows
symlinks.
"""
from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import re
import stat
import sys
from typing import Sequence

DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
MAX_GID = (1 << 31) - 1
MAX_PATHS = 16
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 128
MAX_COMPONENT_BYTES = 255
MAX_TREE_ENTRIES = 20000
MAX_TREE_DIRECTORIES = 4096
MAX_TREE_FILES = 16000
MAX_TREE_DEPTH = 64


def fail(message: str) -> int:
    print(f"Bionic artifact ownership: {message}", file=sys.stderr)
    return 2


def parse_gid(value: str) -> int:
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value) is None:
        raise argparse.ArgumentTypeError("group id must be a canonical nonnegative decimal")
    parsed = int(value)
    if parsed > MAX_GID:
        raise argparse.ArgumentTypeError("group id exceeds the platform bound")
    return parsed


def split_path(value: str) -> tuple[int, list[str]]:
    if not value or "\x00" in value or "\n" in value:
        raise ValueError("artifact path is empty or contains a forbidden character")
    if len(os.fsencode(value)) > MAX_PATH_BYTES:
        raise ValueError(f"artifact path exceeds {MAX_PATH_BYTES} encoded bytes")
    path = Path(value)
    components = list(path.parts[1:] if path.is_absolute() else path.parts)
    if any(component == ".." for component in components):
        raise ValueError("artifact path must not contain parent-directory components")
    components = [component for component in components if component not in {"", ".", os.sep}]
    if not components:
        raise ValueError("filesystem root or current directory is not an artifact path")
    if len(components) > MAX_PATH_COMPONENTS:
        raise ValueError(f"artifact path exceeds {MAX_PATH_COMPONENTS} components")
    if any(len(os.fsencode(component)) > MAX_COMPONENT_BYTES for component in components):
        raise ValueError(f"artifact path component exceeds {MAX_COMPONENT_BYTES} encoded bytes")
    descriptor = os.open("/" if path.is_absolute() else ".", DIRECTORY_FLAGS)
    return descriptor, components


def open_real_directory(value: str, *, create_missing: bool = False) -> tuple[int, os.stat_result]:
    descriptor, components = split_path(value)
    try:
        created_suffix = False
        for component in components:
            creation_attempted = False
            try:
                next_descriptor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create_missing:
                    raise
                creation_attempted = True
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    # Another actor won the name. Open it without following
                    # links, then require that it belongs to this host writer.
                    pass
                next_descriptor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                metadata = os.fstat(next_descriptor)
                if (created_suffix or creation_attempted) and metadata.st_uid != os.geteuid():
                    raise ValueError("new artifact path component is not owned by the host writer")
            except BaseException:
                os.close(next_descriptor)
                raise
            created_suffix = created_suffix or creation_attempted
            try:
                os.close(descriptor)
            except BaseException:
                os.close(next_descriptor)
                raise
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("artifact path is not a directory")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def open_regular_file(value: str) -> tuple[int, os.stat_result]:
    path = Path(value)
    name = path.name
    if not name or name in {".", ".."}:
        raise ValueError("artifact file path has no regular final component")
    parent = str(path.parent) if str(path.parent) else "."
    descriptor, _ = open_real_directory(parent)
    try:
        file_descriptor = os.open(name, FILE_FLAGS, dir_fd=descriptor)
        try:
            metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("artifact file is not a regular file")
        except BaseException:
            os.close(file_descriptor)
            raise
        return file_descriptor, metadata
    finally:
        os.close(descriptor)


def validate_paths(directories: list[str], files: list[str]) -> None:
    if len(directories) + len(files) > MAX_PATHS:
        raise ValueError(f"path count exceeds {MAX_PATHS}")
    for directory in directories:
        descriptor, _ = open_real_directory(directory)
        os.close(descriptor)
    for file_path in files:
        descriptor, _ = open_regular_file(file_path)
        os.close(descriptor)


def validate_tree_descriptor(
    root_descriptor: int,
    *,
    maximum_entries: int = MAX_TREE_ENTRIES,
    maximum_directories: int = MAX_TREE_DIRECTORIES,
    maximum_files: int = MAX_TREE_FILES,
    maximum_depth: int = MAX_TREE_DEPTH,
) -> None:
    """Validate a bounded tree rooted at an already-open directory.

    The root counts as one entry and one directory, and has depth zero. File
    contents are not read. Regular files with multiple hard links are refused
    because a later host redirection could otherwise mutate an inode also
    reachable outside this evidence tree.
    """
    limits = (maximum_entries, maximum_directories, maximum_files, maximum_depth)
    if any(limit < 0 for limit in limits) or maximum_entries < 1 or maximum_directories < 1:
        raise ValueError("artifact tree limits must be nonnegative with room for the root")

    counts = {"entries": 1, "directories": 1, "files": 0}
    if counts["entries"] > maximum_entries:
        raise ValueError(f"artifact tree exceeds {maximum_entries} total entries")

    def add_entry() -> None:
        counts["entries"] += 1
        if counts["entries"] > maximum_entries:
            raise ValueError(f"artifact tree exceeds {maximum_entries} total entries")

    def ensure_same_entry(before: os.stat_result, after: os.stat_result, relative: str) -> None:
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError(f"artifact tree entry changed during validation: {relative}")

    def visit(directory_descriptor: int, depth: int, relative_directory: str) -> None:
        # scandir accepts a descriptor but does not close it with its iterator.
        # Duplicate the retained descriptor, then close the duplicate explicitly
        # on success and every exceptional path.
        scan_descriptor = os.dup(directory_descriptor)
        try:
            with os.scandir(scan_descriptor) as entries:
                for entry in entries:
                    name = entry.name
                    if name in {"", ".", ".."} or os.sep in name or "\x00" in name:
                        raise ValueError("artifact tree contains an invalid entry name")
                    relative = f"{relative_directory}/{name}" if relative_directory else name
                    child_depth = depth + 1
                    if child_depth > maximum_depth:
                        raise ValueError(f"artifact tree exceeds depth {maximum_depth}")
                    add_entry()
                    before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
                    if stat.S_ISLNK(before.st_mode):
                        raise ValueError(f"artifact tree contains a symlink: {relative}")
                    if stat.S_ISDIR(before.st_mode):
                        counts["directories"] += 1
                        if counts["directories"] > maximum_directories:
                            raise ValueError(f"artifact tree exceeds {maximum_directories} directories")
                        child_descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=directory_descriptor)
                        try:
                            after = os.fstat(child_descriptor)
                            ensure_same_entry(before, after, relative)
                            if not stat.S_ISDIR(after.st_mode):
                                raise ValueError(f"artifact tree entry is not a directory: {relative}")
                            visit(child_descriptor, child_depth, relative)
                        finally:
                            os.close(child_descriptor)
                    elif stat.S_ISREG(before.st_mode):
                        counts["files"] += 1
                        if counts["files"] > maximum_files:
                            raise ValueError(f"artifact tree exceeds {maximum_files} files")
                        if before.st_nlink != 1:
                            raise ValueError(f"artifact tree contains a multiply-linked regular file: {relative}")
                        child_descriptor = os.open(name, FILE_FLAGS, dir_fd=directory_descriptor)
                        try:
                            after = os.fstat(child_descriptor)
                            ensure_same_entry(before, after, relative)
                            if not stat.S_ISREG(after.st_mode):
                                raise ValueError(f"artifact tree entry is not a regular file: {relative}")
                            if after.st_nlink != 1:
                                raise ValueError(f"artifact tree contains a multiply-linked regular file: {relative}")
                        finally:
                            os.close(child_descriptor)
                    else:
                        raise ValueError(f"artifact tree contains a non-regular, non-directory entry: {relative}")
        finally:
            os.close(scan_descriptor)

    visit(root_descriptor, 0, "")


def validate_tree(value: str, **limits: int) -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("no-follow directory access is unavailable")
    descriptor, _ = open_real_directory(value)
    try:
        validate_tree_descriptor(descriptor, **limits)
    finally:
        os.close(descriptor)


def validate_trees(paths: list[str]) -> None:
    if not paths or len(paths) > MAX_PATHS:
        raise ValueError(f"tree-path count must be between 1 and {MAX_PATHS}")
    for path in paths:
        validate_tree(path)


def validate_creation_path(value: str) -> None:
    descriptor, components = split_path(value)
    try:
        for component in components:
            try:
                next_descriptor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                # Nothing after a missing component can exist at this lexical
                # location. The later create operation reopens every component
                # and uses mkdir relative to the retained parent descriptor.
                return
            os.close(descriptor)
            descriptor = next_descriptor
    finally:
        os.close(descriptor)


def validate_creation_paths(paths: list[str]) -> None:
    if not paths or len(paths) > MAX_PATHS:
        raise ValueError(f"creation-path count must be between 1 and {MAX_PATHS}")
    for value in paths:
        validate_creation_path(value)


def prepare(directories: list[str], group_gid: int, *, create_missing: bool = False) -> None:
    if not directories or len(directories) > MAX_PATHS:
        raise ValueError(f"artifact write root count must be between 1 and {MAX_PATHS}")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("no-follow directory access is unavailable")
    if os.geteuid() != 0 and group_gid not in {os.getegid(), *os.getgroups()}:
        raise ValueError("shared group is not owned by the host writer")

    opened: list[tuple[int, os.stat_result]] = []
    try:
        for directory in directories:
            descriptor, metadata = open_real_directory(directory, create_missing=create_missing)
            if metadata.st_uid != os.geteuid():
                os.close(descriptor)
                raise ValueError("artifact write root is not owned by the host writer")
            opened.append((descriptor, metadata))

        identities = [(metadata.st_dev, metadata.st_ino) for _, metadata in opened]
        if len(identities) != len(set(identities)):
            raise ValueError("artifact write roots must be distinct directories")

        for descriptor, metadata in opened:
            if metadata.st_gid != group_gid:
                os.fchown(descriptor, -1, group_gid)
            # setgid makes descendants inherit the one shared group. 0770
            # keeps access limited to the host owner and that group.
            os.fchmod(descriptor, 0o2770)
    finally:
        for descriptor, _ in opened:
            os.close(descriptor)


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group-gid", type=parse_gid)
    parser.add_argument("--directory", action="append", default=[])
    parser.add_argument("--create-directory", action="append", default=[])
    parser.add_argument("--validate-directory", action="append", default=[])
    parser.add_argument("--validate-file", action="append", default=[])
    parser.add_argument("--validate-tree", action="append", default=[])
    parser.add_argument("--validate-creation-path", action="append", default=[])
    try:
        options = parser.parse_args(argv[1:])
        path_count = sum(len(value) for value in (
            options.directory,
            options.create_directory,
            options.validate_directory,
            options.validate_file,
            options.validate_tree,
            options.validate_creation_path,
        ))
        if path_count > MAX_PATHS:
            raise ValueError(f"path count exceeds {MAX_PATHS}")
        if options.directory or options.create_directory:
            if options.group_gid is None:
                raise ValueError("--group-gid is required when preparing write roots")
            if options.directory and options.create_directory:
                raise ValueError("--directory and --create-directory cannot be combined")
            if options.validate_directory or options.validate_file or options.validate_tree or options.validate_creation_path:
                raise ValueError("write-root preparation cannot be combined with validation")
            prepare(
                options.directory or options.create_directory,
                options.group_gid,
                create_missing=bool(options.create_directory),
            )
        else:
            validate_paths(options.validate_directory, options.validate_file)
            if options.validate_tree:
                validate_trees(options.validate_tree)
            if options.validate_creation_path:
                validate_creation_paths(options.validate_creation_path)
            if not options.validate_directory and not options.validate_file and not options.validate_tree and not options.validate_creation_path:
                raise ValueError("at least one path operation is required")
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            return fail("artifact path contains a symlink or non-directory component")
        if error.errno == errno.ENOENT:
            return fail("artifact path does not exist")
        return fail("artifact path could not be opened safely")
    except (ValueError, RuntimeError) as error:
        return fail(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
