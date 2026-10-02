#!/usr/bin/env python3
"""Acquire and assemble one bounded native AArch64 runtime closure.

The caller owns the source archive hash check. This helper owns the locked
Debian/Alpine index check, dependency resolution, archive hashes, safe
extraction, and the generated closure lock retained as text evidence.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
from collections import deque
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import posixpath
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zlib
from typing import Iterable, Iterator


MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def ensure_directory_no_symlink(path: Path) -> Path:
    """Create a directory tree without traversing a symlink component."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            fail(f"directory component is a symlink: {current}")
        if current.exists() and not current.is_dir():
            fail(f"directory component is not a directory: {current}")
        current.mkdir(exist_ok=True)
    return absolute


def bounded_file_digest(
    path: Path, algorithm: str, max_bytes: int | None = None
) -> tuple[str, int]:
    digest = hashlib.new(algorithm)
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"file exceeds bounded size: {path}")
            digest.update(block)
    return digest.hexdigest(), total


def download(
    url: str,
    destination: Path,
    expected_sha256: str | None = None,
    max_bytes: int = MAX_INDEX_BYTES,
    expected_size: int | None = None,
) -> None:
    """Download or validate a bounded file without buffering it in memory."""
    ensure_directory_no_symlink(destination.parent)
    if destination.is_symlink():
        fail(f"download destination is a symlink: {destination}")
    if destination.exists() and not destination.is_file():
        fail(f"download destination is not a regular file: {destination}")

    expected = expected_sha256.lower() if expected_sha256 else None
    if destination.is_file():
        try:
            actual, actual_size = bounded_file_digest(destination, "sha256", max_bytes)
        except (OSError, ValueError) as error:
            fail(f"cached download cannot be verified: {error}")
        if (expected_size is None or actual_size == expected_size) and (
            expected is None or actual == expected
        ):
            return
        # A regular, digest-mismatched cache entry can be repaired.  Symlinks
        # were rejected above and are never followed or replaced.
        try:
            destination.unlink()
        except OSError as error:
            fail(f"cannot replace invalid cached download {destination}: {error}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    temporary = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            with urllib.request.urlopen(url, timeout=60) as response:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > max_bytes:
                        fail(f"download exceeds bounded size: {url}")
                    if expected_size is not None and total > expected_size:
                        fail(f"download exceeds locked package size: {url}")
                    digest.update(block)
                    output.write(block)
            if expected_size is not None and total != expected_size:
                fail(
                    f"download size {total} does not match locked package size "
                    f"{expected_size}: {url}"
                )
            if expected is not None and digest.hexdigest() != expected:
                fail(f"SHA-256 mismatch for {url}")
        if destination.is_symlink():
            fail(f"download destination became a symlink: {destination}")
        os.replace(temporary, destination)
        temporary = Path()
    except SystemExit:
        raise
    except (OSError, urllib.error.URLError) as error:
        fail(f"download failed for {url}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary != Path():
            temporary.unlink(missing_ok=True)


def file_digest(path: Path, algorithm: str) -> str:
    return bounded_file_digest(path, algorithm)[0]


def package_size(record: dict, package_name: str, *fields: str) -> int:
    value = next(
        (record.get(field) for field in fields if record.get(field) not in (None, "")),
        None,
    )
    try:
        size = int(value)
    except (TypeError, ValueError):
        fail(f"package {package_name} has no valid locked archive size")
    if size <= 0:
        fail(f"package {package_name} has a non-positive locked archive size")
    if size > MAX_PACKAGE_BYTES:
        fail(f"package {package_name} exceeds bounded archive size")
    return size


def normalize_apk_checksum(value: str, package_name: str) -> tuple[str, str]:
    """Normalize apk-tools' C field (MD5 or the encoded SHA-1 identity)."""
    checksum = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", checksum):
        return "md5", checksum.lower()
    if checksum.startswith("Q1"):
        encoded = checksum[2:]
        if len(encoded) != 28:
            fail(f"package {package_name} has an invalid APK archive checksum")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if (
            len(decoded) == hashlib.sha1().digest_size
            and base64.b64encode(decoded).decode() == encoded
        ):
            return "sha1", decoded.hex()
    elif checksum.startswith("X1") and re.fullmatch(r"[0-9a-fA-F]{40}", checksum[2:]):
        return "sha1", checksum[2:].lower()
    fail(f"package {package_name} has an invalid APK archive checksum")


def package_expectation(runtime: str, record: dict, package_name: str) -> tuple[str, str, int]:
    if runtime == "glibc":
        value = record.get("SHA256")
        digest = value.strip() if isinstance(value, str) else ""
        if re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            fail(f"package {package_name} has an invalid Debian SHA-256")
        return "sha256", digest.lower(), package_size(record, package_name, "Size")
    checksum = record.get("C")
    if not isinstance(checksum, str) or not checksum.strip():
        fail(f"package {package_name} has no locked APK C checksum")
    algorithm, digest = normalize_apk_checksum(checksum, package_name)
    return f"apk-{algorithm}", digest, package_size(record, package_name, "S", "Size")


def apk_identity_digest(path: Path, algorithm: str) -> str:
    """Hash the APK v2 control gzip member represented by index field C."""
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for member in range(2):
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            while not decompressor.eof:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    raise ValueError("APK archive has fewer than two gzip members")
                try:
                    decompressor.decompress(chunk)
                except zlib.error as error:
                    raise ValueError(f"invalid APK gzip member: {error}") from error
                consumed = len(chunk) - len(decompressor.unused_data)
                if member == 1:
                    digest.update(chunk[:consumed])
                if decompressor.eof:
                    stream.seek(stream.tell() - len(decompressor.unused_data))
    return digest.hexdigest()


def archive_digest(path: Path, algorithm: str) -> str:
    if algorithm.startswith("apk-"):
        return apk_identity_digest(path, algorithm.removeprefix("apk-"))
    return file_digest(path, algorithm)


def safe_cache_component(value: str) -> str:
    component = re.sub(r"[^A-Za-z0-9._+-]", "_", value)
    component = component.strip(".")
    if not component or component in {".", ".."}:
        return "package"
    return component[:160]


def package_cache_path(
    package_cache: Path,
    package_name: str,
    archive_name: str,
    algorithm: str,
    digest: str,
) -> tuple[Path, Path]:
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", digest) is None:
        fail(f"invalid normalized package digest for {package_name}")
    root = ensure_directory_no_symlink(package_cache)
    safe_name = "-".join(
        (safe_cache_component(package_name), safe_cache_component(Path(archive_name).name))
    )
    path = root / algorithm / digest / safe_name
    if root != path and root not in path.parents:
        fail(f"package cache path escapes its root for {package_name}")
    return root, path


def package_mismatch(path: Path, algorithm: str, digest: str, expected_size: int) -> str | None:
    if path.is_symlink():
        return "cached package is a symlink"
    if not path.is_file():
        return "cached package is missing"
    try:
        actual_size = path.stat().st_size
    except OSError as error:
        return f"cached package cannot be stat'ed: {error}"
    if actual_size != expected_size:
        return f"cached package size is {actual_size}, expected {expected_size}"
    try:
        actual_digest = archive_digest(path, algorithm)
    except (OSError, ValueError, zlib.error) as error:
        return f"cached package digest could not be verified: {error}"
    if actual_digest != digest:
        return f"cached package {algorithm} is {actual_digest}, expected {digest}"
    return None


def verify_package(path: Path, package_name: str, algorithm: str, digest: str, expected_size: int) -> None:
    mismatch = package_mismatch(path, algorithm, digest, expected_size)
    if mismatch is not None:
        fail(f"package {package_name}: {mismatch}")


def acquire_package(
    url: str,
    destination: Path,
    package_cache: Path | None,
    package_name: str,
    archive_name: str,
    algorithm: str,
    digest: str,
    expected_size: int,
) -> Path:
    if package_cache is None:
        download(
            url,
            destination,
            max_bytes=MAX_PACKAGE_BYTES,
            expected_size=expected_size,
        )
        verify_package(destination, package_name, algorithm, digest, expected_size)
        return destination

    cache_root, cached = package_cache_path(
        package_cache, package_name, archive_name, algorithm, digest
    )
    relative_parent = cached.parent.relative_to(cache_root)
    current = cache_root
    for component in relative_parent.parts:
        current /= component
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            fail(f"package cache path is not a directory: {current}")
        current.mkdir(exist_ok=True)
    if cached.exists() or cached.is_symlink():
        mismatch = package_mismatch(cached, algorithm, digest, expected_size)
        if mismatch is None:
            return cached
        if cached.is_symlink():
            fail(f"package cache entry is not a regular file: {cached}")
        if cached.is_file():
            cached.unlink()
        else:
            fail(f"package cache entry is not a regular file: {cached}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{cached.name}.", suffix=".tmp", dir=str(cached.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        download(
            url,
            temporary,
            max_bytes=MAX_PACKAGE_BYTES,
            expected_size=expected_size,
        )
        verify_package(temporary, package_name, algorithm, digest, expected_size)
        os.replace(temporary, cached)
        return cached
    finally:
        temporary.unlink(missing_ok=True)


def iter_stanzas(
    stream: Iterable[bytes | str], max_bytes: int = MAX_INDEX_BYTES
) -> Iterator[dict[str, str]]:
    fields: dict[str, str] = {}
    total = 0
    for raw in stream:
        if isinstance(raw, bytes):
            total += len(raw)
            if total > max_bytes:
                fail("decompressed package index exceeds bounded size")
            line = raw.decode("utf-8", errors="strict")
        else:
            line = raw
            total += len(line.encode("utf-8"))
            if total > max_bytes:
                fail("decompressed package index exceeds bounded size")
        line = line.rstrip("\r\n")
        if not line:
            if fields:
                yield fields
                fields = {}
        elif line.startswith((" ", "\t")) and fields:
            current = next(reversed(fields))
            fields[current] += "\n" + line.strip()
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    if fields:
        yield fields


def parse_stanzas(data: bytes) -> list[dict[str, str]]:
    return list(iter_stanzas(io.BytesIO(data)))


def dependency_names(value: str | None) -> list[str]:
    if not value:
        return []
    names: list[str] = []
    for item in value.split(","):
        alternatives = item.strip().split("|")
        chosen = alternatives[0].strip()
        chosen = chosen.split("(", 1)[0].strip()
        chosen = chosen.split(":", 1)[0]
        if chosen and not chosen.startswith("${"):
            names.append(chosen)
    return names


def safe_extract_tar(archive: Path, root: Path, apk: bool) -> None:
    mode = "r:gz" if apk else "r:*"
    with tarfile.open(archive, mode) as tar:
        members = tar.getmembers()
        if len(members) > 100_000:
            fail(f"archive has too many members: {archive}")
        root_resolved = root.resolve()
        archive_links = {
            posixpath.normpath(member.name).lstrip("./")
            for member in members
            if member.issym() or member.islnk()
        }
        safe_members: list[tarfile.TarInfo] = []
        for member in members:
            normalized_name = posixpath.normpath(member.name).lstrip("./")
            name_parts = normalized_name.split("/")
            if any("/".join(name_parts[:index]) in archive_links for index in range(1, len(name_parts))):
                fail(f"archive member traverses an archive link: {member.name}")
            for parent in Path(member.name).parents:
                if str(parent) == ".":
                    continue
                if (root / parent).is_symlink():
                    fail(f"archive member traverses an existing link: {member.name}")
            target = (root / member.name).resolve()
            if target != root_resolved and root_resolved not in target.parents:
                fail(f"archive traversal: {member.name}")
            if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
                fail(f"unsupported special archive member: {member.name}")
            if member.issym() or member.islnk():
                if member.islnk():
                    link_target = (
                        root / member.linkname.lstrip("/")
                        if member.linkname.startswith("/")
                        else root / member.linkname
                    ).resolve()
                else:
                    link_target = (
                        root / member.linkname.lstrip("/")
                        if member.linkname.startswith("/")
                        else root / Path(member.name).parent / member.linkname
                    ).resolve()
                if link_target != root_resolved and root_resolved not in link_target.parents:
                    fail(f"archive link escapes root: {member.name} -> {member.linkname}")
                if member.linkname.startswith("/"):
                    rewritten = copy.copy(member)
                    if member.issym():
                        link_parent = (root / Path(member.name).parent).resolve()
                    else:
                        link_parent = root_resolved
                    rewritten.linkname = os.path.relpath(link_target, link_parent)
                    member = rewritten
            safe_members.append(member)
        # Rewrite absolute links such as /bin/sh to equivalent links relative
        # to this private root.  Keeping the link absolute on the build host
        # would point at the host filesystem rather than the eventual chroot.
        tar.extractall(root, members=safe_members)


def parse_debian_index(index: Path) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    by_name: dict[str, dict] = {}
    by_filename: dict[str, dict] = {}
    providers: dict[str, dict] = {}
    with lzma.open(index, "rb") as stream:
        for record in iter_stanzas(stream):
            if record.get("Architecture") not in {"arm64", "all"}:
                continue
            filename = record.get("Filename")
            package = record.get("Package")
            digest = record.get("SHA256")
            if not filename or not package or not digest:
                continue
            if record.get("Architecture") == "arm64" or package not in by_name:
                by_name[package] = record
            by_filename[filename] = record
            for provided in record.get("Provides", "").split(","):
                provided_name = provided.split("(", 1)[0].strip().split(":", 1)[0]
                if provided_name:
                    providers.setdefault(provided_name, record)
    return by_name, by_filename, providers


def build_debian(args: argparse.Namespace, runtime: dict, project: dict) -> dict:
    index = args.index_dir / "debian-Packages.xz"
    download(runtime["packageIndexUrl"], index, runtime["packageIndexSha256"])
    by_name, by_filename, providers = parse_debian_index(index)
    source_path = project["provenance"]["archivePath"]
    seed = by_filename.get(source_path)
    if seed is None:
        fail(f"source package is absent from the locked Debian index: {source_path}")
    pending = deque([seed["Package"]])
    # Some Go/C packages omit libc6 from package metadata while still being
    # dynamically linked. Keep every glibc closure executable by including
    # the locked loader package as a runtime invariant.
    if "libc6" in by_name and seed["Package"] != "libc6":
        pending.append("libc6")
    selected: dict[str, dict] = {}
    project_policy = args.closure.get("projects", {}).get(project.get("projectId"), {})
    excluded = {
        item.get("package")
        for item in project_policy.get("excludeDependencies", [])
        if isinstance(item, dict) and isinstance(item.get("package"), str)
    }
    while pending:
        name = pending.popleft()
        if name in selected:
            continue
        record = by_name.get(name) or providers.get(name)
        if record is None:
            fail(f"Debian dependency is absent from the locked index: {name}")
        selected[name] = record
        for dependency in dependency_names(record.get("Pre-Depends")) + dependency_names(record.get("Depends")):
            if dependency in excluded:
                continue
            if dependency not in selected:
                pending.append(dependency)

    packages_root = args.work_root / "deb-packages"
    root = args.rootfs
    root.mkdir(parents=True, exist_ok=True)
    locks: list[dict] = []
    for name in sorted(selected):
        record = selected[name]
        relative = record["Filename"]
        archive_name = Path(relative).name
        archive = packages_root / archive_name
        url = runtime["repositoryRoot"].rstrip("/") + "/" + relative
        algorithm, digest, expected_size = package_expectation("glibc", record, name)
        archive = acquire_package(
            url,
            archive,
            args.package_cache,
            name,
            archive_name,
            algorithm,
            digest,
            expected_size,
        )
        if archive.stat().st_size > MAX_PACKAGE_BYTES:
            fail(f"package exceeds bounded size: {archive}")
        subprocess.run(["dpkg-deb", "-x", str(archive), str(root)], check=True)
        locks.append({
            "name": name,
            "version": record.get("Version", ""),
            "architecture": record.get("Architecture", ""),
            "filename": relative,
            "sha256": digest,
            "size": expected_size,
            "depends": record.get("Depends", ""),
        })
    return {
        "runtime": "glibc",
        "resolver": "deb-depends-v1",
        "indexSha256": runtime["packageIndexSha256"],
        "packages": locks,
    }


def parse_apk_index(index: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    by_name: dict[str, dict] = {}
    providers: dict[str, dict] = {}
    with tarfile.open(index, "r:gz") as tar:
        member_count = 0
        for candidate in tar:
            member_count += 1
            if member_count > 100_000:
                fail(f"APK index has too many members: {index}")
            if candidate.name != "APKINDEX":
                continue
            member = tar.extractfile(candidate)
            if member is None:
                fail("APKINDEX is not a regular file")
            for record in iter_stanzas(member):
                if record.get("A") != "aarch64" or not record.get("P"):
                    continue
                by_name[record["P"]] = record
                for provided in record.get("p", "").split():
                    providers[provided.split("=", 1)[0]] = record
                providers[record["P"]] = record
            break
        else:
            fail("APKINDEX is missing from the locked index archive")
    return by_name, providers


def build_apk(args: argparse.Namespace, runtime: dict, project: dict) -> dict:
    index = args.index_dir / "alpine-APKINDEX.tar.gz"
    download(runtime["packageIndexUrl"], index, runtime["packageIndexSha256"])
    by_name, providers = parse_apk_index(index)
    source_package = project["provenance"].get("packageName")
    source_version = project["provenance"].get("version")
    if not source_package or source_package not in by_name:
        fail(f"source APK package is absent from the locked index: {source_package}")
    source_record = by_name[source_package]
    if source_version and source_record.get("V") != source_version:
        fail(
            f"source APK version differs from the locked index: "
            f"{source_record.get('V')} != {source_version}"
        )
    pending = deque([source_package])
    selected: dict[str, dict] = {}
    project_policy = args.closure.get("projects", {}).get(project.get("projectId"), {})
    excluded = {
        item.get("package")
        for item in project_policy.get("excludeDependencies", [])
        if isinstance(item, dict) and isinstance(item.get("package"), str)
    }
    while pending:
        name = pending.popleft()
        record = providers.get(name)
        if record is None:
            fail(f"Alpine dependency is absent from the locked index: {name}")
        package_name = record["P"]
        if package_name in selected:
            continue
        selected[package_name] = record
        for dependency in record.get("D", "").split():
            dependency = dependency.split("=", 1)[0]
            dependency = dependency.split(">", 1)[0].split("<", 1)[0]
            if dependency.startswith("!"):
                continue
            if dependency in excluded:
                continue
            if dependency:
                pending.append(dependency)

    packages_root = args.work_root / "apk-packages"
    root = args.rootfs
    root.mkdir(parents=True, exist_ok=True)
    locks: list[dict] = []
    for name in sorted(selected):
        record = selected[name]
        filename = f"{record['P']}-{record['V']}.apk"
        archive = packages_root / filename
        url = runtime["repositoryRoot"].rstrip("/") + "/" + filename
        algorithm, digest, expected_size = package_expectation("musl", record, name)
        archive = acquire_package(
            url,
            archive,
            args.package_cache,
            name,
            filename,
            algorithm,
            digest,
            expected_size,
        )
        if archive.stat().st_size > MAX_PACKAGE_BYTES:
            fail(f"package exceeds bounded size: {archive}")
        safe_extract_tar(archive, root, apk=True)
        locks.append({
            "name": name,
            "version": record.get("V", ""),
            "architecture": record.get("A", ""),
            "filename": filename,
            "sha1": file_digest(archive, "sha1"),
            "size": expected_size,
            "indexChecksum": record.get("C", ""),
            "verifiedChecksum": digest,
            "verifiedChecksumAlgorithm": algorithm.removeprefix("apk-"),
            "depends": record.get("D", ""),
        })
    return {
        "runtime": "musl",
        "resolver": "apk-depends-v1",
        "indexSha256": runtime["packageIndexSha256"],
        "packages": locks,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", choices=("glibc", "musl"), required=True)
    parser.add_argument("--runtime-closures", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--index-dir", type=Path, required=True)
    parser.add_argument(
        "--package-cache",
        type=Path,
        default=None,
        help="optional shared content-addressed package archive cache",
    )
    parser.add_argument("--lock-output", type=Path, required=True)
    args = parser.parse_args()
    closure = json.loads(args.runtime_closures.read_text())
    project = json.loads(args.project.read_text())
    args.closure = closure
    runtime = closure["runtimes"][args.runtime]
    args.work_root = ensure_directory_no_symlink(args.work_root)
    args.index_dir = ensure_directory_no_symlink(args.index_dir)
    if args.package_cache is not None:
        args.package_cache = ensure_directory_no_symlink(args.package_cache)
    if args.runtime == "glibc":
        lock = build_debian(args, runtime, project)
    else:
        lock = build_apk(args, runtime, project)
    (args.rootfs / "etc").mkdir(parents=True, exist_ok=True)
    (args.rootfs / "etc/hostname").write_text("urprotect\n")
    (args.rootfs / "etc/passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n"
    )
    (args.rootfs / "etc/group").write_text("root:x:0:\nnogroup:x:65534:\n")
    args.lock_output.parent.mkdir(parents=True, exist_ok=True)
    args.lock_output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
