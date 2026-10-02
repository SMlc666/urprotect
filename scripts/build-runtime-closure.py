#!/usr/bin/env python3
"""Acquire and assemble one bounded native AArch64 runtime closure.

The caller owns the source archive hash check. This helper owns the locked
Debian/Alpine index check, dependency resolution, archive hashes, safe
extraction, and the generated closure lock retained as text evidence.
"""

from __future__ import annotations

import argparse
import base64
from collections import deque
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.request


MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 128 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def download(
    url: str,
    destination: Path,
    expected_sha256: str | None = None,
    max_bytes: int = MAX_INDEX_BYTES,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        data = destination.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            fail(f"download exceeds bounded size: {url}")
        destination.write_bytes(data)
    if expected_sha256 and hashlib.sha256(data).hexdigest() != expected_sha256:
        fail(f"SHA-256 mismatch for {url}")


def parse_stanzas(data: bytes) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for raw in data.decode("utf-8", errors="strict").split("\n\n"):
        fields: dict[str, str] = {}
        current: str | None = None
        for line in raw.splitlines():
            if line.startswith((" ", "\t")) and current:
                fields[current] += "\n" + line.strip()
            elif ":" in line:
                current, value = line.split(":", 1)
                fields[current] = value.strip()
        if fields:
            result.append(fields)
    return result


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
        for member in members:
            target = (root / member.name).resolve()
            if target != root_resolved and root_resolved not in target.parents:
                fail(f"archive traversal: {member.name}")
            if member.issym() or member.islnk():
                if member.linkname.startswith("/"):
                    fail(f"absolute archive link: {member.name}")
        tar.extractall(root, filter="data")


def parse_debian_index(index: Path) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    records = parse_stanzas(lzma.decompress(index.read_bytes()))
    by_name: dict[str, dict] = {}
    by_filename: dict[str, dict] = {}
    providers: dict[str, dict] = {}
    for record in records:
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
    selected: dict[str, dict] = {}
    while pending:
        name = pending.popleft()
        if name in selected:
            continue
        record = by_name.get(name) or providers.get(name)
        if record is None:
            fail(f"Debian dependency is absent from the locked index: {name}")
        selected[name] = record
        for dependency in dependency_names(record.get("Pre-Depends")) + dependency_names(record.get("Depends")):
            if dependency not in selected:
                pending.append(dependency)

    packages_root = args.work_root / "deb-packages"
    root = args.rootfs
    root.mkdir(parents=True, exist_ok=True)
    locks: list[dict] = []
    for name in sorted(selected):
        record = selected[name]
        relative = record["Filename"]
        archive = packages_root / Path(relative).name
        url = runtime["repositoryRoot"].rstrip("/") + "/" + relative
        download(url, archive, record["SHA256"], MAX_PACKAGE_BYTES)
        if archive.stat().st_size > MAX_PACKAGE_BYTES:
            fail(f"package exceeds bounded size: {archive}")
        subprocess.run(["dpkg-deb", "-x", str(archive), str(root)], check=True)
        locks.append({
            "name": name,
            "version": record.get("Version", ""),
            "architecture": record.get("Architecture", ""),
            "filename": relative,
            "sha256": record["SHA256"],
            "depends": record.get("Depends", ""),
        })
    return {"runtime": "glibc", "resolver": "deb-depends-v1", "indexSha256": runtime["packageIndexSha256"], "packages": locks}


def parse_apk_index(index: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    with tarfile.open(index, "r:gz") as tar:
        member = tar.extractfile("APKINDEX")
        if member is None:
            fail("APKINDEX is missing from the locked index archive")
        records = parse_stanzas(member.read())
    by_name: dict[str, dict] = {}
    providers: dict[str, dict] = {}
    for record in records:
        if record.get("A") != "aarch64" or not record.get("P"):
            continue
        by_name[record["P"]] = record
        for provided in record.get("p", "").split():
            providers[provided.split("=", 1)[0]] = record
        providers[record["P"]] = record
    return by_name, providers


def build_apk(args: argparse.Namespace, runtime: dict, project: dict) -> dict:
    index = args.index_dir / "alpine-APKINDEX.tar.gz"
    download(runtime["packageIndexUrl"], index, runtime["packageIndexSha256"])
    by_name, providers = parse_apk_index(index)
    source_package = project["provenance"].get("packageName")
    source_version = project["provenance"].get("version")
    if not source_package or source_package not in by_name:
        fail(f"source APK package is absent from the locked index: {source_package}")
    pending = deque([source_package])
    selected: dict[str, dict] = {}
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
        download(url, archive, max_bytes=MAX_PACKAGE_BYTES)
        if archive.stat().st_size > MAX_PACKAGE_BYTES:
            fail(f"package exceeds bounded size: {archive}")
        safe_extract_tar(archive, root, apk=True)
        locks.append({
            "name": name,
            "version": record.get("V", ""),
            "architecture": record.get("A", ""),
            "filename": filename,
            "sha1": hashlib.sha1(archive.read_bytes()).hexdigest(),
            "indexChecksum": record.get("C", ""),
            "depends": record.get("D", ""),
        })
    return {"runtime": "musl", "resolver": "apk-depends-v1", "indexSha256": runtime["packageIndexSha256"], "packages": locks}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", choices=("glibc", "musl"), required=True)
    parser.add_argument("--runtime-closures", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--index-dir", type=Path, required=True)
    parser.add_argument("--lock-output", type=Path, required=True)
    args = parser.parse_args()
    closure = json.loads(args.runtime_closures.read_text())
    project = json.loads(args.project.read_text())
    runtime = closure["runtimes"][args.runtime]
    args.work_root.mkdir(parents=True, exist_ok=True)
    args.index_dir.mkdir(parents=True, exist_ok=True)
    if args.runtime == "glibc":
        lock = build_debian(args, runtime, project)
    else:
        lock = build_apk(args, runtime, project)
    (args.rootfs / "etc").mkdir(parents=True, exist_ok=True)
    (args.rootfs / "etc/hostname").write_text("urprotect\n")
    (args.rootfs / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (args.rootfs / "etc/group").write_text("root:x:0:\n")
    args.lock_output.parent.mkdir(parents=True, exist_ok=True)
    args.lock_output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
