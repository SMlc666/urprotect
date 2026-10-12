#!/usr/bin/env python3
"""Validate managed/native Android tag and PT_TLS predicate prerequisite evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"^[0-9a-f]{64}$")
TAG_NAMES = (
    "DT_ANDROID_REL",
    "DT_ANDROID_RELSZ",
    "DT_ANDROID_RELA",
    "DT_ANDROID_RELASZ",
    "DT_ANDROID_RELR",
    "DT_ANDROID_RELRCOUNT",
    "DT_ANDROID_RELRSZ",
    "DT_ANDROID_RELRENT",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_manifest(root: Path) -> None:
    manifest = root / "SHA256SUMS"
    if not manifest.is_file():
        fail("prerequisite SHA256SUMS is missing")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or not DIGEST.fullmatch(parts[0]):
            fail(f"invalid prerequisite SHA256SUMS line {line_number}")
        relative = parts[1]
        path = Path(relative)
        if path.is_absolute() or "\\" in relative or ".." in path.parts:
            fail(f"prerequisite manifest path escapes root: {relative}")
        target = root / path
        if target.is_symlink() or not target.is_file() or relative in entries:
            fail(f"invalid or duplicate prerequisite manifest path: {relative}")
        if digest(target) != parts[0]:
            fail(f"prerequisite digest mismatch: {relative}")
        entries[relative] = parts[0]
    files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest
    }
    if files != set(entries):
        fail(f"prerequisite SHA256SUMS is not closed (missing={sorted(files - set(entries))}, extra={sorted(set(entries) - files)})")


def check_tag_rows(root: Path, document: dict[str, Any]) -> None:
    rows = document.get("rows")
    if not isinstance(rows, list) or len(rows) != len(TAG_NAMES):
        fail("Android packed-tag prerequisite must contain exactly eight rows")
    names = set()
    for row in rows:
        if not isinstance(row, dict):
            fail("Android packed-tag row is not an object")
        name = row.get("tagName")
        if name not in TAG_NAMES or name in names:
            fail(f"invalid Android packed-tag row name: {name!r}")
        names.add(name)
        if not isinstance(row.get("tag"), str) or not re.fullmatch(r"0x[0-9A-F]+", row["tag"]):
            fail(f"{name}: tag is not canonical hex")
        if row.get("managedHostContextPolicy") != "rejected":
            fail(f"{name}: managed HostContext policy did not reject")
        native = row.get("nativePreflight")
        if not isinstance(native, dict) or native.get("status") != -2 or native.get("processStatus") != 0:
            fail(f"{name}: native preflight did not return unsupported")
        if row.get("handlePublished") is not False or row.get("publication") != "not-published":
            fail(f"{name}: publication/handle boundary is invalid")
        source_hash = row.get("sourceSha256")
        if not isinstance(source_hash, str) or not DIGEST.fullmatch(source_hash):
            fail(f"{name}: source hash is invalid")
    if names != set(TAG_NAMES):
        fail("Android packed-tag prerequisite has missing rows")


def check_parity(root: Path, document: dict[str, Any]) -> None:
    rows = document.get("rows")
    if not isinstance(rows, list) or len(rows) != 6:
        fail("PT_TLS parity prerequisite must contain six bounded cases")
    names = {row.get("case") for row in rows}
    required = {"baseline", "tls-executable", "owner-read-only", "tls-empty-memory", "filesz-exceeds-memsz", "non-power-two-alignment"}
    if names != required:
        fail(f"PT_TLS parity cases drifted: {sorted(names)}")
    for row in rows:
        if not isinstance(row.get("managedStructural"), dict) or not isinstance(row.get("nativePreflight"), dict):
            fail(f"{row.get('case')}: parity result is malformed")
        if row.get("layerBoundary") not in {"common-predicate", "managed-structural-observation-only; host-context requires writable PT_LOAD owner"}:
            fail(f"{row.get('case')}: parity layer boundary is invalid")
        if not isinstance(row.get("sourceSha256"), str) or not DIGEST.fullmatch(row["sourceSha256"]):
            fail(f"{row.get('case')}: source hash is invalid")
    baseline = next(row for row in rows if row["case"] == "baseline")
    if baseline["managedStructural"].get("status") != "accepted" or baseline["nativePreflight"].get("status") != 0:
        fail("PT_TLS baseline does not pass both layers")
    for case in required - {"baseline"}:
        row = next(item for item in rows if item["case"] == case)
        if row["nativePreflight"].get("status") not in {-2, -3}:
            fail(f"{case}: native preflight accepted malformed PT_TLS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    args = parser.parse_args()
    root = args.artifact_root.resolve()
    if not root.is_dir():
        fail("TLS prerequisite artifact root is missing")
    check_manifest(root)
    tags = json.loads((root / "android-packed-tags.json").read_text(encoding="utf-8"))
    parity = json.loads((root / "pt-tls-predicate-parity.json").read_text(encoding="utf-8"))
    check_tag_rows(root, tags)
    check_parity(root, parity)
    policy_log = root / "managed-host-context-policy-test.txt"
    if "Passed!" not in policy_log.read_text(encoding="utf-8"):
        fail("managed Android policy test log does not record a pass")
    print("TLS prerequisite evidence valid: Android tags=8, PT_TLS cases=6")


if __name__ == "__main__":
    main()
