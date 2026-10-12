#!/usr/bin/env python3
"""Run bounded managed/native TLS prerequisite probes and retain closed evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
NATIVE_ROOT = ROOT / "native/urprotect-runtime"
FIXTURE = NATIVE_ROOT / "build/host-context-tls-fixture.so"
PROBE = NATIVE_ROOT / "build/host-image-validation-probe"
TAGS = {
    "DT_ANDROID_REL": 0x6000000F,
    "DT_ANDROID_RELSZ": 0x60000010,
    "DT_ANDROID_RELA": 0x60000011,
    "DT_ANDROID_RELASZ": 0x60000012,
    "DT_ANDROID_RELR": 0x6FFFE000,
    "DT_ANDROID_RELRCOUNT": 0x6FFFE005,
    "DT_ANDROID_RELRSZ": 0x6FFFE001,
    "DT_ANDROID_RELRENT": 0x6FFFE003,
}


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=check)


def read_phdrs(data: bytearray) -> tuple[int, int, list[dict[str, int]]]:
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    if phentsize != 56 or phnum == 0 or phnum > 4096:
        fail("probe source has unsupported program headers")
    headers = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        headers.append({
            "index": index,
            "offset": offset,
            "type": int.from_bytes(data[offset:offset + 4], "little"),
            "flags": int.from_bytes(data[offset + 4:offset + 8], "little"),
            "fileOffset": int.from_bytes(data[offset + 8:offset + 16], "little"),
            "virtualAddress": int.from_bytes(data[offset + 16:offset + 24], "little"),
            "fileSize": int.from_bytes(data[offset + 32:offset + 40], "little"),
            "memorySize": int.from_bytes(data[offset + 40:offset + 48], "little"),
            "alignment": int.from_bytes(data[offset + 48:offset + 56], "little"),
        })
    return phoff, phentsize, headers


def write_u32(data: bytearray, offset: int, value: int) -> None:
    data[offset:offset + 4] = value.to_bytes(4, "little")


def write_u64(data: bytearray, offset: int, value: int) -> None:
    data[offset:offset + 8] = value.to_bytes(8, "little")


def native_result(path: Path) -> dict[str, Any]:
    completed = run([str(PROBE), str(path)], check=False)
    if completed.returncode != 0:
        return {"processStatus": completed.returncode, "status": None, "stderr": completed.stderr[-4096:]}
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        fail(f"native probe returned invalid JSON: {error}")
    document["processStatus"] = completed.returncode
    return document


def managed_result(path: Path) -> dict[str, Any]:
    cli = ROOT / "src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
    if not cli.is_file():
        return {"processStatus": 127, "status": "environment-unavailable", "reason": "managed Release CLI is absent"}
    completed = run(["dotnet", str(cli), "validate", str(path), "--json", "-"], check=False)
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {
            "processStatus": completed.returncode,
            "status": "invalid-report",
            "stderr": completed.stderr[-4096:],
        }
    return {
        "processStatus": completed.returncode,
        "status": "accepted" if report.get("success") is True else "rejected",
        "diagnosticCodes": sorted({
            item.get("code")
            for item in report.get("diagnostics", [])
            if isinstance(item, dict) and isinstance(item.get("code"), str)
        }),
        "stderr": completed.stderr[-4096:],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()

    root = (args.artifact_root or (ROOT / ".artifacts" / "tls-prerequisites" / args.tier)).resolve()
    try:
        root.relative_to((ROOT / ".artifacts" / "tls-prerequisites").resolve())
    except ValueError:
        fail("prerequisite artifact root must be under .artifacts/tls-prerequisites")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    cc = os.environ.get("NATIVE_LAUNCHER_CC", "cc")
    run(["make", "-C", str(NATIVE_ROOT), f"CC={cc}", "tls-fixture", "host-image-validation-probe"])
    if not FIXTURE.is_file() or not PROBE.is_file():
        fail("TLS prerequisite fixture or native probe is missing")

    source = bytearray(FIXTURE.read_bytes())
    _, phentsize, headers = read_phdrs(source)
    tls = next((header for header in headers if header["type"] == 7), None)
    if tls is None:
        fail("TLS prerequisite fixture has no PT_TLS")
    dynamic = next((header for header in headers if header["type"] == 2), None)
    if dynamic is None:
        fail("TLS prerequisite fixture has no PT_DYNAMIC")
    dynamic_offset = dynamic["fileOffset"]
    dynamic_size = dynamic["fileSize"]
    terminator = None
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        if int.from_bytes(source[offset:offset + 8], "little") == 0:
            terminator = offset
            break
    if terminator is None:
        fail("TLS prerequisite fixture has no DT_NULL terminator")

    managed_policy_log = root / "managed-host-context-policy-test.txt"
    test = run([
        "dotnet", "test", "tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj",
        "--configuration", "Release", "--no-restore",
        "--filter", "FullyQualifiedName~CanonicalAndroidPackedRelocationTagsAreRejectedByHostContextPolicy",
    ], check=False)
    managed_policy_log.write_text(test.stdout + test.stderr, encoding="utf-8")
    if test.returncode != 0:
        fail("managed Android packed-tag policy test failed")

    android_rows = []
    for name, tag in TAGS.items():
        image = bytearray(source)
        write_u64(image, terminator, tag)
        path = root / "android-packed" / f"{name}.so"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(image)
        native = native_result(path)
        android_rows.append({
            "tagName": name,
            "tag": f"0x{tag:X}",
            "sourceSha256": digest(path),
            "managedStructural": managed_result(path),
            "managedHostContextPolicy": "rejected",
            "nativePreflight": native,
            "handlePublished": False,
            "publication": "not-published",
        })
        if native.get("status") != -2:
            fail(f"native probe accepted Android packed tag {name}: {native}")

    parity_cases: list[tuple[str, bytearray]] = []
    baseline = bytearray(source)
    parity_cases.append(("baseline", baseline))
    mutation = bytearray(source)
    write_u32(mutation, tls["offset"] + 4, 5)
    parity_cases.append(("tls-executable", mutation))
    mutation = bytearray(source)
    write_u32(mutation, tls["offset"] + 4, 4)
    owner = next(header for header in headers if header["index"] == 1)
    write_u32(mutation, owner["offset"] + 4, 4)
    parity_cases.append(("owner-read-only", mutation))
    mutation = bytearray(source)
    write_u64(mutation, tls["offset"] + 40, 0)
    parity_cases.append(("tls-empty-memory", mutation))
    mutation = bytearray(source)
    write_u64(mutation, tls["offset"] + 32, tls["memorySize"] + 1)
    parity_cases.append(("filesz-exceeds-memsz", mutation))
    mutation = bytearray(source)
    write_u64(mutation, tls["offset"] + 48, 3)
    parity_cases.append(("non-power-two-alignment", mutation))

    parity_rows = []
    for name, image in parity_cases:
        path = root / "pt-tls-parity" / f"{name}.so"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(image)
        managed = managed_result(path)
        native = native_result(path)
        parity_rows.append({
            "case": name,
            "sourceSha256": digest(path),
            "managedStructural": managed,
            "nativePreflight": native,
            "layerBoundary": (
                "managed-structural-observation-only; host-context requires writable PT_LOAD owner"
                if name == "owner-read-only" and managed["status"] == "accepted" and native.get("status") == -2
                else "common-predicate"
            ),
        })

    (root / "android-packed-tags.json").write_text(
        json.dumps({"schemaVersion": 1, "rows": android_rows}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "pt-tls-predicate-parity.json").write_text(
        json.dumps({
            "schemaVersion": 1,
            "managedContract": "StructuralElf observation plus HostContextEntryMaterializationPolicy handoff predicate",
            "nativeContract": "urp_host_image_validate",
            "rows": parity_rows,
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    environment = {
        "schemaVersion": 1,
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "pageSize": os.sysconf("SC_PAGESIZE"),
        "sourceSha256": digest(FIXTURE),
        "nativeCompiler": cc,
        "managedPolicyTest": "passed",
    }
    (root / "environment.json").write_text(json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        entries.append(f"{digest(path)}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(f"TLS prerequisite probes: Android tags={len(android_rows)}, PT_TLS cases={len(parity_rows)}")


if __name__ == "__main__":
    main()
