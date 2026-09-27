#!/usr/bin/env python3
"""Fail closed when selected runtime cells lack retained native evidence."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

TIERS = {"pr", "nightly", "release"}
CONTAINER_FIXTURES = {
    "glibc.older.ubuntu-22.04-arm64": {
        "glibc-4k",
        "glibc-4k.urp-copy",
        "glibc-16k-align",
        "glibc-16k-align.urp-copy",
    },
    "musl.1.2.5.alpine-3.22.2": {
        "musl-1.2.4-4k",
        "musl-1.2.4-4k.urp-copy",
        "musl-1.2.4-16k-align",
        "musl-1.2.4-16k-align.urp-copy",
    },
}


def fail(message: str) -> None:
    raise SystemExit(f"runtime matrix evidence: {message}")


def require_file(path: Path, label: str, *, nonempty: bool = True) -> None:
    if not path.is_file():
        fail(f"{label} is missing: {path}")
    if nonempty and path.stat().st_size == 0:
        fail(f"{label} is empty: {path}")


def read_json(path: Path, label: str) -> Any:
    require_file(path, label)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{label} is invalid JSON: {exc}")


def parse_key_values(path: Path, label: str) -> dict[str, str]:
    require_file(path, label)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"{label} repeats field {key!r}")
        values[key] = value
    return values


def parse_sha256(path: Path, label: str, expected_name: str) -> str:
    require_file(path, label)
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        fail(f"{label} must contain exactly one digest record")
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", lines[0])
    if match is None or Path(match.group(2)).name != expected_name:
        fail(f"{label} has a malformed or mismatched filename")
    return match.group(1)


def safe_artifact(root: Path, relative: str, label: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes its artifact root: {relative}")
    return candidate


def check_bionic_evidence(
    cell: dict[str, Any],
    root: Path,
    fixture_manifest_path: Path = Path("fixtures/manifest.json"),
) -> None:
    result_path = root / "result.json"
    document = read_json(result_path, "bionic result.json")
    if not isinstance(document, dict):
        fail("bionic result.json must be an object")

    expected_fields = {
        "schemaVersion": 1,
        "status": "validated",
        "case": "c-termux-bionic-pie",
        "execution": "native-arm64-bionic-container",
        "packageProvenance": "version-and-sha256-locked-package-set",
        "directLinkerMode": "identity",
        "handoffStatus": "validated-host-context-v2-adapter-self-test",
    }
    for key, expected in expected_fields.items():
        if document.get(key) != expected:
            fail(f"bionic result {key} must equal {expected!r}")

    expected_flags = {
        "androidRuntime": False,
        "emulation": False,
        "packageInputsReproducible": True,
    }
    for key, expected in expected_flags.items():
        if type(document.get(key)) is not bool or document[key] is not expected:
            fail(f"bionic result {key} must be boolean {expected}")

    if document.get("linker") != "/system/bin/linker64":
        fail("bionic result does not identify /system/bin/linker64")
    for key in ("baselineStatus", "directLinkerStatus"):
        if type(document.get(key)) is not int or document[key] != 0:
            fail(f"bionic {key} must be zero")
    if not isinstance(document.get("clangVersion"), str) or not document["clangVersion"].strip():
        fail("bionic clang version is missing")
    for key in ("hostKernel", "containerKernel"):
        if not isinstance(document.get(key), str) or not document[key].strip():
            fail(f"bionic {key} is missing")
    for key in ("hostPageSize", "containerPageSize"):
        if type(document.get(key)) is not int or document[key] <= 0:
            fail(f"bionic {key} must be a positive integer")
    if document["hostPageSize"] != document["containerPageSize"]:
        fail("bionic host/container page sizes must match")

    oracle = document.get("hostContextAdapterOracle")
    if (
        not isinstance(oracle, dict)
        or oracle.get("status") != "validated"
        or oracle.get("abi") != "HostContext-v1"
        or oracle.get("frame") != "HostContext-v2"
        or oracle.get("sealedImage") is not True
        or oracle.get("entryDispatch") != "urp_entry"
        or oracle.get("executableTemporaryPath") is not False
    ):
        fail("bionic HostContext adapter oracle is incomplete")

    required_artifacts = cell.get("requiredArtifacts")
    if not isinstance(required_artifacts, list) or not required_artifacts:
        fail("bionic requiredArtifacts must be a non-empty array")
    for relative in required_artifacts:
        if not isinstance(relative, str) or not relative:
            fail("bionic requiredArtifacts contains an invalid path")
        require_file(safe_artifact(root, relative, "bionic evidence path"), f"bionic {relative}")

    lock_path = root / "compiler-package-lock.json"
    lock = read_json(lock_path, "bionic compiler package lock")
    if not isinstance(lock, list) or len(lock) != 8:
        fail("bionic compiler package lock must contain the reviewed eight-package closure")
    if hashlib.sha256(lock_path.read_bytes()).hexdigest() != document.get("packageLockSha256"):
        fail("bionic result package-lock digest does not match retained lock")

    fixture_manifest = read_json(fixture_manifest_path, "fixture manifest")
    try:
        manifest_case = next(
            case for case in fixture_manifest["cases"]
            if case.get("id") == "c-termux-bionic-pie"
        )
    except (KeyError, StopIteration, TypeError):
        fail("locked bionic case is missing from fixtures/manifest.json")
    host_lock = manifest_case.get("host", {})
    expected_clang = str(host_lock.get("compilerPackage", "")).split("=", 1)[-1]
    if expected_clang not in document.get("clangVersion", ""):
        fail("bionic clang version differs from its compiler-package lock")
    if lock != host_lock.get("compilerPackages"):
        fail("retained bionic package lock differs from the reviewed manifest")
    for key, expected in (
        ("image", host_lock.get("image")),
        ("compilerPackages", lock),
        ("compilerPackage", host_lock.get("compilerPackage")),
        ("termuxSourceCommit", host_lock.get("sourceCommit")),
        ("packageRepository", host_lock.get("packageRepository")),
    ):
        if document.get(key) != expected:
            fail(f"bionic result {key} does not match its reviewed manifest fact")

    for package in lock:
        if not isinstance(package, dict):
            fail("bionic compiler package lock contains a non-object entry")
        required = ("name", "version", "filename", "sha256", "licenseSource")
        if any(not isinstance(package.get(key), str) or not package[key] for key in required):
            fail("bionic compiler package lock entry is incomplete")
        if re.fullmatch(r"[0-9a-f]{64}", package["sha256"]) is None:
            fail("bionic compiler package lock contains malformed SHA-256")
        if not isinstance(package.get("licenses"), list) or not package["licenses"]:
            fail("bionic compiler package lock lacks license identifiers")
        archive_path = root / "apt-archives" / Path(package["filename"]).name
        require_file(archive_path, f"bionic package archive {package['name']}")
        if hashlib.sha256(archive_path.read_bytes()).hexdigest() != package["sha256"]:
            fail(f"bionic downloaded package does not match the lock: {package['name']}")

    expected_sums = {
        f"{package['sha256']}  apt-archives/{Path(package['filename']).name}"
        for package in lock
    }
    sums_path = root / "package-sha256sums.txt"
    require_file(sums_path, "bionic package SHA256SUMS")
    actual_sums = set(sums_path.read_text(encoding="utf-8").splitlines())
    if len(actual_sums) != len(lock) or actual_sums != expected_sums:
        fail("bionic SHA256SUMS do not exactly match the reviewed package lock")

    expected_verification = {
        f"apt-archives/{Path(package['filename']).name}: OK"
        for package in lock
    }
    verification_path = root / "package-hash-verification.txt"
    require_file(verification_path, "bionic package hash verification")
    actual_verification = set(verification_path.read_text(encoding="utf-8").splitlines())
    if len(actual_verification) != len(lock) or actual_verification != expected_verification:
        fail("bionic package hash verification does not exactly match the package lock")

    fixture_digest = oracle.get("fixtureSha256")
    if not isinstance(fixture_digest, str) or re.fullmatch(r"[0-9a-f]{64}", fixture_digest) is None:
        fail("bionic HostContext fixture hash is missing or malformed")
    fixture_hash_path = root / "host-context/entry-fixture.sha256"
    retained_hash = fixture_hash_path.read_text(encoding="utf-8").split()
    if not retained_hash or retained_hash[0] != fixture_digest:
        fail("bionic HostContext fixture hash does not match retained hash evidence")
    fixture_binary = root / "host-context/build/host-context-entry-fixture.so"
    if hashlib.sha256(fixture_binary.read_bytes()).hexdigest() != fixture_digest:
        fail("bionic HostContext fixture bytes do not match result.json digest")
    self_test_path = root / "host-context/build-and-test.log"
    if "HostContext runtime self-test: PASS" not in self_test_path.read_text(encoding="utf-8"):
        fail("bionic HostContext self-test lacks its PASS oracle")
    host_result = (root / "host-context/result.txt").read_text(encoding="utf-8")
    if "status=validated" not in host_result or "entry=urp_entry" not in host_result:
        fail("bionic HostContext result lacks validated entry-dispatch evidence")
    fixture_readelf = (root / "host-context/entry-fixture-readelf.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    if (
        "ELF64" not in fixture_readelf
        or "AArch64" not in fixture_readelf
        or not re.search(r"Type:\s+DYN", fixture_readelf)
        or "urp_entry" not in fixture_readelf
    ):
        fail("bionic HostContext fixture readelf identity is incomplete")
    if (root / "linker.status").read_text(encoding="utf-8").strip() != "0":
        fail("bionic direct linker status artifact is not zero")
    if (root / "baseline.status").read_text(encoding="utf-8").strip() != "0":
        fail("bionic baseline status artifact is not zero")
    if "This is /system/bin/linker64, the helper program for dynamic executables." not in (
        root / "linker.stdout"
    ).read_text(encoding="utf-8", errors="replace"):
        fail("bionic direct linker output does not prove linker64 identity")


def check_page_probe(cell: dict[str, Any], root: Path, cell_id: str) -> None:
    path = root / "cells" / f"{cell_id}.result.txt"
    fields = parse_key_values(path, "16KiB native page-size probe")
    status = fields.get("status")
    if fields.get("probe") != "completed" or status not in {"validated", "environment-unavailable"}:
        fail("16KiB native page probe status is missing or invalid")

    try:
        observed_size = int(fields.get("observed_page_size", ""))
    except ValueError:
        fail("16KiB native page probe lacks an integer observed page size")
    manifest_size = parse_key_values(root / "run-manifest.txt", "run manifest").get("host_page_size")
    if manifest_size != str(observed_size):
        fail("16KiB probe page size differs from the run manifest")

    if status == "environment-unavailable":
        if cell.get("claimRequired") is True:
            fail("required 16KiB runtime claim is unavailable")
        if fields.get("claim") != "unknown" or observed_size == 16384:
            fail("unavailable 16KiB probe must remain unknown and record a non-16KiB host")
    elif observed_size != 16384 or fields.get("claim") != "validated":
        fail("validated 16KiB runtime claim requires observed native 16384-byte pages")


def check_container_cell(cell: dict[str, Any], root: Path) -> None:
    cell_id = cell["id"]
    base = root / "cells" / cell_id
    required = (
        "result.json",
        "environment.txt",
        "oracle.log",
        "stdout",
        "pull.log",
        "image-identity.txt",
        "image.json",
        "exit-status.txt",
        "fixture-hashes.txt",
    )
    for relative in required:
        require_file(base / relative, f"{cell_id} {relative}")
    require_file(base / "stderr", f"{cell_id} stderr", nonempty=False)

    oracle = (base / "oracle.log").read_text(encoding="utf-8", errors="replace")
    expected_version = "2.35" if cell_id.startswith("glibc.") else "1.2.5"
    expected_runtime = (
        rf"^runtime_identity=glibc {re.escape(expected_version)}(?:\s|$)"
        if cell_id.startswith("glibc.")
        else rf"^runtime_identity=Version {re.escape(expected_version)}(?:\s|$)"
    )
    if not any(re.search(expected_runtime, line) for line in oracle.splitlines()):
        fail(f"{cell_id} exact runtime version was not observed")
    if (base / "exit-status.txt").read_text(encoding="utf-8").strip() != "0":
        fail(f"{cell_id} bounded Docker run did not return zero")
    environment = parse_key_values(base / "environment.txt", f"{cell_id} environment")
    expected_page = environment.get("host_page_size")
    oracle_page = next(
        (line.split("=", 1)[1] for line in oracle.splitlines() if line.startswith("container_page_size=")),
        None,
    )
    if not expected_page or oracle_page != expected_page:
        fail(f"{cell_id} container page size differs from the inherited native kernel")
    if (
        environment.get("docker_server_platform") != "linux/arm64"
        or environment.get("host_arch") != "aarch64"
        or environment.get("host_os_id") != "ubuntu"
        or environment.get("host_os_version") != "24.04"
    ):
        fail(f"{cell_id} host execution was not native AArch64")
    isolation = environment.get("isolation", "")
    for required_isolation in (
        "network-none",
        "read-only-rootfs",
        "cap-drop-all",
        "no-new-privileges",
        "memory-512MiB",
        "pids-64",
        "timeout-180s",
    ):
        if required_isolation not in isolation:
            fail(f"{cell_id} isolation evidence omits {required_isolation}")

    image_identity = parse_key_values(base / "image-identity.txt", f"{cell_id} image identity")
    if image_identity.get("image") != cell.get("image"):
        fail(f"{cell_id} image name differs from the reviewed registry")
    if image_identity.get("oci_digest") != cell.get("imageDigest"):
        fail(f"{cell_id} OCI digest differs from the reviewed registry")
    if (
        image_identity.get("docker_server_platform") != "linux/arm64"
        or image_identity.get("execution") != "native-arm64-no-emulation"
    ):
        fail(f"{cell_id} did not run on a native ARM64 Docker server")
    image_inspect = read_json(base / "image.json", f"{cell_id} OCI image inspection")
    if (
        not isinstance(image_inspect, list)
        or len(image_inspect) != 1
        or not isinstance(image_inspect[0], dict)
        or image_inspect[0].get("Os") != "linux"
        or image_inspect[0].get("Architecture") != "arm64"
    ):
        fail(f"{cell_id} retained OCI inspection is not linux/arm64")
    pull_output = (base / "pull.log").read_text(encoding="utf-8", errors="replace")
    if f"Digest: {cell.get('imageDigest')}" not in pull_output:
        fail(f"{cell_id} docker pull output does not match the pinned OCI index digest")

    loader_line = next(
        (line for line in oracle.splitlines() if line.startswith("loader=")), ""
    )
    expected_loader = "ld-linux-aarch64.so.1" if cell_id.startswith("glibc.") else "ld-musl-aarch64.so.1"
    if not loader_line.endswith(expected_loader):
        fail(f"{cell_id} direct loader identity is missing")
    loader_output = base / "container-results/loader-identity.txt"
    require_file(loader_output, f"{cell_id} direct loader identity output")
    loader_status = (base / "container-results/loader-identity.status").read_text(encoding="utf-8").strip()
    allowed_loader_statuses = {"0", "1"} if cell_id.startswith("musl.") else {"0"}
    if loader_status not in allowed_loader_statuses:
        fail(f"{cell_id} direct loader identity probe has an invalid exit status")
    version_pattern = rf"{re.escape(expected_version)}(?:[\s.,]|$)"
    if not re.search(version_pattern, loader_output.read_text(encoding="utf-8", errors="replace")):
        fail(f"{cell_id} direct loader version does not match {expected_version}")

    result = read_json(base / "result.json", f"{cell_id} result.json")
    check_common_result(cell_id, result)
    if type(result.get("containerExit")) is not int or result["containerExit"] != 0:
        fail(f"{cell_id} Docker cell exit status differs from its successful result")
    runs = result.get("fixtureRuns") if isinstance(result, dict) else None
    if not isinstance(runs, list):
        fail(f"{cell_id} fixture run records are missing")
    by_name = {
        record.get("fixture"): record
        for record in runs
        if isinstance(record, dict) and isinstance(record.get("fixture"), str)
    }
    if set(by_name) != CONTAINER_FIXTURES[cell_id] or len(by_name) != len(runs):
        fail(f"{cell_id} fixture run set differs from the reviewed covering cell")

    retained_hashes: dict[str, str] = {}
    hashes_path = base / "fixture-hashes.txt"
    for line in hashes_path.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or re.fullmatch(r"[0-9a-f]{64}", parts[0]) is None:
            fail(f"{cell_id} contains a malformed fixture hash record")
        name = Path(parts[1].strip()).name
        if name in retained_hashes:
            fail(f"{cell_id} repeats fixture hash for {name}")
        retained_hashes[name] = parts[0]
    if set(retained_hashes) != CONTAINER_FIXTURES[cell_id]:
        fail(f"{cell_id} fixture hashes do not match its reviewed run set")
    for name, digest in retained_hashes.items():
        fixture_path = root / "fixtures" / name
        require_file(fixture_path, f"{cell_id} source fixture {name}")
        if hashlib.sha256(fixture_path.read_bytes()).hexdigest() != digest:
            fail(f"{cell_id} recorded fixture hash changed for {name}")
        if name.endswith(".urp-copy"):
            source_name = name.removesuffix(".urp-copy")
            if source_name not in retained_hashes or retained_hashes[source_name] != digest:
                fail(f"{cell_id} parser-produced fixture copy differs in bytes: {name}")

    for name, record in by_name.items():
        if type(record.get("status")) is not int or record.get("status") != 0 or record.get("timeoutSeconds") != 20:
            fail(f"{cell_id} fixture {name} failed or lacks its 20-second bound")
        status_path = base / "container-results" / f"{name}.status"
        require_file(status_path, f"{cell_id} fixture {name} status")
        if status_path.read_text(encoding="utf-8").strip() != str(record["status"]):
            fail(f"{cell_id} fixture {name} status record differs from result.json")
        for stream in ("stdout", "stderr"):
            relative = record.get(stream)
            if not isinstance(relative, str):
                fail(f"{cell_id} fixture {name} lacks its {stream} path")
            path = safe_artifact(base, relative, f"{cell_id} fixture {stream}")
            require_file(path, f"{cell_id} fixture {name} {stream}", nonempty=False)
        if not (base / record["stdout"]).read_text(encoding="utf-8").strip():
            fail(f"{cell_id} fixture {name} emitted no runtime output")
        if "runtime-matrix-fixture-ok" not in (base / record["stdout"]).read_text(encoding="utf-8"):
            fail(f"{cell_id} fixture {name} lacks its runtime output marker")

    for name, record in by_name.items():
        if not name.endswith(".urp-copy"):
            continue
        original = name.removesuffix(".urp-copy")
        if original not in by_name:
            fail(f"{cell_id} parser copy has no direct baseline: {name}")
        for stream in ("stdout", "stderr"):
            copy_stream = safe_artifact(base, record[stream], f"{cell_id} copy stream")
            direct_stream = safe_artifact(base, by_name[original][stream], f"{cell_id} direct stream")
            if copy_stream.read_bytes() != direct_stream.read_bytes():
                fail(f"{cell_id} direct and parser-copy {stream} differ for {original}")

    source_names = (
        (("glibc-4k", "0x1000"), ("glibc-16k-align", "0x4000"))
        if cell_id.startswith("glibc.")
        else (("musl-1.2.4-4k", "0x1000"), ("musl-1.2.4-16k-align", "0x4000"))
    )
    interpreter, needed = (
        ("/lib/ld-linux-aarch64.so.1", "libc.so.6")
        if cell_id.startswith("glibc.")
        else ("/lib/ld-musl-aarch64.so.1", "libc.so")
    )
    for name, alignment in source_names:
        report = root / "fixtures" / f"{name}.readelf.txt"
        identity_path = root / "fixtures" / f"{name}.fixture-identity.txt"
        require_file(report, f"{cell_id} source ELF report {name}")
        require_file(identity_path, f"{cell_id} source ELF identity {name}")
        verified = subprocess.run(
            [
                sys.executable,
                "scripts/check-runtime-fixture.py",
                str(report),
                alignment,
                interpreter,
                needed,
            ],
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            check=False,
        )
        if verified.returncode != 0 or verified.stdout != identity_path.read_text(encoding="utf-8"):
            fail(f"{cell_id} source fixture {name} failed independent ELF checks")


def check_common_result(cell_id: str, result: Any) -> None:
    if not isinstance(result, dict):
        fail(f"{cell_id} result.json must be an object")
    if (
        result.get("status") != "validated"
        or type(result.get("directStatus")) is not int
        or result.get("directStatus") != 0
        or type(result.get("copyStatus")) is not int
        or result.get("copyStatus") != 0
        or result.get("streamsMatch") is not True
    ):
        fail(f"{cell_id} direct oracle failed or parser copy differs")


def check_native_cell(cell_id: str, root: Path) -> None:
    if cell_id == "glibc.current.native-arm64":
        check_native_fixture(
            "glibc.current.native-arm64",
            root,
            align="0x1000",
            interpreter="/lib/ld-linux-aarch64.so.1",
            needed="libc.so.6",
            expected_runtime="glibc 2.39",
            require_environment=True,
        )
        check_native_fixture(
            "glibc.current.native-arm64-16k",
            root,
            align="0x4000",
            interpreter="/lib/ld-linux-aarch64.so.1",
            needed="libc.so.6",
            expected_runtime="glibc 2.39",
            require_environment=True,
        )
        return
    if cell_id == "musl.1.2.4.ubuntu-native":
        check_native_fixture(
            "musl.1.2.4.ubuntu-native",
            root,
            align="0x1000",
            interpreter="/lib/ld-musl-aarch64.so.1",
            needed="libc.so",
            expected_runtime="Version 1.2.4",
            require_environment=True,
        )
        check_native_fixture(
            "musl.1.2.4.ubuntu-native-16k",
            root,
            align="0x4000",
            interpreter="/lib/ld-musl-aarch64.so.1",
            needed="libc.so",
            expected_runtime="Version 1.2.4",
            require_environment=True,
        )
        check_musl_toolchain(root)
        return


def check_native_fixture(
    fixture_id: str,
    root: Path,
    *,
    align: str,
    interpreter: str,
    needed: str,
    expected_runtime: str,
    require_environment: bool,
) -> None:
    base = root / "cells" / fixture_id
    for relative in (
        "result.json",
        "environment.txt",
        "oracle.log",
        "stdout",
        "readelf.txt",
        "fixture-identity.txt",
        "pt-load-alignment.txt",
        "status.txt",
        "validator.stdout",
        "copy.sha256",
        "source.sha256",
        "parser-copy",
        "copy.stdout",
        "copy.stderr",
        "toolchain-lock.txt",
    ):
        require_file(
            base / relative,
            f"{fixture_id} {relative}",
            nonempty=relative not in {"copy.stderr"},
        )
    for relative in ("stderr", "validator.stderr"):
        require_file(base / relative, f"{fixture_id} {relative}", nonempty=False)

    identity = (base / "fixture-identity.txt").read_text(encoding="utf-8")
    readelf_path = base / "readelf.txt"
    checked = subprocess.run(
        [
            sys.executable,
            "scripts/check-runtime-fixture.py",
            str(readelf_path),
            align,
            interpreter,
            needed,
        ],
        cwd=Path.cwd(),
        check=False,
        capture_output=True,
        text=True,
    )
    if checked.returncode != 0 or checked.stdout != identity:
        fail(f"{fixture_id} retained readelf identity fails independent validation")
    alignment = subprocess.run(
        [sys.executable, "scripts/check-pt-load-alignment.py", str(readelf_path), align],
        cwd=Path.cwd(),
        check=False,
        capture_output=True,
        text=True,
    )
    if alignment.returncode != 0 or alignment.stdout != (base / "pt-load-alignment.txt").read_text(encoding="utf-8"):
        fail(f"{fixture_id} retained PT_LOAD alignment fails independent validation")

    statuses = parse_key_values(base / "status.txt", f"{fixture_id} command status")
    for key in ("direct", "validate", "copy"):
        if statuses.get(key) != "0":
            fail(f"{fixture_id} {key} command did not return zero")
    if (base / "oracle.log").read_bytes() != (
        (base / "status.txt").read_bytes() + (base / "stdout").read_bytes()
    ):
        fail(f"{fixture_id} oracle log does not match its status and direct output")
    if (base / "stdout").read_bytes() != (base / "copy.stdout").read_bytes():
        fail(f"{fixture_id} no-op copy stdout differs from the source")
    if (base / "stderr").read_bytes() != (base / "copy.stderr").read_bytes():
        fail(f"{fixture_id} no-op copy stderr differs from the source")
    if not (base / "stdout").read_text(encoding="utf-8").strip():
        fail(f"{fixture_id} fixture runtime output is empty")
    if "runtime-matrix-fixture-ok" not in (base / "stdout").read_text(encoding="utf-8"):
        fail(f"{fixture_id} fixture output marker is missing")

    environment = parse_key_values(base / "environment.txt", f"{fixture_id} environment")
    if environment.get("host_arch") != "aarch64":
        fail(f"{fixture_id} runtime did not record native AArch64")
    if environment.get("host_os_id") != "ubuntu" or environment.get("host_os_version") != "24.04":
        fail(f"{fixture_id} did not run on the declared Ubuntu 24.04 AArch64 userland")
    if environment.get("host_page_size") not in {"4096", "16384"}:
        fail(f"{fixture_id} host page-size observation is missing or unrecognized")
    runtime = environment.get("glibc" if expected_runtime.startswith("glibc") else "musl_version")
    if runtime != expected_runtime:
        fail(f"{fixture_id} runtime identity is {runtime!r}, expected {expected_runtime!r}")
    if expected_runtime.startswith("glibc"):
        loader = environment.get("loader", "")
        if not loader.endswith(interpreter.rsplit("/", 1)[-1]):
            fail(f"{fixture_id} glibc loader identity is missing or unexpected")
    else:
        expected_musl_runtime = str(
            (root / "package-locks/musl-1.2.4/prefix/lib/libc.so").resolve()
        )
        if (
            environment.get("runtime_loader_path") != interpreter
            or environment.get("runtime_loader_resolved") != expected_musl_runtime
        ):
            fail(f"{fixture_id} loader path is not the recorded pinned musl runtime")
    if expected_runtime.startswith("glibc") and not environment.get("compiler", "").startswith("gcc "):
        fail(f"{fixture_id} compiler identity is missing")
    elif expected_runtime.startswith("Version") and not environment.get("musl-gcc", "").strip():
        fail(f"{fixture_id} musl compiler identity is missing")

    fixture_name = {
        "glibc.current.native-arm64": "glibc-4k",
        "glibc.current.native-arm64-16k": "glibc-16k-align",
        "musl.1.2.4.ubuntu-native": "musl-1.2.4-4k",
        "musl.1.2.4.ubuntu-native-16k": "musl-1.2.4-16k-align",
    }.get(fixture_id)
    if fixture_name is None:
        fail(f"{fixture_id} has no reviewed input fixture identity")

    result = read_json(base / "result.json", f"{fixture_id} result.json")
    check_common_result(fixture_id, result)
    if type(result.get("directStatus")) is not int or type(result.get("validatorStatus")) is not int or type(result.get("copyStatus")) is not int:
        fail(f"{fixture_id} command statuses must be integers")
    if result.get("validatorStatus") != 0:
        fail(f"{fixture_id} UrProtect validation did not pass")
    if result.get("directStatus") != 0 or result.get("copyStatus") != 0:
        fail(f"{fixture_id} direct or copied image did not return zero")
    if result.get("application") != "UrProtect CLI validate --no-analysis --copy":
        fail(f"{fixture_id} does not record the expected UrProtect validation oracle")
    digest = result.get("applicationBuildSha256")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        fail(f"{fixture_id} UrProtect CLI assembly hash is missing or malformed")
    if not isinstance(result.get("sdkVersion"), str) or not result["sdkVersion"].strip():
        fail(f"{fixture_id} .NET SDK identity is missing")
    validator_output = (base / "validator.stdout").read_text(encoding="utf-8")
    if not validator_output.startswith("Validated AArch64 ET_DYN"):
        fail(f"{fixture_id} UrProtect validation output is missing its success diagnostic")
    source_hash = parse_sha256(base / "source.sha256", f"{fixture_id} source hash", fixture_name)
    copy_hash = parse_sha256(base / "copy.sha256", f"{fixture_id} copy hash", "parser-copy")
    if source_hash != copy_hash or hashlib.sha256((base / "parser-copy").read_bytes()).hexdigest() != source_hash:
        fail(f"{fixture_id} UrProtect no-op copy is not byte-identical")
    source_binary = root / "fixtures" / fixture_name
    require_file(source_binary, f"{fixture_id} direct input binary")
    if hashlib.sha256(source_binary.read_bytes()).hexdigest() != source_hash:
        fail(f"{fixture_id} source fixture bytes differ from the observed direct input")
    readelf = shutil.which("readelf")
    if readelf is None:
        fail("readelf is missing during runtime evidence recheck")
    readelf_run = subprocess.run(
        [readelf, "-hW", "-lW", "-dW", str(source_binary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if readelf_run.returncode != 0 or readelf_run.stdout != readelf_path.read_text(encoding="utf-8"):
        fail(f"{fixture_id} retained readelf output differs from the exact direct input binary")
    if not (source_binary.stat().st_mode & stat.S_IXUSR):
        fail(f"{fixture_id} direct input binary has no owner execute permission")
    for label, binary, recorded_status, recorded_stdout, recorded_stderr in (
        (
            "direct",
            source_binary,
            statuses["direct"],
            base / "stdout",
            base / "stderr",
        ),
        (
            "copy",
            base / "parser-copy",
            statuses["copy"],
            base / "copy.stdout",
            base / "copy.stderr",
        ),
    ):
        execution = subprocess.run(
            ["timeout", "20", str(binary)],
            check=False,
            capture_output=True,
        )
        if execution.returncode != int(recorded_status):
            fail(f"{fixture_id} repeated {label} execution status differs from retained evidence")
        if execution.stdout != recorded_stdout.read_bytes() or execution.stderr != recorded_stderr.read_bytes():
            fail(f"{fixture_id} repeated {label} execution streams differ from retained evidence")
    cli_assembly = Path("src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll")
    if not cli_assembly.is_file():
        fail("UrProtect CLI build assembly is missing during evidence recheck")
    current_application_hash = "sha256:" + hashlib.sha256(cli_assembly.read_bytes()).hexdigest()
    if digest != current_application_hash:
        fail(f"{fixture_id} application build hash differs from the executed CLI assembly")
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        fail(".NET SDK executable is missing during evidence recheck")
    sdk = subprocess.run([dotnet, "--version"], check=False, capture_output=True, text=True)
    if sdk.returncode != 0 or result["sdkVersion"] != sdk.stdout.strip():
        fail(f"{fixture_id} SDK identity differs from the current test runner")
    tool_hashes = (base / "toolchain-lock.txt").read_text(encoding="utf-8").splitlines()
    if len(tool_hashes) != 3 or any(re.fullmatch(r"[0-9a-f]{64}  .+", line) is None for line in tool_hashes):
        fail(f"{fixture_id} native toolchain hashes are incomplete")
    hash_by_name: dict[str, str] = {}
    for line in tool_hashes:
        digest_value, recorded_path = line.split("  ", 1)
        name = Path(recorded_path).name
        if name in hash_by_name:
            fail(f"{fixture_id} native toolchain lock repeats {name}")
        hash_by_name[name] = digest_value
    expected_tools = (
        {
            "musl-gcc": shutil.which("musl-gcc"),
            "readelf": shutil.which("readelf"),
            "libc.so": environment.get("runtime_loader_resolved"),
        }
        if expected_runtime.startswith("Version")
        else {
            "gcc": shutil.which("gcc"),
            "ld": shutil.which("ld"),
            "readelf": shutil.which("readelf"),
        }
    )
    for name, executable in expected_tools.items():
        if not executable or name not in hash_by_name:
            fail(f"{fixture_id} toolchain hash evidence is missing {name}")
        if hashlib.sha256(Path(executable).read_bytes()).hexdigest() != hash_by_name[name]:
            fail(f"{fixture_id} toolchain hash no longer matches {name}")


def check_musl_toolchain(root: Path) -> None:
    matrix = read_json(Path("fixtures/runtime-matrix.json"), "runtime matrix registry")
    selected_cell = next(
        (cell for cell in matrix.get("cells", []) if cell.get("id") == "musl.1.2.4.ubuntu-native"),
        None,
    )
    if not isinstance(selected_cell, dict):
        fail("musl 1.2.4 runtime cell is missing")
    base = root
    for relative in selected_cell.get("toolchainEvidence", []):
        require_file(base / relative, f"musl toolchain {relative}")
    toolchain = read_json(Path("fixtures/runtime-matrix-toolchains.json"), "musl toolchain lock")
    try:
        lock = next(
            item for item in toolchain["toolchains"]
            if item.get("id") == "musl.1.2.4.ubuntu-native"
        )
    except (KeyError, StopIteration, TypeError):
        fail("musl source toolchain lock entry is missing")
    base = root / "package-locks/musl-1.2.4"
    source_archive = base / "source/musl-1.2.4.tar.gz"
    source_record = read_json(base / "source/toolchain-source.json", "musl source record")
    source_hash = hashlib.sha256(source_archive.read_bytes()).hexdigest()
    expected_source = {
        "schemaVersion": 1,
        "id": lock.get("id"),
        "source": lock.get("source"),
        "filename": lock.get("sourceFilename"),
        "sourceSha256": lock.get("sourceSha256"),
        "version": lock.get("version"),
        "sourceBytes": source_archive.stat().st_size,
    }
    if source_record != expected_source or source_hash != lock.get("sourceSha256"):
        fail("musl source archive/record differs from the committed cryptographic lock")

    prefix = base / "prefix"
    build_facts = parse_key_values(base / "build-facts.txt", "musl build facts")
    if build_facts.get("native_arch") != "aarch64" or build_facts.get("configure_target") != "aarch64-linux-musl":
        fail("musl source build was not produced for native AArch64")
    if build_facts.get("runtime_loader") != "/lib/ld-musl-aarch64.so.1":
        fail("musl source build runtime interpreter differs from the lock")
    if build_facts.get("runtime_loader_resolved") != str((prefix / "lib/libc.so").resolve()):
        fail("musl runtime loader does not resolve to the locked source build")
    lock_hash = hashlib.sha256(Path("fixtures/runtime-matrix-toolchains.json").read_bytes()).hexdigest()
    if build_facts.get("source_lock_sha256") != lock_hash or build_facts.get("source_archive_sha256") != source_hash:
        fail("musl build facts do not match the committed source-lock and archive hashes")
    for key, path in (
        ("musl_gcc_sha256", prefix / "bin/musl-gcc"),
        ("musl_loader_sha256", prefix / "lib/libc.so"),
    ):
        if hashlib.sha256(path.read_bytes()).hexdigest() != build_facts.get(key):
            fail(f"musl build artifact hash differs from retained build facts: {key}")
    for tool in ("gcc", "ld", "ar", "readelf", "make"):
        path_key = f"{tool}_path"
        digest_key = f"{tool}_sha256"
        executable = build_facts.get(path_key)
        digest = build_facts.get(digest_key)
        if not executable or re.fullmatch(r"[0-9a-f]{64}", digest or "") is None:
            fail(f"musl source build does not record the {tool} path/hash")
        if hashlib.sha256(Path(executable).read_bytes()).hexdigest() != digest:
            fail(f"musl source build {tool} hash differs from retained build facts")
    if "Version 1.2.4" not in (base / "logs/loader-version.txt").read_text(encoding="utf-8"):
        fail("musl source-built loader does not identify runtime version 1.2.4")
    if (base / "created-loader-link.txt").read_text(encoding="utf-8").strip() != "/lib/ld-musl-aarch64.so.1":
        fail("musl temporary native interpreter link ownership marker is invalid")
    cleanup = parse_key_values(base / "loader-link-cleanup.txt", "musl loader-link cleanup record")
    if (
        cleanup.get("path") != "/lib/ld-musl-aarch64.so.1"
        or cleanup.get("status") != "removed"
        or Path(cleanup["path"]).exists()
        or Path(cleanup["path"]).is_symlink()
    ):
        fail("musl native test-owned loader symlink was not removed after runtime execution")

    sums_path = base / "SHA256SUMS"
    checksums: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            fail("musl toolchain SHA256SUMS contains malformed records")
        path = Path(match.group(2)).resolve()
        try:
            relative = path.relative_to(base.resolve())
        except ValueError:
            fail("musl toolchain checksum path escapes the retained toolchain root")
        if str(relative) in checksums:
            fail(f"musl toolchain checksum list repeats {relative}")
        checksums[str(relative)] = match.group(1)
        require_file(path, f"musl toolchain checksum input {relative}", nonempty=False)
        if hashlib.sha256(path.read_bytes()).hexdigest() != match.group(1):
            fail(f"musl toolchain checksum mismatch for {relative}")
    required_hashes = {
        "source/musl-1.2.4.tar.gz",
        "source/toolchain-source.json",
        "created-loader-link.txt",
        "loader-link-cleanup.txt",
        "build-facts.txt",
        "prefix/bin/musl-gcc",
        "prefix/lib/libc.so",
    }
    if not required_hashes.issubset(checksums):
        fail("musl source, compiler, and loader artifacts are missing from SHA256SUMS")
    expected_files = {
        str(path.resolve().relative_to(base.resolve()))
        for path in base.rglob("*")
        if path.is_file() and not path.is_symlink() and path.resolve() != sums_path.resolve()
    }
    if set(checksums) != expected_files:
        fail("musl toolchain SHA256SUMS do not cover the exact retained source/build artifacts")


def check_musl_product_smoke(root: Path) -> None:
    base = root / "musl-1.2.4-smoke"
    required = (
        "build/fixture",
        "no-op-copy",
        "packed-fixture",
        "native-launcher/urprotect-launcher",
        "baseline.status",
        "output.status",
        "packed.status",
        "baseline.stdout",
        "baseline.stderr",
        "output.stdout",
        "output.stderr",
        "packed.stdout",
        "packed.stderr",
        "validator.stdout",
        "validator.stderr",
        "musl-launcher-toolchain.txt",
        "packed-report.json",
        "readelf.txt",
        "packed-file.txt",
        "packed-readelf.txt",
    )
    for relative in required:
        require_file(base / relative, f"musl product smoke {relative}", nonempty=relative.endswith(".status") or relative.endswith(".stdout") or relative.endswith(".json") or relative.endswith(".txt"))
    baseline = (base / "baseline.status").read_text(encoding="utf-8").strip()
    if baseline != "0":
        fail("musl baseline did not return status zero")
    if (base / "output.status").read_text(encoding="utf-8").strip() != baseline:
        fail("musl no-op copy status differs from baseline")
    if (base / "packed.status").read_text(encoding="utf-8").strip() != baseline:
        fail("musl packed wrapper status differs from baseline")
    for output in ("output", "packed"):
        for stream in ("stdout", "stderr"):
            if (base / f"baseline.{stream}").read_bytes() != (base / f"{output}.{stream}").read_bytes():
                fail(f"musl {output} {stream} differs from baseline")
    launcher_facts = parse_key_values(base / "musl-launcher-toolchain.txt", "musl launcher toolchain facts")
    if launcher_facts.get("musl_source_build") != "1.2.4":
        fail("musl launcher smoke did not use the pinned 1.2.4 source toolchain")
    for key in ("musl_toolchain_root", "musl_base_specs", "musl_static_pie_specs"):
        if not launcher_facts.get(key):
            fail(f"musl launcher toolchain facts omit {key}")


def check_sha256_manifest(runtime_root: Path, bionic_root: Path) -> None:
    checksum_path = runtime_root / "SHA256SUMS"
    require_file(checksum_path, "runtime and bionic combined checksum manifest")
    allowed_roots = {runtime_root.resolve(), bionic_root.resolve()}
    expected_files: set[Path] = set()
    for artifact_root in allowed_roots:
        if not artifact_root.is_dir():
            fail(f"checksum root is missing: {artifact_root}")
        expected_files.update(
            path.resolve()
            for path in artifact_root.rglob("*")
            if path.is_file() and not path.is_symlink()
            and path.resolve() != checksum_path.resolve()
        )

    observed_files: set[Path] = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            fail("combined checksum manifest contains a malformed record")
        path = Path(match.group(2)).resolve()
        if path in observed_files:
            fail(f"combined checksum manifest repeats {path}")
        observed_files.add(path)
        if not any(path.is_relative_to(artifact_root) for artifact_root in allowed_roots):
            fail(f"combined checksum path escapes retained artifact roots: {path}")
        require_file(path, f"combined checksum input {path}", nonempty=False)
        if hashlib.sha256(path.read_bytes()).hexdigest() != match.group(1):
            fail(f"combined checksum mismatch: {path}")
    if observed_files != expected_files:
        missing = sorted(str(path) for path in expected_files - observed_files)
        extra = sorted(str(path) for path in observed_files - expected_files)
        fail(f"combined checksum coverage differs; missing={missing[:5]} extra={extra[:5]}")


def main() -> None:
    if len(sys.argv) not in (4, 5) or sys.argv[1] not in TIERS:
        raise SystemExit(
            "usage: check-runtime-matrix-evidence.py pr|nightly|release ARTIFACT_ROOT BIONIC_ARTIFACT_ROOT [FIXTURE_MANIFEST_FOR_TEST]"
        )
    tier, root, bionic_root = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    fixture_manifest = Path(sys.argv[4]) if len(sys.argv) == 5 else Path("fixtures/manifest.json")
    registry = read_json(Path("fixtures/runtime-matrix.json"), "runtime matrix registry")
    if not isinstance(registry, dict) or tier not in registry.get("tiers", {}):
        fail(f"runtime matrix registry has no {tier} tier")
    manifest = parse_key_values(root / "run-manifest.txt", "runtime matrix run manifest")
    if (
        manifest.get("tier") != tier
        or manifest.get("execution") != "native AArch64; emulation=false"
        or manifest.get("host_arch") != "aarch64"
        or manifest.get("host_os_id") != "ubuntu"
        or manifest.get("host_os_version") != "24.04"
        or not manifest.get("host_kernel")
        or not manifest.get("covering_rationale")
    ):
        fail("runtime matrix run manifest tier/execution does not match this native run")
    selected = registry["tiers"][tier]
    if manifest.get("selected_cells") != ",".join(selected):
        fail("runtime matrix run manifest selected cells differ from the registry")
    registry_digest = hashlib.sha256(Path("fixtures/runtime-matrix.json").read_bytes()).hexdigest()
    if manifest.get("runtime_registry_sha256") != registry_digest:
        fail("runtime matrix run manifest registry digest differs from source registry")

    cells = {cell["id"]: cell for cell in registry["cells"]}
    for cell_id in selected:
        if cell_id == "bionic.termux.locked":
            check_bionic_evidence(cells[cell_id], bionic_root, fixture_manifest)
        elif cell_id == "kernel-page.16k.native-aarch64":
            check_page_probe(cells[cell_id], root, cell_id)
        elif cell_id in CONTAINER_FIXTURES:
            check_container_cell(cells[cell_id], root)
        else:
            check_native_cell(cell_id, root)

    page_cell_id = "kernel-page.16k.native-aarch64"
    page_result = parse_key_values(
        root / "cells" / f"{page_cell_id}.result.txt", "16KiB native page-size probe"
    )
    expected_claims = [
        cell_id for cell_id in selected
        if cell_id != page_cell_id or page_result.get("status") == "validated"
    ]
    if manifest.get("validated_claim_cells") != ",".join(expected_claims):
        fail("runtime matrix release claim list does not exactly match validated evidence")

    for cell_id, expected_align in (
        ("glibc.current.native-arm64", "0x1000"),
        ("glibc.current.native-arm64-16k", "0x4000"),
    ):
        identity = root / "cells" / cell_id / "fixture-identity.txt"
        require_file(identity, f"{cell_id} PT_LOAD alignment evidence")
        if f"expected_p_align={expected_align}" not in identity.read_text(encoding="utf-8"):
            fail(f"{cell_id} PT_LOAD alignment does not match {expected_align}")

    if tier != "pr":
        check_musl_product_smoke(root)
    check_sha256_manifest(root, bionic_root)
    print(f"runtime matrix evidence valid: {tier}")


if __name__ == "__main__":
    main()
