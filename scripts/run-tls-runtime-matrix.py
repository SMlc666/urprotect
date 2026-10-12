#!/usr/bin/env python3
"""Produce the independent transformed TLS model/profile/runtime/lifecycle matrix."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "fixtures/tls-runtime-matrix.json"
TLS_FIXTURE = ROOT / "native/urprotect-runtime/build/host-context-tls-fixture.so"
TLS_RUNNER = ROOT / "scripts/run-tls-host-context-rehydration-e2e.sh"
PROBE = ROOT / "native/urprotect-runtime/build/host-image-validation-probe"


def fail(message: str) -> None:
    raise SystemExit(message)


def run(command: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=check)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tls_facts(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        fail("TLS fixture is not ELF64 little-endian")
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    if phentsize != 56 or phnum == 0 or phnum > 4096:
        fail("TLS fixture has unsupported program headers")
    tls = None
    loads = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type = int.from_bytes(data[offset:offset + 4], "little")
        flags = int.from_bytes(data[offset + 4:offset + 8], "little")
        p_offset = int.from_bytes(data[offset + 8:offset + 16], "little")
        p_vaddr = int.from_bytes(data[offset + 16:offset + 24], "little")
        p_filesz = int.from_bytes(data[offset + 32:offset + 40], "little")
        p_memsz = int.from_bytes(data[offset + 40:offset + 48], "little")
        p_align = int.from_bytes(data[offset + 48:offset + 56], "little")
        if p_type == 1:
            loads.append((index, p_offset, p_vaddr, p_filesz, p_memsz, flags))
        elif p_type == 7:
            if tls is not None:
                fail("TLS fixture has duplicate PT_TLS")
            tls = (index, p_offset, p_vaddr, p_filesz, p_memsz, p_align, flags)
    if tls is None:
        fail("TLS fixture has no PT_TLS")
    index, p_offset, p_vaddr, p_filesz, p_memsz, p_align, flags = tls
    if p_filesz > p_memsz or p_offset + p_filesz > len(data):
        fail("TLS fixture PT_TLS range is invalid")
    owners = []
    for load_index, load_offset, load_vaddr, load_filesz, load_memsz, load_flags in loads:
        if p_vaddr < load_vaddr or p_memsz > load_memsz or p_vaddr - load_vaddr > load_memsz - p_memsz:
            continue
        delta = p_vaddr - load_vaddr
        if p_filesz and (
            p_offset < load_offset
            or p_offset - load_offset != delta
            or p_filesz > load_filesz - delta
        ):
            continue
        owners.append(load_index)
    if len(owners) != 1:
        fail(f"TLS fixture has {len(owners)} PT_TLS owners")
    template = data[p_offset:p_offset + p_filesz]
    return {
        "sourceSha256": sha256(path),
        "fileSize": p_filesz,
        "memorySize": p_memsz,
        "zeroFillSize": p_memsz - p_filesz,
        "alignment": p_align,
        "owningLoad": owners[0],
        "template": template,
        "templateSha256": hashlib.sha256(template).hexdigest(),
        "flags": flags,
    }


def native_result(path: Path) -> dict[str, Any]:
    completed = subprocess.run([str(PROBE), str(path)], cwd=ROOT, text=True, capture_output=True)
    if completed.returncode != 0:
        return {"schemaVersion": 1, "processStatus": completed.returncode, "status": None, "stderr": completed.stderr[-4096:]}
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        fail(f"native TLS validation probe returned invalid JSON: {error}")
    result["processStatus"] = completed.returncode
    return result


def copy_evidence(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def base_row(
    root: Path,
    row_id: str,
    model: str,
    profile: str,
    runtime: str,
    lifecycle: str,
    result: str,
    reason: str,
    facts: dict[str, Any],
    native_status: dict[str, Any],
    managed_gate_path: Path,
    *,
    managed_status: str,
    loader_status: str,
    toolchain: str,
    loader: str,
    first_failure: str | None,
    publication: str,
    rollback: str,
    per_thread: str,
    zero_fill: str,
    lifecycle_order: str,
) -> dict[str, Any]:
    row_root = root / row_id
    row_root.mkdir(parents=True, exist_ok=True)
    copy_evidence(TLS_FIXTURE, row_root / "source-image.bin")
    (row_root / "pt-tls-template.bin").write_bytes(facts["template"])
    copy_evidence(managed_gate_path, row_root / "managed-semantic-gate.txt")
    (row_root / "native-preflight.json").write_text(
        json.dumps(native_status, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    relative = lambda name: str((Path(row_id) / name).as_posix())
    return {
        "schemaVersion": 1,
        "rowId": row_id,
        "model": model,
        "profile": profile,
        "runtime": runtime,
        "lifecycle": lifecycle,
        "result": result,
        "reason": reason,
        "managedStatus": managed_status,
        "loaderStatus": loader_status,
        "toolchainIdentity": toolchain,
        "loaderIdentity": loader,
        "sourceSha256": sha256(row_root / "source-image.bin"),
        "protectedSha256": None,
        "nativeSha256": None,
        "ptTls": {
            "templatePath": relative("pt-tls-template.bin"),
            "templateSha256": sha256(row_root / "pt-tls-template.bin"),
            "fileSize": facts["fileSize"],
            "memorySize": facts["memorySize"],
            "zeroFillSize": facts["zeroFillSize"],
            "alignment": facts["alignment"],
            "owningLoad": facts["owningLoad"],
        },
        "perThread": per_thread,
        "zeroFill": zero_fill,
        "lifecycleOrder": lifecycle_order,
        "firstFailureStage": first_failure,
        "publicationResult": publication,
        "rollbackResult": rollback,
        "evidencePaths": [
            relative("source-image.bin"),
            relative("pt-tls-template.bin"),
            relative("native-preflight.json"),
            relative("managed-semantic-gate.txt"),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()

    artifact_root = (args.artifact_root or (ROOT / ".artifacts" / "tls-runtime" / args.tier)).resolve()
    try:
        artifact_root.relative_to((ROOT / ".artifacts" / "tls-runtime").resolve())
    except ValueError:
        fail("TLS matrix artifact root must be under .artifacts/tls-runtime")
    if artifact_root.exists():
        shutil.rmtree(artifact_root)
    artifact_root.mkdir(parents=True)
    facts_work = Path(tempfile.mkdtemp(prefix="urprotect-tls-matrix-", dir=os.environ.get("RUNNER_TEMP", "/tmp")))
    try:
        native_compiler = os.environ.get("NATIVE_LAUNCHER_CC", "cc")
        subprocess.run(
            ["make", "-C", str(ROOT / "native/urprotect-runtime"), f"CC={native_compiler}", "tls-fixture", "host-image-validation-probe"],
            check=True,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if not TLS_FIXTURE.is_file() or not PROBE.is_file():
            fail("TLS fixture build did not produce the source image")
        facts = tls_facts(TLS_FIXTURE)
        managed_gate_path = artifact_root / "managed-semantic-gate.txt"
        managed_gate = subprocess.run(
            [
                "dotnet", "test", "tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj",
                "--configuration", "Release", "--no-build", "--no-restore",
                "--filter", "FullyQualifiedName~TlsLocalExecWorkflowTests|FullyQualifiedName~Aarch64TlsSequenceRecognizerTests",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        managed_gate_path.write_text(managed_gate.stdout + managed_gate.stderr, encoding="utf-8")
        if managed_gate.returncode != 0:
            fail("managed TLS semantic gate failed")
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        rows: list[dict[str, Any]] = []
        control_id = registry["controlRow"]
        control_success = False
        control_artifact_root = facts_work / "control"
        if platform.machine() in {"aarch64", "arm64"}:
            control_env = os.environ.copy()
            control_env["TLS_EVIDENCE_ARTIFACT_ROOT"] = str(control_artifact_root)
            completed = subprocess.run(
                [str(TLS_RUNNER), "--tier", args.tier, "--unit", control_id],
                cwd=ROOT,
                env=control_env,
                text=True,
                capture_output=True,
            )
            control_root = control_artifact_root / control_id
            control_success = completed.returncode == 0 and (control_root / "protected-image.bin").is_file()
            if not control_success:
                fail("native glibc transformed TLS control row failed: " + completed.stderr[-4096:])
        if control_success:
            row_root = artifact_root / control_id
            row_root.mkdir(parents=True)
            for name in ("source-image.bin", "protected-image.bin", "native-image.bin", "tls-template.bin"):
                copy_evidence(control_root / name, row_root / name)
            facts_path = row_root / "pt-tls-template.bin"
            if not facts_path.is_file():
                facts_path.write_bytes(facts["template"])
            row = base_row(
                artifact_root, control_id, "initial-exec", "host-context-entry", "glibc", "current-thread",
                "accepted-and-runs", "dedicated transformed native AArch64 glibc TLSIE control row",
                facts, native_result(TLS_FIXTURE), managed_gate_path, managed_status="accepted", loader_status="accepted-and-runs",
                toolchain="gcc/binutils native AArch64", loader="host-context.sealed-memfd.dlopen",
                first_failure=None, publication="published", rollback="not-applicable",
                per_thread="observed", zero_fill="observed",
                lifecycle_order="entry-dispatch-before-release-image",
            )
            row_root.joinpath("pt-tls-template.bin").write_bytes(facts["template"])
            row["sourceSha256"] = sha256(row_root / "source-image.bin")
            row["protectedSha256"] = sha256(row_root / "protected-image.bin")
            row["nativeSha256"] = sha256(row_root / "native-image.bin")
            row["ptTls"]["templateSha256"] = sha256(row_root / "pt-tls-template.bin")
            row["evidencePaths"] = [
                f"{control_id}/source-image.bin",
                f"{control_id}/protected-image.bin",
                f"{control_id}/native-image.bin",
                f"{control_id}/pt-tls-template.bin",
                f"{control_id}/native-preflight.json",
                f"{control_id}/managed-semantic-gate.txt",
            ]
            rows.append(row)

        has_musl = shutil.which("musl-gcc") is not None
        has_bionic = shutil.which(os.environ.get("BIONIC_CONTAINER_RUNTIME", "docker")) is not None
        for model, profile, runtime, lifecycle in itertools.product(
            registry["models"], registry["profiles"], registry["runtimes"], registry["lifecycles"]
        ):
            row_id = f"{model}.{profile}.{runtime}.{lifecycle}"
            if row_id == control_id:
                continue
            if profile == "outer-execveat" and lifecycle == "registered-worker":
                result, reason, first_failure = (
                    "not-applicable",
                    "outer-execveat has no registered HostContext worker lifecycle",
                    "scope",
                )
            elif lifecycle == "registered-worker":
                result, reason, first_failure = (
                    "not-applicable",
                    "registered-worker transformed TLS requires a dedicated managed lifecycle oracle",
                    "scope",
                )
            elif runtime == "musl" and not has_musl:
                result, reason, first_failure = (
                    "environment-unavailable",
                    "musl transformed TLS requires the pinned musl toolchain/runtime",
                    "environment",
                )
            elif runtime == "musl":
                result, reason, first_failure = (
                    "not-applicable",
                    "an independent transformed musl TLS loader/handoff oracle is not registered",
                    "scope",
                )
            elif runtime == "bionic" and not has_bionic:
                result, reason, first_failure = (
                    "environment-unavailable",
                    "bionic transformed TLS requires the native arm64 Termux container",
                    "environment",
                )
            elif runtime == "bionic":
                result, reason, first_failure = (
                    "not-applicable",
                    "an independent transformed bionic TLS loader/handoff oracle is not registered",
                    "scope",
                )
            elif model != "initial-exec" or profile != "host-context-entry":
                result, reason, first_failure = (
                    "not-applicable",
                    "managed semantic/layout support exists but no transformed runtime oracle is registered for this row",
                    "semantic",
                )
            else:
                result, reason, first_failure = (
                    "not-applicable",
                    "runtime-specific transformed oracle is not registered for this row",
                    "scope",
                )
            rows.append(base_row(
                artifact_root, row_id, model, profile, runtime, lifecycle, result, reason, facts,
                native_result(TLS_FIXTURE), managed_gate_path, managed_status="semantic-gate-passed", loader_status="not-run",
                toolchain="not-run", loader="not-run",
                first_failure=first_failure, publication="not-published",
                rollback="not-applicable", per_thread="not-run",
                zero_fill="not-run", lifecycle_order="not-applicable",
            ))

        document = {
            "schemaVersion": 1,
            "kind": "tls-runtime-evidence",
            "registry": "fixtures/tls-runtime-matrix.json",
            "tier": args.tier,
            "producer": "scripts/run-tls-runtime-matrix.py",
            "rows": rows,
        }
        (artifact_root / "matrix.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        environment = {
            "schemaVersion": 1,
            "architecture": platform.machine(),
            "kernel": platform.release(),
            "pageSize": os.sysconf("SC_PAGESIZE"),
            "muslToolchain": has_musl,
            "bionicContainerRuntime": shutil.which(os.environ.get("BIONIC_CONTAINER_RUNTIME", "docker")),
            "controlRow": control_id,
            "controlRowAccepted": control_success,
        }
        (artifact_root / "environment.json").write_text(json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        entries = []
        for path in sorted(p for p in artifact_root.rglob("*") if p.is_file()):
            entries.append(f"{sha256(path)}  {path.relative_to(artifact_root).as_posix()}")
        (artifact_root / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
        checker = subprocess.run(
            [sys.executable, str(ROOT / "scripts/check-tls-runtime-matrix-evidence.py"), str(artifact_root), "--registry", str(REGISTRY_PATH)],
            cwd=ROOT,
            text=True,
        )
        if checker.returncode:
            raise SystemExit(checker.returncode)
        print(f"TLS transformed matrix: {len(rows)} rows; control={control_id}; accepted={control_success}")
    finally:
        shutil.rmtree(facts_work, ignore_errors=True)


if __name__ == "__main__":
    main()
