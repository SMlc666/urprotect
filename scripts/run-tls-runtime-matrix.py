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

from tls_runtime_identity import identify_native_glibc

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "fixtures/tls-runtime-matrix.json"
TLS_FIXTURE = ROOT / "native/urprotect-runtime/build/host-context-tls-fixture.so"
TLSLE_FIXTURE = ROOT / "native/urprotect-runtime/build/host-context-tlsle-fixture.so"
TLSLD_FIXTURE = ROOT / "native/urprotect-runtime/build/host-context-tlsld-fixture.so"
TLSGD_FIXTURE = ROOT / "native/urprotect-runtime/build/host-context-tlsgd-fixture.so"
TLSDESC_FIXTURE = ROOT / "native/urprotect-runtime/build/host-context-tlsdesc-fixture.so"
TLS_RUNNER = ROOT / "scripts/run-tls-host-context-rehydration-e2e.sh"
PROBE = ROOT / "native/urprotect-runtime/build/host-image-validation-probe"
PROMOTED_MODELS = {
    "initial-exec": {
        "fixture": TLS_FIXTURE,
        "selector": ("symtab", "urp_tls_read"),
        "entry_status": 43,
        "producer_id": "gcc-c-tls-initial-exec",
        "reason": "dedicated transformed native AArch64 glibc initial-exec current-thread row",
    },
    "local-dynamic": {
        "fixture": TLSLD_FIXTURE,
        "selector": ("dynsym", "urp_entry"),
        "entry_status": 43,
        "producer_id": "gcc-aarch64-tlsld-fixture",
        "reason": "dedicated transformed native AArch64 glibc local-dynamic current-thread row",
    },
    "general-dynamic": {
        "fixture": TLSGD_FIXTURE,
        "selector": ("dynsym", "urp_entry"),
        "entry_status": 43,
        "producer_id": "gcc-aarch64-tlsgd-fixture",
        "reason": "dedicated transformed native AArch64 glibc general-dynamic current-thread row",
    },
    "tlsdesc": {
        "fixture": TLSDESC_FIXTURE,
        "selector": ("dynsym", "urp_entry"),
        "entry_status": 43,
        "producer_id": "gcc-aarch64-tlsdesc-fixture",
        "reason": "dedicated transformed native AArch64 glibc TLSDESC current-thread row",
    },
}
ROW_FIXTURES = {
    "local-exec": {
        "fixture": TLSLE_FIXTURE,
    },
    **PROMOTED_MODELS,
}


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
    source_fixture: Path,
    source_fixture_id: str,
    profile: str,
    runtime: str,
    lifecycle: str,
    result: str,
    reason: str,
    facts: dict[str, Any],
    managed_gate_path: Path,
    runtime_identity: dict[str, Any],
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
    expected_entry_status: int | None = None,
) -> dict[str, Any]:
    row_root = root / row_id
    row_root.mkdir(parents=True, exist_ok=True)
    relative = lambda name: str((Path(row_id) / name).as_posix())
    copy_evidence(source_fixture, row_root / "source-image.bin")
    source_path = row_root / "source-image.bin"
    source_hash = sha256(source_path)
    (row_root / "pt-tls-template.bin").write_bytes(facts["template"])
    copy_evidence(managed_gate_path, row_root / "managed-semantic-gate.txt")
    native_evidence = native_result(source_path)
    native_evidence.update({
        "rowId": row_id,
        "sourceFixture": source_fixture_id,
        "sourceSha256": source_hash,
    })
    (row_root / "native-preflight.json").write_text(
        json.dumps(native_evidence, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "schemaVersion": 1,
        "rowId": row_id,
        "model": model,
        "sourceFixture": source_fixture_id,
        "profile": profile,
        "runtime": runtime,
        "lifecycle": lifecycle,
        "result": result,
        "reason": reason,
        "managedStatus": managed_status,
        "loaderStatus": loader_status,
        "toolchainIdentity": toolchain,
        "loaderIdentity": loader,
        "sourceSha256": source_hash,
        "protectedSha256": None,
        "nativeSha256": None,
        "expectedEntryStatus": expected_entry_status,
        "runtimeVersion": runtime_identity["version"] if runtime == "glibc" else None,
        "runtimeIdentitySha256": runtime_identity["identitySha256"] if runtime == "glibc" else None,
        "libcPath": runtime_identity["libcPath"] if runtime == "glibc" else None,
        "libcSha256": runtime_identity["libcSha256"] if runtime == "glibc" else None,
        "loaderPath": runtime_identity["loaderPath"] if runtime == "glibc" else None,
        "loaderSha256": runtime_identity["loaderSha256"] if runtime == "glibc" else None,
        "behavioralOracleSha256": None,
        "behaviorComparisonSha256": None,
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


def find_symbol_selector(path: Path, table: str, name: str) -> str:
    command = ["readelf", "--dyn-syms", "-W"] if table == "dynsym" else ["readelf", "--syms", "-W"]
    completed = run(command + [str(path)], check=False)
    if completed.returncode != 0:
        fail(f"could not inspect {table} for {name}: {completed.stderr[-4096:]}")
    matches: list[str] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[3] != "FUNC" or fields[-1] != name:
            continue
        symbol_index = fields[0].rstrip(":")
        if symbol_index.isdecimal():
            matches.append(f"{table}:{symbol_index}")
    if len(matches) != 1:
        fail(f"{table} function {name} has {len(matches)} exact matches in {path.name}")
    return matches[0]


def retain_failed_promoted_row(
    artifact_root: Path, row_id: str, runner_root: Path,
    completed: subprocess.CompletedProcess[str],
) -> Path:
    """Retain bounded failure diagnostics outside the disposable matrix work tree."""
    if not row_id or Path(row_id).name != row_id or row_id in (".", ".."):
        fail("invalid failed TLS row identity")
    destination = artifact_root / "failures" / row_id
    destination.mkdir(parents=True, exist_ok=False)
    limit = 1024 * 1024
    truncated: list[str] = []
    retained: dict[str, str] = {}
    for name in (
        "producer.json", "producer.stderr", "protected-image.json", "stage.json",
        "rehydration-command.json", "rehydration-command.stderr", "rehydration.json",
        "native-image.json", "handoff.json", "handoff.stdout", "handoff.stderr",
    ):
        path = runner_root / name
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            truncated.append(name)
        output = destination / name
        output.write_bytes(data[:limit])
        retained[name] = sha256(output)
    for name, content in (("runner.stdout", completed.stdout), ("runner.stderr", completed.stderr)):
        data = (content or "").encode("utf-8")
        if len(data) > limit:
            truncated.append(name)
        output = destination / name
        output.write_bytes(data[:limit])
        retained[name] = sha256(output)
    failure_stage = None
    diagnostics: list[Any] = []
    for name in ("rehydration.json", "rehydration-command.json", "producer.json"):
        path = destination / name
        if not path.is_file() or name in truncated:
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError):
            continue
        if isinstance(record, dict):
            failure_stage = record.get("firstFailureStage") or failure_stage
            if isinstance(record.get("diagnostics"), list):
                diagnostics = record["diagnostics"]
            if failure_stage:
                break
    (destination / "runner-result.json").write_text(
        json.dumps({
            "schemaVersion": 1, "status": "failed", "rowId": row_id,
            "processStatus": completed.returncode, "firstFailureStage": failure_stage,
            "diagnostics": diagnostics, "retainedSha256": retained,
            "truncatedFiles": truncated,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return destination


def finalize_promoted_row(row_root: Path, row_id: str, tier: str) -> None:
    """Close the complete durable producer row after matrix-specific additions."""
    paths = sorted(row_root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        fail(f"promoted TLS row contains a symlink: {row_id}")
    entries = [
        f"{sha256(path)}  {path.relative_to(row_root).as_posix()}"
        for path in paths if path.is_file() and path != row_root / "SHA256SUMS"
    ]
    (row_root / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")
    for checker in ("check-protected-image-evidence.py", "check-rehydration-evidence.py"):
        completed = run([
            sys.executable, str(ROOT / "scripts" / checker), str(row_root),
            "--tier", tier, "--runtime", "glibc", "--unit", row_id,
        ], check=False)
        if completed.returncode:
            fail(
                f"finalized TLS row {row_id} failed {checker}: "
                + completed.stdout[-2048:] + completed.stderr[-2048:]
            )


def run_promoted_evidence(
    *,
    artifact_root: Path,
    facts_work: Path,
    managed_gate_path: Path,
    tier: str,
    model: str,
    row_id: str,
    source_fixture_id: str,
    runtime_identity: dict[str, Any],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    fixture = Path(configuration["fixture"])
    if fixture.resolve().relative_to(ROOT).as_posix() != source_fixture_id:
        fail(f"TLS source fixture registry identity drifted for {row_id}")
    facts = tls_facts(fixture)
    table, symbol_name = configuration["selector"]
    selector = find_symbol_selector(fixture, table, symbol_name)
    # Keep the original publication paths durable; a partial copy leaves role
    # and stage paths pointing into deleted temporary work.
    runner_parent = artifact_root
    environment = os.environ.copy()
    environment["TLS_EVIDENCE_ARTIFACT_ROOT"] = str(runner_parent)
    completed = subprocess.run(
        [
            str(TLS_RUNNER),
            "--tier", tier,
            "--unit", row_id,
            "--source", str(fixture),
            "--function-id", selector,
            "--model", model,
            "--profile", "host-context-entry",
            "--runtime", "glibc",
            "--lifecycle", "current-thread",
            "--entry-status", str(configuration["entry_status"]),
            "--producer-id", configuration["producer_id"],
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
    )
    runner_root = runner_parent / row_id
    if completed.returncode != 0 or not (runner_root / "protected-image.bin").is_file():
        failure_root = retain_failed_promoted_row(artifact_root, row_id, runner_root, completed)
        record = json.loads((failure_root / "runner-result.json").read_text(encoding="utf-8"))
        fail(
            f"native glibc transformed TLS row {row_id} failed "
            f"(exit {completed.returncode}, stage {record['firstFailureStage']}); "
            f"retained diagnostics: {failure_root}; "
            + completed.stdout[-2048:] + completed.stderr[-2048:]
        )

    preflight = native_result(fixture)
    if preflight.get("processStatus") != 0 or preflight.get("status") != 0:
        fail(f"native preflight did not accept promoted TLS source {row_id}: {preflight}")
    row = base_row(
        artifact_root,
        row_id,
        model,
        fixture,
        source_fixture_id,
        "host-context-entry",
        "glibc",
        "current-thread",
        "accepted-and-runs",
        configuration["reason"],
        facts,
        managed_gate_path,
        runtime_identity,
        managed_status="accepted",
        loader_status="accepted-and-runs",
        toolchain="gcc/binutils native AArch64",
        loader="host-context.sealed-memfd.dlopen",
        first_failure=None,
        publication="published",
        rollback="not-applicable",
        per_thread="observed",
        zero_fill="not-run" if facts["zeroFillSize"] > 0 else "not-applicable",
        lifecycle_order="entry-dispatch-before-release-image",
        expected_entry_status=configuration["entry_status"],
    )
    row_root = runner_root
    row["sourceSha256"] = sha256(row_root / "source-image.bin")
    row["protectedSha256"] = sha256(row_root / "protected-image.bin")
    row["nativeSha256"] = sha256(row_root / "native-image.bin")
    row["ptTls"]["templateSha256"] = sha256(row_root / "pt-tls-template.bin")
    row["behavioralOracleSha256"] = sha256(row_root / "behavioral-oracle.json")
    row["behaviorComparisonSha256"] = sha256(row_root / "behavior-comparison.json")
    row["evidencePaths"] = [
        f"{row_id}/source-image.bin",
        f"{row_id}/protected-image.bin",
        f"{row_id}/native-image.bin",
        f"{row_id}/pt-tls-template.bin",
        f"{row_id}/native-preflight.json",
        f"{row_id}/managed-semantic-gate.txt",
        f"{row_id}/stage.json",
        f"{row_id}/tls-template.bin",
        f"{row_id}/rehydration.json",
        f"{row_id}/handoff.json",
        f"{row_id}/source-handoff.json",
        f"{row_id}/baseline.stdout",
        f"{row_id}/baseline.stderr",
        f"{row_id}/target.stdout",
        f"{row_id}/target.stderr",
        f"{row_id}/behavior-comparison.json",
        f"{row_id}/behavioral-oracle.json",
        f"{row_id}/SHA256SUMS",
    ]
    finalize_promoted_row(row_root, row_id, tier)
    return row


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
            [
                "make",
                "-C",
                str(ROOT / "native/urprotect-runtime"),
                f"CC={native_compiler}",
                "tls-fixture",
                "tlsle-fixture",
                "tlsld-fixture",
                "tlsgd-fixture",
                "tlsdesc-fixture",
                "host-image-validation-probe",
            ],
            check=True,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if not PROBE.is_file() or any(
            not Path(configuration["fixture"]).is_file()
            for configuration in ROW_FIXTURES.values()
        ):
            fail("TLS matrix fixture build did not produce every required row-specific source image")

        managed_gate_path = artifact_root / "managed-semantic-gate.txt"
        managed_gate = subprocess.run(
            [
                "dotnet",
                "test",
                "tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj",
                "--configuration",
                "Release",
                "--no-build",
                "--no-restore",
                "--filter",
                "FullyQualifiedName~TlsLocalExecWorkflowTests|FullyQualifiedName~Aarch64TlsSequenceRecognizerTests",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        managed_gate_path.write_text(managed_gate.stdout + managed_gate.stderr, encoding="utf-8")
        if managed_gate.returncode != 0:
            fail("managed TLS semantic gate failed")

        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        required_promoted_rows = {
            f"{model}.host-context-entry.glibc.current-thread"
            for model in PROMOTED_MODELS
        }
        if set(registry.get("promotedRows", ())) != required_promoted_rows:
            fail("TLS registry promotedRows does not match the four row-specific glibc HostContext current-thread models")
        expected_source_fixtures = {
            model: Path(configuration["fixture"]).resolve().relative_to(ROOT).as_posix()
            for model, configuration in ROW_FIXTURES.items()
        }
        if registry.get("sourceFixtures") != expected_source_fixtures:
            fail("TLS registry sourceFixtures does not match the model-specific native fixtures")
        rows: list[dict[str, Any]] = []
        promoted_rows: set[str] = set()
        if platform.machine() not in {"aarch64", "arm64"}:
            fail(f"TLS transformed matrix promotion requires native AArch64; got {platform.machine()}")
        runtime_identity = identify_native_glibc()
        if platform.machine() in {"aarch64", "arm64"}:
            for model, configuration in PROMOTED_MODELS.items():
                row_id = f"{model}.host-context-entry.glibc.current-thread"
                rows.append(
                    run_promoted_evidence(
                        artifact_root=artifact_root,
                        facts_work=facts_work,
                        managed_gate_path=managed_gate_path,
                        tier=args.tier,
                        model=model,
                        row_id=row_id,
                        source_fixture_id=registry["sourceFixtures"][model],
                        runtime_identity=runtime_identity,
                        configuration=configuration,
                    )
                )
                promoted_rows.add(row_id)

        has_musl = shutil.which("musl-gcc") is not None
        has_bionic = shutil.which(os.environ.get("BIONIC_CONTAINER_RUNTIME", "docker")) is not None
        for model, profile, runtime, lifecycle in itertools.product(
            registry["models"],
            registry["profiles"],
            registry["runtimes"],
            registry["lifecycles"],
        ):
            row_id = f"{model}.{profile}.{runtime}.{lifecycle}"
            if row_id in promoted_rows:
                continue
            configuration = ROW_FIXTURES[model]
            source_fixture = Path(configuration["fixture"])
            source_fixture_id = registry["sourceFixtures"][model]
            facts = tls_facts(source_fixture)
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
            elif model not in PROMOTED_MODELS or profile != "host-context-entry":
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
            rows.append(
                base_row(
                    artifact_root,
                    row_id,
                    model,
                    source_fixture,
                    source_fixture_id,
                    profile,
                    runtime,
                    lifecycle,
                    result,
                    reason,
                    facts,
                    managed_gate_path,
                    runtime_identity,
                    managed_status="semantic-gate-passed",
                    loader_status="not-run",
                    toolchain="not-run",
                    loader="not-run",
                    first_failure=first_failure,
                    publication="not-published",
                    rollback="not-applicable",
                    per_thread="not-run",
                    zero_fill="not-run",
                    lifecycle_order="not-applicable",
                )
            )

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
            "controlRow": registry["controlRow"],
            "promotedRows": sorted(promoted_rows),
            "runtimeIdentity": runtime_identity,
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
        print(
            f"TLS transformed matrix: {len(rows)} rows; "
            f"promoted={sorted(promoted_rows)}; control={registry['controlRow']}"
        )
    finally:
        shutil.rmtree(facts_work, ignore_errors=True)


if __name__ == "__main__":
    main()
