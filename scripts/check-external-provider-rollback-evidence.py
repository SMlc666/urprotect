#!/usr/bin/env python3
"""Independently validate the provider-loaded consumer-failure rollback oracle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
BUILD_COMMAND = ["make", "-C", "native/urprotect-runtime", "-B", "external-provider-provider-loaded-rollback-test"]
CPP_FLAGS = ["-Iinclude", "-I../urprotect-launcher", "-I../../third_party/miniz"]
C_FLAGS = ["-std=c11", "-O2", "-g0", "-Wall", "-Wextra", "-Werror", "-Wshadow", "-Wconversion", "-pthread"]
EVENTS = [
    "provider-acquired",
    "consumer-dlmopen-succeeded",
    "provider-binding-verified",
    "binding-failpoint-reached",
    "failure-consumer-dlclose-returned",
    "failure-consumer-fd-close-returned",
    "provider-dlclose-returned",
    "provider-fd-close-returned",
    "provider-release-returned",
    "first-load-rejected",
    "provider-acquired",
    "consumer-dlmopen-succeeded",
    "provider-binding-verified",
    "image-handle-published",
    "image-release-started",
    "image-dlclose-returned",
    "image-fd-close-returned",
    "provider-dlclose-returned",
    "provider-fd-close-returned",
    "provider-release-returned",
    "image-release-returned",
]

BUILD_INPUT_FILES = {
    "build-inputs/Makefile",
    "build-inputs/host_adapter.c",
    "build-inputs/host_context_external_provider_self_test.c",
    "build-inputs/host_adapter_provider_rollback_test.h",
    "build-inputs/host_image_validation.c",
    "build-inputs/host_image_validation.h",
    "build-inputs/android_packed_relocation_tags.h",
    "build-inputs/include/urp/host_adapter.h",
    "build-inputs/include/urp/host_context.h",
    "build-inputs/host_context_external_provider_fixture.S",
    "build-inputs/host_context_external_provider_consumer_fixture.S",
    "build-inputs/sha256.c",
    "build-inputs/sha256.h",
}
BUILD_OUTPUT_FILES = {
    "build-outputs/provider-fixture.o",
    "build-outputs/consumer-fixture.o",
    "build-outputs/host-adapter-provider-rollback-test.o",
    "build-outputs/host-image-validation-test.o",
    "build-outputs/sha256.o",
    "build-outputs/rollback-self-test",
    "build-outputs/provider-image.so",
    "build-outputs/consumer-image.so",
}
EVIDENCE_TOOL_FILES = {
    "evidence-tools/check-external-provider-rollback-evidence.py",
    "scripts/check-external-provider-evidence.py",
    "scripts/check-dynamic-import-evidence.py",
    "scripts/check-indirect-control-evidence.py",
    "scripts/tls_runtime_identity.py",
}
TOOLCHAIN_FILES = {
    "toolchain/cc-driver",
    "toolchain/cc1",
    "toolchain/as",
    "toolchain/ld",
    "toolchain/cc-version.txt",
    "toolchain/as-version.txt",
    "toolchain/ld-version.txt",
    "toolchain/target-triple.txt",
}
ROOT_FILES = {
    "native-build.json",
    "native-build.stdout",
    "native-build.stderr",
    "native-build.exit-status",
    "rollback-record.json",
    "rollback-stderr.log",
    "rollback-exit-status",
} | BUILD_INPUT_FILES | BUILD_OUTPUT_FILES | EVIDENCE_TOOL_FILES | TOOLCHAIN_FILES
ALL_FILES = ROOT_FILES | {"report.json", "SHA256SUMS"}


def fail(message: str) -> None:
    raise SystemExit(f"provider-loaded rollback evidence: {message}")


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail("cannot load the independent external-provider ELF parser")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def read_file(root: Path, relative: str, *, allow_empty: bool = False) -> bytes:
    path = root / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot stat evidence file {relative}: {error}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES or (not allow_empty and metadata.st_size == 0):
        fail(f"evidence input is not a bounded regular file: {relative}")
    try:
        data = path.read_bytes()
    except OSError as error:
        fail(f"cannot read evidence file {relative}: {error}")
    if len(data) != metadata.st_size or len(data) > MAX_FILE_BYTES or (not allow_empty and not data):
        fail(f"evidence input changed size or exceeds its bound: {relative}")
    return data


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON property: {key}")
        value[key] = item
    return value


def read_json(root: Path, relative: str) -> dict[str, Any]:
    data = read_file(root, relative)
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"invalid JSON in {relative}: {error}")
    if not isinstance(value, dict):
        fail(f"{relative} must be a JSON object")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_int(value: Any, label: str) -> int:
    if type(value) is not int:
        fail(f"{label} must be an exact JSON integer")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    if set(value) != expected:
        fail(f"{label} has an unsupported property set (missing={sorted(expected - set(value))}, extra={sorted(set(value) - expected)})")
    return value


def require(value: bool, message: str) -> None:
    if not value:
        fail(message)


def _safe_closed_tree(root: Path, expected: set[str], *, sealing: bool) -> None:
    actual: set[str] = set()
    total = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            fail(f"evidence tree contains a symlink: {relative}")
        if path.is_file():
            actual.add(relative)
            total += path.stat().st_size
            if total > MAX_TOTAL_BYTES:
                fail("evidence tree exceeds its aggregate byte bound")
    if sealing:
        required = ROOT_FILES
        if actual != required:
            fail(f"unsealed evidence tree has unexpected file set (missing={sorted(required - actual)}, extra={sorted(actual - required)})")
    elif actual != expected:
        fail(f"evidence tree is not closed (missing={sorted(expected - actual)}, extra={sorted(actual - expected)})")


def _write_manifest(root: Path) -> None:
    rows: list[str] = []
    for relative in sorted(ALL_FILES - {"SHA256SUMS"}):
        data = read_file(root, relative, allow_empty=True)
        rows.append(f"{sha(data)}  {relative}\n")
    (root / "SHA256SUMS").write_text("".join(rows), encoding="ascii")


def _verify_manifest(root: Path) -> None:
    data = read_file(root, "SHA256SUMS")
    try:
        rows = data.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        fail("SHA256SUMS is not ASCII")
    parsed: dict[str, str] = {}
    for row in rows:
        if len(row) < 67 or row[64:66] != "  ":
            fail("SHA256SUMS contains a malformed row")
        digest, relative = row[:64], row[66:]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            fail("SHA256SUMS contains a malformed digest")
        if relative in parsed or relative.startswith("/") or ".." in Path(relative).parts or "\\" in relative:
            fail("SHA256SUMS contains an unsafe or duplicate path")
        parsed[relative] = digest
    expected = ALL_FILES - {"SHA256SUMS"}
    if set(parsed) != expected:
        fail(f"SHA256SUMS is not closed (missing={sorted(expected - set(parsed))}, extra={sorted(set(parsed) - expected)})")
    for relative, expected_digest in parsed.items():
        if sha(read_file(root, relative, allow_empty=True)) != expected_digest:
            fail(f"SHA256SUMS digest mismatch: {relative}")


def _verify_build(root: Path, build: dict[str, Any]) -> dict[str, bytes]:
    exact_keys(build, {
        "schemaVersion", "nativeBuildCommand", "nativeBuildExitStatus", "nativeBuildStdoutSha256",
        "nativeBuildStderrSha256", "rollbackExitStatus", "rollbackStdoutSha256", "rollbackStderrSha256",
        "rollbackBinarySha256", "providerImageSha256", "consumerImageSha256", "nativeBuildInputs", "toolchain", "evidenceTools",
    }, "native build record")
    require(exact_int(build.get("schemaVersion"), "native build schemaVersion") == 1, "native-build.json schema is unsupported")
    require(build.get("nativeBuildCommand") == BUILD_COMMAND, "native build does not bind the exact forced rollback target")
    build_status = exact_int(build.get("nativeBuildExitStatus"), "native build exit status")
    require(build_status == 0, "native rollback build command did not pass")
    require(build.get("nativeBuildStdoutSha256") == sha(read_file(root, "native-build.stdout")), "native build stdout digest mismatch")
    require(build.get("nativeBuildStderrSha256") == sha(read_file(root, "native-build.stderr", allow_empty=True)), "native build stderr digest mismatch")
    require(read_file(root, "native-build.exit-status").decode("ascii").strip() == "0", "retained native build exit status is not zero")
    expected_hashes = {
        "rollbackBinarySha256": "build-outputs/rollback-self-test",
        "providerImageSha256": "build-outputs/provider-image.so",
        "consumerImageSha256": "build-outputs/consumer-image.so",
    }
    for field, relative in expected_hashes.items():
        require(build.get(field) == sha(read_file(root, relative)), f"native build {field} does not bind {relative}")
    source_hashes = exact_keys(build.get("nativeBuildInputs"), {
        "makefileSha256", "hostAdapterSourceSha256", "rollbackHeaderSha256", "selfTestSourceSha256",
        "imageValidationSourceSha256", "imageValidationHeaderSha256", "providerFixtureSourceSha256",
        "consumerFixtureSourceSha256", "hostAdapterObjectSha256", "imageValidationObjectSha256",
        "sha256ObjectSha256", "providerObjectSha256", "consumerObjectSha256",
    }, "native build inputs")
    source_bindings = {
        "makefileSha256": "build-inputs/Makefile",
        "hostAdapterSourceSha256": "build-inputs/host_adapter.c",
        "rollbackHeaderSha256": "build-inputs/host_adapter_provider_rollback_test.h",
        "selfTestSourceSha256": "build-inputs/host_context_external_provider_self_test.c",
        "imageValidationSourceSha256": "build-inputs/host_image_validation.c",
        "imageValidationHeaderSha256": "build-inputs/host_image_validation.h",
        "providerFixtureSourceSha256": "build-inputs/host_context_external_provider_fixture.S",
        "consumerFixtureSourceSha256": "build-inputs/host_context_external_provider_consumer_fixture.S",
        "hostAdapterObjectSha256": "build-outputs/host-adapter-provider-rollback-test.o",
        "imageValidationObjectSha256": "build-outputs/host-image-validation-test.o",
        "sha256ObjectSha256": "build-outputs/sha256.o",
        "providerObjectSha256": "build-outputs/provider-fixture.o",
        "consumerObjectSha256": "build-outputs/consumer-fixture.o",
    }
    for field, relative in source_bindings.items():
        require(source_hashes.get(field) == sha(read_file(root, relative)), f"native build {field} does not bind {relative}")
    toolchain = exact_keys(build.get("toolchain"), {
        "compilerVersionSha256", "assemblerVersionSha256", "linkerVersionSha256", "targetTripleSha256",
        "compilerDriverSha256", "compilerFrontendSha256", "assemblerSha256", "linkerSha256",
    }, "toolchain identity")
    toolchain_bindings = {
        "compilerVersionSha256": "toolchain/cc-version.txt",
        "compilerFrontendSha256": "toolchain/cc1",
        "compilerDriverSha256": "toolchain/cc-driver",
        "assemblerVersionSha256": "toolchain/as-version.txt",
        "assemblerSha256": "toolchain/as",
        "linkerVersionSha256": "toolchain/ld-version.txt",
        "linkerSha256": "toolchain/ld",
        "targetTripleSha256": "toolchain/target-triple.txt",
    }
    for field, relative in toolchain_bindings.items():
        require(toolchain.get(field) == sha(read_file(root, relative)), f"toolchain {field} does not bind {relative}")
    evidence_tools = exact_keys(build.get("evidenceTools"), {
        "providerElfParserSha256", "rollbackCheckerSha256", "dynamicImportParserSha256",
        "indirectControlParserSha256", "runtimeIdentityVerifierSha256",
    }, "evidence tool identity")
    checker_source = read_file(root, "evidence-tools/check-external-provider-rollback-evidence.py")
    require(evidence_tools.get("rollbackCheckerSha256") == sha(checker_source), "retained rollback checker source digest mismatch")
    require(sha(checker_source) == sha(Path(__file__).resolve().read_bytes()), "running rollback checker differs from retained checker source")
    tool_bindings = {
        "providerElfParserSha256": "scripts/check-external-provider-evidence.py",
        "dynamicImportParserSha256": "scripts/check-dynamic-import-evidence.py",
        "indirectControlParserSha256": "scripts/check-indirect-control-evidence.py",
        "runtimeIdentityVerifierSha256": "scripts/tls_runtime_identity.py",
    }
    for field, relative in tool_bindings.items():
        retained = read_file(root, relative)
        require(evidence_tools.get(field) == sha(retained), f"retained evidence tool digest mismatch for {relative}")
        require(sha(retained) == sha((ROOT / relative).read_bytes()), f"running evidence tool differs from retained source: {relative}")
    target = read_file(root, "toolchain/target-triple.txt").decode("ascii", errors="strict").strip()
    require(target == "aarch64-linux-gnu", "native C compiler target is not aarch64-linux-gnu")
    cc_version = read_file(root, "toolchain/cc-version.txt").decode("utf-8", errors="strict").splitlines()
    as_version = read_file(root, "toolchain/as-version.txt").decode("utf-8", errors="strict").splitlines()
    ld_version = read_file(root, "toolchain/ld-version.txt").decode("utf-8", errors="strict").splitlines()
    require(bool(cc_version and cc_version[0]) and bool(as_version and as_version[0]) and bool(ld_version and ld_version[0]), "retained tool version output is empty")

    stdout = read_file(root, "native-build.stdout").decode("utf-8", errors="strict").splitlines()
    commands: list[list[str]] = []
    for line in stdout:
        try:
            commands.append(shlex.split(line))
        except ValueError:
            continue

    def exactly_one(predicate, expected: list[str], label: str) -> None:
        matches = [command for command in commands if predicate(command)]
        if matches != [expected]:
            fail(f"retained build log does not bind the exact {label} invocation")

    exactly_one(lambda row: "host_adapter.c" in row and "-c" in row, [
        "cc", *CPP_FLAGS, *C_FLAGS,
        "-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1",
        "-DURP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT=1",
        "-c", "host_adapter.c", "-o", "build/host_adapter_provider_rollback_test.o",
    ], "test-only failpoint adapter compilation")
    exactly_one(lambda row: row and row[-1] == "build/host-context-external-provider-rollback-self-test", [
        "cc", *CPP_FLAGS, *C_FLAGS,
        "-DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1",
        "-DURP_HOST_ADAPTER_TEST_PROVIDER_BINDING_FAILPOINT=1",
        "-DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1",
        "host_context_external_provider_self_test.c",
        "build/host_adapter_provider_rollback_test.o",
        "build/host_image_validation_test.o", "build/sha256.o", "-ldl", "-pthread",
        "-o", "build/host-context-external-provider-rollback-self-test",
    ], "rollback helper compilation")
    exactly_one(lambda row: "host_image_validation.c" in row and "-c" in row, [
        "cc", *CPP_FLAGS, *C_FLAGS,
        "-DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1", "-c", "host_image_validation.c",
        "-o", "build/host_image_validation_test.o",
    ], "provider parser test-object compilation")
    exactly_one(lambda row: "../urprotect-launcher/sha256.c" in row, [
        "cc", *CPP_FLAGS, *C_FLAGS, "-c", "../urprotect-launcher/sha256.c", "-o", "build/sha256.o",
    ], "SHA-256 object compilation")
    exactly_one(lambda row: row and row[-1] == "host_context_external_provider_fixture.S", [
        "as", "-o", "build/host-context-external-provider-fixture.S.o", "host_context_external_provider_fixture.S",
    ], "provider fixture assembly")
    exactly_one(lambda row: "-soname" in row and "liburprotect-jump-table-provider.so.1" in row and row[-1] == "build/liburprotect-jump-table-provider.so.1", [
        "ld", "-shared", "-z", "separate-code", "--build-id=sha1", "--hash-style=gnu", "-soname",
        "liburprotect-jump-table-provider.so.1", "build/host-context-external-provider-fixture.S.o", "-o",
        "build/liburprotect-jump-table-provider.so.1",
    ], "provider linking")
    exactly_one(lambda row: row and row[-1] == "host_context_external_provider_consumer_fixture.S", [
        "as", "-o", "build/host-context-external-provider-consumer-fixture.S.o", "host_context_external_provider_consumer_fixture.S",
    ], "consumer fixture assembly")
    exactly_one(lambda row: "-l:liburprotect-jump-table-provider.so.1" in row, [
        "ld", "-shared", "--build-id=none", "--hash-style=gnu", "--no-undefined", "-z", "now",
        "build/host-context-external-provider-consumer-fixture.S.o", "-Lbuild",
        "-l:liburprotect-jump-table-provider.so.1", "-o", "build/host-context-external-provider-consumer.so",
    ], "consumer fixture linking")
    return {relative: read_file(root, relative) for relative in BUILD_INPUT_FILES | BUILD_OUTPUT_FILES}


def _validate_record(root: Path, build: dict[str, Any], external_parser: Any) -> dict[str, Any]:
    native_machine = platform.machine().lower()
    require(native_machine in {"aarch64", "arm64"}, "checker host is not native AArch64")
    record = read_json(root, "rollback-record.json")
    require(build.get("rollbackStdoutSha256") == sha(read_file(root, "rollback-record.json")), "rollback stdout digest does not bind retained JSON bytes")
    require(build.get("rollbackStderrSha256") == sha(read_file(root, "rollback-stderr.log", allow_empty=True)), "rollback stderr digest mismatch")
    rollback_status = exact_int(build.get("rollbackExitStatus"), "rollback exit status")
    require(rollback_status == 0, "provider-loaded rollback helper did not exit successfully")
    require(read_file(root, "rollback-exit-status").decode("ascii").strip() == "0", "retained rollback exit status is not zero")
    require(not read_file(root, "rollback-stderr.log", allow_empty=True), "rollback helper emitted unexpected stderr")
    exact_keys(record, {
        "schemaVersion", "oracle", "architecture", "runtime", "glibcVersion", "provider", "input", "baseline",
        "failpoint", "firstLoad", "cleanup", "retry", "release", "counters", "events", "eventOverflow", "oraclePassed",
    }, "rollback record")
    require(exact_int(record.get("schemaVersion"), "rollback schemaVersion") == 1 and record.get("oracle") == "provider-loaded-consumer-binding-failure-rollback", "rollback record schema/oracle is unsupported")
    require(record.get("architecture") == "aarch64" and record.get("runtime") == "glibc", "rollback record is not native AArch64/glibc")
    libc_line = os.confstr("CS_GNU_LIBC_VERSION")
    require(isinstance(libc_line, str) and libc_line.startswith("glibc "), "checker is not running with a native glibc identity")
    require(record.get("glibcVersion") == libc_line.split(" ", 1)[1], "rollback glibc version does not match the native checker process")
    require(record.get("oraclePassed") is True, "native rollback oracle did not attest success")
    require(record.get("eventOverflow") is False, "native rollback event trace overflowed")
    require(record.get("events") == EVENTS, "native lifecycle event ordering is incomplete or incorrect")

    provider_data = read_file(root, "build-outputs/provider-image.so")
    consumer_data = read_file(root, "build-outputs/consumer-image.so")
    provider = external_parser.parse_provider(provider_data)
    consumer = external_parser.parse_consumer(consumer_data, "rollback consumer", require_source_dispatch=True)
    provider_claim = exact_keys(record.get("provider"), {"soname", "buildId", "sha256", "size", "tableBytesHex"}, "provider identity")
    consumer_claim = exact_keys(record.get("input"), {"consumerSha256", "consumerSize"}, "consumer identity")
    require(provider_claim.get("soname") == provider["soname"] == external_parser.PROVIDER_SONAME, "provider SONAME differs from parsed fixture bytes")
    require(provider_claim.get("buildId") == provider["buildId"], "provider GNU build ID differs from parsed fixture bytes")
    require(provider_claim.get("sha256") == provider["sha256"] == build.get("providerImageSha256"), "provider digest differs from parsed provider bytes")
    require(exact_int(provider_claim.get("size"), "provider size") == provider["size"], "provider byte length differs from parsed provider bytes")
    require(provider_claim.get("tableBytesHex") == provider["table"]["bytesHex"], "provider table bytes differ from parsed provider ELF")
    require(consumer_claim.get("consumerSha256") == consumer["sha256"] == build.get("consumerImageSha256"), "consumer digest differs from parsed consumer bytes")
    require(exact_int(consumer_claim.get("consumerSize"), "consumer size") == consumer["size"], "consumer byte length differs from parsed consumer bytes")

    baseline = exact_keys(record.get("baseline"), {"nextImageHandle", "openDescriptorCount", "registeredImageCount", "activeProviderPresent"}, "baseline state")
    failpoint = exact_keys(record.get("failpoint"), {"oneShot", "placement", "providerAcquisitions", "consumerDlmopenSuccesses", "bindingVerifications", "reached"}, "failpoint")
    first = exact_keys(record.get("firstLoad"), {
        "statusCode", "expectedFailureStatusCode", "publishedHandle", "memfdAttemptsDelta", "loaderAttemptsDelta",
        "providerTableAddress", "providerLoadBias", "consumerGotSlotAddress", "consumerGotValue", "consumerLoadBias",
        "providerMappingPresentAfterCleanup", "consumerMappingPresentAfterCleanup", "postCleanupState",
    }, "first load")
    cleanup = exact_keys(record.get("cleanup"), {
        "consumerDlcloseResult", "consumerFdCloseResult", "providerReleaseStatus", "providerDlcloseResult",
        "providerFdCloseResult", "providerReleaseCallsAfterFailure", "consumerDlcloseCalls", "consumerFdCloseCalls",
    }, "rollback cleanup")
    retry = exact_keys(record.get("retry"), {
        "loadStatusCode", "handlePublished", "memfdAttemptsDelta", "loaderAttemptsDelta", "providerTableAddress",
        "providerLoadBias", "providerMappingPermissions", "consumerGotSlotAddress", "consumerGotPermissions",
        "consumerGotValue", "consumerLoadBias", "providerTableBytesHex", "entryLookupStatus", "observerLookupStatus",
        "entryStatus", "observerStatus", "stdoutHex", "stdoutSha256", "stderrHex", "stderrSha256", "activeState",
    }, "successful retry")
    release = exact_keys(record.get("release"), {"statusCode", "providerMappingAbsent", "consumerMappingAbsent", "finalState"}, "retry release")
    counters = exact_keys(record.get("counters"), {"memfdAttemptsBefore", "memfdAttemptsAfter", "loaderAttemptsBefore", "loaderAttemptsAfter"}, "attempt counters")

    require(failpoint.get("oneShot") is True and failpoint.get("placement") == "after-provider-consumer-GOT-binding-verification-before-image-handle-publication", "failure injection is not the exact one-shot post-binding gate")
    for field in ("providerAcquisitions", "consumerDlmopenSuccesses", "bindingVerifications", "reached"):
        require(exact_int(failpoint.get(field), f"failpoint {field}") == 1, f"first load did not reach verified provider binding before failure ({field})")
    require(exact_int(first.get("statusCode"), "first load status") == -2, "post-binding first consumer load was not rejected with URP_STATUS_UNSUPPORTED")
    require(exact_int(first.get("expectedFailureStatusCode"), "expected first failure status") == -2, "recorded expected failure status is inconsistent")
    require(exact_int(first.get("publishedHandle"), "first load image handle") == 0, "failed load published an image handle")
    require(exact_int(first.get("memfdAttemptsDelta"), "first memfd attempt count") == 2, "first load did not create exactly provider and consumer memfds")
    require(exact_int(first.get("loaderAttemptsDelta"), "first loader attempt count") == 2, "first load did not execute both provider and consumer loaders")

    first_provider_va = exact_int(first.get("providerTableAddress"), "first provider table address")
    first_provider_bias = exact_int(first.get("providerLoadBias"), "first provider load bias")
    first_consumer_slot = exact_int(first.get("consumerGotSlotAddress"), "first consumer GOT address")
    first_consumer_value = exact_int(first.get("consumerGotValue"), "first consumer GOT value")
    first_consumer_bias = exact_int(first.get("consumerLoadBias"), "first consumer load bias")
    require(first_provider_va == first_provider_bias + provider["table"]["virtualAddress"], "failed-load provider mapping base/table address relation is false")
    require(first_consumer_slot == first_consumer_bias + consumer["got"]["virtualAddress"], "failed-load consumer mapping base/GOT address relation is false")
    require(first_consumer_value == first_provider_va, "failed-load consumer GOT did not bind to the loaded provider table")
    require(first_provider_va > 0 and first_consumer_slot > 0, "failure evidence has a null runtime mapping address")
    require(first.get("providerMappingPresentAfterCleanup") is False and first.get("consumerMappingPresentAfterCleanup") is False, "provider or consumer mapping remains after injected rollback")
    post = exact_keys(first.get("postCleanupState"), {
        "activeProviderDescriptorOpen", "activeProviderPresent", "activeProviderReferences",
        "failureConsumerDescriptorOpen", "failureProviderDescriptorOpen", "nextImageHandle",
        "openDescriptorCount", "registeredImageCount", "registeredImageDescriptorCount",
    }, "first-load post-cleanup state")
    require(post.get("activeProviderPresent") is False and exact_int(post.get("activeProviderReferences"), "post-failure provider references") == 0, "failed load left an active provider reference")
    require(post.get("activeProviderDescriptorOpen") is False and post.get("failureProviderDescriptorOpen") is False and post.get("failureConsumerDescriptorOpen") is False, "failed load left a provider or consumer descriptor open")
    require(exact_int(post.get("registeredImageCount"), "post-failure image registry count") == 0 and exact_int(post.get("registeredImageDescriptorCount"), "post-failure image descriptor count") == 0, "failed load registered an image or image descriptor")
    require(exact_int(post.get("openDescriptorCount"), "post-failure descriptor count") == exact_int(baseline.get("openDescriptorCount"), "baseline descriptor count"), "failed load changed the process open-descriptor count")
    require(exact_int(post.get("nextImageHandle"), "post-failure next image handle") == exact_int(baseline.get("nextImageHandle"), "baseline image handle"), "failed load consumed/published an image handle")
    require(exact_int(baseline.get("registeredImageCount"), "baseline image registry count") == 0 and baseline.get("activeProviderPresent") is False, "oracle baseline was not empty")

    for field in ("consumerDlcloseResult", "consumerFdCloseResult", "providerReleaseStatus", "providerDlcloseResult", "providerFdCloseResult"):
        require(exact_int(cleanup.get(field), f"cleanup {field}") == 0, f"rollback cleanup operation failed: {field}")
    require(exact_int(cleanup.get("providerReleaseCallsAfterFailure"), "provider release calls") == 1, "rollback did not release exactly one provider reference")
    require(exact_int(cleanup.get("consumerDlcloseCalls"), "consumer dlclose calls") == 1 and exact_int(cleanup.get("consumerFdCloseCalls"), "consumer fd close calls") == 1, "rollback did not close consumer loader and descriptor exactly once")

    retry_bias = exact_int(retry.get("consumerLoadBias"), "retry consumer load bias")
    retry_slot = exact_int(retry.get("consumerGotSlotAddress"), "retry consumer GOT address")
    retry_provider = exact_int(retry.get("providerTableAddress"), "retry provider table address")
    retry_provider_bias = exact_int(retry.get("providerLoadBias"), "retry provider load bias")
    retry_got_value = exact_int(retry.get("consumerGotValue"), "retry consumer GOT value")
    require(exact_int(retry.get("loadStatusCode"), "retry load status") == 0 and retry.get("handlePublished") is True, "retry did not successfully publish an image handle")
    require(exact_int(retry.get("memfdAttemptsDelta"), "retry memfd count") == 2 and exact_int(retry.get("loaderAttemptsDelta"), "retry loader count") == 2, "successful retry did not execute a fresh provider/consumer load")
    require(retry_provider == retry_provider_bias + provider["table"]["virtualAddress"], "retry provider table mapping address is inconsistent")
    require(retry_slot == retry_bias + consumer["got"]["virtualAddress"], "retry consumer GOT mapping address is inconsistent")
    require(retry_got_value == retry_provider, "successful retry GOT does not resolve to the newly loaded provider table")
    require(retry.get("providerTableBytesHex") == provider["table"]["bytesHex"], "successful retry mapped table bytes differ from provider ELF bytes")
    require(retry.get("providerMappingPermissions") == "r--p" and retry.get("consumerGotPermissions") == "r--p", "loaded provider/table or consumer GOT mapping is not observed read-only")
    require(exact_int(retry.get("entryLookupStatus"), "entry lookup status") == 0 and exact_int(retry.get("observerLookupStatus"), "observer lookup status") == 0, "successful retry could not resolve both fixture entries")
    require(exact_int(retry.get("entryStatus"), "retry entry status") == 17 and exact_int(retry.get("observerStatus"), "retry observer status") == 17, "successful retry did not dispatch selected and observer entries through the provider")
    empty_sha = hashlib.sha256(b"").hexdigest()
    require(retry.get("stdoutHex") == "" and retry.get("stderrHex") == "" and retry.get("stdoutSha256") == empty_sha and retry.get("stderrSha256") == empty_sha, "successful retry emitted unexpected fixture streams")
    active = exact_keys(retry.get("activeState"), {
        "activeProviderDescriptorOpen", "activeProviderPresent", "activeProviderReferences",
        "failureConsumerDescriptorOpen", "failureProviderDescriptorOpen", "nextImageHandle",
        "openDescriptorCount", "registeredImageCount", "registeredImageDescriptorCount",
    }, "retry active lifecycle state")
    require(active.get("activeProviderPresent") is True and exact_int(active.get("activeProviderReferences"), "retry provider refs") == 1 and active.get("activeProviderDescriptorOpen") is True, "successful retry lacks one live provider reference/descriptor")
    require(exact_int(active.get("registeredImageCount"), "retry image count") == 1 and exact_int(active.get("registeredImageDescriptorCount"), "retry image descriptors") == 1, "successful retry did not retain exactly one registered image")
    require(exact_int(active.get("openDescriptorCount"), "retry open descriptors") == exact_int(baseline.get("openDescriptorCount"), "baseline descriptors") + 2, "successful retry descriptor delta is not exactly provider plus consumer")

    require(exact_int(release.get("statusCode"), "retry release status") == 0, "successful retry image release failed")
    require(release.get("providerMappingAbsent") is True and release.get("consumerMappingAbsent") is True, "retry release left a provider/consumer mapping")
    final = exact_keys(release.get("finalState"), {
        "activeProviderDescriptorOpen", "activeProviderPresent", "activeProviderReferences",
        "failureConsumerDescriptorOpen", "failureProviderDescriptorOpen", "nextImageHandle",
        "openDescriptorCount", "registeredImageCount", "registeredImageDescriptorCount",
    }, "final release state")
    require(final.get("activeProviderPresent") is False and exact_int(final.get("activeProviderReferences"), "final provider refs") == 0 and final.get("activeProviderDescriptorOpen") is False, "retry release leaked provider handle, descriptor, or reference")
    require(exact_int(final.get("registeredImageCount"), "final image registry count") == 0 and exact_int(final.get("registeredImageDescriptorCount"), "final image descriptor count") == 0, "retry release left a registered image or descriptor")
    require(exact_int(final.get("openDescriptorCount"), "final descriptor count") == exact_int(baseline.get("openDescriptorCount"), "baseline descriptor count"), "retry release did not restore baseline process descriptor count")
    require(exact_int(final.get("nextImageHandle"), "final handle counter") == exact_int(baseline.get("nextImageHandle"), "baseline handle counter") + 1, "retry handle publication counter did not advance exactly once")
    require(exact_int(counters.get("memfdAttemptsAfter"), "final memfd attempts") - exact_int(counters.get("memfdAttemptsBefore"), "initial memfd attempts") == 4, "two load attempts did not create exactly four sealed memfds")
    require(exact_int(counters.get("loaderAttemptsAfter"), "final loader attempts") - exact_int(counters.get("loaderAttemptsBefore"), "initial loader attempts") == 4, "two load attempts did not make exactly four loader calls")

    return {
        "schemaVersion": 1,
        "status": "accepted",
        "oracle": record["oracle"],
        "providerSha256": provider["sha256"],
        "consumerSha256": consumer["sha256"],
        "nativeRuntime": f"AArch64 glibc {record['glibcVersion']}",
        "eventCount": len(EVENTS),
        "failureMappingsAbsent": True,
        "failureDescriptorsAndReferencesCleared": True,
        "successfulReloadAndReleaseObserved": True,
    }


def validate(root: Path, *, seal: bool) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        fail("evidence root must be a real directory")
    _safe_closed_tree(root, ALL_FILES, sealing=seal)
    if not seal:
        _verify_manifest(root)
    build = read_json(root, "native-build.json")
    _verify_build(root, build)
    external_parser = load_module(
        "urp_provider_rollback_retained_external_evidence",
        root / "scripts/check-external-provider-evidence.py",
    )
    report = _validate_record(root, build, external_parser)
    if seal:
        (root / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        _write_manifest(root)
        _safe_closed_tree(root, ALL_FILES, sealing=False)
        _verify_manifest(root)
    else:
        existing = read_json(root, "report.json")
        if existing != report:
            fail("retained report does not equal independently recomputed rollback acceptance")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--seal", action="store_true", help="validate and create report.json plus the closed SHA256SUMS")
    args = parser.parse_args()
    report = validate(args.root, seal=args.seal)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
