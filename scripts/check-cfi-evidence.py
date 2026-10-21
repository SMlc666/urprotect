#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

from tls_runtime_identity import verify_artifact_identity

DIGEST = re.compile(r"^[0-9a-f]{64}$")
HEX_BUILD_ID = re.compile(r"^[0-9a-fA-F]{16,}$")
CFI_CPP_TEST_TOKEN = 0x4346495F45584331
CPP_ORACLE_KIND = "typed-cpp-throw-catch-through-mapped-cfi-target-v1"
CPP_OBSERVATION_KEYS = (
    "cppBoundaryStatus",
    "cppRegisterCallAttempted",
    "cppRegisterCallReturned",
    "cppTargetNormalReturned",
    "cppCaughtSpecificType",
    "cppCaughtToken",
    "cppRaiiCleanupCount",
    "cppHostCallbackEntered",
    "cppHostCallbackReturned",
    "cppThrowSiteTargetFrameObserved",
    "cppThrowSiteFrameCount",
    "cppThrowSiteReturnAddressInTarget",
    "cppThrowSiteReturnPc",
    "cppThrowSiteTargetFramePc",
    "imageLoadBias",
    "loadedEntryAddress",
    "loadedEntryVaddr",
    "mappedTargetVaddr",
    "mappedTargetSize",
    "callbackReturnPc",
    "targetFramePc",
    "targetRangeStart",
    "targetRangeEnd",
    "targetSymbolSize",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_file(root: Path, relative: str) -> Path:
    candidate = root / relative
    if candidate.is_symlink() or not candidate.is_file():
        fail(f"missing or symlinked CFI evidence file: {relative}")
    path = candidate.resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        fail("path escapes CFI root")
    return path


def read_json(root: Path, relative: str) -> dict[str, Any]:
    value = json.loads(evidence_file(root, relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"CFI JSON record is not an object: {relative}")
    return value


def integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_harness_output(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        fail(f"CFI harness output must contain exactly one observation line: {path.name}")
    result: dict[str, Any] = {}
    for key, value in re.findall(r"([A-Za-z][A-Za-z0-9]*)=([^ ]+)", lines[0]):
        if key in result:
            fail(f"duplicate CFI harness observation: {key}")
        if re.fullmatch(r"0x[0-9a-fA-F]+", value):
            result[key] = int(value, 16)
        elif re.fullmatch(r"-?[0-9]+", value):
            result[key] = int(value)
        else:
            result[key] = value
    if not result:
        fail(f"empty CFI harness observation: {path.name}")
    return result


def validate_runtime_identity(root: Path) -> str:
    relative = "cpp-runtime-identity.json"
    identity_path = evidence_file(root, relative)
    identity = read_json(root, relative)
    if identity.get("schemaVersion") != 1 or identity.get("hostArchitecture") not in ("aarch64", "arm64"):
        fail("C++ oracle runtime identity is invalid")
    for compiler_key in ("cCompiler", "cxxCompiler"):
        compiler = identity.get(compiler_key)
        if not isinstance(compiler, dict) or not all(
            isinstance(compiler.get(field), str) and compiler[field]
            for field in ("path", "version", "target", "sha256", "buildId")
        ):
            fail(f"C++ oracle compiler identity missing: {compiler_key}")
        if not compiler["target"].startswith("aarch64"):
            fail(f"C++ oracle compiler target is not AArch64: {compiler_key}")
        if not DIGEST.fullmatch(compiler["sha256"]) or not HEX_BUILD_ID.fullmatch(compiler["buildId"]):
            fail(f"C++ oracle compiler binary identity is malformed: {compiler_key}")
    if not identity["cxxCompiler"]["version"].strip():
        fail("C++ compiler version is empty")
    retained_glibc = read_json(root, "glibc-runtime-identity.json")
    verify_artifact_identity(retained_glibc)
    if identity.get("glibcRuntimeIdentity") != retained_glibc:
        fail("C++ runtime record differs from retained measured glibc identity")
    for runtime_key, soname in (("libstdcxx", "libstdc++.so.6"), ("libgccUnwinder", "libgcc_s.so.1")):
        runtime = identity.get(runtime_key)
        if not isinstance(runtime, dict):
            fail(f"C++ runtime identity missing: {runtime_key}")
        if runtime.get("soname") != soname:
            fail(f"unexpected C++ runtime soname: {runtime_key}")
        if not isinstance(runtime.get("resolvedPath"), str) or not runtime["resolvedPath"].startswith("/"):
            fail(f"C++ runtime path missing: {runtime_key}")
        if not isinstance(runtime.get("sha256"), str) or not DIGEST.fullmatch(runtime["sha256"]):
            fail(f"C++ runtime digest invalid: {runtime_key}")
        if not isinstance(runtime.get("buildId"), str) or not HEX_BUILD_ID.fullmatch(runtime["buildId"]):
            fail(f"C++ runtime build ID invalid: {runtime_key}")
    return digest(identity_path)


def readelf_fde_ranges(output: str) -> list[tuple[int, int]]:
    return [
        (int(start, 16), int(end, 16))
        for start, end in re.findall(r"\bFDE\b.*?\bpc=(?:0x)?([0-9a-fA-F]+)\.\.(?:0x)?([0-9a-fA-F]+)", output)
    ]


def parse_pt_load_segments(root: Path, relative: str, label: str) -> tuple[bytes, list[dict[str, int]]]:
    data = evidence_file(root, relative).read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        fail(f"CFI {label} is not a bounded little-endian ELF64 image")
    elf_type, machine, version = struct.unpack_from("<HHI", data, 16)
    if elf_type not in (2, 3) or machine != 183 or version != 1:
        fail(f"CFI {label} ELF class/type/machine is unsupported")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    ehsize, phentsize, phnum = struct.unpack_from("<HHH", data, 52)
    if ehsize != 64 or phentsize < 56 or phnum == 0 or phnum > 4096:
        fail(f"CFI {label} ELF program-header table is malformed or excessive")
    table_size = phentsize * phnum
    if phoff > len(data) or table_size > len(data) - phoff:
        fail(f"CFI {label} ELF program-header table is outside the file")

    segments: list[dict[str, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, flags, file_offset, virtual_address, _, file_size, memory_size, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_type != 1:
            continue
        if file_size > memory_size or file_offset > len(data) or file_size > len(data) - file_offset:
            fail(f"CFI {label} PT_LOAD file range is malformed")
        if virtual_address > 0xFFFFFFFFFFFFFFFF - memory_size:
            fail(f"CFI {label} PT_LOAD virtual range overflows")
        segments.append({
            "flags": flags,
            "fileOffset": file_offset,
            "virtualAddress": virtual_address,
            "fileSize": file_size,
            "memorySize": memory_size,
        })
    if not segments:
        fail(f"CFI {label} ELF has no PT_LOAD segments")

    for index, left in enumerate(segments):
        left_start = left["virtualAddress"]
        left_end = left_start + left["memorySize"]
        left_file_start = left["fileOffset"]
        left_file_end = left_file_start + left["fileSize"]
        for right in segments[index + 1:]:
            right_start = right["virtualAddress"]
            right_end = right_start + right["memorySize"]
            right_file_start = right["fileOffset"]
            right_file_end = right_file_start + right["fileSize"]
            if left["memorySize"] and right["memorySize"] and left_start < right_end and right_start < left_end:
                fail(f"CFI {label} ELF has overlapping PT_LOAD memory ranges")
            if left["fileSize"] and right["fileSize"] and left_file_start < right_file_end and right_file_start < left_file_end:
                fail(f"CFI {label} ELF has overlapping PT_LOAD file ranges")
    return data, segments


def validate_fde_pt_load_mapping(root: Path, relative: str, label: str, start: int, size: int) -> None:
    if size <= 0:
        fail(f"CFI {label} FDE extent is empty")
    end = checked_address_add(start, size, f"{label} FDE end")
    data, segments = parse_pt_load_segments(root, relative, label)
    owners = [
        segment for segment in segments
        if segment["flags"] & 1
        and segment["virtualAddress"] <= start
        and end <= segment["virtualAddress"] + segment["fileSize"]
    ]
    if len(owners) != 1:
        fail(f"CFI {label} FDE is not uniquely mapped to a file-backed executable PT_LOAD")
    owner = owners[0]
    file_start = owner["fileOffset"] + (start - owner["virtualAddress"])
    if file_start > len(data) or size > len(data) - file_start:
        fail(f"CFI {label} FDE file-backed executable PT_LOAD mapping exceeds the image")


def integer_or_hex(value: Any) -> int:
    if isinstance(value, bool):
        fail("CFI address map contains a Boolean integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    fail("CFI address map contains a malformed integer")


def validate_target_map(root: Path, record: dict[str, Any], baseline: dict[str, Any], transformed: dict[str, Any]) -> None:
    mapping = record.get("targetAddressMap")
    if not isinstance(mapping, dict):
        fail("CFI transformed target address-map binding is missing")
    source_vaddr = mapping.get("sourceVirtualAddress")
    output_vaddr = mapping.get("outputVirtualAddress")
    mapped_size = mapping.get("size")
    if not all(integer(value) for value in (source_vaddr, output_vaddr, mapped_size)) or mapped_size <= 0:
        fail("CFI transformed target address-map binding is malformed")
    output_map_end = checked_address_add(output_vaddr, mapped_size, "output mapped target end")

    rehydration = read_json(root / "positive" / record["unitId"], "rehydration.json")
    entries = rehydration.get("layoutEvidence", {}).get("addressMap")
    if not isinstance(entries, list):
        fail("CFI rehydration address map is missing")
    matches = []
    for entry in entries:
        try:
            if integer_or_hex(entry["sourceRange"]["virtualAddress"]["value"]) == source_vaddr:
                matches.append(entry)
        except (KeyError, TypeError):
            continue
    if len(matches) != 1:
        fail("CFI source target is not uniquely bound in the rehydration address map")
    output = matches[0].get("outputRange", {})
    if integer_or_hex(output.get("virtualAddress", {}).get("value")) != output_vaddr or integer_or_hex(output.get("size")) != mapped_size:
        fail("CFI transformed invocation range differs from the rehydration address map")
    if baseline.get("targetInvocationMode") != "direct-symbol":
        fail("CFI baseline target must use its source symbol")
    if transformed.get("targetInvocationMode") != "address-map":
        fail("CFI transformed target was not invoked through the rehydration address map")
    if not integer(baseline.get("targetSymbolSize")):
        fail("CFI source target symbol extent is malformed")
    source_size = baseline["targetSymbolSize"]
    source_mapped_size = integer_or_hex(matches[0].get("sourceRange", {}).get("size"))
    if source_size <= 0 or source_size != source_mapped_size:
        fail("CFI source target extent differs from its rehydration source range")
    source_target_end = checked_address_add(source_vaddr, source_size, "source target end")

    relocated_fde = record.get("relocatedFde")
    if not isinstance(relocated_fde, dict):
        fail("CFI relocated transformed target FDE record is missing")
    fde_vaddr = relocated_fde.get("virtualAddress")
    fde_size = relocated_fde.get("size")
    if not integer(fde_vaddr) or not integer(fde_size) or fde_size <= 0:
        fail("CFI relocated transformed target FDE record is malformed")
    fde_end = checked_address_add(fde_vaddr, fde_size, "relocated FDE end")
    if fde_vaddr < output_vaddr or fde_end > output_map_end:
        fail("relocated transformed target FDE is outside the rehydration output address map")
    if transformed.get("targetSymbolSize") != fde_size:
        fail("CFI transformed target size differs from the relocated FDE extent")

    range_text = evidence_file(root, f"positive/{record['unitId']}/transformed-fde-range.txt").read_text(encoding="utf-8", errors="strict").strip()
    range_match = re.fullmatch(r"mappedFdeVaddr=(0x[0-9a-fA-F]+|[0-9]+) mappedFdeSize=(0x[0-9a-fA-F]+|[0-9]+)", range_text)
    if range_match is None or (int(range_match.group(1), 0), int(range_match.group(2), 0)) != (fde_vaddr, fde_size):
        fail("CFI relocated FDE record differs from the retained emitted FDE range")

    source_relative = f"positive/{record['unitId']}/source-image.bin"
    native_relative = f"positive/{record['unitId']}/native-image.bin"
    validate_fde_pt_load_mapping(root, source_relative, "source", source_vaddr, source_size)
    validate_fde_pt_load_mapping(root, native_relative, "relocated", fde_vaddr, fde_size)
    source_readelf = evidence_file(root, f"positive/{record['unitId']}/source-unwind-readelf.txt").read_text(encoding="utf-8", errors="replace")
    native_readelf = evidence_file(root, f"positive/{record['unitId']}/native-unwind-readelf.txt").read_text(encoding="utf-8", errors="replace")
    source_fdes = readelf_fde_ranges(source_readelf)
    native_fdes = readelf_fde_ranges(native_readelf)
    if not any(start <= source_vaddr and end >= source_target_end for start, end in source_fdes):
        fail("CFI source target is not covered by a complete readelf FDE")
    if native_fdes.count((fde_vaddr, fde_end)) != 1:
        fail("relocated transformed target FDE is not uniquely present in native readelf evidence")


def checked_address(value: Any, label: str) -> int:
    if not integer(value) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        fail(f"CFI runtime address witness is malformed: {label}")
    return value


def checked_address_add(left: int, right: int, label: str) -> int:
    if left > 0xFFFFFFFFFFFFFFFF - right:
        fail(f"CFI runtime address witness overflows: {label}")
    return left + right


def validate_runtime_address_observations(
    record: dict[str, Any], baseline: dict[str, Any], transformed: dict[str, Any]
) -> None:
    mapping = record.get("targetAddressMap")
    if not isinstance(mapping, dict):
        fail("CFI runtime target map is missing")
    source_vaddr = checked_address(mapping.get("sourceVirtualAddress"), "sourceVirtualAddress")
    relocated_fde = record.get("relocatedFde")
    if not isinstance(relocated_fde, dict):
        fail("CFI runtime relocated FDE binding is missing")
    output_fde_vaddr = checked_address(relocated_fde.get("virtualAddress"), "relocated FDE virtualAddress")
    output_fde_size = checked_address(relocated_fde.get("size"), "relocated FDE size")
    if output_fde_size == 0:
        fail("CFI runtime relocated FDE extent is empty")

    for label, observed, expected_vaddr, expected_size in (
        ("baseline", baseline, source_vaddr, baseline.get("targetSymbolSize")),
        ("transformed", transformed, output_fde_vaddr, output_fde_size),
    ):
        expected_size = checked_address(expected_size, f"{label} target extent")
        if expected_size == 0:
            fail(f"CFI runtime target extent is empty: {label}")
        bias = checked_address(observed.get("imageLoadBias"), f"{label} image load bias")
        entry_vaddr = checked_address(observed.get("loadedEntryVaddr"), f"{label} entry VA")
        entry_address = checked_address(observed.get("loadedEntryAddress"), f"{label} entry PC")
        mapped_vaddr = checked_address(observed.get("mappedTargetVaddr"), f"{label} mapped target VA")
        mapped_size = checked_address(observed.get("mappedTargetSize"), f"{label} mapped target extent")
        start = checked_address(observed.get("targetRangeStart"), f"{label} runtime target start")
        end = checked_address(observed.get("targetRangeEnd"), f"{label} runtime target end")
        if checked_address_add(bias, entry_vaddr, f"{label} entry address") != entry_address:
            fail(f"CFI runtime entry address is not related to the measured load bias: {label}")
        if mapped_vaddr != expected_vaddr or mapped_size != expected_size:
            fail(f"CFI runtime target VA/extent differs from the retained address map: {label}")
        expected_start = checked_address_add(bias, mapped_vaddr, f"{label} target start")
        expected_end = checked_address_add(expected_start, mapped_size, f"{label} target end")
        if start != expected_start or end != expected_end or end <= start:
            fail(f"CFI runtime target range is not related to the measured load bias and map: {label}")

        callback_pc = checked_address(observed.get("callbackReturnPc"), f"{label} callback return PC")
        target_frame_pc = checked_address(observed.get("targetFramePc"), f"{label} target frame PC")
        cpp_return_pc = checked_address(observed.get("cppThrowSiteReturnPc"), f"{label} C++ throw-site return PC")
        cpp_frame_pc = checked_address(observed.get("cppThrowSiteTargetFramePc"), f"{label} C++ throw-site frame PC")
        in_range = lambda pc: start <= pc < end
        expected_claims = {
            "returnAddressInTarget": int(in_range(callback_pc)),
            "targetFrameObserved": int(in_range(target_frame_pc)),
            "transformedFrameObserved": int(label == "transformed" and in_range(target_frame_pc)),
            "cppThrowSiteReturnAddressInTarget": int(in_range(cpp_return_pc)),
            "cppThrowSiteTargetFrameObserved": int(in_range(cpp_return_pc) and in_range(cpp_frame_pc)),
        }
        for key, expected in expected_claims.items():
            if observed.get(key) != expected:
                fail(f"CFI runtime boolean is inconsistent with numeric address witnesses: {label}.{key}")
        if not all(in_range(pc) for pc in (callback_pc, target_frame_pc, cpp_return_pc, cpp_frame_pc)):
            fail(f"CFI callback/frame PC lies outside the mapped target range: {label}")


def validate_cpp_observations(record: dict[str, Any], baseline: dict[str, Any], transformed: dict[str, Any], runtime_digest: str) -> None:
    cpp = record.get("cppException")
    if not isinstance(cpp, dict) or cpp.get("oracleKind") != CPP_ORACLE_KIND:
        fail("genuine C++ exception oracle is missing or misidentified")
    if cpp.get("runtimeIdentitySha256") != runtime_digest or cpp.get("requiredToken") != CFI_CPP_TEST_TOKEN:
        fail("C++ exception runtime/token binding mismatch")
    if "exceptionBoundaryEqual" in record:
        fail("legacy exceptionBoundary field is ambiguous; C longjmp must remain separate")

    for label, measured, nested in (
        ("baseline", baseline, cpp.get("baseline")),
        ("transformed", transformed, cpp.get("transformed")),
    ):
        if not isinstance(nested, dict):
            fail(f"C++ exception observations missing for {label}")
        projection = {key: measured.get(key) for key in CPP_OBSERVATION_KEYS}
        if nested != projection:
            fail(f"C++ exception record differs from measured {label} harness output")
        requirements = {
            "cppBoundaryStatus": 1,
            "cppRegisterCallAttempted": 1,
            "cppRegisterCallReturned": 0,
            "cppTargetNormalReturned": 0,
            "cppCaughtSpecificType": 1,
            "cppCaughtToken": CFI_CPP_TEST_TOKEN,
            "cppRaiiCleanupCount": 1,
            "cppHostCallbackEntered": 1,
            "cppHostCallbackReturned": 0,
            "cppThrowSiteTargetFrameObserved": 1,
            "cppThrowSiteReturnAddressInTarget": 1,
            "releaseStatus": 0,
        }
        for key, expected in requirements.items():
            if measured.get(key) != expected:
                fail(f"genuine C++ exception observation incomplete for {label}: {key}")
        if not integer(measured.get("cppThrowSiteFrameCount")) or measured["cppThrowSiteFrameCount"] < 1:
            fail(f"C++ throw-site frame trace missing for {label}")


def validate_runtime_outputs(root: Path, unit: str, record: dict[str, Any]) -> None:
    fixture_dynamic = evidence_file(root, "cfi-fixture-dynamic-readelf.txt").read_text(encoding="utf-8", errors="replace")
    if re.search(r"libstdc\+\+|libgcc_s", fixture_dynamic):
        fail("C++ runtime dependencies escaped into the native C fixture")
    relative = f"positive/{unit}"
    for name in ("source-unwind-readelf.txt", "native-unwind-readelf.txt"):
        output = evidence_file(root, f"{relative}/{name}").read_text(encoding="utf-8", errors="replace")
        if ".eh_frame" not in output or "FDE" not in output:
            fail(f"CFI readelf structural witness is incomplete: {name}")
    harness = evidence_file(root, "cpp-harness-unwind-readelf.txt").read_text(encoding="utf-8", errors="replace")
    if ".eh_frame" not in harness or "FDE" not in harness:
        fail("C++ harness readelf frame witness is missing")
    symbols: dict[str, tuple[int, int]] = {}
    for address, size, name in re.findall(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+\d+\s+(urp_cfi_invoke_with_registers|urp_cfi_run_cpp_exception_boundary)$",
        harness,
        flags=re.MULTILINE,
    ):
        symbols[name] = (int(address, 16), int(size))
    fdes = readelf_fde_ranges(harness)
    for symbol in ("urp_cfi_invoke_with_registers", "urp_cfi_run_cpp_exception_boundary"):
        if symbol not in symbols:
            fail(f"C++ oracle harness witness lacks frame function: {symbol}")
        start, size = symbols[symbol]
        if size <= 0 or not any(fde_start < start + size and fde_end > start for fde_start, fde_end in fdes):
            fail(f"C++ oracle harness function lacks a covering FDE: {symbol}")

    call_return_values = {
        int(address, 16)
        for address in re.findall(
            r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+urp_cfi_invoke_with_registers_call_return$",
            harness,
            flags=re.MULTILINE,
        )
    }
    if "urp_cfi_invoke_with_registers" not in symbols or len(call_return_values) != 1:
        fail("C++ harness readelf witness lacks a unique register-call return-PC symbol")
    call_function_start, call_function_size = symbols["urp_cfi_invoke_with_registers"]
    call_return_pc = next(iter(call_return_values))
    call_witness = record.get("registerCallUnwindWitness")
    expected_witness = {
        "functionSymbol": "urp_cfi_invoke_with_registers",
        "callReturnPcSymbol": "urp_cfi_invoke_with_registers_call_return",
        "functionStart": call_function_start,
        "functionSize": call_function_size,
        "callReturnPc": call_return_pc,
        "callReturnOffset": call_return_pc - call_function_start,
    }
    if not isinstance(call_witness, dict) or call_witness != expected_witness:
        fail("register-call unwind witness differs from the retained symbol table")
    if call_function_size <= 0 or not (call_function_start <= call_return_pc < call_function_start + call_function_size):
        fail("register-call return-PC is outside the assembly function")
    if not any(fde_start <= call_return_pc < fde_end for fde_start, fde_end in fdes):
        fail("register-call assembly FDE does not cover the BLR return PC")


def validate_manifest(root: Path) -> None:
    manifest = evidence_file(root, "SHA256SUMS")
    entries: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest_value, separator, relative = line.partition("  ")
        if not separator or not DIGEST.fullmatch(digest_value) or relative in entries:
            fail("CFI checksum manifest is malformed or duplicated")
        if digest(evidence_file(root, relative)) != digest_value:
            fail(f"CFI checksum mismatch: {relative}")
        entries[relative] = digest_value
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            fail("CFI evidence root contains a symlink")
        if path.is_file() and path.name != "SHA256SUMS":
            actual.add(path.relative_to(root).as_posix())
    if actual != set(entries):
        fail("CFI manifest not closed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--tier", required=True, choices=("pr", "nightly", "release"))
    parser.add_argument("--runtime", required=True, choices=("glibc",))
    parser.add_argument("--unit", required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    unit = arguments.unit
    behavior_path = f"positive/{unit}/cfi-behavior.json"
    record = read_json(root, behavior_path)
    if record.get("schemaVersion") != 2 or record.get("unitId") != unit:
        fail("CFI behavior identity/schema mismatch")
    if not re.fullmatch(r"(?:dynsym|symtab):[0-9]+", str(record.get("selectedFunction", ""))):
        fail("CFI selected function identity is malformed")

    for relative, key in (
        (f"positive/{unit}/source-image.bin", "sourceImageSha256"),
        (f"positive/{unit}/protected-image.bin", "protectedImageSha256"),
        (f"positive/{unit}/native-image.bin", "nativeImageSha256"),
    ):
        value = record.get(key)
        if not isinstance(value, str) or not DIGEST.fullmatch(value) or digest(evidence_file(root, relative)) != value:
            fail(f"CFI image hash mismatch: {key}")
    if record.get("sourceFixtureSha256") != record.get("sourceImageSha256"):
        fail("CFI source fixture is not bound to the measured baseline image")

    baseline = record.get("baseline")
    transformed = record.get("transformed")
    if not isinstance(baseline, dict) or not isinstance(transformed, dict):
        fail("CFI baseline or transformed measurements are missing")
    positive_root = root / "positive" / unit
    observed_baseline = parse_harness_output(evidence_file(root, f"positive/{unit}/baseline-unwind.txt"))
    observed_transformed = parse_harness_output(evidence_file(root, f"positive/{unit}/transformed-unwind.txt"))
    if baseline != observed_baseline or transformed != observed_transformed:
        fail("CFI JSON observations differ from retained harness output")
    if record.get("baselineStatus") != 0 or record.get("transformedStatus") != 0:
        fail("CFI baseline or transformed harness returned nonzero")

    if baseline.get("targetInvocationMode") != "direct-symbol" or transformed.get("targetInvocationMode") != "address-map":
        fail("CFI target invocation did not distinguish source symbol from mapped transformed target")
    validate_target_map(root, record, baseline, transformed)
    validate_runtime_address_observations(record, baseline, transformed)
    runtime_digest = validate_runtime_identity(root)
    validate_cpp_observations(record, baseline, transformed, runtime_digest)

    expected_summary = {
        "frameCountEqual": baseline.get("frameCount") == transformed.get("frameCount"),
        "transformedFrameObserved": transformed.get("transformedFrameObserved") == 1,
        "entryStatusEqual": baseline.get("targetStatus") == transformed.get("targetStatus") == 42,
        "releaseStatusEqual": baseline.get("releaseStatus") == transformed.get("releaseStatus") == 0,
        "sourceDirectTargetTransformedAddressMap": baseline.get("targetInvocationMode") == "direct-symbol" and transformed.get("targetInvocationMode") == "address-map",
        "registerFrameStateEqual": all(baseline.get(key) == transformed.get(key) == 1 for key in ("framePointerAligned", "returnAddressInTarget", "registersPreserved")),
        "signalBoundaryEqual": baseline.get("signalBoundary") == transformed.get("signalBoundary") == 1,
        "signalFrameObserved": transformed.get("signalFrameObserved") == 1,
        "longjmpBoundaryEqual": baseline.get("longjmpBoundary") == transformed.get("longjmpBoundary") == 1,
        "cancellationBoundaryEqual": baseline.get("cancellationBoundary") == transformed.get("cancellationBoundary") == 1,
    }
    for key, expected in expected_summary.items():
        if record.get(key) is not expected:
            fail(f"CFI comparison summary is false or inconsistent: {key}")
    if "exceptionBoundaryEqual" in record:
        fail("ambiguous legacy exceptionBoundaryEqual field is forbidden")

    for label, measured in (("baseline", baseline), ("transformed", transformed)):
        required = {
            "targetStatus": 42,
            "signalStatus": 42,
            "diagnosticCalls": 1,
            "framePointerAligned": 1,
            "returnAddressInTarget": 1,
            "registersPreserved": 1,
            "signalBoundary": 1,
            "signalFrameObserved": 1,
            "longjmpBoundary": 1,
            "cancellationBoundary": 1,
            "releaseStatus": 0,
        }
        for key, expected in required.items():
            if measured.get(key) != expected:
                fail(f"CFI baseline/transformed oracle incomplete for {label}: {key}")
        if not integer(measured.get("frameCount")) or measured["frameCount"] < 2:
            fail(f"CFI backtrace frame count invalid for {label}")
        expected_transformed = int(label == "transformed")
        if measured.get("transformedImage") != expected_transformed or measured.get("transformedFrameObserved") != expected_transformed:
            fail(f"CFI transformed-image observation invalid for {label}")

    validate_runtime_outputs(root, unit, record)
    actual_negative = read_json(root, "negative-malformed-eh-frame/producer.stdout")
    observed_stage = read_json(root, "negative-malformed-eh-frame/stage.json")
    negative_source = evidence_file(root, "negative-malformed-eh-frame/source-image.bin")
    diagnostics = observed_stage.get("diagnostics")
    if (
        actual_negative.get("success") is not False
        or actual_negative.get("stage") != observed_stage
        or observed_stage.get("status") != "failed"
        or observed_stage.get("firstFailureStage") != "protected-image-producer"
        or observed_stage.get("publicationComplete") is not False
        or observed_stage.get("unitId") != f"{unit}.negative"
        or observed_stage.get("sourceSha256") != digest(negative_source)
        or not isinstance(diagnostics, list)
        or not any(
            isinstance(item, dict)
            and item.get("severity") == "Error"
            and item.get("code") == "UnwindMetadataMalformed"
            for item in diagnostics
        )
    ):
        fail("CFI malformed-metadata negative lacks an actual UnwindMetadataMalformed producer failure")
    negative = read_json(root, "negative-malformed-eh-frame/negative-result.json")
    if (
        negative.get("status") != "passed"
        or not integer(negative.get("producerExitStatus"))
        or negative["producerExitStatus"] == 0
        or negative.get("nativeImagePublished")
        or negative.get("protectedImagePublished")
        or negative.get("loaderInvoked")
        or negative.get("expectedDiagnosticFamily") != "UnwindMetadataMalformed"
    ):
        fail("CFI malformed-metadata negative evidence invalid")

    validate_manifest(root)
    print("CFI evidence valid: transformed C++ exception unwind, register/frame state, signal/cancellation, and malformed rollback")


if __name__ == "__main__":
    main()
