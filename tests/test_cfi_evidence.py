from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-cfi-evidence.py"
UNIT = "runtime.cfi.transformed-backtrace.glibc.host-context-entry"
TOKEN = 0x4346495F45584331
CPP_KEYS = (
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
HEX_OBSERVATION_KEYS = {
    "cppCaughtToken", "cppThrowSiteReturnPc", "cppThrowSiteTargetFramePc",
    "imageLoadBias", "loadedEntryAddress", "callbackReturnPc", "targetFramePc",
    "targetRangeStart", "targetRangeEnd",
}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_observation(record: dict[str, object]) -> str:
    values = []
    for key, value in record.items():
        if key in HEX_OBSERVATION_KEYS and isinstance(value, int) and not isinstance(value, bool):
            encoded = f"0x{value:x}"
        else:
            encoded = str(value)
        values.append(f"{key}={encoded}")
    return " ".join(values) + "\n"


def refresh_manifest(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def synthetic_aarch64_elf(loads: list[tuple[int, int, int, int, int]] | None = None) -> bytes:
    """Minimal ELF64 image with explicit, test-owned PT_LOAD ranges.

    Each load is (flags, virtual address, file offset, file size, memory size).
    The checker must derive unique executable/file-backed ownership from these
    source and Native Image bytes rather than trusting the JSON claim.
    """
    if loads is None:
        loads = [(5, 0x1000, 0, 512, 512)]
    image = bytearray(max(1024, 64 + 56 * len(loads)))
    image[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", image, 16, 3, 183, 1)
    struct.pack_into("<Q", image, 32, 64)
    struct.pack_into("<HHH", image, 52, 64, 56, len(loads))
    for index, (flags, vaddr, file_offset, file_size, memory_size) in enumerate(loads):
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            64 + index * 56,
            1,
            flags,
            file_offset,
            vaddr,
            vaddr,
            file_size,
            memory_size,
            0x1000,
        )
        if file_offset + file_size > len(image):
            image.extend(b"\0" * (file_offset + file_size - len(image)))
    return bytes(image)


def valid_observation(transformed: bool) -> dict[str, object]:
    image_bias = 0x710000000000 if transformed else 0x700000000000
    mapped_vaddr = 0x4000 if transformed else 0x1000
    mapped_size = 84
    target_start = image_bias + mapped_vaddr
    target = {
        "schemaVersion": 2,
        "targetStatus": 42,
        "signalStatus": 42,
        "diagnosticCalls": 1,
        "frameCount": 8,
        "signalFrameCount": 10,
        "transformedImage": int(transformed),
        "targetFrameObserved": 1,
        "transformedFrameObserved": int(transformed),
        "framePointerAligned": 1,
        "returnAddressInTarget": 1,
        "registersPreserved": 1,
        "signalBoundary": 1,
        "signalFrameObserved": 1,
        "longjmpBoundary": 1,
        "cancellationBoundary": 1,
        "cppBoundaryStatus": 1,
        "cppRegisterCallAttempted": 1,
        "cppRegisterCallReturned": 0,
        "cppTargetNormalReturned": 0,
        "cppCaughtSpecificType": 1,
        "cppCaughtToken": TOKEN,
        "cppRaiiCleanupCount": 1,
        "cppHostCallbackEntered": 1,
        "cppHostCallbackReturned": 0,
        "cppThrowSiteTargetFrameObserved": 1,
        "cppThrowSiteFrameCount": 9,
        "cppThrowSiteReturnAddressInTarget": 1,
        "releaseStatus": 0,
        "imageLoadBias": image_bias,
        "loadedEntryAddress": image_bias + 0x100,
        "loadedEntryVaddr": 0x100,
        "mappedTargetVaddr": mapped_vaddr,
        "mappedTargetSize": mapped_size,
        "callbackReturnPc": target_start + 0x10,
        "targetFramePc": target_start + 0x18,
        "cppThrowSiteReturnPc": target_start + 0x20,
        "cppThrowSiteTargetFramePc": target_start + 0x28,
        "targetRangeStart": target_start,
        "targetRangeEnd": target_start + mapped_size,
        "targetInvocationMode": "address-map" if transformed else "direct-symbol",
        "targetSymbolSize": mapped_size,
    }
    return target


class CfiEvidenceTests(unittest.TestCase):
    def create_valid_tree(self, root: Path) -> None:
        positive = root / "positive" / UNIT
        positive.mkdir(parents=True)
        source = synthetic_aarch64_elf([(5, 0x1000, 0, 512, 512)])
        protected = b"synthetic protected image"
        native = synthetic_aarch64_elf([(5, 0x4000, 0, 512, 512)])
        (positive / "source-image.bin").write_bytes(source)
        (positive / "protected-image.bin").write_bytes(protected)
        (positive / "native-image.bin").write_bytes(native)
        (positive / "stage.json").write_text(json.dumps({"unitId": UNIT, "profile": "host-context-entry"}), encoding="utf-8")
        write_json(
            positive / "rehydration.json",
            {
                "layoutEvidence": {
                    "addressMap": [
                        {
                            "sourceRange": {"virtualAddress": {"value": 0x1000}, "size": 84},
                            "outputRange": {"virtualAddress": {"value": 0x4000}, "size": 84},
                        }
                    ]
                }
            },
        )
        baseline = valid_observation(False)
        transformed = valid_observation(True)
        (positive / "baseline-unwind.txt").write_text(render_observation(baseline), encoding="utf-8")
        (positive / "transformed-unwind.txt").write_text(render_observation(transformed), encoding="utf-8")
        (positive / "source-unwind-readelf.txt").write_text(".eh_frame\nFDE cie=00000000 pc=1000..1054\n", encoding="utf-8")
        (positive / "native-unwind-readelf.txt").write_text(".eh_frame\nFDE cie=00000000 pc=4000..4054\n", encoding="utf-8")
        (positive / "transformed-fde-range.txt").write_text("mappedFdeVaddr=0x4000 mappedFdeSize=84\n", encoding="utf-8")
        (root / "cpp-harness-unwind-readelf.txt").write_text(
            ".eh_frame\n"
            "FDE cie=00000000 pc=0000000000002f60..0000000000003034\n"
            "FDE cie=00000000 pc=000000000000303c..00000000000030a4\n"
            "81: 0000000000002f60 212 FUNC GLOBAL DEFAULT 12 urp_cfi_run_cpp_exception_boundary\n"
            "90: 0000000000003034 112 FUNC GLOBAL DEFAULT 12 urp_cfi_invoke_with_registers\n"
            "91: 0000000000003060 0 NOTYPE GLOBAL DEFAULT 12 urp_cfi_invoke_with_registers_call_return\n",
            encoding="utf-8",
        )
        glibc_identity = {
            "runtime": "glibc",
            "architecture": "aarch64",
            "version": "glibc 2.43",
            "libcPath": "/usr/lib/aarch64-linux-gnu/libc.so.6",
            "libcSha256": "e" * 64,
            "libcElfClass": 64,
            "libcElfData": "little",
            "libcMachine": 183,
            "loaderPath": "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            "loaderSha256": "f" * 64,
            "loaderElfClass": 64,
            "loaderElfData": "little",
            "loaderMachine": 183,
        }
        glibc_identity["identitySha256"] = hashlib.sha256(
            json.dumps(glibc_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        glibc_identity_path = root / "glibc-runtime-identity.json"
        write_json(glibc_identity_path, glibc_identity)
        identity = {
            "schemaVersion": 1,
            "hostArchitecture": "aarch64",
            "cCompiler": {
                "path": "/usr/bin/cc", "version": "cc test", "target": "aarch64-linux-gnu",
                "sha256": "1" * 64, "buildId": "2" * 40,
            },
            "cxxCompiler": {
                "path": "/usr/bin/g++", "version": "g++ test", "target": "aarch64-linux-gnu",
                "sha256": "3" * 64, "buildId": "4" * 40,
            },
            "libstdcxx": {
                "soname": "libstdc++.so.6",
                "resolvedPath": "/usr/lib/aarch64-linux-gnu/libstdc++.so.6",
                "sha256": "a" * 64,
                "buildId": "b" * 40,
            },
            "libgccUnwinder": {
                "soname": "libgcc_s.so.1",
                "resolvedPath": "/usr/lib/aarch64-linux-gnu/libgcc_s.so.1",
                "sha256": "c" * 64,
                "buildId": "d" * 40,
            },
            "glibcRuntimeIdentity": glibc_identity,
        }
        identity_path = root / "cpp-runtime-identity.json"
        write_json(identity_path, identity)
        projected_baseline = {key: baseline[key] for key in CPP_KEYS}
        projected_transformed = {key: transformed[key] for key in CPP_KEYS}
        behavior = {
            "schemaVersion": 2,
            "unitId": UNIT,
            "selectedFunction": "dynsym:7",
            "sourceFixtureSha256": hashlib.sha256(source).hexdigest(),
            "sourceImageSha256": hashlib.sha256(source).hexdigest(),
            "protectedImageSha256": hashlib.sha256(protected).hexdigest(),
            "nativeImageSha256": hashlib.sha256(native).hexdigest(),
            "targetAddressMap": {"sourceVirtualAddress": 0x1000, "outputVirtualAddress": 0x4000, "size": 84},
            "relocatedFde": {"virtualAddress": 0x4000, "size": 84},
            "registerCallUnwindWitness": {
                "functionSymbol": "urp_cfi_invoke_with_registers",
                "callReturnPcSymbol": "urp_cfi_invoke_with_registers_call_return",
                "functionStart": 0x3034,
                "functionSize": 112,
                "callReturnPc": 0x3060,
                "callReturnOffset": 0x2C,
            },
            "baseline": baseline,
            "transformed": transformed,
            "baselineStatus": 0,
            "transformedStatus": 0,
            "frameCountEqual": True,
            "transformedFrameObserved": True,
            "entryStatusEqual": True,
            "releaseStatusEqual": True,
            "sourceDirectTargetTransformedAddressMap": True,
            "registerFrameStateEqual": True,
            "signalBoundaryEqual": True,
            "signalFrameObserved": True,
            "longjmpBoundaryEqual": True,
            "cancellationBoundaryEqual": True,
            "cppException": {
                "oracleKind": "typed-cpp-throw-catch-through-mapped-cfi-target-v1",
                "runtimeIdentitySha256": hashlib.sha256(identity_path.read_bytes()).hexdigest(),
                "requiredToken": TOKEN,
                "baseline": projected_baseline,
                "transformed": projected_transformed,
            },
            "firstFailureStage": None,
        }
        write_json(positive / "cfi-behavior.json", behavior)
        (root / "cfi-fixture-dynamic-readelf.txt").write_text("Dynamic section at offset 0x0 contains 1 entry:\\n  NEEDED Shared library: [libc.so.6]\\n", encoding="utf-8")
        negative = root / "negative-malformed-eh-frame"
        negative.mkdir(parents=True)
        negative_source = synthetic_aarch64_elf([(5, 0x1000, 0, 512, 512)])
        (negative / "source-image.bin").write_bytes(negative_source)
        negative_stage = {
            "schemaVersion": 1,
            "status": "failed",
            "firstFailureStage": "protected-image-producer",
            "publicationComplete": False,
            "unitId": f"{UNIT}.negative",
            "sourceSha256": hashlib.sha256(negative_source).hexdigest(),
            "diagnostics": [{"severity": "Error", "code": "UnwindMetadataMalformed"}],
        }
        write_json(negative / "stage.json", negative_stage)
        write_json(negative / "producer.stdout", {"success": False, "stage": negative_stage})
        write_json(
            negative / "negative-result.json",
            {
                "status": "passed",
                "producerExitStatus": 4,
                "nativeImagePublished": False,
                "protectedImagePublished": False,
                "loaderInvoked": False,
                "expectedDiagnosticFamily": "UnwindMetadataMalformed",
            },
        )
        refresh_manifest(root)

    def checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(root), "--tier", "release", "--runtime", "glibc", "--unit", UNIT],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def copy_tree(self, source: Path, parent: Path) -> Path:
        copied = parent / "copy"
        shutil.copytree(source, copied)
        return copied

    def mutate_observation(self, root: Path, side: str, key: str, value: object) -> None:
        positive = root / "positive" / UNIT
        behavior_path = positive / "cfi-behavior.json"
        behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
        behavior[side][key] = value
        if key in CPP_KEYS:
            behavior["cppException"][side][key] = value
        write_json(behavior_path, behavior)
        observed_path = positive / ("baseline-unwind.txt" if side == "baseline" else "transformed-unwind.txt")
        observed = valid_observation(side == "transformed")
        observed.update(behavior[side])
        observed_path.write_text(render_observation(observed), encoding="utf-8")
        refresh_manifest(root)

    def test_measured_typed_cpp_exception_evidence_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-valid-") as directory:
            root = Path(directory) / "evidence"
            self.create_valid_tree(root)
            result = self.checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("transformed C++ exception unwind", result.stdout)

    def test_longjmp_boundary_without_cpp_exception_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-missing-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            behavior_path = root / "positive" / UNIT / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior.pop("cppException")
            write_json(behavior_path, behavior)
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("C++ exception", result.stderr)

    def assert_semantic_mutation_rejected(self, key: str, value: object, test_name: str) -> None:
        with tempfile.TemporaryDirectory(prefix=f"cfi-cpp-evidence-{test_name}-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            self.mutate_observation(root, "transformed", key, value)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_false_host_throw_callback_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppHostCallbackEntered", 0, "throw")

    def test_wrong_cpp_catch_type_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppCaughtSpecificType", 0, "catch")

    def test_missing_raii_unwind_cleanup_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppRaiiCleanupCount", 0, "raii")

    def test_wrong_typed_exception_payload_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppCaughtToken", TOKEN + 1, "payload")

    def test_transformed_target_must_use_address_map_not_source_symbol(self) -> None:
        self.assert_semantic_mutation_rejected("targetInvocationMode", "direct-symbol", "stale-symbol")

    def test_register_call_return_pc_must_match_retained_symbol(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-call-pc-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            behavior_path = root / "positive" / UNIT / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["registerCallUnwindWitness"]["callReturnPc"] += 4
            behavior["registerCallUnwindWitness"]["callReturnOffset"] += 4
            write_json(behavior_path, behavior)
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symbol table", result.stderr)

    def test_register_call_fde_must_cover_exact_blr_return_pc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-call-fde-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            witness = root / "cpp-harness-unwind-readelf.txt"
            text = witness.read_text(encoding="utf-8")
            text = text.replace(
                "FDE cie=00000000 pc=000000000000303c..00000000000030a4",
                "FDE cie=00000000 pc=0000000000003034..0000000000003038",
            )
            witness.write_text(text, encoding="utf-8")
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("BLR return PC", result.stderr)

    def test_changed_runtime_target_range_with_stale_bias_and_pcs_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-runtime-range-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            self.mutate_observation(root, "transformed", "targetRangeStart", 0x710000005000)
            self.mutate_observation(root, "transformed", "targetRangeEnd", 0x710000005054)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("load bias and map", result.stderr)

    def test_runtime_target_va_must_match_rehydration_map(self) -> None:
        self.assert_semantic_mutation_rejected("mappedTargetVaddr", 0x4004, "wrong-mapped-va")

    def test_throw_site_pc_must_be_inside_mapped_target(self) -> None:
        self.assert_semantic_mutation_rejected("cppThrowSiteReturnPc", 0x7100000040A0, "throw-pc")

    def test_missing_runtime_bias_witness_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-missing-bias-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            positive = root / "positive" / UNIT
            behavior_path = positive / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["transformed"].pop("imageLoadBias")
            behavior["cppException"]["transformed"].pop("imageLoadBias")
            write_json(behavior_path, behavior)
            output = positive / "transformed-unwind.txt"
            output.write_text(
                " ".join(part for part in output.read_text(encoding="utf-8").split() if not part.startswith("imageLoadBias=")) + "\n",
                encoding="utf-8",
            )
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)

    def test_malformed_runtime_pc_and_overflowing_bias_are_rejected(self) -> None:
        self.assert_semantic_mutation_rejected("cppThrowSiteReturnPc", "bad-pc", "malformed-pc")
        self.assert_semantic_mutation_rejected("imageLoadBias", 0xFFFFFFFFFFFFFFFE, "overflow-bias")

    def test_coherent_aslr_relocation_remains_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-aslr-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            positive = root / "positive" / UNIT
            behavior_path = positive / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            relocated_fields = (
                "imageLoadBias", "loadedEntryAddress", "callbackReturnPc", "targetFramePc",
                "cppThrowSiteReturnPc", "cppThrowSiteTargetFramePc", "targetRangeStart", "targetRangeEnd",
            )
            for side, delta in (("baseline", 0x120000000), ("transformed", 0x230000000)):
                for key in relocated_fields:
                    behavior[side][key] += delta
                behavior["cppException"][side] = {key: behavior[side].get(key) for key in CPP_KEYS}
                output = positive / ("baseline-unwind.txt" if side == "baseline" else "transformed-unwind.txt")
                output.write_text(render_observation(behavior[side]), encoding="utf-8")
            write_json(behavior_path, behavior)
            refresh_manifest(root)
            result = self.checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_readelf_fde_must_cover_mapped_target_range(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-target-fde-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            readelf_path = root / "positive" / UNIT / "native-unwind-readelf.txt"
            readelf_path.write_text(".eh_frame\\nFDE cie=00000000 pc=6000..6054\\n", encoding="utf-8")
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("relocated transformed target FDE", result.stderr)

    def test_malformed_metadata_negative_requires_actual_diagnostic_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-unrelated-negative-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            negative = root / "negative-malformed-eh-frame"
            stage_path = negative / "stage.json"
            producer_path = negative / "producer.stdout"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["diagnostics"][0]["code"] = "OutputIoFailure"
            write_json(stage_path, stage)
            write_json(producer_path, {"success": False, "stage": stage})
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("actual UnwindMetadataMalformed producer failure", result.stderr)

    def test_relocated_fde_must_be_file_backed_by_executable_load(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-no-exec-load-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            positive = root / "positive" / UNIT
            native_path = positive / "native-image.bin"
            native_path.write_bytes(synthetic_aarch64_elf([(5, 0x3000, 0, 512, 512)]))
            behavior_path = positive / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["nativeImageSha256"] = hashlib.sha256(native_path.read_bytes()).hexdigest()
            write_json(behavior_path, behavior)
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("file-backed executable PT_LOAD", result.stderr)

    def test_partially_overlapping_pt_load_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-overlapping-load-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            positive = root / "positive" / UNIT
            native_path = positive / "native-image.bin"
            native_path.write_bytes(
                synthetic_aarch64_elf([(5, 0x4000, 0, 512, 512), (4, 0x4050, 512, 256, 256)])
            )
            behavior_path = positive / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["nativeImageSha256"] = hashlib.sha256(native_path.read_bytes()).hexdigest()
            write_json(behavior_path, behavior)
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlapping PT_LOAD memory ranges", result.stderr)

    def test_cpp_runtime_identity_digest_mismatch_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cfi-cpp-evidence-runtime-identity-") as directory:
            source = Path(directory) / "source"
            self.create_valid_tree(source)
            root = self.copy_tree(source, Path(directory))
            behavior_path = root / "positive" / UNIT / "cfi-behavior.json"
            behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
            behavior["cppException"]["runtimeIdentitySha256"] = "0" * 64
            write_json(behavior_path, behavior)
            refresh_manifest(root)
            result = self.checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runtime/token binding", result.stderr)

    def test_missing_target_frame_at_throw_site_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppThrowSiteTargetFrameObserved", 0, "target-frame")

    def test_missing_target_return_address_observation_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppThrowSiteReturnAddressInTarget", 0, "target-return-address")

    def test_normal_target_return_is_rejected_after_manifest_refresh(self) -> None:
        self.assert_semantic_mutation_rejected("cppTargetNormalReturned", 1, "normal-return")


if __name__ == "__main__":
    unittest.main()
