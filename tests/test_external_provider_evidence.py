from __future__ import annotations

import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check-external-provider-evidence.py"
SPEC = importlib.util.spec_from_file_location("external_provider_evidence_test_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load external-provider evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ExternalProviderRootResourceBoundsTests(unittest.TestCase):
    def test_manifest_writer_accepts_exact_empty_count_limits_and_rejects_plus_one_before_file_open(self) -> None:
        original_open = os.open
        opened_flags: list[int] = []

        def tracked_open(path, flags, *args, **kwargs):
            opened_flags.append(flags)
            return original_open(path, flags, *args, **kwargs)

        with tempfile.TemporaryDirectory(prefix="provider-root-count-bounds-") as directory:
            parent = Path(directory)
            exact = parent / "exact"
            exact.mkdir()
            (exact / "empty-a").write_bytes(b"")
            (exact / "empty-b").write_bytes(b"")
            (exact / "one-dir").mkdir()
            with (
                mock.patch.object(CHECKER, "MAX_PROVIDER_ROOT_FILES", 2),
                mock.patch.object(CHECKER, "MAX_PROVIDER_ROOT_DIRECTORIES", 2),
                mock.patch.object(CHECKER.os, "open", side_effect=tracked_open),
            ):
                CHECKER.write_closed_manifest(exact)
            self.assertEqual(2, len((exact / "SHA256SUMS").read_text(encoding="utf-8").splitlines()))

            opened_flags.clear()
            over_files = parent / "over-files"
            over_files.mkdir()
            for name in ("empty-a", "empty-b", "empty-c"):
                (over_files / name).write_bytes(b"")
            with (
                mock.patch.object(CHECKER, "MAX_PROVIDER_ROOT_FILES", 2),
                mock.patch.object(CHECKER.os, "open", side_effect=tracked_open),
            ):
                with self.assertRaisesRegex(SystemExit, "file-count bound"):
                    CHECKER.write_closed_manifest(over_files)
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for flags in opened_flags))

            opened_flags.clear()
            over_directories = parent / "over-directories"
            over_directories.mkdir()
            (over_directories / "dir-a").mkdir()
            (over_directories / "dir-b").mkdir()
            with (
                mock.patch.object(CHECKER, "MAX_PROVIDER_ROOT_DIRECTORIES", 2),
                mock.patch.object(CHECKER.os, "open", side_effect=tracked_open),
            ):
                with self.assertRaisesRegex(SystemExit, "directory-count bound"):
                    CHECKER.write_closed_manifest(over_directories)
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for flags in opened_flags))

    def test_manifest_line_count_is_checked_before_splitlines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-manifest-entry-bound-") as directory:
            root = Path(directory)
            (root / "SHA256SUMS").write_bytes(b"\n" * (CHECKER.MAX_PROVIDER_MANIFEST_ENTRIES + 1))
            with self.assertRaisesRegex(SystemExit, "manifest-entry bound"):
                CHECKER.check_closed_manifest(root)


class ExternalProviderElfEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if platform.machine().lower() not in {"aarch64", "arm64"}:
            raise unittest.SkipTest("provider fixture assembly tests require a native AArch64 toolchain")
        subprocess.run(
            ["make", "-C", str(ROOT / "native/urprotect-runtime"), "external-provider-image-handoff"],
            check=True,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        build = ROOT / "native/urprotect-runtime/build"
        cls.provider_path = build / "liburprotect-jump-table-provider.so.1"
        cls.consumer_path = build / "host-context-external-provider-consumer.so"
        cls.provider_bytes = cls.provider_path.read_bytes()
        cls.consumer_bytes = cls.consumer_path.read_bytes()
        cls.provider = CHECKER.parse_provider(cls.provider_bytes)
        cls.consumer = CHECKER.parse_consumer(cls.consumer_bytes, "test source consumer", require_source_dispatch=True)

    def test_project_provider_proves_ro_table_signed_targets_and_self_containment(self) -> None:
        self.assertEqual("liburprotect-jump-table-provider.so.1", self.provider["soname"])
        self.assertEqual([], self.provider["needed"])
        self.assertEqual(16, self.provider["table"]["size"])
        self.assertEqual(4, len(self.provider["table"]["entries"]))
        self.assertEqual(4, self.provider["table"]["segmentFlags"] & 4)
        self.assertEqual(0, self.provider["table"]["segmentFlags"] & 2)
        self.assertEqual(
            ["urp_provider_target_0", "urp_provider_target_1", "urp_provider_target_2", "urp_provider_target_3"],
            [row["targetSymbol"] for row in self.provider["table"]["entries"]],
        )
        self.assertEqual("dynsym:4", self.consumer["sourceDispatch"]["selectedFunction"]["selector"])
        self.assertEqual(1025, self.consumer["relocation"]["type"])
        self.assertEqual(self.consumer["relocation"]["virtualAddress"], self.consumer["got"]["virtualAddress"])
        self.assertEqual("0000000000000000", self.consumer["got"]["initialBytesHex"])
        self.assertEqual(3, self.consumer["sourceDispatch"]["guard"]["bound"])
        self.assertEqual("00008012c0035fd6", self.consumer["sourceDispatch"]["guard"]["defaultBytesHex"])

    def test_provider_table_bytes_tamper_is_rejected_from_retained_elf(self) -> None:
        damaged = bytearray(self.provider_bytes)
        offset = self.provider["table"]["fileOffset"]
        damaged[offset] ^= 1
        with self.assertRaisesRegex(SystemExit, "provider signed table entry"):
            CHECKER.parse_provider(bytes(damaged))

    def test_provider_target_symbol_bytes_tamper_is_rejected(self) -> None:
        damaged = bytearray(self.provider_bytes)
        target = self.provider["targets"][0]
        damaged[target["fileOffset"] + target["size"] - 1] ^= 0x80
        with self.assertRaisesRegex(SystemExit, "does not terminate with RET"):
            CHECKER.parse_provider(bytes(damaged))

    def test_consumer_relocation_type_and_got_owner_tampering_are_rejected(self) -> None:
        image = CHECKER._DYNAMIC.ElfImage(self.consumer_bytes, "source consumer")
        row = image.rela_rows[0]
        info_offset = row["tableFileOffset"] + row["index"] * 24 + 8
        bad_type = bytearray(self.consumer_bytes)
        info = struct.unpack_from("<Q", bad_type, info_offset)[0]
        struct.pack_into("<Q", bad_type, info_offset, (info & ~0xFFFFFFFF) | 1026)
        with self.assertRaisesRegex(SystemExit, "one non-PLT R_AARCH64_GLOB_DAT"):
            CHECKER.parse_consumer(bytes(bad_type), "mutated relocation type", require_source_dispatch=False)

        bad_slot = bytearray(self.consumer_bytes)
        got_offset = self.consumer["got"]["fileOffset"]
        bad_slot[got_offset] = 1
        with self.assertRaisesRegex(SystemExit, "unresolved zero-initialized pointer"):
            CHECKER.parse_consumer(bytes(bad_slot), "mutated GOT slot", require_source_dispatch=False)

    def test_source_bounds_and_default_mutations_are_semantically_rejected(self) -> None:
        dispatch = self.consumer["sourceDispatch"]
        function = dispatch["selectedFunction"]
        entry_file_offset = self.consumer["functions"]["urp_entry"]["fileOffset"]
        branch_offset = entry_file_offset + dispatch["guard"]["branchAddress"] - function["virtualAddress"]
        bad_branch = bytearray(self.consumer_bytes)
        branch_word = struct.unpack_from("<I", bad_branch, branch_offset)[0]
        # Redirect B.HI to the indexed LDRSW rather than the final safe default.
        ldrsw_va = dispatch["dispatch"]["indexedReadAddress"]
        branch_va = dispatch["guard"]["branchAddress"]
        immediate = ((ldrsw_va - branch_va) // 4) & 0x7FFFF
        branch_word = (branch_word & ~(0x7FFFF << 5)) | (immediate << 5)
        struct.pack_into("<I", bad_branch, branch_offset, branch_word)
        with self.assertRaisesRegex(SystemExit, "B.HI does not target"):
            CHECKER.parse_consumer(bytes(bad_branch), "unsafe bounds branch", require_source_dispatch=True)

        bad_default = bytearray(self.consumer_bytes)
        default_offset = entry_file_offset + dispatch["guard"]["defaultAddress"] - function["virtualAddress"]
        struct.pack_into("<I", bad_default, default_offset, 0x52800000)
        with self.assertRaisesRegex(SystemExit, "exact MOV W0,#-1; RET"):
            CHECKER.parse_consumer(bytes(bad_default), "mutated default target", require_source_dispatch=True)

    def test_provider_mapping_requires_exact_observed_integer_types(self) -> None:
        provider_bias = 0x100000
        consumer_bias = 0x200000
        table_address = provider_bias + self.provider["table"]["virtualAddress"]
        got_va = self.consumer["got"]["virtualAddress"]
        got_address = consumer_bias + got_va
        record = {
            "schemaVersion": 1,
            "status": "passed",
            "loaderId": "host-context.sealed-memfd.dlmopen-provider",
            "nativeImageSha256": "a" * 64,
            "entrySymbol": "urp_entry",
            "argumentIndex": 0,
            "entryStatus": 17,
            "processStatus": 17,
            "releaseStatus": "passed",
            "releaseStatusCode": 0,
            "releaseOrder": "dispatch-before-release-image",
            "providerSoname": self.provider["soname"],
            "providerBuildId": self.provider["buildId"],
            "providerSha256": self.provider["sha256"],
            "providerLoadBias": provider_bias,
            "consumerLoadBias": consumer_bias,
            "providerTableAddress": table_address,
            "providerTableVirtualAddress": self.provider["table"]["virtualAddress"],
            "providerTableBytes": self.provider["table"]["bytesHex"],
            "providerTablePermissions": "r--p",
            "providerTableMapping": f"{table_address:x}-{table_address + 0x1000:x} r--p 00020000 00:01 1 /memfd:urprotect-trusted-provider (deleted)",
            "providerMappedPath": "/proc/self/fd/3",
            "consumerMappedPath": "/proc/self/fd/4",
            "providerTargetAddresses": [provider_bias + item["virtualAddress"] for item in self.provider["targets"]],
            "gotVirtualAddress": got_va,
            "gotAddress": got_address,
            "gotValue": table_address,
            "gotPermissions": "r--p",
            "gotMapping": f"{got_address:x}-{got_address + 0x1000:x} r--p 0000f000 00:01 2 /memfd:urprotect-host-image (deleted)",
            "dependencyCount": 1,
            "usesConfiguredProvider": True,
            "imageSealed": True,
            "providerTableFileBytesMatch": True,
            "providerTableUnchangedAfterDispatch": True,
            "providerConsumerMapsIsolated": True,
            "providerReleasedAfterConsumer": True,
            "firstFailureStage": None,
            "entryAddress": consumer_bias + self.consumer["functions"]["urp_entry"]["virtualAddress"],
        }
        CHECKER.validate_handoff_record(
            record,
            image_sha256="a" * 64,
            provider=self.provider,
            consumer=self.consumer,
            entry_symbol="urp_entry",
            index=0,
        )
        tampered = copy.deepcopy(record)
        tampered["releaseStatusCode"] = False
        with self.assertRaisesRegex(SystemExit, "exact JSON integer"):
            CHECKER.validate_handoff_record(
                tampered,
                image_sha256="a" * 64,
                provider=self.provider,
                consumer=self.consumer,
                entry_symbol="urp_entry",
                index=0,
            )
        tampered = copy.deepcopy(record)
        tampered["providerTableFileBytesMatch"] = 1
        with self.assertRaisesRegex(SystemExit, "exact observed true boolean"):
            CHECKER.validate_handoff_record(
                tampered,
                image_sha256="a" * 64,
                provider=self.provider,
                consumer=self.consumer,
                entry_symbol="urp_entry",
                index=0,
            )


class ExternalProviderClosedRootTamperingTests(unittest.TestCase):
    """Optional integration regressions run by the native evidence runner."""

    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT")
        if not value:
            raise unittest.SkipTest("set URP_EXTERNAL_PROVIDER_EVIDENCE_ROOT to run refreshed-manifest evidence regressions")
        cls.origin = Path(value).resolve(strict=True)
        if cls.origin.name != CHECKER.UNIT_ID:
            raise unittest.SkipTest("integration root does not name the exact external-provider unit")
        CHECKER.validate_root(cls.origin, write_report=False)

    def _copy(self, temporary: str) -> Path:
        root = Path(temporary) / CHECKER.UNIT_ID
        shutil.copytree(self.origin, root)
        return root

    def _rewrite_report(self, root: Path, mutate) -> None:
        path = root / "external-provider-evidence.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        mutate(record)
        path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        CHECKER.write_closed_manifest(root)

    @staticmethod
    def _write_json(root: Path, relative: str, record: dict) -> None:
        (root / relative).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _refresh_manifest_entries(root: Path, relatives: set[str]) -> None:
        manifest = root / "SHA256SUMS"
        entries = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, relative = line.split("  ", 1)
            entries[relative] = digest
        for relative in relatives:
            entries[relative] = CHECKER.sha256_bytes((root / relative).read_bytes())
        manifest.write_text("".join(f"{entries[key]}  {key}\n" for key in sorted(entries)), encoding="utf-8")

    def _refresh_producer_manifest(self, root: Path) -> None:
        rows = []
        for relative in ("protected-image.bin", "protected-image.json", "stage.json"):
            rows.append(f"{CHECKER.sha256_bytes((root / relative).read_bytes())}  {relative}")
        (root / "producer-manifest.txt").write_text("\n".join(rows) + "\n", encoding="ascii")

    def _refresh_native_image_chain(self, root: Path, mutate, *, rerun_handoffs: bool = True) -> None:
        native_path = root / "native-image.bin"
        native_data = bytearray(native_path.read_bytes())
        mutate(native_data)
        native_path.write_bytes(native_data)
        native_sha = CHECKER.sha256_bytes(native_data)

        rehydration_path = root / "rehydration.json"
        rehydration = json.loads(rehydration_path.read_text(encoding="utf-8"))
        rehydration["nativeImageSha256"] = native_sha
        rehydration["nativeImageSize"] = len(native_data)
        rehydration["layoutEvidence"]["outputSha256"] = native_sha
        rehydration["layoutEvidence"]["outputLength"] = len(native_data)
        self._write_json(root, "rehydration.json", rehydration)

        native_role_path = root / "native-image.json"
        native_role = json.loads(native_role_path.read_text(encoding="utf-8"))
        native_role["nativeImageSha256"] = native_sha
        native_role["nativeImageSize"] = len(native_data)
        native_role["rehydrationRecordSha256"] = CHECKER.sha256_bytes(rehydration_path.read_bytes())
        self._write_json(root, "native-image.json", native_role)

        command_path = root / "rehydration-command.json"
        command_output = json.loads(command_path.read_text(encoding="utf-8"))
        command_output["record"] = rehydration
        command_output["nativeImage"] = native_role
        self._write_json(root, "rehydration-command.json", command_output)

        changed = {
            "native-image.bin", "rehydration.json", "native-image.json", "rehydration-command.json",
        }
        if rerun_handoffs:
            for symbol in CHECKER.ENTRY_SYMBOLS:
                for index in CHECKER.INDICES:
                    relative = f"handoffs/transformed/{symbol}/index-{index}.json"
                    handoff = json.loads((root / relative).read_text(encoding="utf-8"))
                    handoff["nativeImageSha256"] = native_sha
                    self._write_json(root, relative, handoff)
                    changed.add(relative)

        negative_path = root / "negative-provider-sha256.json"
        negative = json.loads(negative_path.read_text(encoding="utf-8"))
        negative["negativeRecordSha256"] = CHECKER.sha256_bytes((root / "negative-rehydration.json").read_bytes())
        self._write_json(root, "negative-provider-sha256.json", negative)
        changed.add("negative-provider-sha256.json")

        self._refresh_producer_manifest(root)
        changed.add("producer-manifest.txt")
        commands_path = root / "commands.json"
        commands = json.loads(commands_path.read_text(encoding="utf-8"))
        commands["transformedNativeRollback"]["nativeImageSha256"] = native_sha
        self._write_json(root, "commands.json", commands)
        changed.add("commands.json")

        report_path = root / "external-provider-evidence.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["artifacts"]["nativeImageSha256"] = native_sha
        report["transformedNativeRollback"]["nativeImageSha256"] = native_sha
        native_facts = report["nativeElfFacts"]
        native_facts["sha256"] = native_sha
        entry = native_facts["functions"]["urp_entry"]
        entry["bytesSha256"] = CHECKER.sha256_bytes(
            native_data[entry["fileOffset"] : entry["fileOffset"] + entry["size"]]
        )
        stub_word = struct.unpack_from("<I", native_data, entry["fileOffset"])[0]
        stub = native_facts.get("liveDispatch", {}).get("entryStub", {})
        stub["instructionWord"] = f"0x{stub_word:08x}"
        stub["branchTarget"] = (
            entry["virtualAddress"] + CHECKER._sign_extend(stub_word & 0x03FFFFFF, 26) * 4
            if stub_word & 0xFC000000 == 0x14000000 else None
        )
        stub["fileOffset"] = entry["fileOffset"]
        layout_range = rehydration["layoutEvidence"]["addressMap"][0]["outputRange"]
        output_file = layout_range["fileOffset"]["value"]
        output_va = layout_range["virtualAddress"]["value"]
        dispatcher = native_facts["liveDispatch"]["dispatch"]
        dispatcher["guard"]["defaultBytesHex"] = native_data[output_file + 56 : output_file + 64].hex()
        dispatcher["dispatch"]["instructionWords"] = [
            f"0x{struct.unpack_from('<I', native_data, output_file + offset)[0]:08x}"
            for offset in range(36, 56, 4)
        ]
        transitions = []
        for offset, state in ((64, 0), (72, 1), (80, 2)):
            word = struct.unpack_from("<I", native_data, output_file + offset + 4)[0]
            target = output_va + offset + 4 + CHECKER._sign_extend((word >> 5) & 0x7FFFF, 19) * 4
            transitions.append({"state": state, "branchAddress": output_va + offset + 4, "targetAddress": target})
        dispatcher["stateTransitions"] = transitions
        for symbol in CHECKER.ENTRY_SYMBOLS:
            for index, handoff_summary in enumerate(report["handoffs"]["transformed"][symbol]):
                relative = f"handoffs/transformed/{symbol}/index-{index}.json"
                handoff_path = root / relative
                if not rerun_handoffs:
                    handoff_claim = json.loads(handoff_path.read_text(encoding="utf-8"))
                    handoff_claim["nativeImageSha256"] = native_sha
                    self._write_json(root, relative, handoff_claim)
                    changed.add(relative)
                handoff_summary["handoffSha256"] = CHECKER.sha256_bytes(handoff_path.read_bytes())
        self._write_json(root, "external-provider-evidence.json", report)
        changed.add("external-provider-evidence.json")
        if rerun_handoffs:
            self._refresh_all_handoffs(root, report, native_sha)
            changed.add("commands.json")
            for lane in ("source", "transformed"):
                for symbol in CHECKER.ENTRY_SYMBOLS:
                    for index in CHECKER.INDICES:
                        base = f"handoffs/{lane}/{symbol}/index-{index}"
                        changed.update({f"{base}.json", f"{base}.stdout", f"{base}.stderr", f"{base}.exit-status"})
        changed.add("negative-provider-sha256.json")
        self._write_json(root, "external-provider-evidence.json", report)
        changed.add("external-provider-evidence.json")
        self._refresh_manifest_entries(root, changed)

    def _refresh_all_handoffs(self, root: Path, report: dict, native_sha: str) -> None:
        commands_path = root / "commands.json"
        commands = json.loads(commands_path.read_text(encoding="utf-8"))
        provider = report["providerFacts"]
        command_rows = {(row["lane"], row["entrySymbol"], row["argumentIndex"]): row for row in commands["handoffs"]}
        for lane in ("source", "transformed"):
            image = root / ("source-image.bin" if lane == "source" else "native-image.bin")
            for symbol in CHECKER.ENTRY_SYMBOLS:
                for index in CHECKER.INDICES:
                    relative = f"handoffs/{lane}/{symbol}/index-{index}"
                    record_path = root / f"{relative}.json"
                    argv = [
                        str(root / "host-context-external-provider-image-handoff"),
                        str(root / "provider-image.so"), provider["soname"], provider["buildId"], provider["sha256"],
                        str(image), symbol, str(index), str(record_path),
                    ]
                    env = os.environ.copy()
                    for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
                        env.pop(name, None)
                    result = subprocess.run(argv, check=False, env=env, capture_output=True)
                    (root / f"{relative}.stdout").write_bytes(result.stdout)
                    (root / f"{relative}.stderr").write_bytes(result.stderr)
                    (root / f"{relative}.exit-status").write_text(f"{result.returncode}\n", encoding="ascii")
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    command = command_rows[(lane, symbol, index)]
                    command["exitStatus"] = result.returncode
                    command["streams"] = {
                        "stdoutSha256": CHECKER.sha256_bytes(result.stdout),
                        "stderrSha256": CHECKER.sha256_bytes(result.stderr),
                    }
                    row = report["handoffs"][lane][symbol][index]
                    row.update({
                        "argumentIndex": index,
                        "defaultTarget": record.get("entryStatus") == -1,
                        "entryStatus": record.get("entryStatus"),
                        "processStatus": record.get("processStatus"),
                        "handoffSha256": CHECKER.sha256_bytes(record_path.read_bytes()),
                        "stdoutSha256": CHECKER.sha256_bytes(result.stdout),
                        "stderrSha256": CHECKER.sha256_bytes(result.stderr),
                        "providerTargetAddress": (
                            record["providerTargetAddresses"][index]
                            if index < 4 and record.get("entryStatus") == CHECKER.ENTRY_STATUSES[index]
                            else None
                        ),
                    })
        self._write_json(root, "commands.json", commands)
        negative_path = root / "negative-provider-sha256.json"
        negative = json.loads(negative_path.read_text(encoding="utf-8"))
        negative["negativeRecordSha256"] = CHECKER.sha256_bytes((root / "negative-rehydration.json").read_bytes())
        self._write_json(root, "negative-provider-sha256.json", negative)

    def test_refreshed_provider_identity_and_table_claims_are_rejected(self) -> None:
        mutations = (
            lambda report: report["providerFacts"].__setitem__("buildId", "0" * 40),
            lambda report: report["providerFacts"]["table"].__setitem__("bytesHex", "ff" * 16),
            lambda report: report["providerFacts"]["targets"][0].__setitem__("symbol", "urp_provider_target_3"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = self._copy(temporary)
                self._rewrite_report(root, mutation)
                with self.assertRaises(SystemExit):
                    CHECKER.validate_root(root, write_report=False)

    def test_refreshed_native_entry_and_live_dispatch_bypasses_are_rejected_semantically(self) -> None:
        for case in ("entry-stub-return", "state-1-live-chain-bypass"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._copy(temporary)
                native = bytearray((root / "native-image.bin").read_bytes())
                facts = CHECKER.parse_consumer(bytes(native), "mutated native image", require_source_dispatch=False)
                if case == "entry-stub-return":
                    offset = facts["functions"]["urp_entry"]["fileOffset"]
                    native[offset : offset + 8] = bytes.fromhex("00008012c0035fd6")
                    expected = "does not begin with the expected live B stub"
                else:
                    rehydration = json.loads((root / "rehydration.json").read_text(encoding="utf-8"))
                    output_range = rehydration["layoutEvidence"]["addressMap"][0]["outputRange"]
                    file_offset = output_range["fileOffset"]["value"] + 76
                    output_va = output_range["virtualAddress"]["value"]
                    branch_pc = output_va + 76
                    bypass_target = output_va + 56
                    word = struct.unpack_from("<I", native, file_offset)[0]
                    immediate = ((bypass_target - branch_pc) // 4) & 0x7FFFF
                    word = (word & ~(0x7FFFF << 5)) | (immediate << 5)
                    struct.pack_into("<I", native, file_offset, word)
                    expected = "state 1 bypasses its mapped semantic block"
                # Refreshed malformed output is never handed to the loader.
                self._refresh_native_image_chain(
                    root,
                    lambda image: image.__setitem__(slice(None), native),
                    rerun_handoffs=False,
                )
                with self.assertRaisesRegex(SystemExit, expected):
                    CHECKER.validate_root(root, write_report=False)

    def test_every_consumed_schema_and_ordinal_field_rejects_bool_float_and_string(self) -> None:
        schema_fields = [
            ("commands.json", ("schemaVersion",)),
            ("stage.json", ("schemaVersion",)), ("stage.json", ("abiVersion",)),
            ("protected-image.json", ("schemaVersion",)), ("protected-image.json", ("abiVersion",)),
            ("native-image.json", ("schemaVersion",)), ("native-image.json", ("abiVersion",)),
            ("rehydration.json", ("schemaVersion",)), ("rehydration.json", ("abiVersion",)),
            ("rehydration.json", ("layoutEvidence", "schemaVersion")),
            ("native-build.json", ("schemaVersion",)),
            ("negative-provider-sha256.json", ("schemaVersion",)),
            ("negative-rehydration.json", ("schemaVersion",)), ("negative-rehydration.json", ("abiVersion",)),
            ("transformed-native-rollback.json", ("schemaVersion",)),
            ("producer.json", ("schemaVersion",)), ("rehydration-command.json", ("schemaVersion",)),
        ]
        for lane in ("source", "transformed"):
            for symbol in CHECKER.ENTRY_SYMBOLS:
                for index in CHECKER.INDICES:
                    schema_fields.append((f"handoffs/{lane}/{symbol}/index-{index}.json", ("schemaVersion",)))
        ordinal_fields = [
            ("stage.json", ("abiVersion",)),
            ("protected-image.json", ("artifactSize",)),
            ("native-image.json", ("requiredCapabilities",)), ("native-image.json", ("hostContextAbiVersion",)), ("native-image.json", ("nativeImageSize",)),
            ("rehydration.json", ("hostContextAbiVersion",)), ("rehydration.json", ("requiredCapabilities",)), ("rehydration.json", ("nativeImageSize",)),
            ("rehydration.json", ("layoutEvidence", "strategy")), ("rehydration.json", ("layoutEvidence", "outputLength")),
            ("negative-rehydration.json", ("requiredCapabilities",)), ("negative-rehydration.json", ("hostContextAbiVersion",)),
            ("negative-provider-sha256.json", ("exitStatus",)),
            ("commands.json", ("producer", "exitStatus")), ("commands.json", ("rehydration", "exitStatus")),
            ("commands.json", ("wrongProviderSha256Rollback", "exitStatus")),
            ("commands.json", ("transformedNativeRollback", "exitStatus")),
            ("transformed-native-rollback.json", ("provider", "size")),
            ("transformed-native-rollback.json", ("input", "nativeImageSize")),
            ("transformed-native-rollback.json", ("failpoint", "reached")),
            ("transformed-native-rollback.json", ("retry", "entryStatus")),
            ("commands.json", ("handoffs", 0, "argumentIndex")),  ("commands.json", ("handoffs", 0, "exitStatus")),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            for relative, path in schema_fields + ordinal_fields:
                record_path = root / relative
                original = record_path.read_bytes()
                for malformed in (True, 1.0, "1", None):
                    with self.subTest(record=relative, field=path, value=malformed):
                        record = json.loads(original.decode("utf-8"))
                        target = record
                        for key in path[:-1]:
                            target = target[key]
                        target[path[-1]] = malformed
                        self._write_json(root, relative, record)
                        self._refresh_manifest_entries(root, {relative})
                        with self.assertRaisesRegex(SystemExit, "exact JSON integer"):
                            CHECKER._validate_root_integer_schemas(root)
                        record_path.write_bytes(original)
                        self._refresh_manifest_entries(root, {relative})
                with self.subTest(record=relative, field=path, value="missing"):
                    record = json.loads(original.decode("utf-8"))
                    target = record
                    for key in path[:-1]:
                        target = target[key]
                    del target[path[-1]]
                    self._write_json(root, relative, record)
                    self._refresh_manifest_entries(root, {relative})
                    with self.assertRaisesRegex(SystemExit, "exact JSON integer"):
                        CHECKER._validate_root_integer_schemas(root)
                    record_path.write_bytes(original)
                    self._refresh_manifest_entries(root, {relative})

    def test_provider_limit_is_enforced_at_exact_max_plus_one_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            provider_path = root / "provider-image.so"
            original = provider_path.read_bytes()
            exact_limit_data = original + b"\0" * (CHECKER.MAX_PROVIDER_BYTES - len(original))
            provider_path.write_bytes(exact_limit_data)
            accepted = CHECKER.read_file(root, "provider-image.so", limit=CHECKER.MAX_PROVIDER_BYTES)
            self.assertEqual(CHECKER.MAX_PROVIDER_BYTES, len(accepted))
            self.assertEqual(CHECKER.parse_provider(accepted)["buildId"], CHECKER.parse_provider(original)["buildId"])

            oversized = exact_limit_data + b"\0"
            self.assertEqual(CHECKER.MAX_PROVIDER_BYTES + 1, len(oversized))
            provider_path.write_bytes(oversized)
            with self.assertRaisesRegex(SystemExit, "per-file byte limit: provider-image.so"):
                CHECKER.validate_root(root, write_report=False)

    def test_forged_retained_build_and_managed_executable_hashes_are_rejected(self) -> None:
        mutations = (
            ("makefileSha256", lambda record, commands: record.__setitem__("makefileSha256", "0" * 64), "native build makefileSha256 does not bind retained bytes"),
            ("toolchain", lambda record, commands: record["toolchain"].__setitem__("assemblerVersionLine", "forged assembler version"), "native tool identity claim assemblerVersionLine differs from its retained version bytes"),
            ("managed-cli", lambda record, commands: record["managedBuild"].__setitem__("cliAssemblySha256", "0" * 64), "managed executable identity claim"),
        )
        for label, mutate, expected in mutations:
            with self.subTest(field=label), tempfile.TemporaryDirectory() as temporary:
                root = self._copy(temporary)
                build_path = root / "native-build.json"
                build = json.loads(build_path.read_text(encoding="utf-8"))
                commands_path = root / "commands.json"
                commands = json.loads(commands_path.read_text(encoding="utf-8"))
                report_path = root / "external-provider-evidence.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                mutate(build, commands)
                if label == "managed-cli":
                    commands["managedCliSha256"] = "0" * 64
                    report["buildProvenance"]["managedCliAssemblySha256"] = "0" * 64
                elif label == "toolchain":
                    report["buildProvenance"]["assemblerVersion"] = "forged assembler version"
                elif label == "makefileSha256":
                    report["buildProvenance"]["makefileSha256"] = "0" * 64
                self._write_json(root, "native-build.json", build)
                self._write_json(root, "commands.json", commands)
                self._write_json(root, "external-provider-evidence.json", report)
                self._refresh_manifest_entries(root, {"native-build.json", "commands.json", "external-provider-evidence.json"})
                with self.assertRaisesRegex(SystemExit, expected):
                    CHECKER.validate_root(root, write_report=False)

    def test_refreshed_relocation_bounds_and_output_claims_are_rejected(self) -> None:
        mutations = (
            lambda report: report["sourceElfFacts"]["relocation"].__setitem__("virtualAddress", report["sourceElfFacts"]["relocation"]["virtualAddress"] + 8),
            lambda report: report["sourceElfFacts"]["sourceDispatch"]["guard"].__setitem__("defaultAddress", report["sourceElfFacts"]["sourceDispatch"]["guard"]["branchAddress"]),
            lambda report: report["artifacts"].__setitem__("nativeImageSha256", "f" * 64),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = self._copy(temporary)
                self._rewrite_report(root, mutation)
                with self.assertRaises(SystemExit):
                    CHECKER.validate_root(root, write_report=False)

    def test_refreshed_command_release_and_publication_mutations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            commands_path = root / "commands.json"
            commands = json.loads(commands_path.read_text(encoding="utf-8"))
            commands["producer"]["argv"].remove("--provider-build-id")
            commands_path.write_text(json.dumps(commands, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            CHECKER.write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "exact required all-or-none provider configuration"):
                CHECKER.validate_root(root, write_report=False)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            record_path = root / "handoffs/source/urp_entry/index-0.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["releaseOrder"] = "release-before-dispatch"
            record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            CHECKER.write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "releaseOrder"):
                CHECKER.validate_root(root, write_report=False)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            (root / "negative-native-image.bin").write_bytes(b"unexpected publication")
            CHECKER.write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "unexpected path: negative-native-image.bin"):
                CHECKER.validate_root(root, write_report=False)

    def test_refreshed_runtime_identity_with_forged_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            identity_path = root / "runtime-identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["version"] = "glibc 2.99"
            identity["identitySha256"] = CHECKER._IDENTITY.canonical_identity_digest(identity)
            identity_path.write_text(json.dumps(identity, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            report_path = root / "external-provider-evidence.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["execution"]["glibcVersion"] = identity["version"]
            report["execution"]["runtimeIdentitySha256"] = identity["identitySha256"]
            report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            CHECKER.write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "directly executing current process"):
                CHECKER.validate_root(root, write_report=False)

    def _append_native_pt_load(
        self,
        image: bytearray,
        *,
        flags: int,
        virtual_address: int,
        file_offset: int,
        file_size: int,
        memory_size: int,
    ) -> None:
        self.assertGreaterEqual(memory_size, file_size)
        self.assertLessEqual(file_offset, len(image))
        self.assertLessEqual(file_size, len(image) - file_offset)
        old_phoff = struct.unpack_from("<Q", image, 32)[0]
        phentsize = struct.unpack_from("<H", image, 54)[0]
        phnum = struct.unpack_from("<H", image, 56)[0]
        self.assertGreaterEqual(phentsize, 56)
        self.assertLess(phnum, 0xFFFF)
        old_table_size = phentsize * phnum
        self.assertLessEqual(old_phoff, len(image))
        self.assertLessEqual(old_table_size, len(image) - old_phoff)

        relocated_table = bytes(image[old_phoff : old_phoff + old_table_size])
        added_header = bytearray(phentsize)
        struct.pack_into(
            "<IIQQQQQQ",
            added_header,
            0,
            1,  # PT_LOAD
            flags,
            file_offset,
            virtual_address,
            0,
            file_size,
            memory_size,
            1,  # p_align
        )
        new_phoff = len(image)
        image.extend(relocated_table)
        image.extend(added_header)
        struct.pack_into("<Q", image, 32, new_phoff)
        struct.pack_into("<H", image, 56, phnum + 1)

    def test_refreshed_pt_load_code_overlaps_are_rejected_and_adjacent_ranges_remain_valid(self) -> None:
        root_data = json.loads((self.origin / "rehydration.json").read_text(encoding="utf-8"))
        output_range = root_data["layoutEvidence"]["addressMap"][0]["outputRange"]
        output_file = output_range["fileOffset"]["value"]
        output_va = output_range["virtualAddress"]["value"]
        output_size = output_range["size"]
        native_facts = json.loads((self.origin / "external-provider-evidence.json").read_text(encoding="utf-8"))["nativeElfFacts"]
        entry_file = native_facts["functions"]["urp_entry"]["fileOffset"]
        entry_va = native_facts["functions"]["urp_entry"]["virtualAddress"]

        overlap_cases = (
            (
                "one-byte-PF_R-interior",
                4,
                output_va + 1,
                output_file + 1,
                1,
                1,
                "complete emitted Native Image urp_entry output range intersects another PT_LOAD memory range",
            ),
            (
                "PF_RX-interior-instruction-subrange",
                5,
                output_va + 4,
                output_file + 4,
                4,
                4,
                "complete emitted Native Image urp_entry output range intersects another PT_LOAD memory range",
            ),
            (
                "duplicate-full-PF_RX-owner",
                5,
                output_va,
                output_file,
                output_size,
                output_size,
                "complete emitted Native Image urp_entry output range is not uniquely backed by a file range in one PT_LOAD",
            ),
            (
                "BSS-only-interior",
                4,
                output_va + 2,
                output_file + 2,
                0,
                1,
                "complete emitted Native Image urp_entry output range intersects another PT_LOAD memory range",
            ),
            (
                "one-byte-PF_R-live-entry-stub",
                4,
                entry_va + 1,
                entry_file + 1,
                1,
                1,
                "Native Image urp_entry branch stub intersects another PT_LOAD memory range",
            ),
        )
        for name, flags, virtual_address, file_offset, file_size, memory_size, expected in overlap_cases:
            with self.subTest(overlap=name), tempfile.TemporaryDirectory() as temporary:
                root = self._copy(temporary)

                def mutate(image: bytearray) -> None:
                    self._append_native_pt_load(
                        image,
                        flags=flags,
                        virtual_address=virtual_address,
                        file_offset=file_offset,
                        file_size=file_size,
                        memory_size=memory_size,
                    )

                self._refresh_native_image_chain(root, mutate, rerun_handoffs=False)
                # The closed manifest is valid; rejection must be semantic, not stale checksums.
                CHECKER.check_closed_manifest(root)
                with self.assertRaisesRegex(SystemExit, expected):
                    CHECKER.validate_root(root, write_report=False)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)

            def add_half_open_controls(image: bytearray) -> None:
                self._append_native_pt_load(
                    image,
                    flags=4,
                    virtual_address=output_va - 1,
                    file_offset=output_file - 1,
                    file_size=1,
                    memory_size=1,
                )
                self._append_native_pt_load(
                    image,
                    flags=4,
                    virtual_address=output_va + output_size,
                    file_offset=output_file + output_size - 1,
                    file_size=1,
                    memory_size=1,
                )
                self._append_native_pt_load(
                    image,
                    flags=4,
                    virtual_address=output_va + output_size + 2,
                    file_offset=0,
                    file_size=0,
                    memory_size=1,
                )
                self._append_native_pt_load(
                    image,
                    flags=4,
                    virtual_address=output_va + 1,
                    file_offset=0,
                    file_size=0,
                    memory_size=0,
                )

            native_data = bytearray((root / "native-image.bin").read_bytes())
            add_half_open_controls(native_data)
            elf = CHECKER._DYNAMIC.ElfImage(bytes(native_data), "half-open PT_LOAD controls")
            loads = [{
                "fileOffset": segment["offset"],
                "virtualAddress": segment["vaddr"],
                "fileSize": segment["filesz"],
                "memorySize": segment["memsz"],
            } for segment in elf.loads]
            owner_offset, _owner = CHECKER._unique_code_load_owner(
                bytes(native_data), loads, output_va, output_size,
                "adjacent-range complete Native Image urp_entry output control",
            )
            stub_offset, _stub_owner = CHECKER._unique_code_load_owner(
                bytes(native_data), loads, entry_va, 4,
                "adjacent-range Native Image urp_entry branch stub control",
            )
            self.assertEqual(output_file, owner_offset)
            self.assertEqual(entry_file, stub_offset)

    def test_checked_code_load_intervals_accept_u64_endpoint_and_reject_overflow(self) -> None:
        file_offset, owner = CHECKER._unique_code_load_owner(
            b"x",
            [{"flags": 5, "fileOffset": 0, "virtualAddress": (1 << 64) - 1, "fileSize": 1, "memorySize": 1}],
            (1 << 64) - 1,
            1,
            "u64-endpoint test",
        )
        self.assertEqual((0, 5), (file_offset, owner["flags"]))
        with self.assertRaisesRegex(SystemExit, "overflowing PT_LOAD interval"):
            CHECKER._unique_code_load_owner(
                b"xx",
                [{"flags": 5, "fileOffset": 0, "virtualAddress": (1 << 64) - 1, "fileSize": 2, "memorySize": 2}],
                (1 << 64) - 1,
                2,
                "u64-overflow test",
            )

    def test_refreshed_native_output_pt_load_truncation_is_rejected_before_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            rehydration = json.loads((root / "rehydration.json").read_text(encoding="utf-8"))
            output_range = rehydration["layoutEvidence"]["addressMap"][0]["outputRange"]
            output_file = output_range["fileOffset"]["value"]
            output_va = output_range["virtualAddress"]["value"]
            output_size = output_range["size"]
            source_size = json.loads((root / "external-provider-evidence.json").read_text(encoding="utf-8"))["nativeElfFacts"]["functions"]["urp_entry"]["size"]
            self.assertEqual((40, 92), (source_size, output_size))

            native_path = root / "native-image.bin"
            native = bytearray(native_path.read_bytes())
            phoff = struct.unpack_from("<Q", native, 32)[0]
            phentsize = struct.unpack_from("<H", native, 54)[0]
            phnum = struct.unpack_from("<H", native, 56)[0]
            candidates = []
            for index in range(phnum):
                header_offset = phoff + index * phentsize
                p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from(
                    "<IIQQQQQQ", native, header_offset
                )
                if (
                    p_type == 1
                    and output_va >= p_vaddr
                    and output_va + output_size <= p_vaddr + p_filesz
                    and p_filesz <= p_memsz
                    and p_offset + p_filesz <= len(native)
                ):
                    candidates.append((header_offset, p_vaddr, p_filesz, p_memsz))
            self.assertEqual(1, len(candidates))
            header_offset, segment_va, old_filesz, _old_memsz = candidates[0]
            truncated_size = output_va - segment_va + source_size
            self.assertLess(truncated_size, old_filesz)
            struct.pack_into("<Q", native, header_offset + 32, truncated_size)
            struct.pack_into("<Q", native, header_offset + 40, truncated_size)
            segments = CHECKER._INDIRECT.parse_load_segments(bytes(native), "truncated Native Image")
            mapped_prefix, _ = CHECKER._INDIRECT.mapped_file_offset(
                segments, output_va, source_size, "retained 40-byte source-sized prefix"
            )
            self.assertEqual(output_file, mapped_prefix)
            with self.assertRaisesRegex(SystemExit, "complete emitted Native Image urp_entry output range"):
                CHECKER._INDIRECT.mapped_file_offset(
                    segments, output_va, output_size, "complete emitted Native Image urp_entry output range"
                )
            with self.assertRaisesRegex(SystemExit, "live dispatcher branch target"):
                CHECKER._INDIRECT.mapped_file_offset(
                    segments, output_va + 64, 4, "live dispatcher branch target"
                )

            # Refresh only file/report digests. Do not invoke the HostContext
            # helper with this deliberately malformed PT_LOAD map.
            self._refresh_native_image_chain(
                root,
                lambda image: image.__setitem__(slice(None), native),
                rerun_handoffs=False,
            )
            with self.assertRaisesRegex(SystemExit, "complete emitted Native Image urp_entry output range"):
                CHECKER.validate_root(root, write_report=False)

    @staticmethod
    def _pax_record(key: str, value: bytes) -> bytes:
        body = key.encode("ascii") + b"=" + value + b"\n"
        length = len(body) + 2
        while True:
            updated = len(body) + len(str(length)) + 1
            if updated == length:
                return str(length).encode("ascii") + b" " + body
            length = updated

    @classmethod
    def _tar_with_pax_headers(cls, payloads: list[bytes]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for payload in payloads:
                info = tarfile.TarInfo("././@PaxHeader")
                info.type = tarfile.XHDTYPE
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        return output.getvalue()

    def _write_provenance_stream(self, root: Path, compressed: bytes) -> None:
        (root / "build-provenance.tar.gz").write_bytes(compressed)

    def test_positive_provider_provenance_pins_sibling_range_helper_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-provider-range-helper-tamper-") as temporary:
            root = self._copy(temporary)
            compressed = (root / "build-provenance.tar.gz").read_bytes()
            expanded = bytearray(CHECKER._decompress_provenance_gzip(compressed))
            target = "build-inputs/evidence-tools/scripts/evidence_load_range.py"
            offset = 0
            found = False
            while offset + 512 <= len(expanded):
                header = bytes(expanded[offset : offset + 512])
                if header == bytes(512):
                    break
                name = header[:100].split(b"\0", 1)[0].decode("utf-8", errors="strict")
                size_text = header[124:136].strip(b"\0 ")
                size = int(size_text or b"0", 8)
                payload_start = offset + 512
                if name == target:
                    if size == 0:
                        self.fail("retained evidence helper unexpectedly has no source bytes")
                    expanded[payload_start] ^= 1
                    found = True
                    break
                offset = payload_start + ((size + 511) // 512) * 512
            self.assertTrue(found, "provider provenance archive omits the range helper")
            (root / "build-provenance.tar.gz").write_bytes(gzip.compress(bytes(expanded)))
            CHECKER.write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "evidenceLoadRangeHelperSha256 does not bind retained evidence tool source"):
                CHECKER.validate_root(root, write_report=False)

    def test_compressed_small_expanded_over_limit_pax_is_rejected_before_tarfile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pax = self._pax_record("comment", b"x" * 24_000)
            expanded = self._tar_with_pax_headers([pax])
            compressed = gzip.compress(expanded, compresslevel=9)
            self.assertLess(len(compressed), 4096)
            self.assertGreater(len(expanded), 4096)
            self._write_provenance_stream(root, compressed)
            with (
                mock.patch.object(CHECKER, "MAX_PROVENANCE_EXPANDED_BYTES", 4096),
                mock.patch.object(CHECKER.tarfile, "open", side_effect=AssertionError("tar parser must not run")) as tar_open,
            ):
                with self.assertRaisesRegex(SystemExit, "expanded tar exceeds its 4096-byte bound"):
                    CHECKER._read_build_provenance_bundle(root)
                tar_open.assert_not_called()

    def test_repeated_hidden_pax_headers_are_rejected_before_tarfile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mtime = self._pax_record("mtime", b"1.25")
            compressed = gzip.compress(self._tar_with_pax_headers([mtime, mtime]), compresslevel=9)
            self._write_provenance_stream(root, compressed)
            with mock.patch.object(
                CHECKER.tarfile,
                "open",
                side_effect=AssertionError("tar parser must not run"),
            ) as tar_open:
                with self.assertRaisesRegex(SystemExit, "repeated hidden PAX extension headers"):
                    CHECKER._read_build_provenance_bundle(root)
                tar_open.assert_not_called()

    def test_truncated_and_concatenated_provenance_gzip_are_rejected(self) -> None:
        single = gzip.compress(b"bounded tar bytes")
        with self.assertRaisesRegex(SystemExit, "gzip is truncated or malformed"):
            CHECKER._decompress_provenance_gzip(single[:-4])
        with self.assertRaisesRegex(SystemExit, "trailing bytes or concatenated members"):
            CHECKER._decompress_provenance_gzip(single + gzip.compress(b"second member"))

    def _assert_rehashed_transformed_rollback_rejected(self, root: Path, mutate, message: str) -> None:
        path = root / "transformed-native-rollback.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        mutate(record)
        self._write_json(root, "transformed-native-rollback.json", record)
        commands_path = root / "commands.json"
        commands = json.loads(commands_path.read_text(encoding="utf-8"))
        commands["transformedNativeRollback"]["recordSha256"] = CHECKER.sha256_bytes(path.read_bytes())
        self._write_json(root, "commands.json", commands)
        CHECKER.write_closed_manifest(root)
        with self.assertRaisesRegex(SystemExit, message):
            CHECKER.validate_root(root, write_report=False)

    def test_refreshed_transformed_rollback_rejects_detached_native_input_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            source_sha = CHECKER.sha256_bytes((root / "source-image.bin").read_bytes())
            self._assert_rehashed_transformed_rollback_rejected(
                root,
                lambda record: record["input"].__setitem__("nativeImageSha256", source_sha),
                "did not consume the exact retained transformed Native Image bytes",
            )

    def test_refreshed_transformed_rollback_rejects_source_chain_digest_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            commands_path = root / "commands.json"
            commands = json.loads(commands_path.read_text(encoding="utf-8"))
            commands["transformedNativeRollback"]["sourceImageSha256"] = "0" * 64
            self._write_json(root, "commands.json", commands)
            CHECKER.write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "does not bind exact source/protected/native/runtime evidence bytes"):
                CHECKER.validate_root(root, write_report=False)

    def test_refreshed_transformed_rollback_rejects_extra_record_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            self._assert_rehashed_transformed_rollback_rejected(
                root, lambda record: record.__setitem__("unrecognized", True),
                "record fields are not the exact schema",
            )

    def test_refreshed_transformed_rollback_rejects_missing_pt_load_mapping_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)

            def remove_owner_byte(record: dict) -> None:
                evidence = record["mappingEvidence"]["retry"]
                consumer = evidence["consumer"]
                identity = consumer["identity"]
                data = (root / "native-image.bin").read_bytes()
                loads = CHECKER._parse_mapped_elf_loads(data, "mutated native image")
                bias = record["retry"]["consumerLoadBias"]
                segment_start = bias + next(segment["vaddr"] for segment in loads if segment["memsz"] != 0)
                rows = evidence["processMapsActive"]
                owner = next(row for row in rows
                    if row["start"] == segment_start
                    and row["deviceMajor"] == identity["deviceMajor"]
                    and row["deviceMinor"] == identity["deviceMinor"]
                    and row["inode"] == identity["inode"])
                owner["start"] += 1
                owner["offset"] += 1
                recorded_owner = next(row for row in consumer["active"]
                    if row["deviceMajor"] == identity["deviceMajor"]
                    and row["deviceMinor"] == identity["deviceMinor"]
                    and row["inode"] == identity["inode"]
                    and row["end"] == owner["end"] and row["offset"] + 1 == owner["offset"])
                recorded_owner["start"] += 1
                recorded_owner["offset"] += 1

            self._assert_rehashed_transformed_rollback_rejected(
                root, remove_owner_byte, "PT_LOAD .* byte has no unique live mapping owner")

    def test_refreshed_transformed_rollback_rejects_cleanup_mapping_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)

            def restore_residual_map(record: dict) -> None:
                evidence = record["mappingEvidence"]["failpoint"]
                provider = evidence["provider"]
                provider["afterCleanup"] = [dict(provider["beforeCleanup"][0])]

            self._assert_rehashed_transformed_rollback_rejected(
                root, restore_residual_map, "remains mapped after rollback/release")

    def test_refreshed_transformed_rollback_rejects_forged_live_libc_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)

            def forge_libc_identity(record: dict) -> None:
                record["mappingEvidence"]["runtimeLibraries"]["libc"]["identity"]["inode"] += 1

            self._assert_rehashed_transformed_rollback_rejected(
                root, forge_libc_identity, "runtime libc mapping identity is not the actual loaded libc/loader backing file")


if __name__ == "__main__":
    unittest.main()
