from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check-static-function-pointer-evidence.py"
FIXTURE_PATH = ROOT / "tests/UrProtect.Core.Tests/Fixtures/StaticFunctionPointers/liburp-static-function-pointer.so"
SPEC = importlib.util.spec_from_file_location("static_function_pointer_evidence", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class StaticFunctionPointerEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = CHECKER.ElfImage(FIXTURE_PATH)
        self.caller = self.image.unique_symbol(".dynsym", "urp_entry")
        self.callback = self.image.unique_symbol(".symtab", "urp_static_callback")
        self.chain = CHECKER.find_chain(self.image, self.caller, self.callback)

    def test_native_entry_redirect_decodes_to_moved_emitted_function(self) -> None:
        self.assertEqual(0x20150, CHECKER.decode_b(0x14007FDA, 0x1E8))
        self.assertIsNone(CHECKER.decode_b(0x94007FDA, 0x1E8))  # BL is not the entry tail branch.

    def test_source_fixture_has_one_relocation_owned_static_callback_chain(self) -> None:
        owner = CHECKER.check_source_relocations(self.image, self.caller, self.callback, self.chain)

        self.assertEqual(self.callback.value, self.chain["targetAddress"])
        self.assertEqual(".rela.text", owner["relocationSectionName"])
        self.assertEqual(self.caller.section_index, owner["relocationSectionInfo"])
        self.assertEqual(self.callback.section_index, owner["targetSectionIndex"])
        self.assertEqual([275, 277], [row["relocationType"] for row in owner["rows"]])
        self.assertEqual([0, 0], [row["addend"] for row in owner["rows"]])

    def test_checker_rejects_broken_stack_roundtrip(self) -> None:
        mutated = bytearray(self.image.data)
        offset = self.image.file_offset(self.chain["storeAddress"], 4)
        struct.pack_into("<I", mutated, offset, 0xD503201F)  # NOP replaces STR.
        image = self._parse_mutated(mutated)

        with self.assertRaises(CHECKER.EvidenceError):
            CHECKER.find_chain(
                image,
                image.unique_symbol(".dynsym", "urp_entry"),
                image.unique_symbol(".symtab", "urp_static_callback"),
            )

    def test_checker_rejects_wrong_add_relocation_kind(self) -> None:
        mutated = bytearray(self.image.data)
        section = next(section for section in self.image.sections if section.kind == 4 and section.info == self.caller.section_index)
        row_index = next(index for index, row in enumerate(self.image.relocations[section.index]) if row[0] == self.chain["addAddress"])
        row_file_offset = section.offset + row_index * section.entry_size
        info = struct.unpack_from("<Q", mutated, row_file_offset + 8)[0]
        struct.pack_into("<Q", mutated, row_file_offset + 8, (info & 0xFFFFFFFF00000000) | 275)
        image = self._parse_mutated(mutated)
        caller = image.unique_symbol(".dynsym", "urp_entry")
        callback = image.unique_symbol(".symtab", "urp_static_callback")
        chain = CHECKER.find_chain(image, caller, callback)

        with self.assertRaises(CHECKER.EvidenceError):
            CHECKER.check_source_relocations(image, caller, callback, chain)

    def test_intact_copied_observer_evidence_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = parent / "source"
            self._create_observer_evidence(source)
            copied = parent / "intact-copy"
            shutil.copytree(source, copied)

            CHECKER.verify_manifest(copied)
            observer, observer_source, observer_target = CHECKER.validate_observer_evidence(
                copied,
                copied / "source-image.bin",
                copied / "native-image.bin",
                {"loaderId": CHECKER.EXPECTED_LOADER_ID},
                "unit.static-function-pointer",
            )

            self.assertEqual("passed", observer["status"])
            self.assertEqual(97, observer_source["processStatus"])
            self.assertEqual(97, observer_target["entryStatus"])

    def test_observer_source_process_status_file_mismatch_is_rejected_after_manifest_refresh(self) -> None:
        self._assert_observer_tamper_rejected(
            lambda root: (root / "observer-source-process-status.txt").write_text("96\n", encoding="ascii"),
            "source observer process-status file differs from its handoff",
        )

    def test_observer_target_process_status_file_mismatch_is_rejected_after_manifest_refresh(self) -> None:
        self._assert_observer_tamper_rejected(
            lambda root: (root / "observer-target-process-status.txt").write_text("96\n", encoding="ascii"),
            "transformed observer process-status file differs from its handoff",
        )

    def test_observer_summary_process_status_is_bound_to_status_files_and_handoffs(self) -> None:
        for field, expected in (
            ("sourceProcessStatus", "observer summary source process status is not bound to expected status 97"),
            ("nativeProcessStatus", "observer summary transformed process status is not bound to expected status 97"),
        ):
            with self.subTest(field=field):
                self._assert_observer_tamper_rejected(
                    lambda root, field=field: self._set_observer_summary(root, field, 96),
                    expected,
                )

    def test_observer_summary_entry_status_is_bound_to_handoff(self) -> None:
        for field, expected in (
            ("sourceEntryStatus", "observer summary source entry status is not bound to expected status 97"),
            ("nativeEntryStatus", "observer summary transformed entry status is not bound to expected status 97"),
        ):
            with self.subTest(field=field):
                self._assert_observer_tamper_rejected(
                    lambda root, field=field: self._set_observer_summary(root, field, 96),
                    expected,
                )

    def test_observer_entry_status_must_be_exact_contract_status_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            source_handoff = self._load_json(root / "observer-source-handoff.json")
            source_handoff["entryStatus"] = 96
            source_handoff["processStatus"] = 96
            self._write_json(root / "observer-source-handoff.json", source_handoff)
            (root / "observer-source-process-status.txt").write_text("96\n", encoding="ascii")
            summary = self._load_json(root / "observer-handoff-evidence.json")
            summary["sourceEntryStatus"] = 96
            summary["sourceProcessStatus"] = 96
            summary["sourceHandoffSha256"] = CHECKER.sha256(root / "observer-source-handoff.json")
            self._write_json(root / "observer-handoff-evidence.json", summary)

        self._assert_observer_tamper_rejected(mutate, "source observer entry status is not 97")

    def test_forged_observer_source_image_hash_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            source_handoff = self._load_json(root / "observer-source-handoff.json")
            source_handoff["nativeImageSha256"] = "a" * 64
            self._write_json(root / "observer-source-handoff.json", source_handoff)
            summary = self._load_json(root / "observer-handoff-evidence.json")
            summary["sourceHandoffSha256"] = CHECKER.sha256(root / "observer-source-handoff.json")
            summary["sourceImageSha256"] = "a" * 64
            self._write_json(root / "observer-handoff-evidence.json", summary)

        self._assert_observer_tamper_rejected(
            mutate,
            "source observer handoff image hash does not bind the retained image bytes",
        )

    def test_forged_observer_native_image_hash_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            summary = self._load_json(root / "observer-handoff-evidence.json")
            summary["nativeImageSha256"] = "b" * 64
            self._write_json(root / "observer-handoff-evidence.json", summary)

        self._assert_observer_tamper_rejected(
            mutate,
            "observer summary Native Image hash does not bind retained Native Image bytes",
        )

    def test_observer_release_order_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            source_handoff = self._load_json(root / "observer-source-handoff.json")
            source_handoff["releaseOrder"] = "release-before-entry-dispatch"
            self._write_json(root / "observer-source-handoff.json", source_handoff)
            self._refresh_observer_handoff_hash(root, "source")

        self._assert_observer_tamper_rejected(
            mutate,
            "source observer release order differs from the HostContext contract",
        )

    def test_transformed_observer_release_order_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            target_handoff = self._load_json(root / "observer-target-handoff.json")
            target_handoff["releaseOrder"] = "release-before-entry-dispatch"
            self._write_json(root / "observer-target-handoff.json", target_handoff)
            self._refresh_observer_handoff_hash(root, "target")

        self._assert_observer_tamper_rejected(
            mutate,
            "transformed observer release order differs from the HostContext contract",
        )

    def test_observer_failure_stage_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            target_handoff = self._load_json(root / "observer-target-handoff.json")
            target_handoff["firstFailureStage"] = "entry-dispatch"
            self._write_json(root / "observer-target-handoff.json", target_handoff)
            self._refresh_observer_handoff_hash(root, "target")

        self._assert_observer_tamper_rejected(
            mutate,
            "transformed observer handoff records a failure stage",
        )

    def test_observer_release_status_must_be_passed_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            source_handoff = self._load_json(root / "observer-source-handoff.json")
            source_handoff["releaseStatus"] = "failed"
            self._write_json(root / "observer-source-handoff.json", source_handoff)
            self._refresh_observer_handoff_hash(root, "source")

        self._assert_observer_tamper_rejected(mutate, "source observer release status is not passed")

    def test_observer_summary_release_status_is_bound_to_handoff(self) -> None:
        self._assert_observer_tamper_rejected(
            lambda root: self._set_observer_summary(root, "sourceReleaseStatus", "failed"),
            "observer summary source release status is not bound to the handoff",
        )

    def test_observer_loader_identity_is_exact_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            target_handoff = self._load_json(root / "observer-target-handoff.json")
            target_handoff["loaderId"] = "another.loader"
            self._write_json(root / "observer-target-handoff.json", target_handoff)
            self._refresh_observer_handoff_hash(root, "target")

        self._assert_observer_tamper_rejected(mutate, "transformed observer handoff has the wrong HostContext loader identity")

    def test_observer_process_entry_mismatch_is_rejected_after_manifest_refresh(self) -> None:
        def mutate(root: Path) -> None:
            source_handoff = self._load_json(root / "observer-source-handoff.json")
            source_handoff["processStatus"] = 96
            self._write_json(root / "observer-source-handoff.json", source_handoff)
            (root / "observer-source-process-status.txt").write_text("96\n", encoding="ascii")
            summary = self._load_json(root / "observer-handoff-evidence.json")
            summary["sourceProcessStatus"] = 96
            summary["sourceHandoffSha256"] = CHECKER.sha256(root / "observer-source-handoff.json")
            self._write_json(root / "observer-handoff-evidence.json", summary)

        self._assert_observer_tamper_rejected(
            mutate,
            "source observer process and entry statuses disagree",
        )

    def test_each_nonempty_observer_stream_is_rejected_after_manifest_refresh(self) -> None:
        for filename, expected in (
            ("observer-source.stdout", "observer source stdout must be empty for this fixture"),
            ("observer-source.stderr", "observer source stderr must be empty for this fixture"),
            ("observer-target.stdout", "observer target stdout must be empty for this fixture"),
            ("observer-target.stderr", "observer target stderr must be empty for this fixture"),
        ):
            with self.subTest(filename=filename):
                self._assert_observer_tamper_rejected(
                    lambda root, filename=filename: (root / filename).write_bytes(b"unexpected output\\n"),
                    expected,
                )

    def test_coherent_nonempty_observer_stdout_pair_is_rejected_after_manifest_refresh(self) -> None:
        self._assert_coherent_observer_stream_pair_rejected(
            "stdout",
            "observer source stdout must be empty for this fixture",
        )

    def test_coherent_nonempty_observer_stderr_pair_is_rejected_after_manifest_refresh(self) -> None:
        self._assert_coherent_observer_stream_pair_rejected(
            "stderr",
            "observer source stderr must be empty for this fixture",
        )

    def test_closed_manifest_rejects_changed_evidence_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "row.json"
            payload.write_text("{}\n", encoding="utf-8")
            digest = CHECKER.sha256(payload)
            (root / "SHA256SUMS").write_text(f"{digest}  row.json\n", encoding="utf-8")
            CHECKER.verify_manifest(root)
            payload.write_text("{\"tampered\": true}\n", encoding="utf-8")

            with self.assertRaises(CHECKER.EvidenceError):
                CHECKER.verify_manifest(root)

    def _assert_observer_tamper_rejected(self, mutate, message: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            self._create_observer_evidence(root)
            mutate(root)
            self._refresh_manifest(root)

            # Prove rejection is semantic: every changed evidence byte has a fresh manifest digest.
            CHECKER.verify_manifest(root)
            with self.assertRaisesRegex(CHECKER.EvidenceError, message):
                CHECKER.validate_observer_evidence(
                    root,
                    root / "source-image.bin",
                    root / "native-image.bin",
                    {"loaderId": CHECKER.EXPECTED_LOADER_ID},
                    "unit.static-function-pointer",
                )

    def _assert_coherent_observer_stream_pair_rejected(self, stream: str, expected: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            self._create_observer_evidence(root)
            payload = f"coherent unexpected {stream}\\n".encode("ascii")
            source_stream = root / f"observer-source.{stream}"
            target_stream = root / f"observer-target.{stream}"
            source_stream.write_bytes(payload)
            target_stream.write_bytes(payload)
            summary = self._load_json(root / "observer-handoff-evidence.json")
            source_digest_field = f"source{stream.capitalize()}Sha256"
            target_digest_field = f"native{stream.capitalize()}Sha256"
            summary[source_digest_field] = CHECKER.sha256(source_stream)
            summary[target_digest_field] = CHECKER.sha256(target_stream)
            self._write_json(root / "observer-handoff-evidence.json", summary)
            self._refresh_manifest(root)

            # The stream pair, summary digests, and complete outer manifest are coherent.
            CHECKER.verify_manifest(root)
            self.assertEqual(payload, source_stream.read_bytes())
            self.assertEqual(source_stream.read_bytes(), target_stream.read_bytes())
            refreshed_summary = self._load_json(root / "observer-handoff-evidence.json")
            self.assertEqual(CHECKER.sha256(source_stream), refreshed_summary[source_digest_field])
            self.assertEqual(CHECKER.sha256(target_stream), refreshed_summary[target_digest_field])

            with self.assertRaisesRegex(CHECKER.EvidenceError, expected):
                CHECKER.validate_observer_evidence(
                    root,
                    root / "source-image.bin",
                    root / "native-image.bin",
                    {"loaderId": CHECKER.EXPECTED_LOADER_ID},
                    "unit.static-function-pointer",
                )

    @classmethod
    def _create_observer_evidence(cls, root: Path) -> None:
        root.mkdir(parents=True)
        (root / "source-image.bin").write_bytes(b"retained source image")
        (root / "native-image.bin").write_bytes(b"retained native image")
        source_hash = CHECKER.sha256(root / "source-image.bin")
        native_hash = CHECKER.sha256(root / "native-image.bin")
        source_handoff = cls._handoff(source_hash)
        target_handoff = cls._handoff(native_hash)
        cls._write_json(root / "observer-source-handoff.json", source_handoff)
        cls._write_json(root / "observer-target-handoff.json", target_handoff)
        (root / "observer-source-process-status.txt").write_text("97\n", encoding="ascii")
        (root / "observer-target-process-status.txt").write_text("97\n", encoding="ascii")
        stream_hash = hashlib.sha256(b"").hexdigest()
        for side in ("source", "target"):
            for stream in ("stdout", "stderr"):
                (root / f"observer-{side}.{stream}").write_bytes(b"")
        summary = {
            "schemaVersion": 1,
            "status": "passed",
            "unitId": "unit.static-function-pointer",
            "sourceImageSha256": source_hash,
            "nativeImageSha256": native_hash,
            "sourceHandoffSha256": CHECKER.sha256(root / "observer-source-handoff.json"),
            "nativeHandoffSha256": CHECKER.sha256(root / "observer-target-handoff.json"),
            "sourceProcessStatus": 97,
            "nativeProcessStatus": 97,
            "sourceEntryStatus": 97,
            "nativeEntryStatus": 97,
            "sourceReleaseStatus": "passed",
            "nativeReleaseStatus": "passed",
            "sourceStdoutSha256": stream_hash,
            "nativeStdoutSha256": stream_hash,
            "sourceStderrSha256": stream_hash,
            "nativeStderrSha256": stream_hash,
            "loaderId": CHECKER.EXPECTED_LOADER_ID,
        }
        cls._write_json(root / "observer-handoff-evidence.json", summary)
        cls._refresh_manifest(root)

    @staticmethod
    def _handoff(image_hash: str) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "status": "passed",
            "stage": "host-context-handoff",
            "entrySymbol": "urp_observer",
            "nativeImageSha256": image_hash,
            "entryStatus": 97,
            "processStatus": 97,
            "releaseStatus": "passed",
            "releaseOrder": CHECKER.EXPECTED_RELEASE_ORDER,
            "firstFailureStage": None,
            "loaderId": CHECKER.EXPECTED_LOADER_ID,
        }

    @classmethod
    def _set_observer_summary(cls, root: Path, field: str, value: object) -> None:
        summary = cls._load_json(root / "observer-handoff-evidence.json")
        summary[field] = value
        cls._write_json(root / "observer-handoff-evidence.json", summary)

    @classmethod
    def _refresh_observer_handoff_hash(cls, root: Path, side: str) -> None:
        summary = cls._load_json(root / "observer-handoff-evidence.json")
        handoff_name = "observer-source-handoff.json" if side == "source" else "observer-target-handoff.json"
        digest_field = "sourceHandoffSha256" if side == "source" else "nativeHandoffSha256"
        summary[digest_field] = CHECKER.sha256(root / handoff_name)
        cls._write_json(root / "observer-handoff-evidence.json", summary)

    @staticmethod
    def _load_json(path: Path) -> dict[str, object]:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _write_json(path: Path, value: dict[str, object]) -> None:
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _refresh_manifest(root: Path) -> None:
        entries = []
        for path in sorted(path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"):
            entries.append(f"{CHECKER.sha256(path)}  {path.relative_to(root).as_posix()}\n")
        (root / "SHA256SUMS").write_text("".join(entries), encoding="utf-8")

    @staticmethod
    def _parse_mutated(data: bytearray):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mutated.so"
            path.write_bytes(data)
            return CHECKER.ElfImage(path)


if __name__ == "__main__":
    unittest.main()
