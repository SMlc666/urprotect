from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check-shared-jump-table-evidence.py"
FIXTURE = ROOT / "tests/fixtures/shared-jump-table-evidence"
UNIT = "runtime.indirect-control.shared-table.glibc.host-context-entry"
EXPECTED_OBSERVER_STATUS = 91


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_manifest(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{_sha(path.read_bytes())}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _dynsym_records(image: bytes) -> dict[int, tuple[str, int, int, int, int, int, int]]:
    shoff = struct.unpack_from("<Q", image, 40)[0]
    shentsize, shnum = struct.unpack_from("<HH", image, 58)
    records: dict[int, tuple[str, int, int, int, int, int, int]] = {}
    for section_index in range(shnum):
        section_offset = shoff + section_index * shentsize
        _name, section_type = struct.unpack_from("<II", image, section_offset)
        if section_type != 11:
            continue
        header = struct.unpack_from("<IIQQQQIIQQ", image, section_offset)
        table_offset, table_size, link, entry_size = header[4], header[5], header[6], header[9]
        string_header = shoff + link * shentsize
        string_data = struct.unpack_from("<IIQQQQ", image, string_header)
        strings = image[string_data[4]:string_data[4] + string_data[5]]
        if entry_size != 24 or table_size % entry_size:
            raise AssertionError("shared-table ELF has malformed dynsym")
        for index in range(table_size // entry_size):
            offset = table_offset + index * entry_size
            name_offset, info, other, section, value, size = struct.unpack_from("<IBBHQQ", image, offset)
            end = strings.find(b"\0", name_offset)
            if end < 0:
                raise AssertionError("shared-table ELF has malformed dynsym name")
            records[index] = (strings[name_offset:end].decode(), value, size, info & 0xF, info >> 4, other & 0x3, section)
    return records


def _dynsym_selector(image: bytes) -> str:
    shoff = struct.unpack_from("<Q", image, 40)[0]
    shentsize, shnum = struct.unpack_from("<HH", image, 58)
    for section_index in range(shnum):
        section_offset = shoff + section_index * shentsize
        _name, section_type = struct.unpack_from("<II", image, section_offset)
        if section_type != 11:
            continue
        _name, _type, _flags, _address, table_offset, table_size, link, _info, _align, entry_size = struct.unpack_from(
            "<IIQQQQIIQQ", image, section_offset)
        if entry_size != 24 or table_size % 24:
            raise AssertionError("shared-table source fixture has malformed dynsym")
        string_header = shoff + link * shentsize
        _string_name, _string_type, _string_flags, _string_address, string_offset, string_size = struct.unpack_from(
            "<IIQQQQ", image, string_header)
        strings = image[string_offset:string_offset + string_size]
        for symbol_index in range(table_size // 24):
            symbol_offset = table_offset + symbol_index * 24
            name_offset = struct.unpack_from("<I", image, symbol_offset)[0]
            end = strings.find(b"\0", name_offset)
            if end >= 0 and strings[name_offset:end] == b"urp_entry":
                return f"dynsym:{symbol_index}"
    raise AssertionError("shared-table source fixture has no dynamic urp_entry")


def _file_offset_for_va(image: bytes, address: int, size: int) -> int:
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    matches = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _p_memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", image, offset
        )
        if p_type == 1 and address >= p_vaddr and address - p_vaddr <= p_filesz and size <= p_filesz - (address - p_vaddr):
            matches.append(p_offset + address - p_vaddr)
    if len(matches) != 1:
        raise AssertionError("address is not uniquely file-backed in the test ELF")
    return matches[0]


class _FakeNativeRuntimeIdentity:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str, bool]] = []

    def validate_handoff_runtime_identity(
        self,
        root: Path,
        handoff: dict[str, Any],
        *,
        expected_runtime: str,
        expected_role: str,
        expected_image_sha256: str,
        required: bool,
    ) -> dict[str, str]:
        del root
        self.calls.append((handoff["label"], expected_runtime, expected_role, expected_image_sha256, required))
        identity = handoff.get("runtimeIdentity")
        if identity is None:
            raise ValueError("synthetic identity missing")
        if identity.get("runtime") != expected_runtime:
            raise ValueError("runtime mismatch")
        if identity.get("role") != expected_role:
            raise ValueError("role mismatch")
        if identity.get("imageSha256") != expected_image_sha256:
            raise ValueError("image digest mismatch")
        return {key: identity[key] for key in ("runtime", "runtimeVersion", "libcSha256", "loaderSha256")}

    @staticmethod
    def require_same_runtime_identity(first: dict[str, str], other: dict[str, str]) -> None:
        if first != other:
            raise ValueError("identity mismatch")


class SharedJumpTableEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        if not FIXTURE.is_dir():
            self.skipTest("shared jump-table evidence fixture has not been materialized")
        self.temporary = tempfile.TemporaryDirectory(prefix="shared-jump-table-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "evidence"
        shutil.copytree(FIXTURE, self.root)
        self.source = (self.root / "source-image.bin").read_bytes()
        self.selector = _dynsym_selector(self.source)

    def run_checker(
        self,
        root: Path | None = None,
        *,
        runtime: str = "glibc",
        unit: str = UNIT,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                str(root or self.root),
                "--unit",
                unit,
                "--selected-function",
                self.selector,
                "--runtime",
                runtime,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def refresh_behavior_handoff_digest(self, handoff_name: str, behavior_field: str) -> dict[str, Any]:
        behavior = _read_json(self.root / "shared-table-behavior.json")
        behavior[behavior_field] = _sha((self.root / handoff_name).read_bytes())
        return behavior

    def refresh_native_bindings(self) -> None:
        native_path = self.root / "native-image.bin"
        native = native_path.read_bytes()
        native_hash = _sha(native)
        rehydration_path = self.root / "rehydration.json"
        rehydration = _read_json(rehydration_path)
        rehydration["nativeImageSha256"] = native_hash
        rehydration["nativeImageSize"] = len(native)
        rehydration["layoutEvidence"]["outputSha256"] = native_hash
        _write_json(rehydration_path, rehydration)
        metadata = _read_json(self.root / "native-image.json")
        metadata["nativeImageSha256"] = native_hash
        metadata["nativeImageSize"] = len(native)
        _write_json(self.root / "native-image.json", metadata)
        for name in ("handoff.json", "observer-transformed-handoff.json"):
            path = self.root / name
            record = _read_json(path)
            record["nativeImageSha256"] = native_hash
            _write_json(path, record)
        behavior_path = self.root / "shared-table-behavior.json"
        behavior = _read_json(behavior_path)
        behavior["observerTransformedNativeImageSha256"] = native_hash
        behavior["selectedTransformedHandoffSha256"] = _sha((self.root / "handoff.json").read_bytes())
        behavior["observerTransformedHandoffSha256"] = _sha((self.root / "observer-transformed-handoff.json").read_bytes())
        _write_json(behavior_path, behavior)

    def add_native_load_alias(
        self,
        virtual_address: int,
        file_offset: int,
        size: int,
        flags: int,
        *,
        partial: bool,
    ) -> None:
        if partial:
            virtual_address += size - 1
            file_offset += size - 1
            size = 1
        native_path = self.root / "native-image.bin"
        image = bytearray(native_path.read_bytes())
        phoff = struct.unpack_from("<Q", image, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", image, 54)
        if phentsize != 56:
            raise AssertionError("unexpected native ELF program-header size")
        previous_headers = bytes(image[phoff:phoff + phentsize * phnum])
        relocated_phoff = len(image)
        image.extend(previous_headers)
        image.extend(struct.pack(
            "<IIQQQQQQ", 1, flags, file_offset, virtual_address, virtual_address, size, size, 1
        ))
        struct.pack_into("<Q", image, 32, relocated_phoff)
        struct.pack_into("<H", image, 56, phnum + 1)
        native_path.write_bytes(image)

    def _selected_ranges(self) -> dict[str, tuple[int, int, int, int]]:
        source = (self.root / "source-image.bin").read_bytes()
        native = (self.root / "native-image.bin").read_bytes()
        index = int(self.selector.split(":", 1)[1])
        entry = _dynsym_records(source)[index]
        layout = _read_json(self.root / "rehydration.json")["layoutEvidence"]
        rows = [row for row in layout["addressMap"]
            if row.get("identity", "").startswith("region:")
            and row["sourceRange"]["virtualAddress"]["value"] == entry[1]
            and row["sourceRange"]["size"] == entry[2]]
        if len(rows) != 1:
            raise AssertionError("missing selected generated-code address map")
        code = rows[0]["outputRange"]
        clone = layout["jumpTableClones"][0]["outputRange"]
        return {
            "entry-stub": (entry[1], _file_offset_for_va(native, entry[1], 4), 4, 5),
            "emitted-code": (code["virtualAddress"]["value"], code["fileOffset"]["value"], code["size"], 5),
            "table-clone": (clone["virtualAddress"]["value"], clone["fileOffset"]["value"], clone["size"], 4),
        }

    def test_checked_in_evidence_fixture_is_accepted(self) -> None:
        result = self.run_checker()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_runtime_discriminator_rejects_refreshed_cross_runtime_claim(self) -> None:
        behavior_path = self.root / "shared-table-behavior.json"
        behavior = _read_json(behavior_path)
        behavior["runtime"] = "musl"
        _write_json(behavior_path, behavior)
        _refresh_manifest(self.root)

        result = self.run_checker(runtime="glibc")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("runtime discriminator", result.stderr.lower())
        self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_musl_runtime_requires_its_distinct_unit_id(self) -> None:
        result = self.run_checker(
            runtime="musl",
            unit="runtime.indirect-control.shared-table.glibc.host-context-entry",
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("unit id does not match the selected shared-table runtime", result.stderr.lower())

    def _load_checker_module(self) -> Any:
        checker_spec = importlib.util.spec_from_file_location("shared_identity_test_checker", CHECKER)
        self.assertIsNotNone(checker_spec)
        self.assertIsNotNone(checker_spec.loader)
        checker = importlib.util.module_from_spec(checker_spec)
        checker_spec.loader.exec_module(checker)
        return checker

    @staticmethod
    def _minimal_elf_with_section(section_type: int, file_offset: int, size: int) -> bytes:
        image = bytearray(64 + 2 * 64)
        image[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            image,
            16,
            1,
            183,
            1,
            0,
            0,
            64,
            0,
            64,
            56,
            0,
            64,
            2,
            0,
        )
        struct.pack_into(
            "<IIQQQQIIQQ",
            image,
            128,
            0,
            section_type,
            0,
            0,
            file_offset,
            size,
            0,
            0,
            8,
            0,
        )
        return bytes(image)

    def test_nobits_section_range_is_not_required_to_be_file_backed(self) -> None:
        checker = self._load_checker_module()
        with self.subTest(section_type="SHT_NOBITS"):
            program_headers, sections = checker.parse_elf(
                self._minimal_elf_with_section(8, 192, 64), "synthetic ELF"
            )
            self.assertEqual([], program_headers)
            self.assertEqual(64, sections[1]["size"])

        with self.subTest(section_type="file-backed"):
            with self.assertRaises(SystemExit) as failure:
                checker.parse_elf(self._minimal_elf_with_section(1, 192, 64), "synthetic ELF")
            self.assertIn("out-of-bounds section", str(failure.exception))

        with self.subTest(section_type="SHT_NOBITS offset overflow"):
            with self.assertRaises(SystemExit) as failure:
                checker.parse_elf(
                    self._minimal_elf_with_section(8, (1 << 64) - 32, 64), "synthetic ELF"
                )
            self.assertIn("overflowing section file range", str(failure.exception))

    def test_symbol_record_count_is_bounded_before_record_materialization(self) -> None:
        checker = self._load_checker_module()
        count = checker.MAX_EVIDENCE_SYMBOL_RECORDS + 1
        table_bytes = count * 24
        image = bytes(table_bytes + 1)
        sections = [
            {"type": 11, "link": 1, "entsize": 24, "size": table_bytes, "offset": 0},
            {"type": 3, "offset": table_bytes, "size": 1},
        ]

        with self.assertRaises(SystemExit) as failure:
            checker.symbol_records(image, sections, "synthetic ELF")

        self.assertIn("bounded symbol-record count", str(failure.exception))

        exact_count = checker.MAX_EVIDENCE_SYMBOL_RECORDS
        exact_table_bytes = exact_count * 24
        exact_image = bytes(exact_table_bytes + 1)
        exact_sections = [
            {"type": 11, "link": 1, "entsize": 24, "size": exact_table_bytes, "offset": 0},
            {"type": 3, "offset": exact_table_bytes, "size": 1},
        ]
        self.assertEqual(
            exact_count,
            len(checker.symbol_records(exact_image, exact_sections, "synthetic ELF")),
        )

    def test_symbol_name_decoding_has_per_name_and_aggregate_byte_budgets(self) -> None:
        checker = self._load_checker_module()
        with self.subTest(limit="aggregate maximum"):
            count = checker.MAX_EVIDENCE_SYMBOL_NAME_BYTES // checker.MAX_EVIDENCE_SYMBOL_NAME_LENGTH
            table_bytes = count * 24
            name = b"n" * checker.MAX_EVIDENCE_SYMBOL_NAME_LENGTH + b"\0"
            image = bytes(table_bytes) + name
            sections = [
                {"type": 11, "link": 1, "entsize": 24, "size": table_bytes, "offset": 0},
                {"type": 3, "offset": table_bytes, "size": len(name)},
            ]
            self.assertEqual(count, len(checker.symbol_records(image, sections, "synthetic ELF")))

        with self.subTest(limit="aggregate"):
            count = checker.MAX_EVIDENCE_SYMBOL_NAME_BYTES // checker.MAX_EVIDENCE_SYMBOL_NAME_LENGTH + 1
            table_bytes = count * 24
            name = b"n" * checker.MAX_EVIDENCE_SYMBOL_NAME_LENGTH + b"\0"
            image = bytearray(table_bytes + len(name))
            image[table_bytes:] = name
            sections = [
                {"type": 11, "link": 1, "entsize": 24, "size": table_bytes, "offset": 0},
                {"type": 3, "offset": table_bytes, "size": len(name)},
            ]
            with self.assertRaises(SystemExit) as failure:
                checker.symbol_records(bytes(image), sections, "synthetic ELF")
            self.assertIn("aggregate symbol-name byte count", str(failure.exception))

        with self.subTest(limit="single name"):
            table_bytes = 24
            name = b"n" * (checker.MAX_EVIDENCE_SYMBOL_NAME_LENGTH + 1) + b"\0"
            image = bytearray(table_bytes + len(name))
            image[table_bytes:] = name
            sections = [
                {"type": 11, "link": 1, "entsize": 24, "size": table_bytes, "offset": 0},
                {"type": 3, "offset": table_bytes, "size": len(name)},
            ]
            with self.assertRaises(SystemExit) as failure:
                checker.symbol_records(bytes(image), sections, "synthetic ELF")
            self.assertIn("unterminated or overlong symbol name", str(failure.exception))

    @staticmethod
    def _synthetic_runtime_handoffs(runtime: str = "musl") -> list[tuple[str, dict[str, Any], str, str]]:
        source_sha256 = "a" * 64
        target_sha256 = "b" * 64
        common_identity = {
            "runtime": runtime,
            "runtimeVersion": "1.2.3" if runtime == "musl" else None,
            "libcSha256": "c" * 64,
            "loaderSha256": "d" * 64,
        }
        result = []
        for label, role, image_sha256 in (
            ("selected source", "source", source_sha256),
            ("selected transformed", "target", target_sha256),
            ("observer source", "source", source_sha256),
            ("observer transformed", "target", target_sha256),
        ):
            identity = {**common_identity, "role": role, "imageSha256": image_sha256}
            result.append((label, {"label": label, "runtimeIdentity": identity}, role, image_sha256))
        return result

    def test_all_four_valid_musl_handoffs_share_the_checked_runtime_identity(self) -> None:
        checker = self._load_checker_module()
        handoffs = self._synthetic_runtime_handoffs()
        identity_helper = _FakeNativeRuntimeIdentity()

        checker.validate_runtime_identity_agreement(
            self.root, identity_helper, handoffs, expected_runtime="musl"
        )

        self.assertEqual(
            ["selected source", "selected transformed", "observer source", "observer transformed"],
            [call[0] for call in identity_helper.calls],
        )
        self.assertTrue(all(call[1] == "musl" and call[4] for call in identity_helper.calls))

    def test_all_four_valid_bionic_handoffs_share_the_checked_runtime_identity(self) -> None:
        checker = self._load_checker_module()
        handoffs = self._synthetic_runtime_handoffs("bionic")
        identity_helper = _FakeNativeRuntimeIdentity()

        checker.validate_runtime_identity_agreement(
            self.root, identity_helper, handoffs, expected_runtime="bionic"
        )

        self.assertEqual(
            ["selected source", "selected transformed", "observer source", "observer transformed"],
            [call[0] for call in identity_helper.calls],
        )
        self.assertTrue(all(call[1] == "bionic" and call[4] for call in identity_helper.calls))

    def test_musl_identity_is_required_individually_for_all_four_handoffs(self) -> None:
        checker = self._load_checker_module()
        for missing_index, (label, _handoff, _role, _image_sha256) in enumerate(self._synthetic_runtime_handoffs()):
            with self.subTest(handoff=label):
                handoffs = self._synthetic_runtime_handoffs()
                handoffs[missing_index][1]["runtimeIdentity"] = None
                identity_helper = _FakeNativeRuntimeIdentity()
                with self.assertRaises(SystemExit) as failure:
                    checker.validate_runtime_identity_agreement(
                        self.root, identity_helper, handoffs, expected_runtime="musl"
                    )
                self.assertIn(
                    f"{label} native runtime identity is invalid: synthetic identity missing",
                    str(failure.exception),
                )
                self.assertEqual(
                    [item[0] for item in handoffs[:missing_index + 1]],
                    [call[0] for call in identity_helper.calls],
                )

    def test_musl_identity_binds_each_handoff_role_and_image(self) -> None:
        checker = self._load_checker_module()
        for invalid_field in ("role", "imageSha256"):
            for invalid_index, (label, _handoff, _role, _image_sha256) in enumerate(
                self._synthetic_runtime_handoffs()
            ):
                with self.subTest(handoff=label, field=invalid_field):
                    handoffs = self._synthetic_runtime_handoffs()
                    handoffs[invalid_index][1]["runtimeIdentity"][invalid_field] = "wrong-binding"
                    identity_helper = _FakeNativeRuntimeIdentity()
                    with self.assertRaises(SystemExit) as failure:
                        checker.validate_runtime_identity_agreement(
                            self.root, identity_helper, handoffs, expected_runtime="musl"
                        )
                    self.assertIn(f"{label} native runtime identity is invalid:", str(failure.exception))

    def test_musl_handoffs_must_share_one_runtime_identity(self) -> None:
        checker = self._load_checker_module()
        handoffs = self._synthetic_runtime_handoffs()
        handoffs[3][1]["runtimeIdentity"]["loaderSha256"] = "e" * 64
        with self.assertRaises(SystemExit) as failure:
            checker.validate_runtime_identity_agreement(
                self.root, _FakeNativeRuntimeIdentity(), handoffs, expected_runtime="musl"
            )
        self.assertIn("shared-table handoffs used different native runtime identities", str(failure.exception))

    def test_musl_shared_evidence_without_selected_identity_reports_first_missing_handoff(self) -> None:
        musl_unit = "runtime.indirect-control.shared-table.musl.host-context-entry"
        for name in ("stage.json", "rehydration.json", "native-image.json", "shared-table-behavior.json"):
            path = self.root / name
            record = _read_json(path)
            record["unitId"] = musl_unit
            if name == "shared-table-behavior.json":
                record["runtime"] = "musl"
            _write_json(path, record)
        _refresh_manifest(self.root)

        result = self.run_checker(runtime="musl", unit=musl_unit)

        self.assertNotEqual(0, result.returncode)
        self.assertEqual(
            "selected source native runtime identity is invalid: HostContext handoff is missing its required native runtime identity\n",
            result.stderr,
        )
        self.assertNotIn("malformed", result.stderr.lower())
        self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_bounded_tree_rejects_directory_entry_and_file_count_limits(self) -> None:
        with self.subTest(limit="directories"):
            for index in range(512):
                (self.root / f"directory-{index:04d}").mkdir()
            result = self.run_checker()
            self.assertNotEqual(0, result.returncode)
            self.assertIn("directory count exceeds its configured bound", result.stderr.lower())

        with self.subTest(limit="entries"):
            shutil.rmtree(self.root)
            shutil.copytree(FIXTURE, self.root)
            initial_entries = sum(1 for _ in self.root.rglob("*"))
            directory_count = 511
            for index in range(directory_count):
                (self.root / f"entry-dir-{index:04d}").mkdir()
            file_count = 1025 - initial_entries - directory_count
            for index in range(file_count):
                (self.root / f"entry-file-{index:04d}.txt").touch()
            result = self.run_checker()
            self.assertNotEqual(0, result.returncode)
            self.assertIn("entry count exceeds its configured bound", result.stderr.lower())

        with self.subTest(limit="files"):
            shutil.rmtree(self.root)
            shutil.copytree(FIXTURE, self.root)
            initial_files = sum(1 for path in self.root.rglob("*") if path.is_file())
            for index in range(1000 - initial_files + 1):
                (self.root / f"extra-file-{index:04d}.txt").touch()
            result = self.run_checker()
            self.assertNotEqual(0, result.returncode)
            self.assertIn("file count exceeds its configured bound", result.stderr.lower())

    def test_bounded_tree_rejects_per_file_size_before_file_read(self) -> None:
        oversized = self.root / "oversized.bin"
        with oversized.open("wb") as output:
            output.truncate(16 * 1024 * 1024 + 1)

        result = self.run_checker()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("per-file byte bound", result.stderr.lower())

    def test_bounded_tree_rejects_aggregate_size_before_file_hashing(self) -> None:
        image_size = 128 * 1024 * 1024
        for directory_name, filename in (
            ("aggregate-source", "source-image.bin"),
            ("aggregate-native", "native-image.bin"),
        ):
            directory = self.root / directory_name
            directory.mkdir()
            with (directory / filename).open("wb") as sparse_image:
                sparse_image.truncate(image_size)

        result = self.run_checker()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("exceeds the bounded tree size", result.stderr.lower())

    def test_descriptor_anchored_reader_rejects_in_place_mutation_file_replacement_and_root_replacement(self) -> None:
        prior_range_module = sys.modules.get("evidence_load_range")
        hostile_range_module = types.ModuleType("evidence_load_range")
        hostile_range_module.unique_file_backed_pt_load = lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("ambient evidence-load-range module was used")
        )
        sys.modules["evidence_load_range"] = hostile_range_module
        checker_spec = importlib.util.spec_from_file_location("shared_tree_test_checker", CHECKER)
        self.assertIsNotNone(checker_spec)
        self.assertIsNotNone(checker_spec.loader)
        checker = importlib.util.module_from_spec(checker_spec)
        try:
            checker_spec.loader.exec_module(checker)
            self.assertIsNot(checker._EVIDENCE_RANGE_HELPER, hostile_range_module)
            self.assertEqual(
                str((ROOT / "scripts/evidence_load_range.py").resolve(strict=True)),
                checker._EVIDENCE_RANGE_HELPER.__file__,
            )
            tree = checker._load_bounded_evidence_tree(self.root)
            checker._ACTIVE_EVIDENCE_TREE = tree
            stage_path = self.root / "stage.json"
            with stage_path.open("r+b") as mutated:
                mutated.write(b"[")
            with self.assertRaises(SystemExit) as file_failure:
                checker.read_evidence_bytes(self.root, "stage.json", checker.MAX_EVIDENCE_JSON_BYTES)
            self.assertIn("changed after preflight", str(file_failure.exception).lower())

            replacement_tree = checker._load_bounded_evidence_tree(self.root)
            checker._ACTIVE_EVIDENCE_TREE = replacement_tree
            replacement_path = self.root.parent / "stage-replacement.json"
            replacement_path.write_bytes((FIXTURE / "stage.json").read_bytes())
            original_inode = stage_path.stat().st_ino
            os.replace(replacement_path, stage_path)
            self.assertNotEqual(original_inode, stage_path.stat().st_ino)
            with self.assertRaises(SystemExit) as replacement_failure:
                checker.read_evidence_bytes(self.root, "stage.json", checker.MAX_EVIDENCE_JSON_BYTES)
            self.assertIn("changed after bounded tree preflight", str(replacement_failure.exception).lower())

            root_tree = checker._load_bounded_evidence_tree(self.root)
            moved_root = self.root.with_name("evidence-moved")
            self.root.rename(moved_root)
            self.root.mkdir()
            with self.assertRaises(SystemExit) as root_failure:
                root_tree.read("stage.json", checker.MAX_EVIDENCE_JSON_BYTES)
            self.assertIn("root changed after bounded tree preflight", str(root_failure.exception).lower())
        finally:
            if prior_range_module is None:
                sys.modules.pop("evidence_load_range", None)
            else:
                sys.modules["evidence_load_range"] = prior_range_module

    def test_bounded_sibling_helper_loader_rejects_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shared-table-helper-fifo-") as temporary:
            helper_root = Path(temporary)
            checker_copy = helper_root / CHECKER.name
            shutil.copyfile(CHECKER, checker_copy)
            os.mkfifo(helper_root / "evidence_load_range.py")

            result = subprocess.run(
                [sys.executable, str(checker_copy), str(self.root)],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bounded shared-table PT_LOAD range helper is unavailable", result.stderr)

    def test_bounded_checker_helper_chain_rejects_nested_identity_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(prefix="shared-table-nested-helper-fifo-") as temporary:
            helper_root = Path(temporary) / "scripts"
            helper_root.mkdir()
            for name in (
                CHECKER.name,
                "evidence_load_range.py",
                "check-rehydration-evidence.py",
            ):
                shutil.copyfile(ROOT / "scripts" / name, helper_root / name)
            os.mkfifo(helper_root / "native_runtime_identity.py")
            evidence_root = Path(temporary) / "evidence"
            evidence_root.mkdir()

            result = subprocess.run(
                [
                    sys.executable,
                    str(helper_root / CHECKER.name),
                    str(evidence_root),
                    "--unit",
                    "runtime.indirect-control.shared-table.musl.host-context-entry",
                    "--selected-function",
                    "dynsym:1",
                    "--runtime",
                    "musl",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bounded shared-table evidence reader is unavailable", result.stderr)
        self.assertIn("runtime identity helper", result.stderr)

    def test_artifact_root_rejects_symlink_alias_and_nested_symlink(self) -> None:
        alias = self.root.parent / "evidence-root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        result = self.run_checker(alias)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("must be an isolated non-symlink directory", result.stderr.lower())

        nested = self.root / "unlisted-link"
        nested.symlink_to(self.root, target_is_directory=True)
        result = self.run_checker()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("contains a symlink", result.stderr.lower())

    def test_live_entry_b_stub_must_target_the_mapped_output_function_not_dead_default(self) -> None:
        ranges = self._selected_ranges()
        code_va, code_offset, code_size, _flags = ranges["emitted-code"]
        native_path = self.root / "native-image.bin"
        native = bytearray(native_path.read_bytes())
        words = struct.unpack_from(f"<{code_size // 4}I", native, code_offset)
        defaults = [index for index in range(len(words) - 1)
            if words[index:index + 2] == (0x12800000, 0xD65F03C0)]
        self.assertEqual(1, len(defaults), "expected the emitted safe-default MOV/RET pair")
        target_va = code_va + defaults[0] * 4
        entry_va, _entry_offset, _stub_size, _stub_flags = ranges["entry-stub"]
        delta = target_va - entry_va
        self.assertEqual(0, delta % 4)
        immediate = delta // 4
        self.assertGreaterEqual(immediate, -(1 << 25))
        self.assertLess(immediate, 1 << 25)
        struct.pack_into("<I", native, _file_offset_for_va(native, entry_va, 4), 0x14000000 | (immediate & 0x03FFFFFF))
        native_path.write_bytes(native)
        self.refresh_native_bindings()
        _refresh_manifest(self.root)

        result = self.run_checker()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("entry b target bypasses the exact selected output-function entry", result.stderr.lower())
        self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_partial_pt_load_intersections_reject_stub_code_and_clone(self) -> None:
        cases = (
            ("entry-stub", "native image urp_entry entry b stub"),
            ("emitted-code", "selected emitted shared-table code range"),
            ("table-clone", "native image cloned shared jump table"),
        )
        for mapping, label in cases:
            with self.subTest(mapping=mapping):
                shutil.rmtree(self.root)
                shutil.copytree(FIXTURE, self.root)
                ranges = self._selected_ranges()
                va, offset, size, flags = ranges[mapping]
                self.add_native_load_alias(va, offset, size, flags, partial=True)
                self.refresh_native_bindings()
                _refresh_manifest(self.root)

                result = self.run_checker()

                self.assertNotEqual(0, result.returncode)
                self.assertIn(label, result.stderr.lower())
                self.assertIn("partially intersects another pt_load memory interval", result.stderr.lower())
                self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_duplicate_fully_containing_pt_load_owners_reject_stub_code_and_clone(self) -> None:
        cases = (
            ("entry-stub", "native image urp_entry entry b stub"),
            ("emitted-code", "selected emitted shared-table code range"),
            ("table-clone", "native image cloned shared jump table"),
        )
        for mapping, label in cases:
            with self.subTest(mapping=mapping):
                shutil.rmtree(self.root)
                shutil.copytree(FIXTURE, self.root)
                ranges = self._selected_ranges()
                va, offset, size, flags = ranges[mapping]
                self.add_native_load_alias(va, offset, size, flags, partial=False)
                self.refresh_native_bindings()
                _refresh_manifest(self.root)

                result = self.run_checker()

                self.assertNotEqual(0, result.returncode)
                self.assertIn(label, result.stderr.lower())
                self.assertIn("exactly one fully containing file-backed pt_load owner", result.stderr.lower())
                self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_half_open_adjacent_load_ranges_remain_accepted(self) -> None:
        for va, offset, size, flags in self._selected_ranges().values():
            self.add_native_load_alias(va + size, offset + size, 1, flags, partial=False)
        self.refresh_native_bindings()
        _refresh_manifest(self.root)

        result = self.run_checker()

        self.assertEqual(0, result.returncode, result.stderr)

    def test_layout_clone_ownership_requires_exact_integer_json_token(self) -> None:
        positive = self.run_checker()
        self.assertEqual(0, positive.returncode, positive.stderr)

        rehydration_path = self.root / "rehydration.json"
        rehydration = _read_json(rehydration_path)
        rehydration["layoutEvidence"]["jumpTableClones"][0]["ownership"] = 2.0
        _write_json(rehydration_path, rehydration)
        _refresh_manifest(self.root)

        result = self.run_checker()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("ownership is not an integer", result.stderr.lower())
        self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_observer_source_handoff_tampering_is_rejected_semantically_after_refresh(self) -> None:
        mutations = (
            ("nativeImageSha256", "0" * 64, "image"),
            ("processStatus", EXPECTED_OBSERVER_STATUS + 1, "process"),
            ("loaderId", "forged-loader.identity", "loader"),
            ("releaseOrder", "release-before-entry", "release order"),
        )
        for field, forged_value, expected_message in mutations:
            with self.subTest(field=field):
                shutil.rmtree(self.root)
                shutil.copytree(FIXTURE, self.root)
                handoff_path = self.root / "observer-source-handoff.json"
                handoff = _read_json(handoff_path)
                handoff[field] = forged_value
                behavior = self.refresh_behavior_handoff_digest(
                    "observer-source-handoff.json",
                    "observerSourceHandoffSha256",
                )
                if field == "nativeImageSha256":
                    behavior["observerSourceNativeImageSha256"] = forged_value
                if field == "processStatus":
                    status_path = self.root / "observer-source.process-status"
                    status_path.write_text(f"{forged_value}\n", encoding="ascii")
                    behavior["observerSourceProcessStatus"] = forged_value
                    behavior["observerSourceProcessStatusSha256"] = _sha(status_path.read_bytes())
                _write_json(handoff_path, handoff)
                behavior["observerSourceHandoffSha256"] = _sha(handoff_path.read_bytes())
                _write_json(self.root / "shared-table-behavior.json", behavior)
                _refresh_manifest(self.root)

                result = self.run_checker()

                self.assertNotEqual(0, result.returncode)
                self.assertIn(expected_message, result.stderr.lower())
                self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_observer_source_stdout_tampering_is_rejected_after_binding_refresh(self) -> None:
        stream = self.root / "observer-source.stdout"
        stream.write_bytes(b"forged observer output\n")
        behavior = _read_json(self.root / "shared-table-behavior.json")
        behavior["observerSourceStdoutSha256"] = _sha(stream.read_bytes())
        behavior["observerSourceStdoutSize"] = stream.stat().st_size
        _write_json(self.root / "shared-table-behavior.json", behavior)
        _refresh_manifest(self.root)

        result = self.run_checker()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("expected empty stream", result.stderr.lower())
        self.assertNotIn("manifest digest mismatch", result.stderr.lower())

    def test_changed_rela_target_section_is_rejected_after_metadata_and_manifest_refresh(self) -> None:
        source_path = self.root / "source-image.bin"
        source = bytearray(source_path.read_bytes())
        shoff = struct.unpack_from("<Q", source, 40)[0]
        shentsize, shnum = struct.unpack_from("<HH", source, 58)
        rehydration_path = self.root / "rehydration.json"
        rehydration = _read_json(rehydration_path)
        owners = rehydration["layoutEvidence"]["jumpTableClones"][0]["ownerReferences"]
        owner_function_section = owners[0]["ownerFunctionSectionIndex"]
        source_sections = []
        for index in range(shnum):
            offset = shoff + index * shentsize
            name, section_type = struct.unpack_from("<II", source, offset)
            flags, address, file_offset, size = struct.unpack_from("<QQQQ", source, offset + 8)
            link, info = struct.unpack_from("<II", source, offset + 40)
            alignment, entry_size = struct.unpack_from("<QQ", source, offset + 48)
            source_sections.append({
                "name": name,
                "type": section_type,
                "flags": flags,
                "address": address,
                "offset": file_offset,
                "size": size,
                "link": link,
                "info": info,
                "alignment": alignment,
                "entsize": entry_size,
            })
        replacement_index = next(
            index for index, section in enumerate(source_sections)
            if index not in (0, owner_function_section)
            and section["type"] == 1
            and section["size"] > 0
            and not (section["flags"] & 0x4)
        )
        relocation_section_indices = sorted({owner["relocationSectionIndex"] for owner in owners})
        for relocation_section_index in relocation_section_indices:
            struct.pack_into(
                "<I",
                source,
                shoff + relocation_section_index * shentsize + 44,
                replacement_index,
            )
        source_bytes = bytes(source)
        source_path.write_bytes(source_bytes)
        replacement_section = source_sections[replacement_index]
        for owner in owners:
            owner["targetSectionIndex"] = replacement_index
            owner["ownerFunctionSectionIndex"] = replacement_index
            owner["ownerFunctionSection"] = {
                "name": replacement_section["name"],
                "type": replacement_section["type"],
                "flags": replacement_section["flags"],
                "address": replacement_section["address"],
                "offset": replacement_section["offset"],
                "size": replacement_section["size"],
                "link": replacement_section["link"],
                "info": replacement_section["info"],
                "addressAlignment": replacement_section["alignment"],
                "entrySize": replacement_section["entsize"],
            }
        _write_json(rehydration_path, rehydration)
        source_sha = _sha(source_bytes)
        stage_path = self.root / "stage.json"
        stage = _read_json(stage_path)
        stage["sourceSha256"] = source_sha
        _write_json(stage_path, stage)
        rehydration["sourceSha256"] = source_sha
        _write_json(rehydration_path, rehydration)
        native_metadata_path = self.root / "native-image.json"
        native_metadata = _read_json(native_metadata_path)
        native_metadata["sourceSha256"] = source_sha
        _write_json(native_metadata_path, native_metadata)
        source_handoff_path = self.root / "source-handoff.json"
        source_handoff = _read_json(source_handoff_path)
        source_handoff["nativeImageSha256"] = source_sha
        _write_json(source_handoff_path, source_handoff)
        observer_handoff_path = self.root / "observer-source-handoff.json"
        observer_handoff = _read_json(observer_handoff_path)
        observer_handoff["nativeImageSha256"] = source_sha
        _write_json(observer_handoff_path, observer_handoff)
        behavior = _read_json(self.root / "shared-table-behavior.json")
        behavior["observerSourceNativeImageSha256"] = source_sha
        behavior["observerSourceHandoffSha256"] = _sha(observer_handoff_path.read_bytes())
        behavior["selectedSourceHandoffSha256"] = _sha(source_handoff_path.read_bytes())
        _write_json(self.root / "shared-table-behavior.json", behavior)
        _refresh_manifest(self.root)

        result = self.run_checker()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("target section index does not match", result.stderr.lower())
        self.assertNotIn("manifest digest mismatch", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
