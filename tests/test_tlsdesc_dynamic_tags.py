from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PATCHER_PATH = ROOT / "native/urprotect-runtime/patch_tlsdesc_dynamic_tags.py"
SPEC = importlib.util.spec_from_file_location("tlsdesc_dynamic_tag_patcher", PATCHER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load patcher at {PATCHER_PATH}")
PATCHER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PATCHER
SPEC.loader.exec_module(PATCHER)

DYNAMIC_OFFSET = 0x200
DYNAMIC_ENTRY_SIZE = 16
PROGRAM_HEADER_OFFSET = 64
LOAD_ADDRESS = 0x400000
PLT_ADDRESS = 0x400600
DESCRIPTOR_ADDRESS = 0x400500
RELA_OFFSET = 0x380
PLT_OFFSET = 0x600
SECTION_NAMES_OFFSET = 0x700
SECTION_HEADER_OFFSET = 0x740
FILE_SIZE = SECTION_HEADER_OFFSET + 3 * 64
DT_DEBUG = 21


def valid_dynamic_entries() -> list[tuple[int, int]]:
    return [
        (PATCHER.DT_PLTGOT, LOAD_ADDRESS + 0x4F8),
        (PATCHER.DT_FLAGS, PATCHER.DF_BIND_NOW),
        (PATCHER.DT_JMPREL, LOAD_ADDRESS + RELA_OFFSET),
        (PATCHER.DT_PLTRELSZ, PATCHER.RELA_ENTRY_SIZE),
        (PATCHER.DT_PLTREL, PATCHER.DT_RELA),
        (PATCHER.DT_NULL, 0),
        (PATCHER.DT_NULL, 0),
        (PATCHER.DT_NULL, 0),
    ]


def make_elf(entries: list[tuple[int, int]] | None = None) -> bytes:
    if entries is None:
        entries = valid_dynamic_entries()
    data = bytearray(FILE_SIZE)
    data[:16] = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,  # ET_DYN
        183,  # EM_AARCH64
        1,
        0,
        PROGRAM_HEADER_OFFSET,
        SECTION_HEADER_OFFSET,
        0,
        64,
        PATCHER.ELF64_PHDR_SIZE,
        2,
        PATCHER.ELF64_SHDR_SIZE,
        3,
        2,
    )

    dynamic_size = len(entries) * DYNAMIC_ENTRY_SIZE
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        PROGRAM_HEADER_OFFSET,
        PATCHER.PT_LOAD,
        6,  # PF_R | PF_W; also maps all fixture metadata
        0,
        LOAD_ADDRESS,
        LOAD_ADDRESS,
        FILE_SIZE,
        FILE_SIZE,
        0x1000,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        PROGRAM_HEADER_OFFSET + PATCHER.ELF64_PHDR_SIZE,
        PATCHER.PT_DYNAMIC,
        6,
        DYNAMIC_OFFSET,
        LOAD_ADDRESS + DYNAMIC_OFFSET,
        LOAD_ADDRESS + DYNAMIC_OFFSET,
        dynamic_size,
        dynamic_size,
        8,
    )
    for index, (tag, value) in enumerate(entries):
        struct.pack_into("<QQ", data, DYNAMIC_OFFSET + index * DYNAMIC_ENTRY_SIZE, tag, value)

    # One aligned dynamic R_AARCH64_TLSDESC relocation with a writable,
    # file-backed resolver GOT word immediately before its descriptor.
    rela_info = (1 << 32) | PATCHER.R_AARCH64_TLSDESC
    struct.pack_into("<QQq", data, RELA_OFFSET, DESCRIPTOR_ADDRESS, rela_info, 0)
    data[PLT_OFFSET : PLT_OFFSET + 24] = bytes(range(24))

    names = b"\x00.plt\x00.shstrtab\x00"
    data[SECTION_NAMES_OFFSET : SECTION_NAMES_OFFSET + len(names)] = names
    plt_header = SECTION_HEADER_OFFSET + PATCHER.ELF64_SHDR_SIZE
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        plt_header,
        1,
        PATCHER.SHT_PROGBITS,
        6,
        PLT_ADDRESS,
        PLT_OFFSET,
        24,
        0,
        0,
        4,
        0,
    )
    names_header = SECTION_HEADER_OFFSET + 2 * PATCHER.ELF64_SHDR_SIZE
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        names_header,
        6,
        PATCHER.SHT_STRTAB,
        0,
        0,
        SECTION_NAMES_OFFSET,
        len(names),
        0,
        0,
        1,
        0,
    )
    return bytes(data)


class TlsdescDynamicTagPatcherTests(unittest.TestCase):
    def assert_rejected_unchanged(self, original: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="tlsdesc-patcher-negative-") as directory:
            root = Path(directory)
            fixture = root / "fixture.so"
            fixture.write_bytes(original)
            before_names = sorted(path.name for path in root.iterdir())
            with self.assertRaises(PATCHER.FixtureError):
                PATCHER.patch(fixture)
            self.assertEqual(fixture.read_bytes(), original)
            self.assertEqual(sorted(path.name for path in root.iterdir()), before_names)

    def test_success_changes_only_the_three_reserved_entries(self) -> None:
        original = make_elf()
        with tempfile.TemporaryDirectory(prefix="tlsdesc-patcher-positive-") as directory:
            fixture = Path(directory) / "fixture.so"
            fixture.write_bytes(original)
            PATCHER.patch(fixture)
            actual = fixture.read_bytes()

        expected = bytearray(original)
        null_index = 5
        struct.pack_into(
            "<QQ",
            expected,
            DYNAMIC_OFFSET + null_index * DYNAMIC_ENTRY_SIZE,
            PATCHER.DT_TLSDESC_PLT,
            PLT_ADDRESS,
        )
        struct.pack_into(
            "<QQ",
            expected,
            DYNAMIC_OFFSET + (null_index + 1) * DYNAMIC_ENTRY_SIZE,
            PATCHER.DT_TLSDESC_GOT,
            DESCRIPTOR_ADDRESS - 8,
        )
        # The third designated entry remains the terminating DT_NULL.
        struct.pack_into(
            "<QQ",
            expected,
            DYNAMIC_OFFSET + (null_index + 2) * DYNAMIC_ENTRY_SIZE,
            PATCHER.DT_NULL,
            0,
        )
        self.assertEqual(len(actual), len(original))
        self.assertEqual(actual, bytes(expected))

    def test_nonzero_tag_or_value_in_either_post_null_slot_is_rejected(self) -> None:
        for slot in (6, 7):
            for tag, value in ((DT_DEBUG, 0), (PATCHER.DT_NULL, 1)):
                with self.subTest(slot=slot, tag=tag, value=value):
                    entries = valid_dynamic_entries()
                    entries[slot] = (tag, value)
                    self.assert_rejected_unchanged(make_elf(entries))

    def test_nonzero_first_null_value_is_rejected(self) -> None:
        entries = valid_dynamic_entries()
        entries[5] = (PATCHER.DT_NULL, 1)
        self.assert_rejected_unchanged(make_elf(entries))

    def test_insufficient_physical_slots_are_rejected(self) -> None:
        entries = valid_dynamic_entries()
        for count in (6, 7):
            with self.subTest(physical_entry_count=count):
                self.assert_rejected_unchanged(make_elf(entries[:count]))

    def test_truncated_dynamic_image_is_rejected(self) -> None:
        self.assert_rejected_unchanged(make_elf()[:-1])

    def test_missing_dt_null_is_rejected(self) -> None:
        entries = valid_dynamic_entries()
        entries[5:] = [(DT_DEBUG, 0), (DT_DEBUG, 0), (DT_DEBUG, 0)]
        self.assert_rejected_unchanged(make_elf(entries))

    def test_already_tagged_dynamic_prefix_is_rejected(self) -> None:
        for tag in (PATCHER.DT_TLSDESC_PLT, PATCHER.DT_TLSDESC_GOT):
            with self.subTest(tag=tag):
                entries = valid_dynamic_entries()
                entries[0] = (tag, PLT_ADDRESS)
                self.assert_rejected_unchanged(make_elf(entries))

    def test_failed_atomic_replace_preserves_input_and_removes_temp_output(self) -> None:
        original = make_elf()
        with tempfile.TemporaryDirectory(prefix="tlsdesc-patcher-publish-failure-") as directory:
            root = Path(directory)
            fixture = root / "fixture.so"
            fixture.write_bytes(original)
            with mock.patch.object(PATCHER.os, "replace", side_effect=OSError("injected replace error")):
                with self.assertRaisesRegex(OSError, "injected replace error"):
                    PATCHER.patch(fixture)
            self.assertEqual(fixture.read_bytes(), original)
            self.assertEqual([path.name for path in root.iterdir()], [fixture.name])


if __name__ == "__main__":
    unittest.main()
