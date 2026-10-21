from __future__ import annotations

import unittest

from scripts.evidence_load_range import unique_file_backed_pt_load


class EvidenceLoadRangeTests(unittest.TestCase):
    def test_half_open_adjacent_segment_is_not_an_intersection(self) -> None:
        image = b"abcdefgh"
        segments = [
            {"vaddr": 0x1000, "offset": 0, "filesz": 4, "memsz": 4},
            {"vaddr": 0x1004, "offset": 4, "filesz": 4, "memsz": 4},
        ]
        offset, owner = unique_file_backed_pt_load(
            image, segments, 0x1000, 4, "test range",
            virtual_address_key="vaddr", file_offset_key="offset",
            file_size_key="filesz", memory_size_key="memsz",
        )
        self.assertEqual(0, offset)
        self.assertIs(segments[0], owner)

    def test_exclusive_endpoint_at_two_to_the_sixty_four_is_valid(self) -> None:
        image = b"abcd"
        segment = {"vaddr": (1 << 64) - 4, "offset": 0, "filesz": 4, "memsz": 4}
        offset, owner = unique_file_backed_pt_load(
            image, [segment], (1 << 64) - 4, 4, "top-of-address-space range",
            virtual_address_key="vaddr", file_offset_key="offset",
            file_size_key="filesz", memory_size_key="memsz",
        )
        self.assertEqual(0, offset)
        self.assertIs(segment, owner)

    def test_overflow_partial_bss_overlap_and_duplicate_full_owner_fail_closed(self) -> None:
        image = b"abcdefgh"
        args = dict(
            virtual_address_key="vaddr", file_offset_key="offset",
            file_size_key="filesz", memory_size_key="memsz",
        )
        with self.assertRaisesRegex(ValueError, "overflows ELF64"):
            unique_file_backed_pt_load(
                image, [], (1 << 64) - 2, 3, "overflow", **args
            )

        owner = {"vaddr": 0x1000, "offset": 0, "filesz": 4, "memsz": 4}
        bss_overlap = {"vaddr": 0x1003, "offset": 4, "filesz": 0, "memsz": 2}
        with self.assertRaisesRegex(ValueError, "partially intersects"):
            unique_file_backed_pt_load(
                image, [owner, bss_overlap], 0x1000, 4, "BSS overlap", **args
            )
        with self.assertRaisesRegex(ValueError, "exactly one fully containing"):
            unique_file_backed_pt_load(
                image, [owner, dict(owner)], 0x1000, 4, "duplicate owner", **args
            )


if __name__ == "__main__":
    unittest.main()
