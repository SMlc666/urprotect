from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
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

    def run_checker(self, root: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                str(root or self.root),
                "--unit",
                UNIT,
                "--selected-function",
                self.selector,
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
