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

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                str(self.root),
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

    def test_checked_in_evidence_fixture_is_accepted(self) -> None:
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
