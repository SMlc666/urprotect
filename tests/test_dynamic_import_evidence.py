from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check-dynamic-import-evidence.py"
FIXTURE_PATH = ROOT / "tests/UrProtect.Core.Tests/Fixtures/DynamicImports/liburp-glob-dat-indirect.so"
SPEC = importlib.util.spec_from_file_location("dynamic_import_evidence_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load dynamic-import evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

IDENTITY_PATH = ROOT / "scripts/tls_runtime_identity.py"
IDENTITY_SPEC = importlib.util.spec_from_file_location("dynamic_import_tls_runtime_identity_test", IDENTITY_PATH)
if IDENTITY_SPEC is None or IDENTITY_SPEC.loader is None:
    raise RuntimeError("could not load glibc runtime identity verifier")
IDENTITY = importlib.util.module_from_spec(IDENTITY_SPEC)
IDENTITY_SPEC.loader.exec_module(IDENTITY)


def write_manifest(root: Path) -> None:
    rows = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "SHA256SUMS"):
        rows.append(f"{CHECKER.sha256_file(path)}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def make_runtime_identity(root: Path) -> dict[str, object]:
    runtime_dir = root / "producer-runtime"
    runtime_dir.mkdir(parents=True)
    elf_header = bytearray(64)
    elf_header[:6] = b"\x7fELF\x02\x01"
    elf_header[18:20] = (183).to_bytes(2, "little")
    libc_path = runtime_dir / "libc.so.6"
    loader_path = runtime_dir / "ld-linux-aarch64.so.1"
    libc_path.write_bytes(bytes(elf_header) + b"synthetic libc bytes")
    loader_path.write_bytes(bytes(elf_header) + b"synthetic loader bytes")
    identity: dict[str, object] = {
        "runtime": "glibc",
        "architecture": "aarch64",
        "version": "glibc 2.43",
        "libcPath": str(libc_path.resolve()),
        "libcSha256": IDENTITY.file_digest(libc_path),
        "libcElfClass": 64,
        "libcElfData": "little",
        "libcMachine": 183,
        "loaderPath": str(loader_path.resolve()),
        "loaderSha256": IDENTITY.file_digest(loader_path),
        "loaderElfClass": 64,
        "loaderElfData": "little",
        "loaderMachine": 183,
    }
    identity["identitySha256"] = IDENTITY.canonical_identity_digest(identity)
    return identity


def write_runtime_evidence(root: Path, identity: dict[str, object]) -> None:
    (root / "runtime-identity.json").write_text(
        json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (root / "dynamic-import-evidence.json").write_text(
        json.dumps({"runtime": "glibc", "runtimeIdentity": identity}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_manifest(root)


class DynamicImportEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = FIXTURE_PATH.read_bytes()
        self.facts = CHECKER.ElfImage(self.source, "test fixture").facts()

    def test_source_facts_bind_exact_project_urp_entry_getpid_glob_dat_and_fail_closed_call(self) -> None:
        facts = self.facts
        self.assertEqual("dynsym:3", facts["selectedFunction"]["selector"])
        self.assertEqual("urp_entry", facts["selectedFunction"]["name"])
        self.assertEqual("getpid", facts["importSymbol"]["name"])
        self.assertEqual(2, facts["importSymbol"]["symbolIndex"])
        self.assertEqual(1025, facts["relocation"]["type"])
        self.assertFalse(facts["relocation"]["isPlt"])
        self.assertEqual(facts["relocation"]["virtualAddress"], facts["got"]["virtualAddress"])
        self.assertEqual(6, facts["got"]["segmentFlags"])
        self.assertEqual(97, facts["sourceOracle"]["positiveStatus"])
        self.assertEqual(96, facts["sourceOracle"]["failClosedStatus"])
        self.assertEqual(facts["selectedFunction"]["value"] + 24, facts["sourceOracle"]["callAddress"])
        self.assertEqual(facts["selectedFunction"]["value"] + 48, facts["sourceOracle"]["failureBranchTarget"])
        self.assertEqual(0xA9BF7BFD, facts["sourceOracle"]["returnAddressSaveWord"])
        self.assertEqual(0xA8C17BFD, facts["sourceOracle"]["returnAddressRestoreWord"])

    def test_checksum_refreshed_import_owner_claim_tampering_is_rejected(self) -> None:
        mutations = (
            ("sourceElfFacts.importSymbol.symbolIndex", ("sourceElfFacts", "importSymbol", "symbolIndex"), lambda value: value + 1),
            ("sourceElfFacts.relocation.virtualAddress", ("sourceElfFacts", "relocation", "virtualAddress"), lambda value: value + 8),
            ("sourceElfFacts.got.fileOffset", ("sourceElfFacts", "got", "fileOffset"), lambda value: value + 8),
            ("sourceElfFacts.selectedFunction.selector", ("sourceElfFacts", "selectedFunction", "selector"), lambda _value: "dynsym:2"),
            ("sourceElfFacts.sourceOracle.positiveStatus", ("sourceElfFacts", "sourceOracle", "positiveStatus"), lambda value: value + 1),
        )
        for label, path, mutate in mutations:
            with self.subTest(claim=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "source-image.bin").write_bytes(self.source)
                evidence = {
                    "sourceSha256": CHECKER.sha256_bytes(self.source),
                    "selectedFunction": copy.deepcopy(self.facts["selectedFunction"]),
                    "sourceElfFacts": copy.deepcopy(self.facts),
                }
                nested = evidence
                for element in path[:-1]:
                    nested = nested[element]
                nested[path[-1]] = mutate(nested[path[-1]])
                (root / "dynamic-import-evidence.json").write_text(
                    json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
                )
                write_manifest(root)

                # The attacker refreshes the outer checksums; semantic binding must still fail.
                CHECKER.check_closed_manifest(root)
                with self.assertRaises(SystemExit):
                    CHECKER.validate_source_facts(evidence, root / "source-image.bin")

    def test_native_runtime_identity_verification_rejects_refreshed_false_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained_identity = make_runtime_identity(root)
            write_runtime_evidence(root, retained_identity)
            CHECKER.check_closed_manifest(root)

            with (
                mock.patch.object(CHECKER, "load_runtime_identity_module", return_value=IDENTITY),
                mock.patch.object(IDENTITY, "identify_native_glibc", return_value=retained_identity),
                mock.patch.object(IDENTITY, "verify_identity", wraps=IDENTITY.verify_identity) as verifier,
            ):
                self.assertEqual(retained_identity, CHECKER.verify_runtime_identity(root))
                verifier.assert_called_once_with(retained_identity, verify_current_process=True)

            with (
                mock.patch.object(CHECKER, "load_runtime_identity_module", return_value=IDENTITY),
                mock.patch.object(IDENTITY, "identify_native_glibc", side_effect=SystemExit("native runtime unavailable")),
            ):
                with self.assertRaisesRegex(SystemExit, "native runtime unavailable"):
                    CHECKER.verify_runtime_identity(root)

            forged_identity = copy.deepcopy(retained_identity)
            forged_identity["version"] = "glibc 2.99"
            forged_identity["identitySha256"] = IDENTITY.canonical_identity_digest(forged_identity)
            write_runtime_evidence(root, forged_identity)
            entries = CHECKER.check_closed_manifest(root)
            self.assertEqual(forged_identity, json.loads((root / "dynamic-import-evidence.json").read_text())["runtimeIdentity"])
            self.assertEqual(CHECKER.sha256_file(root / "runtime-identity.json"), entries["runtime-identity.json"])
            self.assertEqual(CHECKER.sha256_file(root / "dynamic-import-evidence.json"), entries["dynamic-import-evidence.json"])
            self.assertEqual(retained_identity["libcSha256"], forged_identity["libcSha256"])
            self.assertEqual(retained_identity["loaderSha256"], forged_identity["loaderSha256"])
            self.assertEqual(IDENTITY.canonical_identity_digest(forged_identity), forged_identity["identitySha256"])

            with (
                mock.patch.object(CHECKER, "load_runtime_identity_module", return_value=IDENTITY),
                mock.patch.object(IDENTITY, "identify_native_glibc", return_value=retained_identity),
                mock.patch.object(IDENTITY, "verify_identity", wraps=IDENTITY.verify_identity) as verifier,
            ):
                with self.assertRaisesRegex(SystemExit, "does not match the producer process runtime"):
                    CHECKER.verify_runtime_identity(root)
                verifier.assert_called_once_with(forged_identity, verify_current_process=True)

    def test_source_elf_truncation_fails_closed(self) -> None:
        with self.assertRaises(SystemExit):
            CHECKER.ElfImage(self.source[:96], "truncated fixture").facts()

    def test_closed_manifest_rejects_dangling_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence.json").write_text("{}\n", encoding="utf-8")
            write_manifest(root)
            (root / "unexpected-link").symlink_to(root / "missing-target")
            with self.assertRaises(SystemExit):
                CHECKER.check_closed_manifest(root)


if __name__ == "__main__":
    unittest.main()
