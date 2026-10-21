from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check-external-provider-rollback-evidence.py"
SPEC = importlib.util.spec_from_file_location("provider_loaded_rollback_evidence_checker_tests", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load provider-loaded rollback evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ProviderRollbackRootResourceBoundsTests(unittest.TestCase):
    @staticmethod
    def _empty_exact_root(parent: Path) -> Path:
        root = parent / "bounded-root"
        root.mkdir()
        for relative in CHECKER.ROOT_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"")
        return root

    def test_rollback_root_count_limits_accept_exact_empty_files_and_fail_plus_one_before_payload_open(self) -> None:
        original_open = os.open
        opened_flags: list[int] = []

        def tracked_open(path, flags, *args, **kwargs):
            opened_flags.append(flags)
            return original_open(path, flags, *args, **kwargs)

        expected_directories = CHECKER._expected_directories(CHECKER.ROOT_FILES)
        with tempfile.TemporaryDirectory(prefix="rollback-root-count-bounds-") as directory:
            root = self._empty_exact_root(Path(directory))
            with (
                mock.patch.object(CHECKER, "MAX_ROOT_FILE_COUNT", len(CHECKER.ROOT_FILES)),
                mock.patch.object(CHECKER, "MAX_ROOT_DIRECTORY_COUNT", len(expected_directories) + 1),
                mock.patch.object(CHECKER, "MAX_TOTAL_BYTES", 0),
                mock.patch.object(CHECKER.os, "open", side_effect=tracked_open),
            ):
                exact = CHECKER._safe_closed_tree(root, CHECKER.ALL_FILES, sealing=True)
            self.assertEqual(CHECKER.ROOT_FILES, exact.file_paths)
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for flags in opened_flags))

            opened_flags.clear()
            with (
                mock.patch.object(CHECKER, "MAX_ROOT_FILE_COUNT", len(CHECKER.ROOT_FILES) - 1),
                mock.patch.object(CHECKER, "MAX_ROOT_DIRECTORY_COUNT", len(expected_directories) + 1),
                mock.patch.object(CHECKER, "MAX_TOTAL_BYTES", 0),
                mock.patch.object(CHECKER.os, "open", side_effect=tracked_open),
            ):
                with self.assertRaisesRegex(SystemExit, "file-count bound"):
                    CHECKER._safe_closed_tree(root, CHECKER.ALL_FILES, sealing=True)
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for flags in opened_flags))

            opened_flags.clear()
            with (
                mock.patch.object(CHECKER, "MAX_ROOT_FILE_COUNT", len(CHECKER.ROOT_FILES)),
                mock.patch.object(CHECKER, "MAX_ROOT_DIRECTORY_COUNT", len(expected_directories)),
                mock.patch.object(CHECKER, "MAX_TOTAL_BYTES", 0),
                mock.patch.object(CHECKER.os, "open", side_effect=tracked_open),
            ):
                with self.assertRaisesRegex(SystemExit, "directory-count bound"):
                    CHECKER._safe_closed_tree(root, CHECKER.ALL_FILES, sealing=True)
            self.assertTrue(all(flags & getattr(os, "O_DIRECTORY", 0) for flags in opened_flags))


class ProviderLoadedRollbackEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT")
        if not value:
            raise unittest.SkipTest("set URP_PROVIDER_ROLLBACK_EVIDENCE_ROOT to run retained rollback evidence regressions")
        cls.origin = Path(value).resolve(strict=True)
        CHECKER.validate(cls.origin, seal=False)

    def _copy(self, temporary: str) -> Path:
        root = Path(temporary) / self.origin.name
        shutil.copytree(self.origin, root)
        for path in root.rglob("*"):
            if path.is_file():
                path.chmod(path.stat().st_mode | 0o200)
        return root

    @staticmethod
    def _refresh_manifest(root: Path) -> None:
        entries = {}
        for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, relative = line.split("  ", 1)
            entries[relative] = digest
        for relative in entries:
            entries[relative] = CHECKER.sha((root / relative).read_bytes())
        (root / "SHA256SUMS").write_text(
            "".join(f"{entries[relative]}  {relative}\n" for relative in sorted(entries)),
            encoding="ascii",
        )

    @staticmethod
    def _write_closed_manifest(root: Path) -> None:
        entries = [
            f"{CHECKER.sha(path.read_bytes())}  {path.relative_to(root).as_posix()}\n"
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.name != "SHA256SUMS"
        ]
        (root / "SHA256SUMS").write_text("".join(entries), encoding="ascii")

    @staticmethod
    def _rewrite_record(root: Path, mutate) -> None:
        record_path = root / "rollback-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        mutate(record)
        record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        build_path = root / "native-build.json"
        build = json.loads(build_path.read_text(encoding="utf-8"))
        build["rollbackStdoutSha256"] = CHECKER.sha(record_path.read_bytes())
        build_path.write_text(json.dumps(build, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        ProviderLoadedRollbackEvidenceTests._refresh_manifest(root)

    def test_retained_root_proves_failure_cleanup_retry_and_release(self) -> None:
        report = CHECKER.validate(self.origin, seal=False)
        self.assertEqual("accepted", report["status"])
        self.assertTrue(report["failureMappingsAbsent"])
        self.assertTrue(report["failureDescriptorsAndReferencesCleared"])
        self.assertTrue(report["successfulReloadAndReleaseObserved"])
        record = json.loads((self.origin / "rollback-record.json").read_text(encoding="utf-8"))
        self.assertEqual(CHECKER.EVENTS, record["events"])
        self.assertEqual(0, record["firstLoad"]["postCleanupState"]["openDescriptorCount"] - record["baseline"]["openDescriptorCount"])

    def test_reordered_lifecycle_trace_is_rejected_even_with_refreshed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            self._rewrite_record(root, lambda record: record["events"].__setitem__(0, "binding-failpoint-reached"))
            with self.assertRaisesRegex(SystemExit, "event ordering"):
                CHECKER.validate(root, seal=False)

    def test_provider_mapping_relation_tampering_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            def mutate(record: dict) -> None:
                record["firstLoad"]["providerLoadBias"] += 4096
            self._rewrite_record(root, mutate)
            with self.assertRaisesRegex(SystemExit, "provider mapping base/table address relation"):
                CHECKER.validate(root, seal=False)

    def test_cleanup_failure_is_rejected_after_manifest_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            self._rewrite_record(root, lambda record: record["cleanup"].__setitem__("providerFdCloseResult", -1))
            with self.assertRaisesRegex(SystemExit, "rollback cleanup operation failed"):
                CHECKER.validate(root, seal=False)

    def test_boolean_schema_version_is_not_accepted_as_integer_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            self._rewrite_record(root, lambda record: record.__setitem__("schemaVersion", True))
            with self.assertRaisesRegex(SystemExit, "schemaVersion must be an exact JSON integer"):
                CHECKER.validate(root, seal=False)

    def test_range_helper_is_required_and_bound_by_retained_source_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            build_path = root / "native-build.json"
            build = json.loads(build_path.read_text(encoding="utf-8"))
            build["evidenceTools"].pop("evidenceLoadRangeHelperSha256")
            build_path.write_text(json.dumps(build, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            self._write_closed_manifest(root)
            with self.assertRaisesRegex(SystemExit, "evidence tool identity has an unsupported property set.*evidenceLoadRangeHelperSha256"):
                CHECKER.validate(root, seal=False)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            helper = root / "scripts/evidence_load_range.py"
            helper.write_bytes(helper.read_bytes() + b"\\n# tampered helper\\n")
            self._refresh_manifest(root)
            with self.assertRaisesRegex(SystemExit, "retained evidence tool digest mismatch for scripts/evidence_load_range.py"):
                CHECKER.validate(root, seal=False)


if __name__ == "__main__":
    unittest.main()
