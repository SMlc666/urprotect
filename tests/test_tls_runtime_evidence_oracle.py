import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
CHECKER_PATH = ROOT / "scripts" / "check-tls-runtime-matrix-evidence.py"
SPEC = importlib.util.spec_from_file_location("tls_runtime_matrix_evidence_checker", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
from tls_runtime_identity import canonical_identity_digest, verify_artifact_identity
REHYDRATION_SPEC = importlib.util.spec_from_file_location(
    "rehydration_evidence_checker", ROOT / "scripts" / "check-rehydration-evidence.py"
)
REHYDRATION_CHECKER = importlib.util.module_from_spec(REHYDRATION_SPEC)
sys.modules[REHYDRATION_SPEC.name] = REHYDRATION_CHECKER
REHYDRATION_SPEC.loader.exec_module(REHYDRATION_CHECKER)


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rewrite_checksums(root):
    rows = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        rows.append(f"{sha_bytes(path.read_bytes())}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def make_behavior_evidence(root):
    row_id = "general-dynamic.host-context-entry.glibc.current-thread"
    source_bytes = b"source fixture"
    protected_bytes = b"protected artifact"
    native_bytes = b"native image"
    source_hash = sha_bytes(source_bytes)
    protected_hash = sha_bytes(protected_bytes)
    native_hash = sha_bytes(native_bytes)
    for name, value in (
        ("source-image.bin", source_bytes),
        ("protected-image.bin", protected_bytes),
        ("native-image.bin", native_bytes),
        ("baseline.stdout", b"observed output\n"),
        ("baseline.stderr", b""),
        ("target.stdout", b"observed output\n"),
        ("target.stderr", b""),
    ):
        (root / name).write_bytes(value)
    common = {
        "schemaVersion": 1,
        "stage": "host-context-handoff",
        "status": "passed",
        "loaderId": "host-context.sealed-memfd.dlopen",
        "entrySymbol": "urp_entry",
        "entryStatus": 43,
        "processStatus": 43,
        "releaseStatus": "passed",
        "releaseOrder": "entry-dispatch-before-release-image",
        "firstFailureStage": None,
    }
    source_record = {**common, "nativeImageSha256": source_hash}
    target_record = {**common, "nativeImageSha256": native_hash}
    source_path = root / "source-handoff.json"
    target_path = root / "handoff.json"
    write_json(source_path, source_record)
    write_json(target_path, target_record)
    streams = {name: (root / name).read_bytes() for name in (
        "baseline.stdout", "baseline.stderr", "target.stdout", "target.stderr"
    )}
    comparison = {
        "schemaVersion": 1,
        "unitId": row_id,
        "oracleId": "fixture.host-context-entry.v1",
        "sourceSha256": source_hash,
        "protectedSha256": protected_hash,
        "nativeImageSha256": native_hash,
        "sourceHandoffSha256": sha_bytes(source_path.read_bytes()),
        "targetHandoffSha256": sha_bytes(target_path.read_bytes()),
        "sourceProcessStatus": 43,
        "targetProcessStatus": 43,
        "sourceEntryStatus": 43,
        "targetEntryStatus": 43,
        "sourceReleaseStatus": "passed",
        "targetReleaseStatus": "passed",
        "baselineStdoutSha256": sha_bytes(streams["baseline.stdout"]),
        "baselineStderrSha256": sha_bytes(streams["baseline.stderr"]),
        "targetStdoutSha256": sha_bytes(streams["target.stdout"]),
        "targetStderrSha256": sha_bytes(streams["target.stderr"]),
        "statusEqual": True,
        "stdoutEqual": True,
        "stderrEqual": True,
    }
    comparison_path = root / "behavior-comparison.json"
    comparison_path.write_text(json.dumps(comparison, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    oracle = {
        **comparison,
        "stage": "behavioral-oracle",
        "status": "passed",
        "comparisonSha256": sha_bytes(comparison_path.read_bytes()),
        "baselineStatus": 43,
        "targetStatus": 43,
        "entryStatus": 43,
        "expectedEntryStatus": 43,
        "firstFailureStage": None,
    }
    oracle_path = root / "behavioral-oracle.json"
    write_json(oracle_path, oracle)
    row = {
        "rowId": row_id,
        "sourceSha256": source_hash,
        "protectedSha256": protected_hash,
        "nativeSha256": native_hash,
        "expectedEntryStatus": 43,
        "behaviorComparisonSha256": sha_bytes(comparison_path.read_bytes()),
        "behavioralOracleSha256": sha_bytes(oracle_path.read_bytes()),
    }
    by_name = {path.name: path for path in root.iterdir() if path.is_file()}
    rewrite_checksums(root)
    CHECKER.check_closed_manifest(root)
    return row, by_name


def make_stage_binding(model="local-dynamic"):
    identity = {
        "runtime": "glibc",
        "version": "glibc 2.43",
        "architecture": "aarch64",
        "identitySha256": "1" * 64,
        "libcSha256": "2" * 64,
        "loaderSha256": "3" * 64,
    }
    row = {
        "rowId": f"{model}.host-context-entry.glibc.current-thread",
        "model": model,
        "profile": "host-context-entry",
        "runtime": "glibc",
        "lifecycle": "current-thread",
        "sourceSha256": "4" * 64,
        "protectedSha256": "5" * 64,
        "nativeSha256": "6" * 64,
        "runtimeIdentitySha256": identity["identitySha256"],
        "expectedEntryStatus": 43,
        "zeroFill": "not-run",
        "perThread": "observed",
    }
    stage = {
        "profile": row["profile"],
        "tlsEvidence": {
            "model": row["model"],
            "runtime": row["runtime"],
            "profile": row["profile"],
            "lifecycle": row["lifecycle"],
            "sourceSha256": row["sourceSha256"],
            "artifactSha256": row["protectedSha256"],
            "transformedSha256": row["protectedSha256"],
            "nativeImageSha256": row["nativeSha256"],
            "runtimeIdentitySha256": row["runtimeIdentitySha256"],
            "runtimeIdentity": identity,
            "expectedEntryStatus": row["expectedEntryStatus"],
            "sourcePath": "source-image.bin",
            "artifactPath": "protected-image.bin",
            "nativeImagePath": "native-image.bin",
            "zeroFill": row["zeroFill"],
            "perThread": row["perThread"],
        },
    }
    return stage, row, identity


class TlsRuntimeEvidenceOracleTests(unittest.TestCase):
    def test_portable_runtime_identity_accepts_nonexistent_producer_paths(self):
        identity = {
            "runtime": "glibc",
            "architecture": "aarch64",
            "version": "glibc 2.43",
            "libcPath": "/producer/root/lib/libc.so.6",
            "libcSha256": "a" * 64,
            "libcElfClass": 64,
            "libcElfData": "little",
            "libcMachine": 183,
            "loaderPath": "/producer/root/lib/ld-linux-aarch64.so.1",
            "loaderSha256": "b" * 64,
            "loaderElfClass": 64,
            "loaderElfData": "little",
            "loaderMachine": 183,
        }
        identity["identitySha256"] = canonical_identity_digest(identity)
        self.assertFalse(Path(identity["libcPath"]).exists())
        self.assertFalse(Path(identity["loaderPath"]).exists())
        self.assertEqual(verify_artifact_identity(identity), identity)

    def test_portable_runtime_identity_rejects_tampered_digest_schema_and_row(self):
        identity = {
            "runtime": "glibc",
            "architecture": "aarch64",
            "version": "glibc 2.43",
            "libcPath": "/producer/root/lib/libc.so.6",
            "libcSha256": "a" * 64,
            "libcElfClass": 64,
            "libcElfData": "little",
            "libcMachine": 183,
            "loaderPath": "/producer/root/lib/ld-linux-aarch64.so.1",
            "loaderSha256": "b" * 64,
            "loaderElfClass": 64,
            "loaderElfData": "little",
            "loaderMachine": 183,
        }
        identity["identitySha256"] = canonical_identity_digest(identity)
        tampered_digest = dict(identity, libcSha256="c" * 64)
        missing_schema = dict(identity)
        del missing_schema["loaderMachine"]
        tampered_elf = dict(identity, libcMachine=62)
        tampered_elf["identitySha256"] = canonical_identity_digest(tampered_elf)
        for candidate in (tampered_digest, missing_schema, tampered_elf):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SystemExit):
                    verify_artifact_identity(candidate)
        stage, row, _ = make_stage_binding()
        stage["tlsEvidence"]["runtimeIdentity"] = identity
        stage["tlsEvidence"]["runtimeIdentitySha256"] = identity["identitySha256"]
        row["runtimeIdentitySha256"] = "d" * 64
        with self.assertRaises(SystemExit):
            CHECKER.check_stage_tls_binding(stage, row, identity)

    def test_valid_measured_host_context_oracle_accepts_nonzero_entry_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, by_name = make_behavior_evidence(root)
            CHECKER.check_behavioral_oracle(root, row, by_name)

    def test_missing_baseline_stream_fails_after_checksums_are_regenerated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, by_name = make_behavior_evidence(root)
            (root / "baseline.stdout").unlink()
            by_name.pop("baseline.stdout")
            rewrite_checksums(root)
            CHECKER.check_closed_manifest(root)
            with self.assertRaises(SystemExit):
                CHECKER.check_behavioral_oracle(root, row, by_name)

    def test_missing_behavioral_oracle_fails_after_checksums_are_regenerated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, by_name = make_behavior_evidence(root)
            (root / "behavioral-oracle.json").unlink()
            by_name.pop("behavioral-oracle.json")
            rewrite_checksums(root)
            CHECKER.check_closed_manifest(root)
            with self.assertRaises(SystemExit):
                CHECKER.check_behavioral_oracle(root, row, by_name)

    def test_changed_baseline_entry_status_fails_after_checksums_are_regenerated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, by_name = make_behavior_evidence(root)
            source = json.loads((root / "source-handoff.json").read_text(encoding="utf-8"))
            source["entryStatus"] = 42
            source["processStatus"] = 42
            write_json(root / "source-handoff.json", source)
            rewrite_checksums(root)
            CHECKER.check_closed_manifest(root)
            with self.assertRaises(SystemExit):
                CHECKER.check_behavioral_oracle(root, row, by_name)

    def test_changed_baseline_stream_fails_after_checksums_are_regenerated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, by_name = make_behavior_evidence(root)
            (root / "baseline.stdout").write_bytes(b"tampered output\n")
            rewrite_checksums(root)
            CHECKER.check_closed_manifest(root)
            with self.assertRaises(SystemExit):
                CHECKER.check_behavioral_oracle(root, row, by_name)

    def test_true_equality_flags_over_different_observed_streams_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, by_name = make_behavior_evidence(root)
            (root / "target.stdout").write_bytes(b"different output\n")
            comparison = json.loads((root / "behavior-comparison.json").read_text(encoding="utf-8"))
            comparison["targetStdoutSha256"] = sha_bytes((root / "target.stdout").read_bytes())
            comparison["stdoutEqual"] = True
            comparison_path = root / "behavior-comparison.json"
            comparison_path.write_text(json.dumps(comparison, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            oracle = json.loads((root / "behavioral-oracle.json").read_text(encoding="utf-8"))
            oracle.update(comparison)
            oracle["comparisonSha256"] = sha_bytes(comparison_path.read_bytes())
            oracle["status"] = "passed"
            oracle["firstFailureStage"] = None
            oracle_path = root / "behavioral-oracle.json"
            write_json(oracle_path, oracle)
            row["behaviorComparisonSha256"] = sha_bytes(comparison_path.read_bytes())
            row["behavioralOracleSha256"] = sha_bytes(oracle_path.read_bytes())
            rewrite_checksums(root)
            CHECKER.check_closed_manifest(root)
            with self.assertRaises(SystemExit):
                CHECKER.check_behavioral_oracle(root, row, by_name)

    def test_generic_rehydration_checker_accepts_measured_nonzero_entry_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, _ = make_behavior_evidence(root)
            record = {
                "unitId": row["rowId"],
                "protectedImageSha256": row["protectedSha256"],
            }
            target_loader = {
                "status": "passed",
                "targetStatus": 43,
                "targetProcessStatus": 43,
            }
            source_hash = row["sourceSha256"]
            native_hash = row["nativeSha256"]
            oracle = REHYDRATION_CHECKER.check_behavior(
                root, record, target_loader, source_hash, native_hash, 43
            )
            self.assertEqual(oracle["status"], "passed")
            with self.assertRaises(SystemExit):
                REHYDRATION_CHECKER.check_behavior(
                    root, record, target_loader, source_hash, native_hash, 44
                )

    def test_generic_rehydration_checker_rejects_changed_source_entry_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row, _ = make_behavior_evidence(root)
            source = json.loads((root / "source-handoff.json").read_text(encoding="utf-8"))
            source["entryStatus"] = 42
            source["processStatus"] = 42
            write_json(root / "source-handoff.json", source)
            record = {
                "unitId": row["rowId"],
                "protectedImageSha256": row["protectedSha256"],
            }
            target_loader = {
                "status": "passed",
                "targetStatus": 43,
                "targetProcessStatus": 43,
            }
            with self.assertRaises(SystemExit):
                REHYDRATION_CHECKER.check_behavior(
                    root, record, target_loader, row["sourceSha256"], row["nativeSha256"], 43
                )

    def test_tlsld_tlsgd_tlsdesc_cannot_be_mislabeled_as_initial_exec(self):
        for model in ("local-dynamic", "general-dynamic", "tlsdesc"):
            with self.subTest(model=model):
                stage, row, identity = make_stage_binding(model)
                CHECKER.check_stage_tls_binding(stage, row, identity)
                stage["tlsEvidence"]["model"] = "initial-exec"
                with self.assertRaises(SystemExit):
                    CHECKER.check_stage_tls_binding(stage, row, identity)

    def test_nested_runtime_profile_and_lifecycle_must_match_row(self):
        for field, wrong in (
            ("runtime", "musl"),
            ("profile", "outer-execveat"),
            ("lifecycle", "registered-worker"),
        ):
            with self.subTest(field=field):
                stage, row, identity = make_stage_binding()
                CHECKER.check_stage_tls_binding(stage, row, identity)
                stage["tlsEvidence"][field] = wrong
                with self.assertRaises(SystemExit):
                    CHECKER.check_stage_tls_binding(stage, row, identity)


if __name__ == "__main__":
    unittest.main()
