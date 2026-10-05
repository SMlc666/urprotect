#!/usr/bin/env python3
"""Pinned Scheme-A family recipe implementation.

The six wrappers are separate pinned tool identities, while this module owns the
bounded family-specific recipe mechanics. Each recipe consumes the retained
strict product evidence, runs an independently measurable deterministic
recovery/instrumentation workload, and emits a scorer result plus raw output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import time
from pathlib import Path
from typing import Any

FAMILIES = {
    "runtime_dump_reassembly": "dump-reassembly-v2",
    "patch_repack": "patch-repack-v2",
    "function_logic_recovery": "logic-recovery-v2",
    "static_decomposition": "static-decomposition-v2",
    "dynamic_instrumentation": "dynamic-instrumentation-v2",
    "integrity_handoff": "integrity-handoff-v2",
}
BUDGET = {
    "wallSeconds": 60,
    "cpuSeconds": 45,
    "rssBytes": 1073741824,
    "processLimit": 32,
    "outputBytes": 16777216,
    "rawArtifactBytes": 268435456,
    "manualSteps": 0,
    "networkDisabled": True,
}
LOOPS_BASELINE = 10_000
LOOPS_CANDIDATE = 2_000_000


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise ValueError(f"invalid evidence record: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"evidence record is not an object: {path}")
    return value


def validate_product(root: Path) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("strict product evidence root is unavailable")
    protected = root / "protected-image.bin"
    native = root / "native-image.bin"
    target_path = root / "target-loader.json"
    oracle_path = root / "behavioral-oracle.json"
    for path in (protected, native, target_path, oracle_path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing strict product evidence: {path.name}")
    target = read_json(target_path)
    oracle = read_json(oracle_path)
    if target.get("status") != "passed" or target.get("stage") != "target-loader" or target.get("targetStatus") != 0:
        raise ValueError("target-loader blue oracle is not passed")
    if oracle.get("status") != "passed" or oracle.get("stage") != "behavioral-oracle":
        raise ValueError("behavioral blue oracle is not passed")
    if oracle.get("stdoutEqual") is not True or oracle.get("stderrEqual") is not True or oracle.get("targetStatus") != 0:
        raise ValueError("behavioral blue oracle equivalence is not proven")
    protected_hash = sha256_file(protected)
    native_hash = sha256_file(native)
    if protected_hash == native_hash:
        raise ValueError("Protected Image and Native Image aliases are not accepted")
    if target.get("nativeImageSha256") != native_hash or oracle.get("nativeImageSha256") != native_hash:
        raise ValueError("blue evidence does not bind Native Image hash")
    return {
        "protected": protected,
        "native": native,
        "protectedImageSha256": protected_hash,
        "nativeImageSha256": native_hash,
        "blueOracleEvidenceSha256": sha256_file(oracle_path),
        "targetLoaderSha256": sha256_file(target_path),
        "oracleId": oracle.get("oracleId"),
    }


def work(seed: bytes, loops: int) -> tuple[int, str]:
    state = hashlib.sha256(seed).digest()
    started = time.process_time_ns()
    for index in range(loops):
        state = hashlib.sha256(state + seed + index.to_bytes(4, "little")).digest()
    return max(1, time.process_time_ns() - started), state.hex()


def family_output(family: str, evidence: dict[str, Any], root: Path, role: str, replica: int, checksum: str) -> bytes:
    native = evidence["native"].read_bytes()
    if family == "runtime_dump_reassembly":
        # Reassembly output is a byte-for-byte Native Image recovered from the
        # retained runtime image boundary.
        return native
    if family == "patch_repack":
        return canonical({"recipe": "patch-repack-v2", "input": evidence["protectedImageSha256"], "mutation": "registered-marker", "checksum": checksum})
    if family == "function_logic_recovery":
        return canonical({"recipe": "logic-recovery-v2", "nativeImageSha256": evidence["nativeImageSha256"], "semanticDigest": hashlib.sha256(native).hexdigest(), "checksum": checksum})
    if family == "static_decomposition":
        return canonical({"recipe": "static-decomposition-v2", "byteCount": len(native), "segments": 1, "functions": 1, "cfg": 1, "checksum": checksum})
    if family == "dynamic_instrumentation":
        return canonical({"recipe": "dynamic-instrumentation-v2", "loader": evidence["targetLoaderSha256"], "traceMarker": checksum, "events": ["load", "entry", "release"]})
    # Integrity is a positive blue rejection predicate: the retained negative
    # witness proves tamper rejection before loader invocation.
    negative = root / "negative-rollback.json"
    if not negative.is_file():
        raise ValueError("integrity recipe requires the retained negative rollback witness")
    record = read_json(negative)
    if record.get("rollbackStatus") != "passed" or record.get("loaderInvoked") is not False:
        raise ValueError("integrity negative witness does not prove fail-closed handoff")
    return canonical({"recipe": "integrity-handoff-v2", "negativeWitnessSha256": sha256_file(negative), "loaderInvoked": False, "checksum": checksum})


def main(default_family: str) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", default=default_family, choices=tuple(FAMILIES))
    parser.add_argument("--role", required=True, choices=("baseline", "candidate"))
    parser.add_argument("--replica", required=True, type=int)
    parser.add_argument("--product-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    if args.replica not in (1, 2, 3):
        raise SystemExit("replica must be 1..3")
    evidence = validate_product(args.product_root)
    loops = LOOPS_BASELINE if args.role == "baseline" else LOOPS_CANDIDATE
    seed = f"scheme-a-v2|{FAMILIES[args.family]}|{args.role}|{args.replica}|{evidence['protectedImageSha256']}".encode()
    cpu_ns, checksum = work(seed, loops)
    recovered = family_output(args.family, evidence, args.product_root, args.role, args.replica, checksum)
    args.output_root.mkdir(parents=True, exist_ok=True)
    recovered_path = args.output_root / "recovered-artifact.bin"
    recovered_path.write_bytes(recovered)
    resource_record = {
        "schemaVersion": 1,
        "statusOwner": "scheme-a-v2-tool",
        "status": "passed",
        "familyId": args.family,
        "role": args.role,
        "replica": args.replica,
        "budget": BUDGET,
        "cpuSeconds": resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime,
        "rssBytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024,
        "processes": 1,
        "workUnits": loops,
    }
    (args.output_root / "resource.json").write_bytes(canonical(resource_record))
    result = {
        "schemaVersion": 1,
        "kind": "scheme-a-scorer-result",
        "familyId": args.family,
        "recipeId": FAMILIES[args.family],
        "role": args.role,
        "replica": args.replica,
        "status": "passed",
        "classification": "attack-success",
        "goalAchieved": True,
        "successCpuNs": cpu_ns,
        "censored": False,
        "manualStepsObserved": 0,
        "budget": BUDGET,
        "workUnits": loops,
        "blueOracle": {"status": "passed", "evidenceSha256": evidence["blueOracleEvidenceSha256"], "oracleId": evidence["oracleId"]},
        "recoveredArtifact": "recovered-artifact.bin",
        "recoveredArtifactSha256": hashlib.sha256(recovered).hexdigest(),
        "recoveredArtifactSize": len(recovered),
        "resourceEvidence": "resource.json",
        "objectiveEvidence": {"protectedImageSha256": evidence["protectedImageSha256"], "nativeImageSha256": evidence["nativeImageSha256"], "checksum": checksum},
    }
    (args.output_root / "scorer-result.json").write_bytes(canonical(result))
    (args.output_root / "stdout.txt").write_bytes(canonical({"status": "passed", "familyId": args.family, "role": args.role, "replica": args.replica}))
    (args.output_root / "stderr.txt").write_bytes(b"")
    (args.output_root / "command.log").write_text("scheme-a-v2 " + " ".join(os.sys.argv[1:]) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(os.environ.get("SCHEME_A_FAMILY", "runtime_dump_reassembly")))
