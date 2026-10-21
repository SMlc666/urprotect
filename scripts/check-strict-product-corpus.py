#!/usr/bin/env python3
"""Fail-closed verification of actual strict compatibility *product* evidence.

This verifier does not measure attack resistance or claim any strength factor.
It independently checks every required corpus unit via the existing six-stage,
hash-bound rehydration verifier. A completed summary alone is never trusted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "fixtures/evaluator/compatibility-corpus.json"
CHECKER = REPO / "scripts/check-rehydration-evidence.py"
REQUIRED_STAGES = (
    "protector", "protected-image", "rehydration",
    "native-image", "target-loader", "behavioral-oracle",
)


def required_units(manifest: Path) -> list[dict]:
    document = json.loads(manifest.read_text(encoding="utf-8"))
    rows = document.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("missing strict compatibility registry")
    selected = [r for r in rows if r.get("required") is True and r.get("applicable") is True]
    units = [r.get("unitId") for r in selected]
    identities = [r.get("identityKey") for r in selected]
    provenance = [r.get("sourceProvenance") for r in selected]
    if len(selected) != 100 or len(set(units)) != 100:
        raise ValueError("strict corpus must retain exactly 100 distinct required units")
    if len(set(identities)) != 100 or len(set(provenance)) != 100:
        raise ValueError("duplicate strict corpus identity or provenance")
    for unit in units:
        if not isinstance(unit, str) or not unit or any(c not in
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for c in unit):
            raise ValueError("unsafe strict corpus unit ID")
    if document.get("fixedRowIds") != ["compat.protection-symbolized-fixture.glibc.outer-execveat"]:
        raise ValueError("frozen original compatibility unit was changed")
    return selected


def check(manifest: Path, root: Path, tier: str, runtime: str, shard_count: int = 4) -> dict:
    rows = required_units(manifest)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("strict product evidence directory is missing or symlinked")
    if shard_count != 4:
        raise ValueError("strict product corpus must use four required shards")
    expected_ids = {row["unitId"] for row in rows}
    actual_ids = {entry.name for entry in root.iterdir() if entry.is_dir()}
    if actual_ids != expected_ids:
        raise ValueError(
            "strict corpus inventory mismatch: "
            f"missing={sorted(expected_ids - actual_ids)[:8]} "
            f"unexpected={sorted(actual_ids - expected_ids)[:8]}"
        )
    found_summaries = {
        path.name for path in root.glob("strict-corpus-summary*.json")
    }
    expected_summaries = {
        f"strict-corpus-summary-shard-{index}-of-{shard_count}.json"
        for index in range(shard_count)
    }
    if found_summaries != expected_summaries:
        raise ValueError("strict shard summary inventory mismatch")
    for index in range(shard_count):
        summary_file = root / f"strict-corpus-summary-shard-{index}-of-{shard_count}.json"
        if summary_file.is_symlink() or not summary_file.is_file():
            raise ValueError(f"missing or symlinked strict shard summary {index}")
        selected = rows[index::shard_count]
        expected = {
            "schemaVersion": 1,
            "kind": "strict-compatibility-corpus-run",
            "tier": tier,
            "runtime": runtime,
            "shardIndex": index,
            "shardCount": shard_count,
            "totalRows": len(selected),
            "completedRows": len(selected),
            "failedRows": 0,
            "status": "passed",
            "unitIds": [row["unitId"] for row in selected],
        }
        if json.loads(summary_file.read_text(encoding="utf-8")) != expected:
            raise ValueError(f"invalid/incomplete strict shard summary {index}")
    report = []
    for row in rows:
        unit = row["unitId"]
        directory = root / unit
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"missing or symlinked product evidence: {unit}")
        digest_path = directory / "SHA256SUMS"
        if digest_path.is_symlink() or not digest_path.is_file():
            raise ValueError(f"missing or symlinked product manifest: {unit}")
        result = subprocess.run(
            [sys.executable, str(CHECKER), str(directory),
             "--tier", tier, "--runtime", runtime, "--unit", unit],
            cwd=REPO, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise ValueError(
                f"invalid six-stage evidence for {unit}: "
                f"{(result.stderr or result.stdout).strip()[:300]}"
            )
        report.append({
            "unitId": unit,
            "identityKey": row["identityKey"],
            "productManifestSha256": hashlib.sha256(digest_path.read_bytes()).hexdigest(),
            "status": "passed",
        })
    return {
        "schemaVersion": 1,
        "kind": "urprotect-strict-compatibility-evidence-check",
        "status": "passed",
        "tier": tier,
        "runtime": runtime,
        "requiredUnits": len(rows),
        "passedUnits": len(report),
        "stages": list(REQUIRED_STAGES),
        "units": report,
        "securityStrengthClaim": None,
        "shardCount": shard_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    parser.add_argument("--runtime", choices=("glibc",), default="glibc")
    parser.add_argument("--shard-count", type=int, default=4)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        data = check(args.manifest, args.evidence_root, args.tier, args.runtime, args.shard_count)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as e:
        print(f"FAIL strict compatibility evidence: {e}", file=sys.stderr)
        return 1
    print(f"PASS strict compatibility evidence: {data['passedUnits']}/{data['requiredUnits']} "
          f"hash-bound product chains verified; no attack-strength claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
