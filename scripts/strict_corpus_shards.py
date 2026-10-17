#!/usr/bin/env python3
"""Deterministic strict-corpus shards and fail-closed merged evidence validation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json"


def required_rows(manifest: Path) -> list[tuple[str, str]]:
    document = json.loads(manifest.read_text(encoding="utf-8"))
    rows = [
        (row["unitId"], row["sourceProvenance"])
        for row in document["rows"]
        if row.get("required") and row.get("applicable")
    ]
    if not rows or len({unit for unit, _ in rows}) != len(rows):
        raise ValueError("required corpus is empty or contains duplicate unit IDs")
    if any("/" in unit or unit in (".", "..") for unit, _ in rows):
        raise ValueError("invalid unit ID in corpus")
    return rows


def selected_rows(
    rows: list[tuple[str, str]], shard_index: int, shard_count: int
) -> list[tuple[str, str]]:
    if shard_count < 1 or shard_count > len(rows):
        raise ValueError("shard count must be between 1 and required corpus size")
    if not 0 <= shard_index < shard_count:
        raise ValueError("shard index is outside the requested shard count")
    return rows[shard_index::shard_count]


def summary_name(index: int, count: int) -> str:
    return f"strict-corpus-summary-shard-{index}-of-{count}.json"


def verify(
    manifest: Path, evidence_root: Path, tier: str, runtime: str, count: int
) -> None:
    rows = required_rows(manifest)
    if count < 2 or count > len(rows):
        raise ValueError("merged evidence requires at least two valid shards")
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        raise ValueError(f"missing or symlinked evidence directory: {evidence_root}")
    expected_units = {unit for unit, _ in rows}
    found_units = {child.name for child in evidence_root.iterdir() if child.is_dir()}
    if found_units != expected_units:
        missing = sorted(expected_units - found_units)
        unexpected = sorted(found_units - expected_units)
        raise ValueError(
            f"merged strict corpus unit inventory differs: missing={missing[:8]} "
            f"unexpected={unexpected[:8]}"
        )
    actual_summaries = {
        entry.name for entry in evidence_root.glob("strict-corpus-summary*.json")
    }
    expected_summaries = {summary_name(index, count) for index in range(count)}
    if actual_summaries != expected_summaries:
        raise ValueError(
            "strict corpus shard summary inventory differs: "
            f"missing={sorted(expected_summaries - actual_summaries)} "
            f"unexpected={sorted(actual_summaries - expected_summaries)}"
        )
    for index in range(count):
        shard = selected_rows(rows, index, count)
        path = evidence_root / summary_name(index, count)
        if path.is_symlink():
            raise ValueError(f"symlinked shard summary: {path}")
        summary = json.loads(path.read_text(encoding="utf-8"))
        expected = {
            "schemaVersion": 1,
            "kind": "strict-compatibility-corpus-run",
            "tier": tier,
            "runtime": runtime,
            "shardIndex": index,
            "shardCount": count,
            "totalRows": len(shard),
            "completedRows": len(shard),
            "failedRows": 0,
            "status": "passed",
            "unitIds": [unit for unit, _ in shard],
        }
        if summary != expected:
            raise ValueError(f"invalid/incomplete summary for strict shard {index}")

    checker = REPO_ROOT / "scripts/check-rehydration-evidence.py"
    for unit, _ in rows:
        unit_root = evidence_root / unit
        if unit_root.is_symlink():
            raise ValueError(f"symlinked strict evidence unit: {unit}")
        check = subprocess.run(
            [
                sys.executable, str(checker), str(unit_root),
                "--tier", tier, "--runtime", runtime, "--unit", unit,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if check.returncode != 0:
            raise ValueError(
                f"invalid strict evidence for {unit}: "
                f"{(check.stderr or check.stdout).strip()[:500]}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    select = subparsers.add_parser("select", help="print TAB-separated unit/source rows")
    select.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    select.add_argument("--shard-index", required=True, type=int)
    select.add_argument("--shard-count", required=True, type=int)
    check = subparsers.add_parser("verify", help="verify all shard evidence before evaluation")
    check.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    check.add_argument("--evidence-root", type=Path, required=True)
    check.add_argument("--tier", choices=("pr", "nightly", "release"), required=True)
    check.add_argument("--runtime", choices=("glibc",), required=True)
    check.add_argument("--shard-count", required=True, type=int)
    args = parser.parse_args()
    try:
        if args.command == "select":
            for unit, source in selected_rows(
                required_rows(args.manifest), args.shard_index, args.shard_count
            ):
                print(f"{unit}\t{source}")
        else:
            verify(
                args.manifest, args.evidence_root,
                args.tier, args.runtime, args.shard_count,
            )
            print(f"PASS merged strict compatibility shards: {args.shard_count} complete")
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"FAIL strict compatibility shards: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
