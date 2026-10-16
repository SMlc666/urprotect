#!/usr/bin/env python3
"""Execute the complete strict compatibility corpus, optionally in parallel.

The same frozen unit registry, E2E runner and per-unit evidence validators are
used in serial and parallel modes. Only scheduling changes.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping

from strict_corpus_shards import required_rows, selected_rows

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "fixtures/evaluator/compatibility-corpus.json"
UNIT_RUNNER = REPO_ROOT / "scripts/run-rehydration-e2e.sh"
UNIT_CHECKER = REPO_ROOT / "scripts/check-rehydration-evidence.py"
NATIVE_HELPER = REPO_ROOT / "native/urprotect-runtime/build/native-image-handoff"
CLI = REPO_ROOT / "src/UrProtect.Cli/bin/Release/net8.0/urprotect.dll"
CORE = REPO_ROOT / "src/UrProtect.Core/bin/Release/net8.0/UrProtect.Core.dll"


def prepare_parallel_runtime(env: dict[str, str]) -> None:
    """Build shared executables once, before child jobs can race on outputs."""
    if not CLI.is_file() or not CORE.is_file():
        raise RuntimeError("parallel strict corpus requires the prebuilt Release .NET CLI/Core")
    build = subprocess.run(
        ["make", "-C", str(REPO_ROOT / "native/urprotect-runtime"), "native-image-handoff"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if build.returncode or not NATIVE_HELPER.is_file():
        raise RuntimeError(
            "native handoff prebuild failed: "
            + (build.stderr or build.stdout)[-1500:]
        )
    env["URPROTECT_PREBUILT_CLI"] = "1"
    env["URPROTECT_NATIVE_HANDOFF_PREBUILT"] = "1"


def run_unit(
    row: tuple[str, str],
    *,
    tier: str,
    runtime: str,
    artifact_root: Path,
    env: Mapping[str, str],
    skip_existing: bool,
) -> tuple[str, bool, str]:
    """Return status and captured output without concurrent log interleaving."""
    unit, source = row
    unit_root = artifact_root / unit
    if skip_existing and (unit_root / "behavioral-oracle.json").is_file() and (unit_root / "SHA256SUMS").is_file():
        check = subprocess.run(
            [
                sys.executable, str(UNIT_CHECKER), str(unit_root),
                "--tier", tier, "--runtime", runtime, "--unit", unit,
            ],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=False,
        )
        if check.returncode == 0:
            return unit, True, "reused previously validated evidence"
    command = [
        str(UNIT_RUNNER),
        "--tier", tier, "--runtime", runtime, "--unit", unit,
        "--source", str(REPO_ROOT / source),
    ]
    # Per-unit override: no child may inherit a shared artifact output directory.
    unit_env = dict(env)
    unit_env["PROTECTED_IMAGE_ARTIFACT_ROOT"] = str(unit_root)
    result = subprocess.run(
        command, cwd=REPO_ROOT, env=unit_env,
        capture_output=True, text=True, errors="replace", check=False,
    )
    detail = (result.stdout + result.stderr).strip()
    if result.returncode:
        detail = f"exit={result.returncode}\n{detail}"
    return unit, result.returncode == 0, detail


def execute(
    *,
    tier: str,
    runtime: str,
    shard_index: int | None,
    shard_count: int | None,
    workers: int,
    skip_existing: bool,
    manifest: Path = CORPUS,
    artifact_root: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    rows = required_rows(manifest)
    if (shard_index is None) != (shard_count is None):
        raise ValueError("both shard-index and shard-count must be provided")
    if shard_index is not None:
        rows = selected_rows(rows, shard_index, shard_count)
    if not 1 <= workers <= 8:
        raise ValueError("workers must be between 1 and 8")
    if not rows:
        raise ValueError("empty strict compatibility work selection")
    root = artifact_root or (
        REPO_ROOT / ".artifacts/protected-image" / tier / runtime
    )
    root.mkdir(parents=True, exist_ok=True)

    child_env = dict(os.environ if env is None else env)
    child_env["PATH"] = (
        child_env.get("DOTNET_ROOT", "/root/.dotnet") + ":"
        + child_env.get("PATH", "")
    )
    if workers > 1:
        prepare_parallel_runtime(child_env)
    else:
        # Do not change the historical single-worker build behavior.
        child_env.pop("URPROTECT_PREBUILT_CLI", None)
        child_env.pop("URPROTECT_NATIVE_HANDOFF_PREBUILT", None)

    results: dict[str, bool] = {}
    def handle(result: tuple[str, bool, str]) -> None:
        unit, passed, detail = result
        results[unit] = passed
        print(f"[strict-corpus] {unit}: {'PASS' if passed else 'FAIL'}", flush=True)
        if detail:
            stream = sys.stdout if passed else sys.stderr
            print(detail[-6000:], file=stream, flush=True)

    if workers == 1:
        for row in rows:
            try:
                handle(run_unit(
                    row, tier=tier, runtime=runtime, artifact_root=root,
                    env=child_env, skip_existing=skip_existing,
                ))
            except Exception as error:
                handle((row[0], False, f"worker exception: {error}"))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    run_unit, row, tier=tier, runtime=runtime,
                    artifact_root=root, env=child_env, skip_existing=skip_existing,
                ): row[0]
                for row in rows
            }
            for future in as_completed(futures):
                try:
                    handle(future.result())
                except Exception as error:
                    handle((futures[future], False, f"worker exception: {error}"))

    completed = sum(results.get(unit, False) for unit, _ in rows)
    failed = len(rows) - completed
    summary: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "strict-compatibility-corpus-run",
        "tier": tier,
        "runtime": runtime,
        "totalRows": len(rows),
        "completedRows": completed,
        "failedRows": failed,
        "status": "passed" if failed == 0 else "failed",
    }
    name = "strict-corpus-summary.json"
    if shard_index is not None:
        summary.update(
            shardIndex=shard_index,
            shardCount=shard_count,
            unitIds=[unit for unit, _ in rows],
        )
        name = f"strict-corpus-summary-shard-{shard_index}-of-{shard_count}.json"
    (root / name).write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    if failed:
        print(f"FAIL strict compatibility corpus: {failed}/{len(rows)} rows", file=sys.stderr)
        return 1
    print(f"PASS strict compatibility corpus: {completed}/{len(rows)} rows")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", required=True, choices=("pr", "nightly", "release"))
    parser.add_argument("--runtime", required=True, choices=("glibc",))
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    try:
        return execute(
            tier=args.tier, runtime=args.runtime,
            shard_index=args.shard_index, shard_count=args.shard_count,
            workers=args.workers, skip_existing=args.skip_existing,
        )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(f"FAIL strict compatibility corpus: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
