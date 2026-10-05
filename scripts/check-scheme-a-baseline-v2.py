#!/usr/bin/env python3
"""Validate the additive immutable Scheme-A baseline-v2 reference."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

FAMILIES = (
    "runtime_dump_reassembly",
    "patch_repack",
    "function_logic_recovery",
    "static_decomposition",
    "dynamic_instrumentation",
    "integrity_handoff",
)
ROOT = Path(__file__).resolve().parent.parent


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, default=ROOT / "fixtures/evaluator/baselines/scheme-a-1x-v2-reference.json")
    parser.add_argument("--artifact", type=Path, default=ROOT / "fixtures/evaluator/baselines/scheme-a-1x-v2.json")
    parser.add_argument("--scheme", type=Path, default=ROOT / "fixtures/evaluator/scheme-a-manifest-v2.json")
    parser.add_argument("--evaluator-root", type=Path)
    args = parser.parse_args()
    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    scheme = json.loads(args.scheme.read_text(encoding="utf-8"))
    if reference.get("kind") != "scheme-a-baseline-reference" or artifact.get("kind") != "scheme-a-baseline":
        fail("Scheme-A baseline-v2 kind is invalid")
    if reference.get("baselineArtifactId") != "scheme-a-baseline-v2" or artifact.get("baselineArtifactId") != reference["baselineArtifactId"]:
        fail("Scheme-A baseline-v2 identity is invalid")
    if reference.get("baselineArtifactSha256") != digest(args.artifact):
        fail("Scheme-A baseline-v2 reference digest does not match artifact")
    if reference.get("schemeManifestSha256") != digest(args.scheme) or artifact.get("schemeManifestSha256") != digest(args.scheme):
        fail("Scheme-A baseline-v2 is not bound to the selected manifest")
    if artifact.get("immutable") is not True or artifact.get("contentAddressed") is not True or artifact.get("neverOverwrite") is not True:
        fail("Scheme-A baseline-v2 must be immutable and content-addressed")
    families = artifact.get("families")
    if artifact.get("requiredFamilies") != list(FAMILIES):
        fail("Scheme-A baseline-v2 family set/order is invalid")
    for family_id in FAMILIES:
        record = families[family_id]
        replicas = record.get("baselineReplicas")
        if not isinstance(replicas, list) or len(replicas) != 3:
            fail(f"{family_id} does not have three baseline replicas")
        costs = [item.get("successCpuNs") for item in replicas]
        if any(not isinstance(cost, int) or isinstance(cost, bool) or cost <= 0 for cost in costs):
            fail(f"{family_id} contains a non-finite baseline cost")
        if record.get("baselineCostCpuNs") != max(costs):
            fail(f"{family_id} baseline cost is not the max of its replicas")
    if args.evaluator_root:
        root = args.evaluator_root.resolve()
        for family_id in FAMILIES:
            for replica in (1, 2, 3):
                attempt = root / "strength" / family_id / f"replica-{replica}" / "baseline" / "attempt.json"
                if not attempt.is_file():
                    fail(f"missing evaluator baseline attempt: {attempt}")
    print("PASS Scheme-A baseline-v2: six immutable families with three finite replicas each")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL Scheme-A baseline-v2: {error}", file=sys.stderr)
        raise SystemExit(1)
