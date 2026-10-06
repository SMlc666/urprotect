#!/usr/bin/env python3
"""Check the machine-readable 100-unit strict compatibility growth gate."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEME_MANIFEST = ROOT / "fixtures/evaluator/scheme-a-manifest.json"
V2_SCHEME_MANIFEST = ROOT / "fixtures/evaluator/scheme-a-manifest-v2.json"
STAGES = (
    "protector",
    "protected-image",
    "rehydration",
    "native-image",
    "target-loader",
    "behavioral-oracle",
)
UNIT_ID = "compat.protection-symbolized-fixture.glibc.outer-execveat"


def fail(message: str) -> int:
    print(f"FAIL strict compatibility growth: {message}", file=sys.stderr)
    return 1


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evaluator_root", type=Path)
    parser.add_argument("--scheme-a-manifest", type=Path, default=DEFAULT_SCHEME_MANIFEST)
    args = parser.parse_args()
    additive_scheme = args.scheme_a_manifest.resolve() != DEFAULT_SCHEME_MANIFEST.resolve()
    root = args.evaluator_root if args.evaluator_root.is_absolute() else ROOT / args.evaluator_root
    checker = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check-independent-evaluator.py"), str(root), "--scheme-a-manifest", str(args.scheme_a_manifest.resolve())],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if checker.returncode != 0:
        return fail(f"independent evidence checker failed: {checker.stderr.strip()[:512]}")
    corpus = read_json(ROOT / "fixtures/evaluator/compatibility-corpus.json")
    rows = corpus.get("rows")
    fixed = corpus.get("fixedRowIds")
    if not isinstance(rows, list) or len(rows) != 100:
        return fail("append-only corpus must contain exactly 100 registered rows")
    if fixed != [UNIT_ID]:
        return fail("v2 fixed view must contain exactly the historical unit")
    if len({row.get("unitId") for row in rows}) != 100:
        return fail("unitId identities are duplicated")
    if len({row.get("identityKey") for row in rows}) != 100:
        return fail("identityKey identities are duplicated")
    if len({row.get("sourceProvenance") for row in rows}) != 100:
        return fail("source provenance identities are duplicated")
    if any(row.get("registrationStatus") not in {"frozen", "growth"} for row in rows):
        return fail("corpus row registration status is outside the reviewed vocabulary")

    gate = read_json(root / "gate.json")
    if not additive_scheme:
        scheme = gate.get("schemeA", {})
        if scheme.get("status") != "baseline-not-calibrated" or any(value is not None for value in scheme.get("familyFactors", {}).values()):
            return fail("historical Scheme-A default must remain baseline-not-calibrated")
        if gate.get("claimable") is not False:
            return fail("historical Scheme-A default cannot make the overall claimable gate true")
        print("PASS strict compatibility growth: historical Scheme-A remains independent")
        return 0
    compatibility = gate.get("compatibility", {})
    environment = gate.get("environment", {})
    if additive_scheme and (environment.get("status") != "available" or environment.get("runtimeCell") != "glibc.current.native-arm64"):
        return fail("declared native glibc evaluator environment is unavailable")
    expected = {
        "baselineCompleteUnits": 1,
        "candidateFixedCompleteUnits": 1,
        "candidateGrowthCompleteUnits": 100,
        "factor": 100.0,
        "growthTarget": 100,
        "fixedViewPass": True,
        "growthViewPass": True,
    }
    for field, value in expected.items():
        if compatibility.get(field) != value:
            return fail(f"gate.compatibility.{field} expected {value!r}, got {compatibility.get(field)!r}")
    if compatibility.get("status") != "measured":
        return fail("compatibility status is not measured")
    scheme = gate.get("schemeA", {})
    if scheme.get("status") != "pass" or scheme.get("allRequiredPass") is not True:
        return fail("Scheme-A six-family calibration is not independently passing")
    if any(not isinstance(value, (int, float)) or value < 100.0 for value in scheme.get("familyFactors", {}).values()):
        return fail("Scheme-A family factor is below the frozen 100x threshold")

    unit_root = root / "compatibility"
    unit_paths = sorted(unit_root.glob("*/unit.json"))
    complete = []
    for path in unit_paths:
        unit = read_json(path)
        if unit.get("complete") is True and unit.get("strictChainMeasured") is True:
            stages = unit.get("stages", {})
            if tuple(stages) != STAGES and set(stages) != set(STAGES):
                return fail(f"unit {unit.get('unitId')} does not contain exactly six stages")
            if any(stages.get(stage, {}).get("status") != "passed" for stage in STAGES):
                return fail(f"unit {unit.get('unitId')} contains a non-passed stage")
            complete.append(unit)
    if len(complete) != 100:
        return fail(f"expected 100 complete strict units, found {len(complete)}")
    if {unit.get("unitId") for unit in complete} != {row.get("unitId") for row in rows}:
        return fail("complete strict unit identities do not match the registered corpus")
    print("PASS strict compatibility growth: 100 complete units, factor=100.0, Scheme-A remains independent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
