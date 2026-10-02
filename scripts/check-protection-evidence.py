#!/usr/bin/env python3
"""Validate normalized function-protection E2E evidence without raw binaries."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


def require_file(root: Path, relative: str) -> Path:
    path = root / relative
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"missing or empty protection evidence: {relative}")
    return path


def check_native(root: Path, tier: str, runtime: str) -> None:
    result = json.loads(require_file(root, "result.json").read_text())
    if result != {
        "schemaVersion": 1,
        "tier": tier,
        "runtime": runtime,
        "baselineStatus": 0,
        "recipes": [
            "register-permutation",
            "control-flow-flattening",
            "combined",
            "branch-control-flow-flattening",
        ],
        "behaviorEquivalent": True,
        "rawInputsRemoved": True,
    }:
        fail("native protection result does not match the required normalized contract")
    for recipe, passes in (
        ("register-permutation", ["register-permutation"]),
        ("control-flow-flattening", ["control-flow-flattening"]),
        ("combined", ["control-flow-flattening", "register-permutation"]),
    ):
        report = json.loads(require_file(root, f"{recipe}.json").read_text())
        if report.get("success") is not True:
            fail(f"{recipe}: protection report is not successful")
        selected = [
            item
            for item in report.get("functions", [])
            if item.get("name") == "urp_transform_target"
        ]
        if len(selected) != 1 or selected[0].get("transformed") is not True:
            fail(f"{recipe}: selected function transformation is missing")
        if selected[0].get("appliedPasses") != passes:
            fail(f"{recipe}: selected pass order is not {passes}")
        if require_file(root, f"{recipe}.status").read_text().strip() != "0":
            fail(f"{recipe}: protected execution did not exit zero")
        require_file(root, f"{recipe}.sha256")
        require_file(root, f"{recipe}-readelf.txt")

    branch_report = json.loads(
        require_file(root, "branch-control-flow-flattening.json").read_text()
    )
    branch_selected = [
        item
        for item in branch_report.get("functions", [])
        if item.get("name") == "urp_flatten_target"
    ]
    if (
        branch_report.get("success") is not True
        or len(branch_selected) != 1
        or branch_selected[0].get("transformed") is not True
        or branch_selected[0].get("appliedPasses") != ["control-flow-flattening"]
    ):
        fail("branch-control-flow-flattening: selected function transformation is missing")
    if require_file(root, "branch-control-flow-flattening.status").read_text().strip() != "0":
        fail("branch-control-flow-flattening: protected execution did not exit zero")
    require_file(root, "branch-control-flow-flattening.sha256")
    require_file(root, "branch-control-flow-flattening-readelf.txt")

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if os.access(path, os.X_OK):
            fail(f"raw executable was retained in protection evidence: {path.relative_to(root)}")


def check_bionic(root: Path) -> None:
    report = json.loads(require_file(root, "protection.json").read_text())
    if report.get("success") is not True:
        fail("bionic protection report is not successful")
    selected = [
        item
        for item in report.get("functions", [])
        if item.get("name") == "urp_transform_target"
    ]
    if len(selected) != 1 or selected[0].get("transformed") is not True:
        fail("bionic selected function transformation is missing")
    if selected[0].get("appliedPasses") != ["register-permutation"]:
        fail("bionic protection pass order is incorrect")
    if require_file(root, "protection.status").read_text().strip() != "0":
        fail("bionic protected execution did not exit zero")
    require_file(root, "protection.sha256")
    require_file(root, "protection-readelf.txt")
    for forbidden in ("protection-input", "protected-fixture"):
        if (root / forbidden).exists():
            fail(f"bionic raw protected executable was retained: {forbidden}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--tier", choices=("pr", "nightly", "release"))
    parser.add_argument("--runtime", choices=("glibc", "musl", "bionic"), required=True)
    args = parser.parse_args()
    if args.runtime == "bionic":
        check_bionic(args.artifact_root)
    else:
        if args.tier is None:
            fail("--tier is required for glibc and musl evidence")
        check_native(args.artifact_root, args.tier, args.runtime)
    print(f"PASS protection evidence: runtime={args.runtime} root={args.artifact_root}")


if __name__ == "__main__":
    main()
