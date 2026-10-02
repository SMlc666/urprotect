#!/usr/bin/env python3
"""Validate the explicit-selector policy used by real-sample protection runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PASSES = {"control-flow-flattening", "register-permutation"}
RUNTIMES = {"glibc", "musl", "bionic"}


def fail(message: str) -> None:
    raise SystemExit(message)


def validate(policy: dict) -> None:
    if policy.get("schemaVersion") != 1:
        fail("protection policy schemaVersion must be 1")
    default = policy.get("default")
    if not isinstance(default, dict) or default.get("status") != "not-applicable":
        fail("protection policy default must be explicit not-applicable")
    if "all" in json.dumps(policy, sort_keys=True).lower():
        fail("protection policy must not contain an all-functions selector")
    projects = policy.get("projects")
    if not isinstance(projects, dict):
        fail("protection policy projects must be an object")
    for project_id, entry in projects.items():
        if not isinstance(project_id, str) or not project_id:
            fail("protection policy project IDs must be non-empty strings")
        if not isinstance(entry, dict):
            fail(f"{project_id}: protection policy entry must be an object")
        selectors = entry.get("selectors")
        passes = entry.get("passes")
        runtime = entry.get("runtime")
        if not isinstance(selectors, list) or not selectors or any(
            not isinstance(value, str) or not value for value in selectors
        ):
            fail(f"{project_id}: selectors must be an explicit non-empty string list")
        if not isinstance(passes, list) or not passes or any(value not in PASSES for value in passes):
            fail(f"{project_id}: passes must contain only known explicit passes")
        if runtime not in RUNTIMES:
            fail(f"{project_id}: runtime must be one of {sorted(RUNTIMES)}")
        if set(passes) == PASSES and entry.get("combinedOrder") != [
            "control-flow-flattening",
            "register-permutation",
        ]:
            fail(f"{project_id}: combinedOrder must preserve flatten-then-permute")
    fixtures = policy.get("smokeFixtures")
    if not isinstance(fixtures, dict) or not fixtures:
        fail("protection policy must retain an explicit symbolized smoke fixture")
    for fixture_id, entry in fixtures.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("selectors"), list):
            fail(f"{fixture_id}: smoke fixture selectors are required")
        if set(entry.get("runtime", [])) != RUNTIMES:
            fail(f"{fixture_id}: smoke fixture must cover glibc, musl, and bionic")
        if set(entry.get("passes", [])) != PASSES:
            fail(f"{fixture_id}: smoke fixture must cover both protection passes")
        if entry.get("combinedOrder") != [
            "control-flow-flattening",
            "register-permutation",
        ]:
            fail(f"{fixture_id}: smoke fixture combinedOrder is incorrect")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    try:
        validate(json.loads(args.policy.read_text()))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"could not read protection policy: {error}")
    print(f"PASS protection policy: {args.policy}")


if __name__ == "__main__":
    main()
