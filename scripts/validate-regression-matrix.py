#!/usr/bin/env python3
"""Validate the machine-readable test/evidence regression matrix."""

from __future__ import annotations

import json
from pathlib import Path
import sys


TIERS = {"pr", "nightly", "release"}
CLASSES = {
    "cli",
    "pack",
    "constants",
    "fuzz",
    "stress",
    "launcher",
    "managed-handoff",
    "host-context",
    "fixture-matrix",
    "packed-fixture",
    "musl",
    "bionic",
    "android-native-bridge",
}
EXPECTED = {"pass", "pass-or-unavailable"}


def fail(message: str) -> None:
    raise SystemExit(f"regression matrix: {message}")


def validate(
    data: dict[str, object],
    selected_tier: str | None = None,
    check_artifacts: bool = False,
    repository_root: Path | None = None,
) -> None:
    if data.get("schemaVersion") != 1:
        fail("schemaVersion must be 1")
    tiers = data.get("tiers")
    if not isinstance(tiers, list) or set(tiers) != TIERS:
        fail("tiers must contain exactly pr, nightly, and release")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        fail("cases must be a non-empty array")

    ids: set[str] = set()
    seen_classes: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            fail(f"case {index} must be an object")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            fail(f"case {index} has a missing or duplicate id")
        ids.add(case_id)
        case_class = case.get("class")
        if case_class not in CLASSES:
            fail(f"{case_id}.class is unsupported")
        seen_classes.add(case_class)
        command = case.get("command")
        if not isinstance(command, str) or not command.strip():
            fail(f"{case_id}.command must be non-empty")
        selected_tiers = case.get("tiers")
        if not isinstance(selected_tiers, list) or not selected_tiers or not set(selected_tiers) <= TIERS:
            fail(f"{case_id}.tiers contains an unsupported or empty selection")
        if case.get("platform") not in {"any", "native-arm64", "native-arm64-container", "x86_64-android-native-bridge"}:
            fail(f"{case_id}.platform is unsupported")
        if not isinstance(case.get("budgetSeconds"), int) or case["budgetSeconds"] <= 0:
            fail(f"{case_id}.budgetSeconds must be positive")
        if not isinstance(case.get("memoryMb"), int) or case["memoryMb"] <= 0:
            fail(f"{case_id}.memoryMb must be positive")
        if not isinstance(case.get("required"), bool):
            fail(f"{case_id}.required must be boolean")
        if case.get("expected") not in EXPECTED:
            fail(f"{case_id}.expected is unsupported")
        artifacts = case.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts or not all(isinstance(item, str) and item for item in artifacts):
            fail(f"{case_id}.artifacts must be a non-empty string array")
        if check_artifacts and selected_tier in case["tiers"]:
            assert repository_root is not None
            missing = [
                pattern
                for pattern in artifacts
                if not any(repository_root.glob(pattern))
            ]
            if missing:
                fail(f"{case_id} is missing artifact witnesses: {', '.join(missing)}")

    required_classes = {"cli", "pack", "constants", "fuzz", "stress", "launcher", "managed-handoff", "host-context", "fixture-matrix", "packed-fixture"}
    missing = sorted(required_classes - seen_classes)
    if missing:
        fail(f"required regression classes are missing: {', '.join(missing)}")


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(
            "usage: validate-regression-matrix.py MATRIX "
            "[--tier pr|nightly|release] [--emit] [--check-artifacts]"
        )
    path = Path(sys.argv[1])
    tier: str | None = None
    emit = False
    check_artifacts = False
    index = 2
    while index < len(sys.argv):
        option = sys.argv[index]
        if option == "--tier" and index + 1 < len(sys.argv):
            tier = sys.argv[index + 1]
            index += 2
        elif option == "--emit":
            emit = True
            index += 1
        elif option == "--check-artifacts":
            check_artifacts = True
            index += 1
        else:
            raise SystemExit(
                "usage: validate-regression-matrix.py MATRIX "
                "[--tier pr|nightly|release] [--emit] [--check-artifacts]"
            )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(str(error))
    if not isinstance(data, dict):
        fail("root must be an object")
    validate(
        data,
        selected_tier=tier,
        check_artifacts=check_artifacts,
        repository_root=path.parent.parent,
    )
    if emit or tier is not None:
        if tier not in TIERS:
            fail(f"unsupported tier: {tier}")
        selected = [case for case in data["cases"] if tier in case["tiers"]]
        print(json.dumps({"schemaVersion": 1, "tier": tier, "cases": selected}, indent=2))
    else:
        print(f"regression matrix valid: {path} ({len(data['cases'])} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
