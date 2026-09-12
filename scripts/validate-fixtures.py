#!/usr/bin/env python3
"""Validate and select the covering native/Android fixture manifest."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


TIERS = {"pr": 0, "nightly": 1, "release": 2}
REQUIRED_FIELDS = {
    "id",
    "language",
    "toolchain",
    "builder",
    "runtime",
    "target",
    "artifact",
    "source",
    "tier",
    "required",
    "execution",
}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: validate-fixtures.py MANIFEST [pr|nightly|release] [--emit]")

    manifest_path = Path(sys.argv[1])
    requested = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "pr"
    emit = "--emit" in sys.argv[2:]
    if requested not in TIERS:
        raise SystemExit(f"unsupported fixture tier: {requested}")

    data = json.loads(manifest_path.read_text())
    if data.get("schemaVersion") != 2:
        raise SystemExit("fixture manifest schemaVersion must be 2")
    android = data.get("android")
    if not isinstance(android, dict):
        raise SystemExit("fixture manifest must contain an android object")
    container = android.get("container")
    if not isinstance(container, dict):
        raise SystemExit("fixture manifest android.container must be an object")
    for field in ("profile", "systemImageUrl", "systemImageSha256", "vendorImageUrl", "vendorImageSha256"):
        if not isinstance(container.get(field), str) or not container[field]:
            raise SystemExit(f"fixture manifest android.container.{field} must be a non-empty string")
    for field in ("systemImageSha256", "vendorImageSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", container[field]):
            raise SystemExit(f"fixture manifest android.container.{field} must be a lowercase SHA-256")
    profiles = data.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise SystemExit("fixture manifest must contain a non-empty profiles array")

    ids: set[str] = set()
    selected: list[dict[str, object]] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            raise SystemExit("each fixture profile must be an object")
        missing = REQUIRED_FIELDS - profile.keys()
        if missing:
            raise SystemExit(f"{profile.get('id', '<unknown>')} missing fields: {sorted(missing)}")
        profile_id = profile["id"]
        tier = profile["tier"]
        if (
            not isinstance(profile_id, str)
            or not ID_PATTERN.fullmatch(profile_id)
            or profile_id in ids
        ):
            raise SystemExit(f"fixture profile ids must be unique non-empty strings: {profile_id!r}")
        if tier not in TIERS:
            raise SystemExit(f"{profile_id} has unsupported tier {tier!r}")
        if not isinstance(profile["required"], bool):
            raise SystemExit(f"{profile_id}.required must be boolean")
        if not isinstance(profile["source"], str) or not profile["source"]:
            raise SystemExit(f"{profile_id}.source must be a non-empty string")
        source = (manifest_path.parent.parent / Path(profile["source"])).resolve()
        repo_root = manifest_path.parent.parent.resolve()
        try:
            source.relative_to(repo_root)
        except ValueError:
            raise SystemExit(f"{profile_id}.source must remain inside the repository")
        if profile["execution"] in {"native-linux", "android-arm64-native-bridge-on-x64"} and not source.exists():
            raise SystemExit(f"{profile_id} source does not exist: {source}")
        ids.add(profile_id)
        if TIERS[tier] <= TIERS[requested]:
            selected.append(profile)

    if not any(profile["tier"] == "pr" for profile in profiles):
        raise SystemExit("fixture manifest must contain at least one PR profile")

    summary = f"validated fixture manifest: {len(profiles)} profiles; requested tier={requested}"
    print(summary, file=sys.stderr if emit else sys.stdout)
    if emit:
        for profile in selected:
            print(json.dumps(profile, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
