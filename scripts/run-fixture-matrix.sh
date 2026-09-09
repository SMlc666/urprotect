#!/usr/bin/env bash
set -euo pipefail

profile="${1:---profile}"
if [[ "${profile}" == "--profile" ]]; then
  profile="${2:-pr}"
fi

case "${profile}" in
  pr|nightly|release) ;;
  *) echo "unsupported fixture profile: ${profile}" >&2; exit 2 ;;
esac

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet is required to run fixture profile ${profile}" >&2
  exit 127
fi

python3 - "${profile}" <<'PY'
import json
import sys
from pathlib import Path

requested = sys.argv[1]
manifest = json.loads(Path("fixtures/manifest.json").read_text())
profiles = manifest.get("profiles")
if not isinstance(profiles, list) or not profiles:
    raise SystemExit("fixture manifest must contain a non-empty profiles array")

ids = [profile.get("id") for profile in profiles]
if any(not isinstance(profile_id, str) or not profile_id for profile_id in ids):
    raise SystemExit("every fixture profile needs a non-empty id")
if len(ids) != len(set(ids)):
    raise SystemExit("fixture profile ids must be unique")

tiers = {profile.get("tier") for profile in profiles}
if requested not in {"pr", "nightly", "release"}:
    raise SystemExit(f"unsupported fixture profile: {requested}")
if requested == "pr" and "pr" not in tiers:
    raise SystemExit("PR fixture profile is missing from the manifest")
print(f"validated fixture manifest: {len(profiles)} profiles; requested tier={requested}")
PY

dotnet test UrProtect.sln --configuration Release --no-restore
