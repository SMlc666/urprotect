#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
dotnet_command="${DOTNET:-dotnet}"
artifact_root="${MANAGED_HOST_CONTEXT_ARTIFACT_ROOT:-${repo_root}/.artifacts/host-context/managed}"

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "managed HostContext handoff requires an aarch64 host" >&2
  exit 2
fi
command -v "${dotnet_command}" >/dev/null 2>&1
command -v make >/dev/null 2>&1

mkdir -p "${artifact_root}"
make -C "${script_dir}" host-context-launcher build/host-context-entry-fixture.so \
  >"${artifact_root}/build.log" 2>&1

output="${artifact_root}/host-context-packed"
report="${artifact_root}/host-context-packed.json"
"${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack "${script_dir}/build/host-context-entry-fixture.so" \
  --output "${output}" \
  --launcher "${script_dir}/build/host-context-launcher" \
  --profile host-context-entry \
  --json "${report}" \
  >"${artifact_root}/pack.log" 2>&1

python3 - "${report}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not report["success"]:
    raise SystemExit("managed HostContext pack report is not successful")
payload = report["payload"]
if payload["profile"] != "host-context-entry":
    raise SystemExit("managed pack selected the wrong profile")
if payload["frameVersion"] != 3:
    raise SystemExit("managed pack did not emit the current frame")
if payload["launcherMarker"] != "URPROTECT-AARCH64-HOST-CONTEXT-V3":
    raise SystemExit("managed pack selected the wrong launcher marker")
PY

set +e
"${output}" >"${artifact_root}/run.stdout" 2>"${artifact_root}/run.stderr"
status=$?
set -e
if [[ "${status}" -ne 23 ]]; then
  echo "HostContext entry returned ${status}, expected 23" >&2
  exit 1
fi

if [[ -s "${artifact_root}/run.stdout" || -s "${artifact_root}/run.stderr" ]]; then
  echo "HostContext entry unexpectedly wrote process streams" >&2
  exit 1
fi

sha256sum "${output}" "${script_dir}/build/host-context-entry-fixture.so" \
  >"${artifact_root}/sha256.txt"
printf 'profile=host-context-entry\nframe_version=3\nentry_status=%s\n' "${status}" \
  >"${artifact_root}/result.txt"
echo "managed HostContext handoff: PASS"
