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

make -C "${script_dir}" symbol-fixture >>"${artifact_root}/build.log" 2>&1
make -C "${script_dir}" symbol-self-test >>"${artifact_root}/build.log" 2>&1
"${script_dir}/build/host-context-symbol-self-test" \
  "${script_dir}/build/host-context-symbol-fixture.so" \
  >"${artifact_root}/symbol-self-test.log" 2>&1
symbol_output="${artifact_root}/host-context-symbol-packed"
symbol_report="${artifact_root}/host-context-symbol-packed.json"
"${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack "${script_dir}/build/host-context-symbol-fixture.so" \
  --output "${symbol_output}" \
  --launcher "${script_dir}/build/host-context-launcher" \
  --profile host-context-entry \
  --json "${symbol_report}" \
  >"${artifact_root}/symbol-pack.log" 2>&1
set +e
"${symbol_output}" >"${artifact_root}/symbol.stdout" 2>"${artifact_root}/symbol.stderr"
symbol_status=$?
set -e
if [[ "${symbol_status}" -ne 29 ]]; then
  echo "GLOB_DAT symbol fixture returned ${symbol_status}, expected 29" >&2
  exit 1
fi
printf 'symbol_profile=host-context-entry\nsymbol_relocation=GLOB_DAT\nsymbol_status=%s\n' "${symbol_status}" \
  >"${artifact_root}/symbol-result.txt"
sha256sum "${symbol_output}" "${script_dir}/build/host-context-symbol-fixture.so" \
  >>"${artifact_root}/sha256.txt"

make -C "${script_dir}" dependency-fixture >>"${artifact_root}/build.log" 2>&1
dependency_output="${artifact_root}/host-context-dependency-packed"
dependency_report="${artifact_root}/host-context-dependency-packed.json"
"${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack "${script_dir}/build/host-context-dependency-fixture.so" \
  --output "${dependency_output}" \
  --launcher "${script_dir}/build/host-context-launcher" \
  --profile host-context-entry \
  --json "${dependency_report}" \
  >"${artifact_root}/dependency-pack.log" 2>&1
set +e
URP_LIFECYCLE_MARKER="${artifact_root}/lifecycle-marker.txt" \
  "${dependency_output}" >"${artifact_root}/dependency.stdout" 2>"${artifact_root}/dependency.stderr"
dependency_status=$?
set -e
if [[ "${dependency_status}" -ne 37 ]]; then
  echo "libc dependency fixture returned ${dependency_status}, expected 37" >&2
  exit 1
fi
if [[ "$(cat "${artifact_root}/lifecycle-marker.txt" 2>/dev/null || true)" != "released" ]]; then
  echo "dependency destructor did not run before HostContext release completed" >&2
  exit 1
fi
printf 'dependency=libc.so.6\ndependency_status=%s\n' "${dependency_status}" \
  >"${artifact_root}/dependency-result.txt"
sha256sum "${dependency_output}" "${script_dir}/build/host-context-dependency-fixture.so" \
  >>"${artifact_root}/sha256.txt"

make -C "${script_dir}" tls-fixture >>"${artifact_root}/build.log" 2>&1
tls_output="${artifact_root}/host-context-tls-packed"
tls_report="${artifact_root}/host-context-tls-packed.json"
"${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack "${script_dir}/build/host-context-tls-fixture.so" \
  --output "${tls_output}" \
  --launcher "${script_dir}/build/host-context-launcher" \
  --profile host-context-entry \
  --json "${tls_report}" \
  >"${artifact_root}/tls-pack.log" 2>&1
set +e
"${tls_output}" >"${artifact_root}/tls.stdout" 2>"${artifact_root}/tls.stderr"
tls_status=$?
set -e
if [[ "${tls_status}" -ne 43 ]]; then
  echo "TLS fixture returned ${tls_status}, expected 43" >&2
  exit 1
fi
printf 'tls_model=initial-exec\ntls_status=%s\n' "${tls_status}" \
  >"${artifact_root}/tls-result.txt"
sha256sum "${tls_output}" "${script_dir}/build/host-context-tls-fixture.so" \
  >>"${artifact_root}/sha256.txt"

make -C "${script_dir}" property-fixture >>"${artifact_root}/build.log" 2>&1
property_output="${artifact_root}/host-context-property-packed"
property_report="${artifact_root}/host-context-property-packed.json"
"${dotnet_command}" run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack "${script_dir}/build/host-context-property-fixture.so" \
  --output "${property_output}" \
  --launcher "${script_dir}/build/host-context-launcher" \
  --profile host-context-entry \
  --json "${property_report}" \
  >"${artifact_root}/property-pack.log" 2>&1
set +e
"${property_output}" >"${artifact_root}/property.stdout" 2>"${artifact_root}/property.stderr"
property_status=$?
set -e
if [[ "${property_status}" -ne 47 ]]; then
  echo "GNU property fixture returned ${property_status}, expected 47" >&2
  exit 1
fi
printf 'gnu_property=BTI\nproperty_status=%s\n' "${property_status}" \
  >"${artifact_root}/property-result.txt"
sha256sum "${property_output}" "${script_dir}/build/host-context-property-fixture.so" \
  >>"${artifact_root}/sha256.txt"
echo "managed HostContext handoff: PASS"
