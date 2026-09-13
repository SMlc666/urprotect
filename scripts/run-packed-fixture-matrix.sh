#!/usr/bin/env bash
set -euo pipefail

requested_profile="${1:---profile}"
if [[ "${requested_profile}" == "--profile" ]]; then
  requested_profile="${2:-pr}"
fi

case "${requested_profile}" in
  pr|nightly|release) ;;
  *)
    echo "unsupported packed fixture profile: ${requested_profile}" >&2
    exit 2
    ;;
esac

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "packed fixture profiles require an aarch64 runner; got $(uname -m)" >&2
  exit 2
fi

for required_command in cmp dotnet file grep head make mktemp readelf timeout python3; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required to run packed fixture profile ${requested_profile}" >&2
    exit 127
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/fixtures/manifest.json"
artifact_root="${PACKED_FIXTURE_ARTIFACT_ROOT:-${repo_root}/.artifacts/packed/${requested_profile}}"
fixture_root="${FIXTURE_ARTIFACT_ROOT:-${repo_root}/.artifacts/fixtures/${requested_profile}}"
run_timeout="${PACKED_FIXTURE_TIMEOUT_SECONDS:-45}"
dotnet_cli=(dotnet run --project "${repo_root}/src/UrProtect.Cli" --configuration Release --no-build --no-restore --)
mkdir -p "${artifact_root}"

if [[ "${requested_profile}" != "pr" ]]; then
  echo "packed fixture profiles currently support only the native glibc PR covering set" >&2
  exit 2
fi

"${repo_root}/scripts/run-fixture-matrix.sh" --profile "${requested_profile}"

launcher_root="${artifact_root}/native-launcher"
native_launcher_compiler="${NATIVE_LAUNCHER_CC:-musl-gcc}"
if ! command -v "${native_launcher_compiler%% *}" >/dev/null 2>&1; then
  echo "${native_launcher_compiler} is required to build the native launcher" >&2
  exit 127
fi
make -C "${repo_root}/native/urprotect-launcher" \
  BUILD_DIR="${launcher_root}" \
  CC="${native_launcher_compiler}" \
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" all self-test
launcher="${launcher_root}/urprotect-launcher"
native_launcher_self_test="${launcher_root}/urprotect-launcher-self-test"
if [[ ! -x "${launcher}" ]]; then
  echo "the native AArch64 launcher was not built: ${launcher}" >&2
  exit 1
fi
if [[ ! -x "${native_launcher_self_test}" ]]; then
  echo "the native AArch64 launcher self-test was not built: ${native_launcher_self_test}" >&2
  exit 1
fi
"${native_launcher_self_test}"
NATIVE_LAUNCHER_TEST_ARTIFACT_ROOT="${artifact_root}/launcher-tests" \
  DOTNET="$(command -v dotnet)" \
  "${repo_root}/native/urprotect-launcher/test_launcher.sh" "${launcher}"

profile_stream="$(python3 "${repo_root}/scripts/validate-fixtures.py" "${manifest}" "${requested_profile}" --emit)"
mapfile -t profiles <<< "${profile_stream}"

profile_value() {
  local profile_json="$1"
  local field="$2"
  python3 - "${profile_json}" "${field}" <<'PY'
import json
import sys

profile = json.loads(sys.argv[1])
value = profile.get(sys.argv[2], "")
print("true" if value is True else "false" if value is False else value)
PY
}

for profile_json in "${profiles[@]}"; do
  id="$(profile_value "${profile_json}" id)"
  binary="${fixture_root}/${id}/build/fixture"
  case_root="${artifact_root}/${id}"
  wrapper="${case_root}/wrapped"
  mkdir -p "${case_root}"

  if [[ ! -x "${binary}" ]]; then
    echo "FAIL ${id}: fixture binary is missing: ${binary}" >&2
    exit 1
  fi

  file "${binary}" > "${case_root}/baseline.file.txt"
  readelf -hW -lW -dW "${binary}" > "${case_root}/baseline.readelf.txt"
  if ! python3 - "${case_root}/baseline.readelf.txt" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()
if fields.get("Class") != "ELF64" or fields.get("Machine") != "AArch64":
    raise SystemExit("fixture is not ELF64 AArch64")
if not fields.get("Type", "").startswith("DYN"):
    raise SystemExit("fixture is not ET_DYN")
PY
  then
    echo "FAIL ${id}: baseline structural oracle rejected the fixture" >&2
    exit 1
  fi

  set +e
  timeout "${run_timeout}" "${binary}" \
    > "${case_root}/baseline.stdout" \
    2> "${case_root}/baseline.stderr"
  baseline_status=$?
  set -e

  "${dotnet_cli[@]}" pack "${binary}" \
    --output "${wrapper}" \
    --launcher "${launcher}" \
    --json "${case_root}/pack.json" \
    > "${case_root}/pack.stdout" \
    2> "${case_root}/pack.stderr"
  if [[ ! -x "${wrapper}" ]]; then
    echo "FAIL ${id}: pack command did not produce an executable wrapper" >&2
    exit 1
  fi
  if cmp -- "${binary}" "${wrapper}" >/dev/null 2>&1; then
    echo "FAIL ${id}: wrapper bytes are identical to the source" >&2
    exit 1
  fi

  file "${wrapper}" > "${case_root}/wrapper.file.txt"
  readelf -hW -lW -dW "${wrapper}" > "${case_root}/wrapper.readelf.txt"
  if ! python3 - "${case_root}/wrapper.readelf.txt" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()
if fields.get("Class") != "ELF64" or fields.get("Machine") != "AArch64":
    raise SystemExit("wrapper is not ELF64 AArch64")
if not fields.get("Type", "").startswith("DYN"):
    raise SystemExit("wrapper is not ET_DYN")
PY
  then
    echo "FAIL ${id}: wrapper structural oracle rejected the generated ELF" >&2
    exit 1
  fi
  set +e
  timeout "${run_timeout}" "${wrapper}" \
    > "${case_root}/wrapped.stdout" \
    2> "${case_root}/wrapped.stderr"
  wrapped_status=$?
  set -e

  printf '%s\n' "${baseline_status}" > "${case_root}/baseline.status"
  printf '%s\n' "${wrapped_status}" > "${case_root}/wrapped.status"
  if [[ "${baseline_status}" -ne "${wrapped_status}" ]]; then
    echo "FAIL ${id}: baseline status ${baseline_status} != wrapped status ${wrapped_status}" >&2
    exit 1
  fi
  cmp -- "${case_root}/baseline.stdout" "${case_root}/wrapped.stdout"
  cmp -- "${case_root}/baseline.stderr" "${case_root}/wrapped.stderr"
  echo "PASS ${id}: packed wrapper preserved native baseline behavior"
done

echo "Packed fixture profile ${requested_profile} completed"
