#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${MUSL_CONTAINER_ARTIFACT_ROOT:-${repo_root}/.artifacts/musl-container}"
run_timeout="${MUSL_CONTAINER_TIMEOUT_SECONDS:-45}"
mkdir -p "${artifact_root}"

for required_command in cmp dotnet file make musl-gcc python3 readelf timeout; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required for the musl container smoke" >&2
    exit 127
  fi
done

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "musl container smoke requires an aarch64 container; got $(uname -m)" >&2
  exit 2
fi

source_file="${repo_root}/fixtures/samples/c/main.c"
build_directory="${artifact_root}/build"
binary="${build_directory}/fixture"
copy="${artifact_root}/no-op-copy"
mkdir -p "${build_directory}"

musl-gcc -std=c11 -O2 -g0 -fPIE -pie -Wl,--build-id=none \
  "${source_file}" -o "${binary}"
file "${binary}" > "${artifact_root}/file.txt"
readelf -hW -lW -dW "${binary}" > "${artifact_root}/readelf.txt"

if ! python3 - "${artifact_root}/readelf.txt" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()

if fields.get("Class") != "ELF64" \
        or fields.get("Data") != "2's complement, little endian" \
        or fields.get("Machine") != "AArch64" \
        or not fields.get("Type", "").startswith("DYN") \
        or "There is no dynamic section in this file." in report:
    raise SystemExit("musl container ELF structural oracle rejected the fixture")
PY
then
  echo "musl container ELF structural oracle rejected the fixture" >&2
  exit 1
fi

set +e
timeout "${run_timeout}" "${binary}" \
  > "${artifact_root}/baseline.stdout" \
  2> "${artifact_root}/baseline.stderr"
baseline_status=$?
set -e
printf '%s\n' "${baseline_status}" > "${artifact_root}/baseline.status"
if [[ "${baseline_status}" -ne 0 ]]; then
  echo "musl container baseline exited with status ${baseline_status}" >&2
  exit 1
fi

dotnet run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release \
  --no-build \
  --no-restore \
  -- validate "${binary}" --no-analysis --copy "${copy}" \
  > "${artifact_root}/validator.stdout" \
  2> "${artifact_root}/validator.stderr"
cmp -- "${binary}" "${copy}"

set +e
timeout "${run_timeout}" "${copy}" \
  > "${artifact_root}/output.stdout" \
  2> "${artifact_root}/output.stderr"
output_status=$?
set -e
printf '%s\n' "${output_status}" > "${artifact_root}/output.status"
if [[ "${output_status}" -ne 0 ]]; then
  echo "musl container no-op output exited with status ${output_status}" >&2
  exit 1
fi

cmp -- "${artifact_root}/baseline.stdout" "${artifact_root}/output.stdout"
cmp -- "${artifact_root}/baseline.stderr" "${artifact_root}/output.stderr"
printf '%s\n' "PASS musl-container: baseline/output behavior and byte identity match"

launcher_directory="${artifact_root}/native-launcher"
launcher="${launcher_directory}/urprotect-launcher"
packed="${artifact_root}/packed-fixture"
mkdir -p "${launcher_directory}"
make -C "${repo_root}/native/urprotect-launcher" \
  BUILD_DIR="${launcher_directory}" \
  CC="${NATIVE_LAUNCHER_CC:-musl-gcc}" \
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" all self-test
if [[ ! -x "${launcher}" ]]; then
  echo "musl launcher build did not produce ${launcher}" >&2
  exit 1
fi
"${launcher_directory}/urprotect-launcher-self-test"
NATIVE_LAUNCHER_TEST_ARTIFACT_ROOT="${artifact_root}/launcher-tests" \
  DOTNET="$(command -v dotnet)" \
  "${repo_root}/native/urprotect-launcher/test_launcher.sh" "${launcher}"

dotnet run --project "${repo_root}/src/UrProtect.Cli" \
  --configuration Release --no-build --no-restore -- \
  pack "${binary}" \
  --output "${packed}" \
  --launcher "${launcher}" \
  --json "${artifact_root}/packed-report.json" \
  > "${artifact_root}/pack.stdout" \
  2> "${artifact_root}/pack.stderr"
if cmp -- "${binary}" "${packed}" >/dev/null 2>&1; then
  echo "musl packed wrapper is byte-identical to the source" >&2
  exit 1
fi
file "${packed}" > "${artifact_root}/packed-file.txt"
readelf -hW -lW -dW "${packed}" > "${artifact_root}/packed-readelf.txt"
python3 - "${artifact_root}/packed-readelf.txt" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()
assert fields.get("Class") == "ELF64"
assert fields.get("Machine") == "AArch64"
assert fields.get("Type", "").startswith("DYN")
PY

set +e
timeout "${run_timeout}" "${packed}" \
  > "${artifact_root}/packed.stdout" \
  2> "${artifact_root}/packed.stderr"
packed_status=$?
set -e
printf '%s\n' "${packed_status}" > "${artifact_root}/packed.status"
if [[ "${packed_status}" -ne "${baseline_status}" ]]; then
  echo "musl packed output status ${packed_status} differs from baseline ${baseline_status}" >&2
  exit 1
fi
cmp -- "${artifact_root}/baseline.stdout" "${artifact_root}/packed.stdout"
cmp -- "${artifact_root}/baseline.stderr" "${artifact_root}/packed.stderr"
printf '%s\n' "PASS musl-container: packed wrapper behavior matches baseline"
