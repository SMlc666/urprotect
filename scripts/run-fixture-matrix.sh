#!/usr/bin/env bash
set -euo pipefail

requested_tier="${1:---tier}"
if [[ "${requested_tier}" == "--tier" ]]; then
  requested_tier="${2:-pr}"
fi

case "${requested_tier}" in
  pr|nightly|release) ;;
  *)
    echo "unsupported fixture tier: ${requested_tier}" >&2
    exit 2
    ;;
esac

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet is required to run fixture tier ${requested_tier}" >&2
  exit 127
fi

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "native fixture tiers require an aarch64 runner; got $(uname -m)" >&2
  exit 2
fi

for required_command in cmp file readelf timeout python3; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required to run fixture tier ${requested_tier}" >&2
    exit 127
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/fixtures/manifest.json"
artifact_root="${FIXTURE_ARTIFACT_ROOT:-${repo_root}/.artifacts/fixtures/${requested_tier}}"
mkdir -p "${artifact_root}"
artifact_root="$(cd "${artifact_root}" && pwd)"

case_stream="$(python3 "${repo_root}/scripts/validate-fixtures.py" "${manifest}" --tier "${requested_tier}" --emit)"
mapfile -t cases <<< "${case_stream}"

run_timeout="${FIXTURE_TIMEOUT_SECONDS:-45}"
dotnet_cli=(dotnet run --project "${repo_root}/src/UrProtect.Cli" --configuration Release --no-restore --)

case_value() {
  local case_json="$1"
  local field="$2"
  python3 - "${case_json}" "${field}" <<'PY'
import json
import sys

case = json.loads(sys.argv[1])
field = sys.argv[2]
value = case.get(field, "")
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

has_tool() {
  command -v "$1" >/dev/null 2>&1
}

required_case() {
  [[ "$(case_value "$1" required)" == "true" ]]
}

skip_or_fail() {
  local case_json="$1"
  local reason="$2"
  local id
  id="$(case_value "${case_json}" id)"
  if required_case "${case_json}"; then
    echo "FAIL ${id}: ${reason}" >&2
    return 1
  fi
  echo "SKIP ${id}: ${reason}"
  return 0
}

run_binary_case() {
  local id="$1"
  local binary="$2"
  local launcher="${3:-}"
  local library_path="${4:-}"
  local variant="${5:-}"
  local artifact="${6:-}"
  local case_root="${artifact_root}/${id}"
  local copy="${case_root}/no-op-copy"
  local baseline_stdout="${case_root}/baseline.stdout"
  local baseline_stderr="${case_root}/baseline.stderr"
  local output_stdout="${case_root}/output.stdout"
  local output_stderr="${case_root}/output.stderr"
  local baseline_status_file="${case_root}/baseline.status"
  local output_status_file="${case_root}/output.status"

  mkdir -p "${case_root}"
  file "${binary}" > "${case_root}/file.txt"
  if ! readelf -hW -lW -dW "${binary}" > "${case_root}/readelf.txt" 2>&1; then
    echo "FAIL ${id}: readelf structural oracle could not inspect the ELF" >&2
    return 1
  fi
  if ! python3 - "${case_root}/readelf.txt" "${id}" "${artifact}" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
case_id = sys.argv[2]
artifact = sys.argv[3]
required = (
    ("Class", "ELF64"),
    ("Data", "2's complement, little endian"),
    ("Machine", "AArch64"),
)
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()
missing = [f"{name}={value}" for name, value in required if fields.get(name) != value]
expected_type = "EXEC" if artifact == "et-exec" else "DYN"
if not fields.get("Type", "").startswith(expected_type):
    missing.append(f"Type={expected_type}")
if "There is no dynamic section in this file." in report:
    missing.append("dynamic section")
if missing:
    print(
        f"{case_id}: readelf oracle mismatch; missing {', '.join(missing)}",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
  then
    echo "FAIL ${id}: readelf structural oracle rejected the supported ELF case" >&2
    return 1
  fi
  if [[ "${variant}" == "release-hardened" ]] && ! python3 - "${case_root}/readelf.txt" "${id}" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
case_id = sys.argv[2]
missing = []
if "GNU_RELRO" not in report:
    missing.append("GNU_RELRO")
if "BIND_NOW" not in report:
    missing.append("BIND_NOW")
if missing:
    raise SystemExit(f"{case_id}: release hardening oracle missing {', '.join(missing)}")
PY
  then
    echo "FAIL ${id}: release hardening oracle rejected the ELF" >&2
    return 1
  fi

  local -a run_command=("${binary}")
  if [[ -n "${launcher}" ]]; then
    run_command=(env "LD_LIBRARY_PATH=${library_path}" "${launcher}" "${binary}")
  fi

  set +e
  timeout "${run_timeout}" "${run_command[@]}" >"${baseline_stdout}" 2>"${baseline_stderr}"
  local baseline_status=$?
  set -e
  printf '%s\n' "${baseline_status}" > "${baseline_status_file}"
  if [[ "${baseline_status}" -ne 0 ]]; then
    echo "FAIL ${id}: baseline exited with status ${baseline_status}" >&2
    return 1
  fi

  "${dotnet_cli[@]}" validate "${binary}" --no-analysis --copy "${copy}" \
    > "${case_root}/validator.stdout" 2> "${case_root}/validator.stderr"
  cmp -- "${binary}" "${copy}"

  if [[ -n "${launcher}" ]]; then
    run_command=(env "LD_LIBRARY_PATH=${library_path}" "${launcher}" "${copy}")
  else
    run_command=("${copy}")
  fi
  set +e
  timeout "${run_timeout}" "${run_command[@]}" >"${output_stdout}" 2>"${output_stderr}"
  local output_status=$?
  set -e
  printf '%s\n' "${output_status}" > "${output_status_file}"
  if [[ "${output_status}" -ne 0 ]]; then
    echo "FAIL ${id}: no-op output exited with status ${output_status}" >&2
    return 1
  fi

  cmp -- "${baseline_stdout}" "${output_stdout}"
  cmp -- "${baseline_stderr}" "${output_stderr}"
  echo "PASS ${id}: baseline/output behavior and byte identity match"
}

build_case() {
  local case_json="$1"
  local id language builder source output_dir binary launcher library_path musl_root variant
  id="$(case_value "${case_json}" id)"
  language="$(case_value "${case_json}" language)"
  builder="$(case_value "${case_json}" builder)"
  variant="$(case_value "${case_json}" variant)"
  source="${repo_root}/$(case_value "${case_json}" source)"
  output_dir="${artifact_root}/${id}/build"
  mkdir -p "${output_dir}"

  if [[ -n "${variant}" && "${variant}" != "release-hardened" ]]; then
    skip_or_fail "${case_json}" "unknown fixture variant ${variant}"
    return
  fi
  local -a release_linker_flags=()
  if [[ "${variant}" == "release-hardened" ]]; then
    release_linker_flags=(-Wl,-z,relro,-z,now)
  fi

  case "${builder}" in
    gcc-c)
      has_tool gcc || { skip_or_fail "${case_json}" "gcc is unavailable"; return; }
      gcc -std=c11 -O2 -g0 -fPIE -pie -Wl,--build-id=none \
        "${release_linker_flags[@]}" "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    gcc-c-exec)
      has_tool gcc || { skip_or_fail "${case_json}" "gcc is unavailable"; return; }
      gcc -std=c11 -O2 -g0 -Wl,--build-id=none -no-pie \
        -Wl,-dynamic-linker,/lib/ld-linux-aarch64.so.1 "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    gcc-cxx)
      has_tool g++ || { skip_or_fail "${case_json}" "g++ is unavailable"; return; }
      g++ -std=c++17 -O2 -g0 -fPIE -pie -Wl,--build-id=none \
        "${release_linker_flags[@]}" "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    clang-c)
      has_tool clang || { skip_or_fail "${case_json}" "clang is unavailable"; return; }
      clang -std=c11 -O2 -g0 -fPIE -pie -Wl,--build-id=none "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    clang-cxx)
      has_tool clang++ || { skip_or_fail "${case_json}" "clang++ is unavailable"; return; }
      clang++ -std=c++17 -O2 -g0 -fPIE -pie -Wl,--build-id=none "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    musl-gcc)
      has_tool musl-gcc || { skip_or_fail "${case_json}" "musl-gcc is unavailable"; return; }
      musl_root="${MUSL_TOOLCHAIN_ROOT:-$(cd "$(dirname "$(command -v musl-gcc)")/.." && pwd)}"
      launcher="${MUSL_TOOLCHAIN_LOADER:-${musl_root}/lib/ld-musl-aarch64.so.1}"
      library_path="${MUSL_TOOLCHAIN_LIBRARY_PATH:-${musl_root}/lib}"
      if [[ ! -x "${launcher}" ]]; then
        skip_or_fail "${case_json}" "musl loader is unavailable: ${launcher}"
        return
      fi
      musl-gcc -std=c11 -O2 -g0 -fPIE -pie -Wl,--build-id=none "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    rust-gnu)
      has_tool rustc || { skip_or_fail "${case_json}" "rustc is unavailable"; return; }
      rustc --target=aarch64-unknown-linux-gnu -C opt-level=2 -C debuginfo=0 \
        -C strip=symbols -C relocation-model=pie "${source}" -o "${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    go-pie)
      has_tool go || { skip_or_fail "${case_json}" "go is unavailable"; return; }
      (cd "$(dirname "${source}")" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
        go build -trimpath -buildvcs=false -buildmode=pie -ldflags='-s -w' \
        -o "${output_dir}/fixture" .)
      binary="${output_dir}/fixture"
      ;;
    zig-musl)
      has_tool zig || { skip_or_fail "${case_json}" "zig is unavailable"; return; }
      musl_root="${MUSL_TOOLCHAIN_ROOT:-}"
      launcher="${MUSL_TOOLCHAIN_LOADER:-${musl_root}/lib/ld-musl-aarch64.so.1}"
      library_path="${MUSL_TOOLCHAIN_LIBRARY_PATH:-${musl_root}/lib}"
      if [[ -z "${musl_root}" || ! -x "${launcher}" ]]; then
        skip_or_fail "${case_json}" "musl loader is unavailable for Zig: ${launcher}"
        return
      fi
      zig build-exe "${source}" -target aarch64-linux-musl -dynamic -fPIE -lc \
        -O ReleaseSafe -fstrip \
        -femit-bin="${output_dir}/fixture"
      binary="${output_dir}/fixture"
      ;;
    nativeaot)
      has_tool dotnet || { skip_or_fail "${case_json}" "dotnet is unavailable"; return; }
      set +e
      timeout 300 dotnet publish "${source}" --configuration Release --runtime linux-arm64 \
        --self-contained true --output "${output_dir}/publish" --nologo \
        -p:PublishAot=true -p:StripSymbols=true -p:DebugType=None \
        > "${output_dir}/nativeaot-build.log" 2>&1
      nativeaot_status=$?
      set -e
      if [[ "${nativeaot_status}" -ne 0 ]]; then
        skip_or_fail "${case_json}" \
          "NativeAOT publish unavailable or failed (status ${nativeaot_status}); see nativeaot-build.log"
        return
      fi
      binary="${output_dir}/publish/urprotect-fixture-nativeaot"
      ;;
    termux-clang)
      skip_or_fail "${case_json}" "bionic case is executed by run-bionic-fixture.sh"
      return
      ;;
    android-ndk)
      skip_or_fail "${case_json}" "Android APK fixture is executed by run-android-avd.sh"
      return
      ;;
    *)
      skip_or_fail "${case_json}" "unknown fixture builder ${builder}"
      return
      ;;
  esac

  if [[ ! -x "${binary}" ]]; then
    echo "FAIL ${id}: builder did not produce executable ${binary}" >&2
    return 1
  fi
  run_binary_case "${id}" "${binary}" "${launcher:-}" "${library_path:-}" "${variant}" "$(case_value "${case_json}" artifact)"
}

echo "Running fixture tier ${requested_tier} on $(uname -m)"
echo "Artifacts: ${artifact_root}"
for case_json in "${cases[@]}"; do
  build_case "${case_json}"
done

echo "Fixture tier ${requested_tier} completed"
