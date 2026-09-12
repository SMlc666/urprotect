#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_root="${1:-${repo_root}/.artifacts/release}"

for required_command in cmp file find grep mktemp python3 readelf realpath sha256sum tar timeout; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required for release smoke testing" >&2
    exit 127
  fi
done

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "release smoke testing requires an ARM64 host; got $(uname -m)" >&2
  exit 2
fi

shopt -s nullglob
archives=("${release_root}"/urprotect-linux-arm64-*.tar.gz)
if [[ "${#archives[@]}" -ne 2 ]]; then
  echo "expected exactly two ARM64 release archives in ${release_root}" >&2
  exit 1
fi

if [[ -f "${release_root}/SHA256SUMS" ]]; then
  (cd "${release_root}" && sha256sum --check SHA256SUMS)
else
  echo "release checksum file is missing" >&2
  exit 1
fi

smoke_artifact_root="${RELEASE_SMOKE_ARTIFACT_ROOT:-}"
if [[ -n "${smoke_artifact_root}" ]]; then
  mkdir -p "${smoke_artifact_root}"
fi
current_extracted=""
cleanup_on_exit() {
  local status=$?
  if [[ -n "${current_extracted}" ]]; then
    if [[ "${status}" -eq 0 || -z "${smoke_artifact_root}" ]]; then
      rm -rf -- "${current_extracted}"
    else
      printf 'release smoke failure artifacts: %s\n' "${current_extracted}" >&2
    fi
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

for archive in "${archives[@]}"; do
  if [[ -n "${smoke_artifact_root}" ]]; then
    extracted="$(mktemp -d "${smoke_artifact_root}/run.XXXXXX")"
  else
    extracted="$(mktemp -d "${release_root}/.smoke.XXXXXX")"
  fi
  current_extracted="${extracted}"
  tar --extract --gzip --file "${archive}" --directory "${extracted}"
  binary="$(find "${extracted}" -type f -name urprotect -perm -u+x -print -quit)"
  if [[ -z "${binary}" ]]; then
    echo "archive has no executable: ${archive}" >&2
    exit 1
  fi
  native_launcher="$(find "${extracted}" -type f -name urprotect-launcher -perm -u+x -print -quit)"
  if [[ -z "${native_launcher}" ]]; then
    echo "archive has no native launcher: ${archive}" >&2
    exit 1
  fi
  native_launcher_self_test="$(find "${extracted}" -type f -name urprotect-launcher-self-test -perm -u+x -print -quit)"
  if [[ -z "${native_launcher_self_test}" ]]; then
    echo "archive has no native launcher self-test: ${archive}" >&2
    exit 1
  fi
  native_launcher_provenance="$(find "${extracted}" -type f -name native-launcher-provenance.txt -print -quit)"
  if [[ -z "${native_launcher_provenance}" ]]; then
    echo "archive has no native launcher provenance: ${archive}" >&2
    exit 1
  fi
  "${native_launcher_self_test}" > "${extracted}/native-launcher-self-test.txt"
  grep -a -q 'URPROTECT-AARCH64-LAUNCHER-V1' "${native_launcher}"
  python3 - "${native_launcher}" "${native_launcher_provenance}" <<'PY'
import hashlib
import pathlib
import sys

launcher, provenance = map(pathlib.Path, sys.argv[1:])
values = {}
for line in provenance.read_text().splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        values[key] = value
actual = hashlib.sha256(launcher.read_bytes()).hexdigest()
assert values.get("launcher_sha256") == actual
assert values.get("schema") == "urprotect-native-launcher-provenance-v1"
assert values.get("launcher_abi") == "1"
assert values.get("launcher_marker") == "URPROTECT-AARCH64-LAUNCHER-V1"
PY
  readelf -lW "${binary}" > "${extracted}/program-headers.txt"
  readelf -hW -lW -dW "${native_launcher}" > "${extracted}/native-launcher-readelf.txt"
  python3 - "${extracted}/native-launcher-readelf.txt" <<'PY'
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
assert "INTERP" not in report
assert "NEEDED" not in report
PY
  launcher=""
  library_path=""
  musl_container_image="${URPROTECT_MUSL_CONTAINER_IMAGE:-}"
  musl_container_binary=""
  if grep -q 'ld-musl-aarch64.so.1' "${extracted}/program-headers.txt"; then
    launcher="/lib/ld-musl-aarch64.so.1"
    library_path="/usr/lib/aarch64-linux-musl:/lib"
    if [[ -n "${musl_container_image}" ]] && command -v docker >/dev/null 2>&1; then
      relative_binary="${binary#${extracted}/}"
      musl_container_binary="/smoke/${relative_binary}"
    elif [[ ! -x "${launcher}" ]]; then
      echo "musl release smoke requires ${launcher}" >&2
      exit 1
    fi
  fi
  if [[ -n "${musl_container_binary}" ]]; then
    docker run --rm --platform linux/arm64 \
      -v "$(realpath "${extracted}"):/smoke" \
      "${musl_container_image}" "${musl_container_binary}" --help \
      > "${extracted}/help.txt"
  elif [[ -n "${launcher}" ]]; then
    env "LD_LIBRARY_PATH=${library_path}" "${launcher}" "${binary}" --help \
      > "${extracted}/help.txt"
  else
    "${binary}" --help > "${extracted}/help.txt"
  fi
  input="/bin/ls"
  copy="${extracted}/copy.elf"
  report="${extracted}/report.json"
  if [[ -n "${musl_container_binary}" ]]; then
    docker run --rm --platform linux/arm64 \
      -v "$(realpath "${extracted}"):/smoke" \
      -v "${input}:/input.elf:ro" \
      "${musl_container_image}" "${musl_container_binary}" \
      validate /input.elf --copy "/smoke/copy.elf" --json "/smoke/report.json" --no-analysis
  elif [[ -n "${launcher}" ]]; then
    env "LD_LIBRARY_PATH=${library_path}" "${launcher}" "${binary}" \
      validate "${input}" --copy "${copy}" --json "${report}" --no-analysis
  else
    "${binary}" validate "${input}" --copy "${copy}" --json "${report}" --no-analysis
  fi
  cmp -- "${input}" "${copy}"
  python3 - "${report}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["schemaVersion"] == 1
assert report["success"] is True
assert report["output"]["byteIdentical"] is True
assert report["input"]["sha256"] == report["output"]["sha256"]
PY

  packed_wrapper="${extracted}/packed.elf"
  packed_report="${extracted}/packed-report.json"
  if [[ -n "${musl_container_binary}" ]]; then
    relative_native_launcher="${native_launcher#${extracted}/}"
    docker run --rm --platform linux/arm64 \
      -v "$(realpath "${extracted}"):/smoke" \
      "${musl_container_image}" "${musl_container_binary}" \
      pack /bin/true \
      --output /smoke/packed.elf \
      --launcher "/smoke/${relative_native_launcher}" \
      --json /smoke/packed-report.json
    docker run --rm --platform linux/arm64 \
      -v "$(realpath "${extracted}"):/smoke" \
      "${musl_container_image}" /smoke/packed.elf \
      > /dev/null
  else
    /bin/true > /dev/null
    "${binary}" pack /bin/true \
      --output "${packed_wrapper}" \
      --launcher "${native_launcher}" \
      --json "${packed_report}"
    "${packed_wrapper}" > /dev/null
  fi
  file "${packed_wrapper}" > "${extracted}/packed-file.txt"
  readelf -hW -lW -dW "${packed_wrapper}" > "${extracted}/packed-readelf.txt"
  python3 - "${extracted}/packed-readelf.txt" <<'PY'
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
  if cmp -- "${binary}" "${packed_wrapper}" >/dev/null 2>&1; then
    echo "release wrapper is byte-identical to its source launcher" >&2
    exit 1
  fi
  python3 - "${packed_report}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["schemaVersion"] == 1
assert report["success"] is True
assert report["payload"]["compression"] == "deflate"
assert report["payload"]["launcherAbiVersion"] == 1
assert report["payload"]["frameVersion"] == 1
assert report["payload"]["launcherMarker"] == "URPROTECT-AARCH64-LAUNCHER-V1"
assert len(report["payload"]["launcherSha256"]) == 64
assert report["output"]["published"] is True
PY
  printf 'PASS release smoke: %s\n' "$(basename "${archive}")"
  rm -rf -- "${extracted}"
  current_extracted=""
done
