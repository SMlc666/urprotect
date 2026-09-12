#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_root="${1:-${repo_root}/.artifacts/release}"

for required_command in cmp file python3 readelf sha256sum tar timeout; do
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

for archive in "${archives[@]}"; do
  extracted="$(mktemp -d "${release_root}/.smoke.XXXXXX")"
  cleanup() {
    rm -rf -- "${extracted}"
  }
  trap cleanup RETURN
  tar --extract --gzip --file "${archive}" --directory "${extracted}"
  binary="$(find "${extracted}" -type f -name urprotect -perm -u+x -print -quit)"
  if [[ -z "${binary}" ]]; then
    echo "archive has no executable: ${archive}" >&2
    exit 1
  fi
  readelf -lW "${binary}" > "${extracted}/program-headers.txt"
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
  source_help="${extracted}/source-run.txt"
  if [[ -n "${musl_container_binary}" ]]; then
    relative_binary="${binary#${extracted}/}"
    docker run --rm --platform linux/arm64 \
      -v "$(realpath "${extracted}"):/smoke" \
      "${musl_container_image}" "${musl_container_binary}" \
      pack /bin/ls \
      --output /smoke/packed.elf \
      --launcher "/smoke/${relative_binary}" \
      --json /smoke/packed-report.json
    docker run --rm --platform linux/arm64 \
      "${musl_container_image}" /bin/true \
      > "${source_help}"
    docker run --rm --platform linux/arm64 \
      -v "$(realpath "${extracted}"):/smoke" \
      "${musl_container_image}" /smoke/packed.elf \
      > "${extracted}/packed-help.txt"
  else
    /bin/true > "${source_help}"
    "${binary}" pack /bin/true \
      --output "${packed_wrapper}" \
      --launcher "${binary}" \
      --json "${packed_report}"
    "${packed_wrapper}" > "${extracted}/packed-help.txt"
  fi
  cmp -- "${source_help}" "${extracted}/packed-help.txt"
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
assert report["output"]["published"] is True
PY
  printf 'PASS release smoke: %s\n' "$(basename "${archive}")"
done
