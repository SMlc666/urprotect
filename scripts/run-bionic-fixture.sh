#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/fixtures/manifest.json"
artifact_root="${BIONIC_ARTIFACT_ROOT:-${repo_root}/.artifacts/bionic}"
case_id="c-termux-bionic-pie"
case_root="${artifact_root}/${case_id}"
container_runtime="${BIONIC_CONTAINER_RUNTIME:-docker}"

mkdir -p "${case_root}"
chmod a+rwx "${case_root}"

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "bionic fixture requires a native aarch64 host; got $(uname -m)" >&2
  exit 2
fi
if ! command -v "${container_runtime}" >/dev/null 2>&1; then
  echo "${container_runtime} is required for the native bionic fixture; no fallback is permitted" >&2
  exit 127
fi
for forbidden in qemu-aarch64 qemu-aarch64-static qemu-system-aarch64 waydroid emulator; do
  if command -v "${forbidden}" >/dev/null 2>&1; then
    echo "bionic fixture refuses a host with ${forbidden}; use a native ARM64 container runner" >&2
    exit 2
  fi
done
for required_command in cmp file getconf readelf python3 sed sha256sum; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required for bionic fixture evidence" >&2
    exit 127
  fi
done

python3 "${repo_root}/scripts/validate-fixtures.py" "${manifest}" --tier nightly \
  > "${case_root}/matrix-validation.txt"

mapfile -t matrix_values < <(
  python3 - "${manifest}" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1]))
case = next(item for item in manifest["cases"] if item["id"] == "c-termux-bionic-pie")
host = case["host"]
for field in ("image", "sourceCommit", "compilerPackage", "linker"):
    print(host[field])
PY
)
if [[ "${#matrix_values[@]}" -ne 4 ]]; then
  echo "bionic case is missing pinned host facts in the fixture manifest" >&2
  exit 1
fi
image="${matrix_values[0]}"
termux_source_commit="${matrix_values[1]}"
clang_package="${matrix_values[2]}"
linker="${matrix_values[3]}"
termux_prefix="/data/data/com.termux/files/usr"
termux_shell="${termux_prefix}/bin/sh"

host_page_size="$(getconf PAGESIZE)"
printf '%s\n' \
  "host_arch=$(uname -m)" \
  "host_page_size=${host_page_size}" \
  "container_runtime=${container_runtime}" \
  "execution=native-arm64-bionic-container" \
  "android_runtime=false" \
  "emulation=false" \
  "termux_source_commit=${termux_source_commit}" \
  "image=${image}" \
  "clang_package=${clang_package}" \
  > "${case_root}/host-provenance.txt"

"${container_runtime}" pull "${image}" > "${case_root}/image-pull.txt"
"${container_runtime}" image inspect "${image}" > "${case_root}/image-inspect.json"
image_arch="$("${container_runtime}" image inspect "${image}" --format '{{.Architecture}}')"
image_digests="$("${container_runtime}" image inspect "${image}" --format '{{join .RepoDigests "\n"}}')"
if [[ "${image_arch}" != "arm64" && "${image_arch}" != "aarch64" ]]; then
  echo "Termux image is not an ARM64 image: ${image_arch}" >&2
  exit 1
fi
if ! grep -Fq "${image}" <<< "${image_digests}"; then
  echo "container did not resolve to the pinned Termux image digest" >&2
  exit 1
fi

container_common=(
  run
  --rm
  --platform linux/arm64
  --user 1000:1000
  --env "PREFIX=${termux_prefix}"
  --env "BIONIC_LINKER=${linker}"
  --env "HOME=/tmp"
  --mount "type=bind,src=${repo_root},dst=/workspace,readonly"
  --mount "type=bind,src=${case_root},dst=/artifacts"
)

run_shell() {
  "${container_runtime}" "${container_common[@]}" \
    "${image}" "${termux_shell}" "$@"
}

run_shell -c '
  set -eu
  printf "container_arch=%s\n" "$(uname -m)"
  container_page_size_kb="$(sed -n "s/^KernelPageSize:[[:space:]]*\\([0-9][0-9]*\\) kB$/\\1/p" /proc/self/smaps | sed -n "1p")"
  test -n "${container_page_size_kb}"
  printf "container_page_size=%s\n" "$((container_page_size_kb * 1024))"
  test -x /system/bin/linker64
  test ! -e /system/bin/app_process
  test ! -e /system/bin/app_process64
  for tool in qemu-aarch64 qemu-aarch64-static qemu-system-aarch64 waydroid emulator; do
    if command -v "$tool" >/dev/null 2>&1; then
      echo "forbidden runtime tool is present: $tool" >&2
      exit 1
    fi
  done
  printf "android_runtime=absent\n"
' > "${case_root}/container-facts.txt"
if ! grep -q '^container_arch=aarch64$' "${case_root}/container-facts.txt"; then
  echo "Termux container did not execute as native AArch64" >&2
  exit 1
fi

run_shell -c '
  set -eu
  export PATH="${PREFIX}/bin:${PATH}"
  apt-get update
  apt-get install -y "${1}"
  dpkg-query -W -f="\${Package}\t\${Version}\n" > /artifacts/packages.txt
  clang --version > /artifacts/clang-version.txt
  clang -fPIE -pie -Wl,--build-id=none -Wl,--dynamic-linker=/system/bin/linker64 \
    /workspace/fixtures/samples/bionic/main.c -o /artifacts/fixture
  sha256sum /system/bin/linker64 /artifacts/fixture > /artifacts/container-sha256sums.txt
' -- "${clang_package}"

file "${case_root}/fixture" > "${case_root}/file.txt"
readelf -hW -lW -dW "${case_root}/fixture" > "${case_root}/readelf.txt"
python3 - "${case_root}/readelf.txt" <<'PY'
import pathlib
import sys

report = pathlib.Path(sys.argv[1]).read_text(errors="replace")
fields = {}
for line in report.splitlines():
    if ":" in line:
        name, value = line.split(":", 1)
        fields[name.strip()] = value.strip()
required = {
    "Class": "ELF64",
    "Data": "2's complement, little endian",
    "Machine": "AArch64",
}
missing = [f"{key}={value}" for key, value in required.items() if fields.get(key) != value]
if not fields.get("Type", "").startswith("DYN"):
    missing.append("Type=DYN")
if "Requesting program interpreter: /system/bin/linker64" not in report:
    missing.append("PT_INTERP=/system/bin/linker64")
if "There is no dynamic section in this file." in report:
    missing.append("dynamic section")
if missing:
    raise SystemExit("bionic ELF oracle mismatch: " + ", ".join(missing))
PY

set +e
run_shell -c 'exec /artifacts/fixture' \
  > "${case_root}/baseline.stdout" \
  2> "${case_root}/baseline.stderr"
baseline_status=$?
run_shell -c 'exec "${BIONIC_LINKER}" /artifacts/fixture' \
  > "${case_root}/linker.stdout" \
  2> "${case_root}/linker.stderr"
linker_status=$?
set -e
printf '%s\n' "${baseline_status}" > "${case_root}/baseline.status"
printf '%s\n' "${linker_status}" > "${case_root}/linker.status"
if [[ "${baseline_status}" -ne 0 || "${linker_status}" -ne 0 ]]; then
  echo "bionic fixture failed: shell status=${baseline_status}, direct linker status=${linker_status}" >&2
  exit 1
fi
cmp -- "${case_root}/baseline.stdout" "${case_root}/linker.stdout"
cmp -- "${case_root}/baseline.stderr" "${case_root}/linker.stderr"

container_page_size="$(sed -n 's/^container_page_size=//p' "${case_root}/container-facts.txt")"
if [[ -z "${container_page_size}" ]]; then
  echo "container page size was not recorded" >&2
  exit 1
fi
printf '%s\n' \
  "image=${image}" \
  "image_arch=${image_arch}" \
  "image_digest=${image##*@}" \
  "termux_source_commit=${termux_source_commit}" \
  "clang_package=${clang_package}" \
  "linker=${linker}" \
  "host_arch=$(uname -m)" \
  "host_page_size=${host_page_size}" \
  "container_arch=aarch64" \
  "container_page_size=${container_page_size}" \
  "android_runtime=false" \
  "execution=native-arm64-bionic-container" \
  "baseline_status=${baseline_status}" \
  "direct_linker_status=${linker_status}" \
  "handoff_status=not-yet-implemented" \
  > "${case_root}/provenance.txt"

python3 - "${case_root}/result.json" "${image}" "${termux_source_commit}" \
  "${clang_package}" "${container_page_size}" "${baseline_status}" "${linker_status}" <<'PY'
import json
import pathlib
import sys

path, image, source_commit, compiler, page_size, baseline, linker = sys.argv[1:]
document = {
    "schemaVersion": 1,
    "case": "c-termux-bionic-pie",
    "status": "validated",
    "execution": "native-arm64-bionic-container",
    "androidRuntime": False,
    "emulation": False,
    "image": image,
    "termuxSourceCommit": source_commit,
    "compilerPackage": compiler,
    "linker": "/system/bin/linker64",
    "containerPageSize": int(page_size),
    "baselineStatus": int(baseline),
    "directLinkerStatus": int(linker),
    "handoffStatus": "not-yet-implemented",
}
pathlib.Path(path).write_text(json.dumps(document, indent=2) + "\n")
PY

echo "PASS ${case_id}: pinned Termux bionic linker and native ARM64 execution validated"
