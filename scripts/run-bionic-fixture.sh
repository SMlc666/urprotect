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

if [[ "${linker}" != "/system/bin/linker64" ]]; then
  echo "unsupported bionic linker path: ${linker}" >&2
  exit 1
fi

host_page_size="$(getconf PAGESIZE)"
host_kernel="$(uname -r)"
if ! [[ "${host_page_size}" =~ ^[0-9]+$ ]] || [[ -z "${host_kernel}" ]]; then
  echo "native bionic kernel and page-size facts were not recorded" >&2
  exit 1
fi
printf '%s\n' \
  "host_arch=$(uname -m)" \
  "host_kernel=${host_kernel}" \
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
  container_kernel="$(uname -r)"
  test -n "${container_kernel}"
  printf "container_kernel=%s\n" "${container_kernel}"
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
  package_spec="${1}"
  package_name="${package_spec%%=*}"
  requested_version="${package_spec#*=}"
  # The package index is intentionally live; retain the complete installed
  # inventory and exact apt logs instead of claiming full reproducibility.
  apt-get update > /artifacts/apt-update.log 2>&1
  apt-get install -y "${package_spec}" > /artifacts/apt-install.log 2>&1
  installed_version="$(dpkg-query -W -f="\${Version}" "${package_name}")"
  test "${installed_version}" = "${requested_version}"
  printf "%s\n" "${installed_version}" > /artifacts/clang-package-version.txt
  printf "package_spec=%s\npackage_name=%s\nrequested_version=%s\ninstalled_version=%s\n" \
    "${package_spec}" "${package_name}" "${requested_version}" "${installed_version}" \
    > /artifacts/package-request.txt
  dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\t\${Status}\n" \
    | sort > /artifacts/packages.txt
  apt-cache policy "${package_name}" > /artifacts/package-policy.txt
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
run_shell -c 'exec /system/bin/linker64' \
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
if ! grep -Fq 'This is /system/bin/linker64, the helper program for dynamic executables.' \
  "${case_root}/linker.stdout"; then
  echo "bionic direct linker identity probe did not identify linker64" >&2
  exit 1
fi
if ! grep -Eq 'Shared library: \[(libc|libdl)\.so\]' "${case_root}/readelf.txt"; then
  echo "bionic fixture did not retain a bionic dynamic dependency witness" >&2
  exit 1
fi

requested_clang_version="${clang_package#*=}"
installed_clang_version="$(sed -n '1p' "${case_root}/clang-package-version.txt")"
if [[ -z "${installed_clang_version}" || "${installed_clang_version}" != "${requested_clang_version}" ]]; then
  echo "Termux clang version does not match the requested package: expected ${requested_clang_version}, got ${installed_clang_version}" >&2
  exit 1
fi

container_page_size="$(sed -n 's/^container_page_size=//p' "${case_root}/container-facts.txt")"
container_kernel="$(sed -n 's/^container_kernel=//p' "${case_root}/container-facts.txt")"
if ! [[ "${container_page_size}" =~ ^[0-9]+$ ]] || [[ -z "${container_kernel}" ]]; then
  echo "container kernel and page-size facts were not recorded" >&2
  exit 1
fi
printf '%s\n' \
  "image=${image}" \
  "image_arch=${image_arch}" \
  "image_digest=${image##*@}" \
  "termux_source_commit=${termux_source_commit}" \
  "clang_package=${clang_package}" \
  "clang_version=${installed_clang_version}" \
  "linker=${linker}" \
  "package_index=live" \
  "fully_reproducible=false" \
  "package_provenance=complete-installed-package-version-inventory" \
  "host_arch=$(uname -m)" \
  "host_kernel=${host_kernel}" \
  "host_page_size=${host_page_size}" \
  "container_arch=aarch64" \
  "container_kernel=${container_kernel}" \
  "container_page_size=${container_page_size}" \
  "android_runtime=false" \
  "execution=native-arm64-bionic-container" \
  "baseline_status=${baseline_status}" \
  "direct_linker_status=${linker_status}" \
  "direct_linker_mode=identity" \
  "handoff_status=not-yet-implemented" \
  > "${case_root}/provenance.txt"

python3 - "${case_root}/result.json" "${image}" "${termux_source_commit}" \
  "${clang_package}" "${installed_clang_version}" "${host_kernel}" "${container_kernel}" "${host_page_size}" \
  "${container_page_size}" "${baseline_status}" "${linker_status}" <<'PY'
import json
import pathlib
import sys

(
    path,
    image,
    source_commit,
    compiler,
    clang_version,
    host_kernel,
    container_kernel,
    host_page_size,
    container_page_size,
    baseline,
    linker,
) = sys.argv[1:]
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
    "clangVersion": clang_version,
    "linker": "/system/bin/linker64",
    "packageIndex": "live",
    "reproducible": False,
    "packageProvenance": "complete-installed-package-version-inventory",
    "hostKernel": host_kernel,
    "containerKernel": container_kernel,
    "hostPageSize": int(host_page_size),
    "containerPageSize": int(container_page_size),
    "baselineStatus": int(baseline),
    "directLinkerStatus": int(linker),
    "directLinkerMode": "identity",
    "handoffStatus": "not-yet-implemented",
}
pathlib.Path(path).write_text(json.dumps(document, indent=2) + "\n")
PY

echo "PASS ${case_id}: requested Termux clang version, bionic linker, and native ARM64 execution validated (live package index; not fully reproducible)"
