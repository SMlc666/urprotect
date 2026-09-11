#!/usr/bin/env bash
set -euo pipefail

output_path="${1:-.artifacts/environment.txt}"
expected_arch="${2:-}"
execution_mode="${3:-unspecified}"
output_dir="$(dirname "${output_path}")"
mkdir -p "${output_dir}"

temporary_path="${output_path}.tmp.$$"
cleanup() {
  rm -f -- "${temporary_path}"
}
trap cleanup EXIT

version_line() {
  local command_name="$1"
  shift
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf '%s' unavailable
    return 0
  fi

  local value
  value="$("${command_name}" "$@" 2>&1 | head -n 1 || true)"
  if [[ -n "${value}" ]]; then
    printf '%s' "${value}"
  else
    printf '%s' available
  fi
}

has_path() {
  if [[ -e "$1" ]]; then
    printf '%s' true
  else
    printf '%s' false
  fi
}

actual_arch="$(uname -m)"
architecture_status=not-checked
if [[ -n "${expected_arch}" ]]; then
  if [[ "${actual_arch}" == "${expected_arch}" ]]; then
    architecture_status=pass
  else
    architecture_status=fail
  fi
fi

libc_version="$(version_line ldd --version)"
page_size="$(getconf PAGESIZE 2>/dev/null || printf '%s' unavailable)"
os_name="$(awk -F= '$1 == "NAME" {gsub(/^\"|\"$/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null || true)"
os_version="$(awk -F= '$1 == "VERSION_ID" {gsub(/^\"|\"$/, "", $2); print $2; exit}' /etc/os-release 2>/dev/null || true)"

{
  printf 'execution_mode=%s\n' "${execution_mode}"
  printf 'expected_arch=%s\n' "${expected_arch:-not-specified}"
  printf 'host_arch=%s\n' "${actual_arch}"
  printf 'architecture_check=%s\n' "${architecture_status}"
  printf 'kernel=%s\n' "$(uname -srvm)"
  printf 'os_name=%s\n' "${os_name:-unknown}"
  printf 'os_version_id=%s\n' "${os_version:-unknown}"
  printf 'page_size=%s\n' "${page_size}"
  printf 'libc=%s\n' "${libc_version}"
  printf 'runner_os=%s\n' "${RUNNER_OS:-unknown}"
  printf 'runner_arch=%s\n' "${RUNNER_ARCH:-unknown}"
  printf 'github_runner_image=%s\n' "${ImageOS:-${ImageVersion:-unknown}}"
  printf 'container_environment=%s\n' "$(if [[ -e /.dockerenv || -e /run/.containerenv ]]; then printf '%s' true; else printf '%s' false; fi)"
  printf 'kvm_device=%s\n' "$(has_path /dev/kvm)"
  printf 'cpu_hypervisor_flag=%s\n' "$(if grep -Eqi '(^|[[:space:]])hypervisor([[:space:]]|$)' /proc/cpuinfo 2>/dev/null; then printf '%s' true; else printf '%s' false; fi)"
  printf 'qemu_user_aarch64=%s\n' "$(command -v qemu-aarch64 >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"
  printf 'qemu_user_x86_64=%s\n' "$(command -v qemu-x86_64 >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"
  printf 'qemu_system=%s\n' "$(if command -v qemu-system-aarch64 >/dev/null 2>&1 || command -v qemu-system-x86_64 >/dev/null 2>&1; then printf '%s' true; else printf '%s' false; fi)"
  printf 'tool.dotnet=%s\n' "$(version_line dotnet --version)"
  printf 'tool.gcc=%s\n' "$(version_line gcc --version)"
  printf 'tool.clang=%s\n' "$(version_line clang --version)"
  printf 'tool.rustc=%s\n' "$(version_line rustc --version)"
  printf 'tool.go=%s\n' "$(version_line go version)"
  printf 'tool.zig=%s\n' "$(version_line zig version)"
  printf 'tool.musl_gcc=%s\n' "$(version_line musl-gcc --version)"
  printf 'tool.readelf=%s\n' "$(version_line readelf --version)"
  printf 'tool.llvm_readelf=%s\n' "$(version_line llvm-readelf --version)"
  printf 'tool.sdkmanager=%s\n' "$(version_line sdkmanager --version)"
  printf 'tool.avdmanager=%s\n' "$(version_line avdmanager --help)"
  printf 'tool.emulator=%s\n' "$(version_line emulator -version)"
  printf 'tool.adb=%s\n' "$(version_line adb version)"
  printf 'tool.gradle=%s\n' "$(version_line gradle --version)"
} > "${temporary_path}"

mv -- "${temporary_path}" "${output_path}"

if [[ "${architecture_status}" == fail ]]; then
  printf 'environment probe failed: expected host architecture %s, got %s\n' \
    "${expected_arch}" "${actual_arch}" >&2
  exit 2
fi
