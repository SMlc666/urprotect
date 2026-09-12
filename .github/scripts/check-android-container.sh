#!/usr/bin/env bash
set -euo pipefail

failures=0
check() {
  local description="$1"
  shift
  if "$@"; then
    printf 'ok: %s\n' "${description}"
  else
    printf 'missing: %s\n' "${description}"
    failures=$((failures + 1))
  fi
}

check "aarch64 host" test "$(uname -m)" = "aarch64"
check "Linux namespaces" test -d /proc/1/ns
check "cgroup filesystem" test -d /sys/fs/cgroup
check "Binder or BinderFS" bash -c 'test -e /dev/binder || test -d /dev/binderfs'
check "LXC" command -v lxc-start
check "Wayland or headless compositor" bash -c 'test -n "${WAYLAND_DISPLAY:-}" || command -v weston'

check_image() {
  local description="$1"
  local image_path="$2"
  local expected_hash="$3"
  if [[ -z "${image_path}" || -z "${expected_hash}" ]]; then
    printf 'missing: %s image path/hash configuration\n' "${description}"
    failures=$((failures + 1))
    return
  fi
  if [[ ! -f "${image_path}" ]]; then
    printf 'missing: %s image file (%s)\n' "${description}" "${image_path}"
    failures=$((failures + 1))
    return
  fi
  local actual_hash
  actual_hash="$(sha256sum "${image_path}" | awk '{print $1}')"
  if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    printf 'missing: %s image checksum mismatch (expected %s, got %s)\n' \
      "${description}" "${expected_hash}" "${actual_hash}"
    failures=$((failures + 1))
    return
  fi
  printf 'ok: %s image checksum\n' "${description}"
}

check_image \
  "ARM64 Android system" \
  "${ANDROID_CONTAINER_SYSTEM_IMAGE:-}" \
  "${ANDROID_CONTAINER_SYSTEM_SHA256:-}"
check_image \
  "ARM64 Android vendor" \
  "${ANDROID_CONTAINER_VENDOR_IMAGE:-}" \
  "${ANDROID_CONTAINER_VENDOR_SHA256:-}"

if (( failures > 0 )); then
  echo "Android container prerequisites are unavailable on this runner." >&2
  exit 1
fi
