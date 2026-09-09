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

if (( failures > 0 )); then
  echo "Android container prerequisites are unavailable on this runner." >&2
  exit 1
fi
