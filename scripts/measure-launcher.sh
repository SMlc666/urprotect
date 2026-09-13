#!/usr/bin/env bash
set -euo pipefail

native_launcher="${1:?usage: measure-launcher.sh <native-launcher> [wrapper-0.1-launcher]}"
legacy_launcher="${2:-}"

for required_command in file readelf stat; do
  if ! command -v "${required_command}" >/dev/null 2>&1; then
    echo "${required_command} is required to measure the native launcher" >&2
    exit 127
  fi
done

if [[ ! -x "${native_launcher}" ]]; then
  echo "native launcher is not executable: ${native_launcher}" >&2
  exit 1
fi

native_size="$(stat -c '%s' "${native_launcher}")"
file -b "${native_launcher}"
readelf -hW -lW -dW "${native_launcher}" | grep -E 'Type:|Machine:|INTERP|NEEDED' || true
printf 'native_launcher_bytes=%s\n' "${native_size}"

if [[ -n "${legacy_launcher}" ]]; then
  if [[ ! -f "${legacy_launcher}" ]]; then
    echo "legacy launcher does not exist: ${legacy_launcher}" >&2
    exit 1
  fi
  legacy_size="$(stat -c '%s' "${legacy_launcher}")"
  printf 'wrapper_0_1_launcher_bytes=%s\n' "${legacy_size}"
  awk -v native="${native_size}" -v legacy="${legacy_size}" \
    'BEGIN { if (native > 0) printf "size_ratio_native_over_wrapper_0_1=%.6f\n", native / legacy }'
fi
