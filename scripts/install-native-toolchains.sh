#!/usr/bin/env bash
set -euo pipefail

# Pinned native ARM64 fixture toolchains. These archives are used only on the
# native aarch64 runner; no QEMU or host-architecture substitution is allowed.
if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "native fixture toolchains require an aarch64 runner; got $(uname -m)" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain_root="${NATIVE_TOOLCHAIN_ROOT:-${RUNNER_TEMP:-${repo_root}/.artifacts}/urprotect-fixture-toolchains}"
mkdir -p "${toolchain_root}"

zig_version="0.13.0"
zig_url="https://ziglang.org/download/${zig_version}/zig-linux-aarch64-${zig_version}.tar.xz"
zig_sha256="041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556"
zig_root="${toolchain_root}/zig-${zig_version}"

musl_version="1.2.4-2"
musl_root="/usr"
musl_loader="/lib/ld-musl-aarch64.so.1"
musl_library_path="/usr/lib/aarch64-linux-musl:/lib"

fetch_archive() {
  local url="$1"
  local archive="$2"
  local partial="${archive}.part"
  if [[ ! -s "${archive}" ]]; then
    echo "Downloading ${url}"
    curl --fail --location --retry 3 --retry-delay 2 --connect-timeout 30 \
      --max-time 900 "${url}" --output "${partial}"
    mv -- "${partial}" "${archive}"
  fi
}

verify_sha256() {
  local expected="$1"
  local archive="$2"
  printf '%s  %s\n' "${expected}" "${archive}" | sha256sum --check --status -
}

zig_archive="${toolchain_root}/zig-${zig_version}.tar.xz"
if [[ ! -x "${zig_root}/zig" ]] || [[ "$("${zig_root}/zig" version 2>/dev/null || true)" != "${zig_version}" ]]; then
  fetch_archive "${zig_url}" "${zig_archive}"
  if ! verify_sha256 "${zig_sha256}" "${zig_archive}"; then
    echo "Zig archive checksum mismatch: ${zig_archive}" >&2
    rm -f -- "${zig_archive}"
    exit 1
  fi
  rm -rf "${zig_root}"
  mkdir -p "${zig_root}"
  tar --extract --xz --file "${zig_archive}" --strip-components=1 --directory "${zig_root}"
fi

if [[ ! -x "${musl_root}/bin/musl-gcc" || ! -x "${musl_loader}" ]]; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends \
    "musl=${musl_version}" "musl-dev=${musl_version}" "musl-tools=${musl_version}"
fi

if [[ ! -x "${zig_root}/zig" || ! -x "${musl_root}/bin/musl-gcc" || ! -x "${musl_loader}" ]]; then
  echo "pinned native fixture toolchain installation is incomplete" >&2
  exit 1
fi

export PATH="${musl_root}/bin:${zig_root}:${PATH}"
export MUSL_TOOLCHAIN_ROOT="${musl_root}"
export MUSL_TOOLCHAIN_LOADER="${musl_loader}"
export MUSL_TOOLCHAIN_LIBRARY_PATH="${musl_library_path}"
export ZIG_ROOT="${zig_root}"

metadata="${toolchain_root}/toolchain-manifest.txt"
{
  echo "host_arch=$(uname -m)"
  echo "zig_version=$("${zig_root}/zig" version)"
  echo "zig_sha256=${zig_sha256}"
  echo "musl_package_version=${musl_version}"
  echo "musl_gcc=$(${musl_root}/bin/musl-gcc --version | head -1)"
  echo "musl_loader=${musl_loader}"
  echo "musl_library_path=${musl_library_path}"
  echo "musl_root=${musl_root}"
  echo "zig_root=${zig_root}"
} | tee "${metadata}"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "PATH=${PATH}"
    echo "MUSL_TOOLCHAIN_ROOT=${MUSL_TOOLCHAIN_ROOT}"
    echo "MUSL_TOOLCHAIN_LOADER=${MUSL_TOOLCHAIN_LOADER}"
    echo "MUSL_TOOLCHAIN_LIBRARY_PATH=${MUSL_TOOLCHAIN_LIBRARY_PATH}"
    echo "ZIG_ROOT=${ZIG_ROOT}"
  } >> "${GITHUB_ENV}"
fi
