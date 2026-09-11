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

musl_url="https://musl.cc/aarch64-linux-musl-native.tgz"
musl_sha512="16d544e09845c9dbba50f29e0cb04dd661e17eb63c56acad6a67fd2a78aa7596b792477c7177d3cd56d408a27dc291a90507df882f2b099c0f25511ce08fd3b5"
musl_root="${toolchain_root}/aarch64-linux-musl-native"

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

verify_sha512() {
  local expected="$1"
  local archive="$2"
  printf '%s  %s\n' "${expected}" "${archive}" | sha512sum --check --status -
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

musl_archive="${toolchain_root}/aarch64-linux-musl-native.tgz"
if [[ ! -x "${musl_root}/bin/musl-gcc" ]] || [[ ! -x "${musl_root}/lib/ld-musl-aarch64.so.1" ]]; then
  fetch_archive "${musl_url}" "${musl_archive}"
  if ! verify_sha512 "${musl_sha512}" "${musl_archive}"; then
    echo "musl toolchain archive checksum mismatch: ${musl_archive}" >&2
    rm -f -- "${musl_archive}"
    exit 1
  fi
  rm -rf "${musl_root}"
  mkdir -p "${musl_root}"
  tar --extract --file "${musl_archive}" --strip-components=1 --directory "${musl_root}"
  ln -sfn aarch64-linux-musl-gcc "${musl_root}/bin/musl-gcc"
fi

if [[ ! -x "${zig_root}/zig" || ! -x "${musl_root}/bin/musl-gcc" || ! -x "${musl_root}/lib/ld-musl-aarch64.so.1" ]]; then
  echo "pinned native fixture toolchain installation is incomplete" >&2
  exit 1
fi

export PATH="${musl_root}/bin:${zig_root}:${PATH}"
export MUSL_TOOLCHAIN_ROOT="${musl_root}"
export ZIG_ROOT="${zig_root}"

metadata="${toolchain_root}/toolchain-manifest.txt"
{
  echo "host_arch=$(uname -m)"
  echo "zig_version=$("${zig_root}/zig" version)"
  echo "zig_sha256=${zig_sha256}"
  echo "musl_toolchain=aarch64-linux-musl-native"
  echo "musl_gcc=$(${musl_root}/bin/musl-gcc --version | head -1)"
  echo "musl_sha512=${musl_sha512}"
  echo "musl_root=${musl_root}"
  echo "zig_root=${zig_root}"
} | tee "${metadata}"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "PATH=${PATH}"
    echo "MUSL_TOOLCHAIN_ROOT=${MUSL_TOOLCHAIN_ROOT}"
    echo "ZIG_ROOT=${ZIG_ROOT}"
  } >> "${GITHUB_ENV}"
fi
