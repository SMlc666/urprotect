#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${RUNTIME_TOOLCHAIN_ARTIFACT_ROOT:-${root}/.artifacts/runtime-matrix/toolchain}"
[[ "$out" == /* ]] || out="$root/$out"
case "$out" in
  "$root"/.artifacts/runtime-matrix/*) ;;
  *) echo "musl evidence root must be under .artifacts/runtime-matrix: $out" >&2; exit 2 ;;
esac
rm -rf -- "$out"
lock="$root/fixtures/runtime-matrix-toolchains.json"
archive_dir="$out/source"
src="$out/build/musl-1.2.4"
prefix="$out/prefix"
loader="/lib/ld-musl-aarch64.so.1"
loader_link_created=0
cleanup_installer_loader_link() {
  local exit_status=$?
  trap - EXIT
  if [[ $exit_status -ne 0 && $loader_link_created == 1 \
      && -L "$loader" \
      && "$(readlink -f "$loader")" == "$prefix/lib/libc.so" ]]; then
    if [[ "$(id -u)" == 0 ]]; then
      rm -f -- "$loader" || true
    elif command -v sudo >/dev/null; then
      sudo rm -f -- "$loader" || true
    fi
  fi
  exit "$exit_status"
}
trap cleanup_installer_loader_link EXIT
mkdir -p "$archive_dir" "$out/build" "$out/logs"
[[ "$(uname -m)" == aarch64 ]] || { echo 'musl 1.2.4 toolchain requires native AArch64' >&2; exit 2; }
for tool in ar gcc ld make readelf sha256sum python3 sudo tar; do
  if [[ "$tool" == sudo && "$(id -u)" == 0 ]]; then continue; fi
  command -v "$tool" >/dev/null || { echo "required musl build tool missing: $tool" >&2; exit 127; }
done
rm -rf -- "$src" "$prefix"
mkdir -p "$out/build"
stage="$out/stage"
rm -rf -- "$stage"
mkdir -p "$stage"

python3 - "$lock" "$archive_dir" "$out/source/toolchain-source.json" <<'PY'
import hashlib
import json
import pathlib
import sys
import urllib.request

lock = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if lock.get("schemaVersion") != 1 or len(lock.get("toolchains", [])) != 1:
    raise SystemExit("runtime toolchain lock schema or entry count is invalid")
toolchain = lock["toolchains"][0]
if toolchain.get("id") != "musl.1.2.4.ubuntu-native" or toolchain.get("architecture") != "aarch64":
    raise SystemExit("runtime toolchain lock selects an unexpected target")
path = pathlib.Path(sys.argv[2]) / toolchain["sourceFilename"]
request = urllib.request.Request(toolchain["source"], headers={"User-Agent": "urprotect-runtime-matrix/1"})
with urllib.request.urlopen(request, timeout=60) as response:
    path.write_bytes(response.read())
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if actual != toolchain["sourceSha256"]:
    raise SystemExit(f"musl source SHA-256 mismatch: {actual}")
record = {
    "schemaVersion": 1,
    "id": toolchain["id"],
    "source": toolchain["source"],
    "filename": path.name,
    "sourceSha256": actual,
    "sourceBytes": path.stat().st_size,
    "version": toolchain["version"],
}
pathlib.Path(sys.argv[3]).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY

tar -xzf "$archive_dir/musl-1.2.4.tar.gz" -C "$out/build"
[[ -x "$src/configure" ]] || { echo 'pinned musl source archive lacks configure' >&2; exit 1; }
(
  cd "$src"
  CC=gcc ./configure \
    --prefix="$prefix" \
    --target=aarch64-linux-musl \
    --syslibdir=/lib \
    --enable-wrapper=gcc \
    2>&1 | tee "$out/logs/configure.log"
  make -s -j2 CROSS_COMPILE= 2>&1 | tee "$out/logs/build.log"
  make -s CROSS_COMPILE= install-headers install-tools 2>&1 | tee "$out/logs/install.log"
  make -s CROSS_COMPILE= DESTDIR="$stage" install-libs 2>&1 | tee -a "$out/logs/install.log"
  printf 'PASS make install-headers install-tools\nPASS make DESTDIR=<locked-stage> install-libs\n' \
    >> "$out/logs/install.log"
)

mkdir -p "$prefix/lib"
cp -a "$stage$prefix/lib/." "$prefix/lib/"
[[ -x "$prefix/bin/musl-gcc" && -s "$prefix/lib/libc.so" ]] || {
  echo 'musl install did not produce its compiler wrapper and runtime image' >&2
  exit 1
}
if [[ -e "$loader" || -L "$loader" ]]; then
  echo "refusing to replace an existing native musl loader path: $loader" >&2
  exit 1
fi
if [[ "$(id -u)" == 0 ]]; then
  ln -s "$prefix/lib/libc.so" "$loader"
else
  sudo ln -s "$prefix/lib/libc.so" "$loader"
fi
loader_link_created=1
printf '%s\n' "$loader" > "$out/created-loader-link.txt"
loader_resolved="$(readlink -f "$loader")"
[[ "$loader_resolved" == "$prefix/lib/libc.so" ]] || {
  echo "musl loader resolves outside the pinned build prefix: $loader_resolved" >&2
  exit 1
}
set +e
"$loader" --help > "$out/logs/loader-version.txt" 2>&1
loader_status=$?
set -e
grep -Fq 'Version 1.2.4' "$out/logs/loader-version.txt" || {
  echo 'built musl loader did not report version 1.2.4' >&2
  exit 1
}
{
  printf 'native_arch=%s\n' "$(uname -m)"
  printf 'kernel=%s\n' "$(uname -r)"
  printf 'page_size=%s\n' "$(getconf PAGESIZE)"
  printf 'gcc=%s\n' "$(gcc --version | head -n1)"
  printf 'gcc_path=%s\n' "$(command -v gcc)"
  printf 'ld=%s\n' "$(ld --version | head -n1)"
  printf 'ld_path=%s\n' "$(command -v ld)"
  printf 'ar=%s\n' "$(ar --version | head -n1)"
  printf 'ar_path=%s\n' "$(command -v ar)"
  printf 'readelf=%s\n' "$(readelf --version | head -n1)"
  printf 'readelf_path=%s\n' "$(command -v readelf)"
  printf 'make=%s\n' "$(make --version | head -n1)"
  printf 'make_path=%s\n' "$(command -v make)"
  printf 'configure_target=aarch64-linux-musl\n'
  printf 'source_lock_sha256=%s\n' "$(sha256sum "$lock" | awk '{print $1}')"
  printf 'source_archive_sha256=%s\n' "$(sha256sum "$archive_dir/musl-1.2.4.tar.gz" | awk '{print $1}')"
  printf 'runtime_loader=%s\n' "$loader"
  printf 'runtime_loader_resolved=%s\n' "$loader_resolved"
  printf 'loader_probe_status=%s\n' "$loader_status"
  for tool in gcc ld ar readelf make; do
    digest="$(sha256sum "$(command -v "$tool")" | awk '{print $1}')"
    printf '%s_sha256=%s\n' "$tool" "$digest"
  done
  printf 'musl_gcc_sha256=%s\n' "$(sha256sum "$prefix/bin/musl-gcc" | awk '{print $1}')"
  printf 'musl_loader_sha256=%s\n' "$(sha256sum "$prefix/lib/libc.so" | awk '{print $1}')"
} > "$out/build-facts.txt"
find "$out" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$out/SHA256SUMS"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$prefix/bin" >> "$GITHUB_PATH"
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'MUSL_TOOLCHAIN_ROOT=%s\n' "$prefix" >> "$GITHUB_ENV"
fi
printf 'PASS pinned musl 1.2.4 source build; toolchain=%s artifacts=%s\n' "$prefix" "$out"
