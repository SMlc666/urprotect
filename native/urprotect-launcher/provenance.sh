#!/usr/bin/env sh
set -eu

output_path=${1:?output path is required}
compiler=${2:?compiler is required}
launcher=${3:?launcher path is required}
source_date_epoch=${4:-0}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compiler_binary=${compiler%% *}
temporary_path="$output_path.tmp.$$"

cleanup() {
    rm -f -- "$temporary_path"
}
trap cleanup EXIT HUP INT TERM

compiler_version=$($compiler_binary --version 2>&1 | head -n 1 || true)
compiler_target=$($compiler_binary -dumpmachine 2>/dev/null || true)
compiler_path=$(command -v "$compiler_binary" || true)
compiler_hash=$(if [ -n "$compiler_path" ] && [ -f "$compiler_path" ]; then sha256sum "$compiler_path" | awk '{print $1}'; fi)
compiler_specs_hash=$($compiler_binary -dumpspecs 2>/dev/null | sha256sum | awk '{print $1}' || true)
launcher_hash=$(sha256sum "$launcher" | awk '{print $1}')
launcher_size=$(wc -c < "$launcher" | tr -d '[:space:]')
miniz_commit=$(tr -d '[:space:]' < "$repo_root/third_party/miniz/COMMIT")
source_git_sha=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)

{
    printf '%s\n' 'schema=urprotect-native-launcher-provenance-v1'
    printf '%s\n' 'launcher_abi=1'
    printf '%s\n' 'launcher_marker=URPROTECT-AARCH64-LAUNCHER-V1'
    printf 'source_date_epoch=%s\n' "$source_date_epoch"
    printf 'compiler=%s\n' "$compiler"
    printf 'compiler_version=%s\n' "$compiler_version"
    printf 'compiler_target=%s\n' "$compiler_target"
    printf 'compiler_path=%s\n' "$compiler_path"
    printf 'compiler_sha256=%s\n' "$compiler_hash"
    printf 'compiler_specs_sha256=%s\n' "$compiler_specs_hash"
    printf 'source_git_sha=%s\n' "$source_git_sha"
    printf 'link_flags=%s\n' '-static-pie -Wl,--build-id=none,--gc-sections,-z,relro,-z,now -Wl,-s'
    printf 'launcher_sha256=%s\n' "$launcher_hash"
    printf 'launcher_size=%s\n' "$launcher_size"
    printf 'miniz_commit=%s\n' "$miniz_commit"
    for file in \
        third_party/miniz/miniz.h \
        third_party/miniz/miniz_common.h \
        third_party/miniz/miniz_export.h \
        third_party/miniz/miniz_tinfl.h \
        third_party/miniz/miniz_tinfl.c \
        third_party/miniz/miniz_tdef.h \
        third_party/miniz/miniz_zip.h \
        third_party/miniz/README.md \
        third_party/miniz/LICENSE
    do
        printf 'sha256.%s=%s\n' "$file" "$(sha256sum "$repo_root/$file" | awk '{print $1}')"
    done
    if command -v dpkg-query >/dev/null 2>&1; then
        for package in musl musl-dev musl-tools; do
            version=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
            if [ -n "$version" ]; then
                printf 'debian_package_%s=%s\n' "$package" "$version"
            fi
        done
    fi
} > "$temporary_path"
mv -- "$temporary_path" "$output_path"
