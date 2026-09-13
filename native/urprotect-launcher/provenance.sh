#!/usr/bin/env sh
set -eu

output_path=${1:?output path is required}
compiler=${2:?compiler is required}
launcher=${3:?launcher path is required}
source_date_epoch=${4:-0}
link_compiler=${5:-$compiler}
link_specs=${6:-}
base_specs=${7:-}
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
link_compiler_binary=${link_compiler%% *}
link_compiler_version=$($link_compiler_binary --version 2>&1 | head -n 1 || true)
link_compiler_target=$($link_compiler_binary -dumpmachine 2>/dev/null || true)
link_compiler_path=$(command -v "$link_compiler_binary" || true)
link_compiler_hash=$(if [ -n "$link_compiler_path" ] && [ -f "$link_compiler_path" ]; then sha256sum "$link_compiler_path" | awk '{print $1}'; fi)
normalized_link_specs=$(printf '%s' "$link_specs" | sed "s#${repo_root}/native/urprotect-launcher/musl-static-pie.specs#native/urprotect-launcher/musl-static-pie.specs#g")
base_specs_sha256=$(if [ -n "$base_specs" ] && [ -f "$base_specs" ]; then sha256sum "$base_specs" | awk '{print $1}'; fi)
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
    printf 'link_compiler=%s\n' "$link_compiler"
    printf 'link_compiler_version=%s\n' "$link_compiler_version"
    printf 'link_compiler_target=%s\n' "$link_compiler_target"
    printf 'link_compiler_path=%s\n' "$link_compiler_path"
    printf 'link_compiler_sha256=%s\n' "$link_compiler_hash"
    printf 'link_specs=%s\n' "$normalized_link_specs"
    printf 'musl_base_specs=%s\n' "$base_specs"
    printf 'musl_base_specs_sha256=%s\n' "$base_specs_sha256"
    printf 'source_git_sha=%s\n' "$source_git_sha"
    printf 'link_flags=%s\n' '-static-pie -Wl,--no-dynamic-linker,--build-id=none,--gc-sections,-z,relro,-z,now -Wl,-s'
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
        third_party/miniz/LICENSE \
        native/urprotect-launcher/musl-static-pie.specs
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
