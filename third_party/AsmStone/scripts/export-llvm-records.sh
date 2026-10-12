#!/usr/bin/env bash
set -euo pipefail

source_root="${1:-third_party/llvm}"
build_root="${2:-build/llvm}"
output="${3:-build/aarch64.records.json}"
tblgen="${TBLGEN:-$build_root/bin/llvm-tblgen}"
expected_commit="87b1a2f7246bc0a4ed5335c45635bddb75847890"

if ! git -C "$source_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'LLVM source is not a Git checkout: %s\n' "$source_root" >&2
    exit 2
fi

actual_commit="$(git -C "$source_root" rev-parse HEAD)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
    printf 'LLVM source commit mismatch: expected %s, got %s\n' "$expected_commit" "$actual_commit" >&2
    exit 3
fi

if [[ ! -x "$tblgen" ]]; then
    printf 'Missing matching llvm-tblgen: %s\n' "$tblgen" >&2
    printf 'Run scripts/build-llvm-tblgen.sh first.\n' >&2
    exit 2
fi

mkdir -p "$(dirname "$output")"
"$tblgen" --dump-json \
    -I "$source_root/llvm/include" \
    -I "$source_root/llvm/lib/Target" \
    -I "$source_root/llvm/lib/Target/AArch64" \
    "$source_root/llvm/lib/Target/AArch64/AArch64.td" \
    -o "$output"

printf 'Wrote %s\n' "$output"
