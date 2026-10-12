#!/usr/bin/env bash
set -euo pipefail

source_root="${1:-third_party/llvm}"
build_root="${2:-build/llvm}"
jobs="${LLVM_BUILD_JOBS:-$(nproc)}"
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

cmake -S "$source_root/llvm" -B "$build_root" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_TARGETS_TO_BUILD=AArch64 \
    -DLLVM_ENABLE_PROJECTS='' \
    -DLLVM_ENABLE_RUNTIMES='' \
    -DLLVM_BUILD_TOOLS=ON \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF
cmake --build "$build_root" --target llvm-tblgen --parallel "$jobs"

printf 'Built %s\n' "$build_root/bin/llvm-tblgen"
