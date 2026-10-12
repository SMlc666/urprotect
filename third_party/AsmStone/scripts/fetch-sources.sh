#!/usr/bin/env bash
set -euo pipefail
root="${1:-third_party}"
mkdir -p "$root"
aarchmrs_url="https://kernel.googlesource.com/pub/scm/linux/kernel/git/maz/AARCHMRS"
aarchmrs_commit="1b73e640fbc3f035d16d7a292308ffd8a1405e74"
llvm_url="https://github.com/llvm/llvm-project.git"
llvm_commit="87b1a2f7246bc0a4ed5335c45635bddb75847890"
if [[ ! -d "$root/AARCHMRS/.git" ]]; then
    git clone --filter=blob:none --depth 1 --branch tooling "$aarchmrs_url" "$root/AARCHMRS"
fi
git -C "$root/AARCHMRS" fetch --depth 1 origin "$aarchmrs_commit"
git -C "$root/AARCHMRS" checkout --detach "$aarchmrs_commit"
if [[ ! -d "$root/llvm/.git" ]]; then
    git clone --filter=blob:none --no-checkout --depth 1 "$llvm_url" "$root/llvm"
fi
git -C "$root/llvm" fetch --depth 1 origin "$llvm_commit"
git -C "$root/llvm" checkout --detach "$llvm_commit"
printf 'Fetched AARCHMRS at %s\n' "$(git -C "$root/AARCHMRS" rev-parse HEAD)"
printf 'Fetched LLVM at %s\n' "$(git -C "$root/llvm" rev-parse HEAD)"
