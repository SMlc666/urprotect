#!/usr/bin/env bash
set -euo pipefail

source_root="${1:-third_party/llvm}"
build_root="${2:-build/llvm}"
records="${3:-build/aarch64.records.json}"
output="${4:-src/AsmStone/Generated/A64GeneratedInstructionTable.cs}"
commit="87b1a2f7246bc0a4ed5335c45635bddb75847890"

scripts/build-llvm-tblgen.sh "$source_root" "$build_root"
scripts/export-llvm-records.sh "$source_root" "$build_root" "$records"
dotnet run --project tools/AsmStone.Generator/AsmStone.Generator.csproj -- \
    emit-csharp "$records" "$output" "$commit"
