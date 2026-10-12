#!/usr/bin/env bash
set -euo pipefail

source_root="${1:-third_party/llvm}"
build_root="${2:-build/llvm}"
records="${3:-build/aarch64.records.json}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

scripts/export-llvm-records.sh "$source_root" "$build_root" "$records"
dotnet run --project tools/AsmStone.Generator/AsmStone.Generator.csproj -- \
    llvm-inventory "$records" "$tmpdir/inventory.json"
dotnet run --project tools/AsmStone.Generator/AsmStone.Generator.csproj -- \
    emit-csharp "$records" "$tmpdir/catalog.cs" 87b1a2f7246bc0a4ed5335c45635bddb75847890

cmp -s "$tmpdir/catalog.cs" src/AsmStone/Generated/A64GeneratedInstructionTable.cs
cmp -s "$tmpdir/A64GeneratedFieldTable.cs" src/AsmStone/Generated/A64GeneratedFieldTable.cs
cmp -s "$tmpdir/A64GeneratedPredicateTable.cs" src/AsmStone/Generated/A64GeneratedPredicateTable.cs
cmp -s "$tmpdir/A64GeneratedBindingTable.cs" src/AsmStone/Generated/A64GeneratedBindingTable.cs
cmp -s "$tmpdir/A64GeneratedMemoryTable.cs" src/AsmStone/Generated/A64GeneratedMemoryTable.cs
printf 'Generated catalog and typed metadata tables are reproducible.\n'
