# ISA Inputs

`source-lock.json` records the exact source revisions used by the generator.
The repository does not vendor the source archives; `scripts/fetch-sources.sh`
obtains them into a local ignored directory.

The operational generator input is the pinned LLVM AArch64 TableGen tree.
AARCHMRS is retained as a redistributable architecture inventory and
cross-check. Arm XML/ASL can be used as a private validation input, but it is
not copied into this repository.

Run the first inventory pass after fetching AARCHMRS:

```sh
dotnet run --project tools/AsmStone.Generator/AsmStone.Generator.csproj -- \
  inventory third_party/AARCHMRS/Instructions.json build/aarchmrs-inventory.json
```

The command fails on duplicate instruction names or an empty instruction set.

Build a matching TableGen binary, export expanded records, and inventory them:

```sh
scripts/build-llvm-tblgen.sh third_party/llvm build/llvm
scripts/export-llvm-records.sh third_party/llvm build/llvm build/aarch64.records.json
dotnet run --project tools/AsmStone.Generator/AsmStone.Generator.csproj -- \
  llvm-inventory build/aarch64.records.json build/llvm-inventory.json
```

Emit the first runtime instruction catalog from the same records:

```sh
dotnet run --project tools/AsmStone.Generator/AsmStone.Generator.csproj -- \
  emit-csharp build/aarch64.records.json \
  src/AsmStone/Generated/A64GeneratedInstructionTable.cs \
  87b1a2f7246bc0a4ed5335c45635bddb75847890
```

Or run the complete pinned-source pipeline with
`scripts/generate-runtime-catalog.sh`.

Check an existing checked-in catalog for drift with
`scripts/check-generated-catalog.sh`.

The checked-in generated catalog contains all `7484` non-pseudo AArch64
records exposed by the pinned LLVM input. The runtime catalog currently
provides exact mask/value lookup and raw field extraction; instruction-family
decoders will consume this metadata incrementally. It also contains the `456`
operand codec records referenced by those instruction records.

`A64InstructionCatalog.TryLookup` defaults to the complete source catalog.
Call its overload with `A64FeatureSet.Base`, `A64FeatureSet.From(...)`, or an
explicit predicate set when architecture feature gating is required.
Queries use a generated-table-backed high-byte candidate index; the original
record order remains the specificity order used for matching.
`TryEncodeFields` accepts the exact generated field map for complex records and
is the low-level escape hatch while a typed operand codec is being added.
Generated decode materializes supported simple operand classes and retains raw
encoded fields for codecs that still require family-specific handlers.
Generated instructions carry their TableGen `SourceName`, so simple generated
records can be encoded back through the same field map without a text parser.
The generated operand materializer treats `adrlabel`, `adrplabel`, and branch
targets with their distinct architectural scales.
