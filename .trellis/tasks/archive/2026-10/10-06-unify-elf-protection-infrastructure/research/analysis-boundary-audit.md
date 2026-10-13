# Architecture audit: structural ELF validation versus code analysis

## Audit question

Does the current wrapper/validation/materialization architecture keep whole-ELF structural work separate from selected-function AArch64 code analysis?

## Evidence

- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs:25-42` defaults `analyzeInstructions` to `true` and invokes `Aarch64Analyzer` after structural parsing.
- `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs:27-121` obtains starts from the ELF entry, dynamic symbols, and RELA offsets, then decodes executable ranges until terminators. It is a heuristic whole-image instruction observer, not a selected-function CFG/data-flow pass.
- `src/UrProtect.Cli/CliApplication.cs:1102-1128` defaults `validate` analysis to enabled and exposes `--no-analysis`; `:374-381` routes that option through `NoOpPipeline`.
- `tests/UrProtect.Core.Tests/NoOpPipelineTests.cs:27-36` names the default behavior as entry-region analysis, but the implementation seeds additional dynamic-symbol and relocation starts. The test contract and implementation scope have drifted.
- `src/UrProtect.Core/Protect/FunctionProtectionService.cs:145-164,327-346` resolves explicit selectors and invokes `Aarch64FunctionAnalyzer` only for selected functions. This is the intended code-analysis boundary.
- `src/UrProtect.Core/Rehydrate/GenericRehydrationEngine.cs:173-190` parses the source and delegates to the layout materializer without rediscovering code semantics.
- `src/UrProtect.Core/Elf/ElfLayout.cs` validates program headers, load mappings, ranges, edits, and reparsed output; it does not need whole-image instruction decoding.
- `src/UrProtect.Core/Pack/ElfPackService.cs:12,103` already defaults packing to structural validation (`AnalyzeInstructions = false`), but the generic validation CLI still defaults to the legacy scan.

## Finding

The architecture has a localized but real scope leak: generic `validate`/`NoOpPipeline` can make unrelated executable bytes and decoder availability affect structural ELF validation. The protection and rehydration paths are closer to the desired boundary, but the shared validation abstraction makes whole-image code analysis appear to be a normal wrapper prerequisite.

## Corrected ownership model

```text
ElfStructuralIndex
  = whole-ELF bounded headers/load-map/symbol/relocation/dynamic/raw-range facts

SelectedFunctionPass
  = explicit function-rooted decode, CFG, data-flow, semantic projection,
    and demand-driven indirect/jump-table queries

ElfLayoutPlan / NativeImageMaterializer
  = whole-file physical placement and byte/header emission; no code rediscovery
```

Whole-file output materialization does not imply whole-program code analysis. A selected-function pass may query a referenced table, relocation, symbol, or exact target range on demand, but no wrapper path scans every executable byte to prepare an ELF.

## Correction plan

1. Make structural validation the generic default and stop treating `Aarch64Analyzer` as a publication prerequisite.
2. Keep any instruction-analysis command explicit and scope it to selected functions or a clearly named observation-only mode.
3. Retire or isolate the legacy global `Aarch64Analyzer`; do not use it in wrapper validation, packing, layout, rehydration, or protection publication.
4. Update CLI/report/test contracts so `--no-analysis` is not the only way to obtain structural validation.
5. Add regressions proving decoder-independent structural validation, selected-function analysis, and no whole-image scan in rehydration/layout paths.
6. Only after this correction is reviewed, continue the indirect-control-flow/jump-table design and implementation.

## Non-goals

This audit does not implement the correction, redesign the jump-table resolver, or change the Protected Image ABI. It establishes the prerequisite ownership boundary for those later changes.
