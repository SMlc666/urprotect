# Support indirect control flow and jump tables

## Goal

Promote indirect branches/calls and ambiguous compiler-generated jump tables from permanent rejection boundaries to modeled, relocatable, and behaviorally verified features.

## Requirements

- Resolve exact and bounded target sets using CFG, value ranges, relocation metadata, function tables, and compiler patterns.
- Model jump-table base, entry width, signedness, relative/absolute representation, bounds, default target, and target ownership.
- Rewrite table entries or references when protected blocks/functions move.
- Define a stable-address veneer or runtime target-translation strategy for opaque targets that can enter relocated code.
- Record unresolved target classification before publication; never guess a target set.

## Confirmed design direction

- Do not classify an indirect control-flow form as unsupported merely because the final instruction is `BR`/`BLR` or because the target is table-driven.
- Any relative-address representation with a recoverable base, entry width, signedness, scale/addend, index bounds, table range, and target ownership must be normalized into a symbolic affine target expression and resolved to an exact or bounded target set.
- Resolution is proof-based rather than a broad static-versus-runtime label. The resolver must preserve the producer chain, the address expression, the bounds proof, the table ownership proof, and the resulting `AddressMap` bindings.
- A target is deferred only when the required expression or proof input is genuinely absent or runtime-owned; the diagnostic must identify the missing proof rather than silently treating the instruction family as unsupported.
- The first promoted family therefore includes compiler-generated relative jump tables and relative indirect-call/branch forms, while full runtime target translation remains a separately declared extension point.


## Max-compatibility policy

- The ELF wrapper must not disassemble or build a whole-image code CFG. Its whole-ELF responsibility is bounded structural indexing of program headers, load maps, symbols, relocations, dynamic metadata, and targeted byte ranges; instruction semantics remain owned by selected-function passes.
- Indirect-target resolution is demand-driven from selected function roots. It may inspect a referenced table, relocation, symbol, or exact target range on demand, but it must not scan every function or every executable byte merely to prepare the wrapper.
- The transformation boundary is therefore `selected function pass -> targeted dependency queries -> resolved protection closure -> whole-file layout/materialization`; whole-file output does not imply whole-program code analysis.
- Compatibility is maximized by adaptive preservation and translation, not by a single static-analysis gate. The resolver must try, in order: exact data-flow resolution; bounded value-set/table resolution; relocation/symbol/loader binding; stable-address preservation through typed veneers; and an explicitly declared runtime target-translation strategy.
- A recognized relative-address form is a supported parsing family whenever its affine expression and bounds can be proven. Section headers and relocation metadata are supporting evidence, not mandatory prerequisites for stripped or sectionless ELF.
- When a target cannot be proven movable, the layout planner should preserve its original address/table or keep the affected block in place and use a typed stable-address veneer where that is sufficient. It must not move the target and hope that an opaque indirect edge follows it.
- Runtime target translation is an extension for cases where preserving the original address is insufficient. It requires a versioned runtime binding, a register/flag/ABI preservation contract, and separate native evidence; it is never inferred from a missing static proof.
- Transformation status is explicit: a preserved region, translated target, deferred reference, or unresolved required target is retained in the plan and evidence. No path may silently downgrade an unresolved target to a guessed address or claim a fully transformed function without validating every reachable target.


## Architecture self-audit: confirmed scope drift

- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs:25-42` defaults `analyzeInstructions` to `true` and invokes the whole-image `Aarch64Analyzer` from a generic ELF validation path.
- `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs:27-121` seeds from the ELF entry, dynamic symbols, and relocation offsets, then decodes executable ranges until terminators. This is heuristic whole-image instruction scanning, not selected-function semantic analysis, and can make unrelated code affect wrapper validation.
- `src/UrProtect.Cli/CliApplication.cs:1102-1128,374-381` makes that scan the default for `validate`; `--no-analysis` is an escape hatch rather than the structural default.
- The intended protection path is already closer to the correct boundary: `FunctionProtectionService` resolves explicit selectors and calls `Aarch64FunctionAnalyzer` only for selected functions (`src/UrProtect.Core/Protect/FunctionProtectionService.cs:145-164,327-346`). `GenericRehydrationEngine` and `ElfLayoutMaterializer` parse and materialize structural ELF data without whole-image code analysis.
- Planning consequence: separate structural ELF validation from code analysis. The wrapper/parser/layout path must remain structural by default; any instruction analysis must be an explicit selected-function pass or a demand-driven bounded query. The legacy global `Aarch64Analyzer` must not be the production prerequisite for wrapper validation or protection publication.

## Acceptance criteria

- [ ] Direct and indirect switch fixtures with bounded targets transform and preserve all cases.
- [ ] Function-pointer and indirect-call fixtures exercise the declared static/runtime mapping strategy.
- [ ] Ambiguous, malformed, out-of-range, and externally owned tables have nearest-negative evidence.
- [ ] All three native runtime lanes retain status, streams, and target-selection evidence for promoted rows.
- [ ] The final report names target-resolution mode and address-map bindings.
