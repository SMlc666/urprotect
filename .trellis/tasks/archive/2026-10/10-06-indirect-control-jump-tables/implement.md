# Implementation plan

## Ordered checklist

### Phase 0: Correct the analysis boundary first

1. Change generic `NoOpPipeline`/CLI validation to structural validation by default; make instruction analysis explicit rather than a wrapper prerequisite.
2. Isolate or retire the legacy whole-image `Aarch64Analyzer` from wrapper validation, packing, layout, rehydration, and protection publication.
3. Update `NoOpPipelineTests`, CLI/report tests, and decoder-failure tests to prove unrelated executable bytes and decoder availability do not affect structural validation.
4. Preserve selected-function `Aarch64FunctionAnalyzer` behavior and add an explicit scope contract for any remaining observation-only analysis.

### Phase 1: Demand-driven resolver contracts

5. Add a bounded `ElfStructuralIndex` projection over existing `ElfFile` facts; do not create a second ELF parser or whole-image disassembler.
6. Add typed indirect-expression, value-range, ownership, and target-resolution records using the shared semantic plan/snapshot extension contracts.
7. Add an affine expression normalizer for selected-function producer chains ending in indirect branches/calls.
8. Add bounded value-set evaluation for index/range proofs and exact/bounded target classification.

### Phase 2: Jump-table discovery and rewriting

9. Recognize the first compiler-generated relative/absolute table patterns from selected-function data-flow, including ADRP/LDRSW/ADD/BR and equivalent forms.
10. Model table base, entry width, signedness, scale/addend, bounds, default target, ownership, and rewrite policy.
11. Resolve private selected tables, shared tables, external tables, and runtime-owned tables through separate preservation/copy/retarget strategies.
12. Rewrite table entries and table references through `AddressMap` and semantic fixups; keep original addresses or install typed stable veneers when a target is not movable.
13. Add typed runtime-target translation bindings without implementing an implicit runtime fallback; promotion requires the workflow/runtime evidence contract.

### Phase 3: Integration and evidence

14. Attach indirect target and jump-table extensions to the existing `SemanticRewritePlan` and canonical snapshot; do not add a parallel raw-byte model.
15. Pass only resolved/preserved/deferred contracts to the shared ELF layout planner/materializer; rehydration must not rediscover code semantics.
16. Add positive fixtures for bounded switches, relative/absolute tables, function-pointer tables, selected/unselected targets, shared-table copy/retarget, and stable veneers.
17. Add nearest-negative fixtures for missing bounds, malformed entries, ambiguous ownership, external tables, out-of-range targets, oversized target sets, and missing runtime bindings.
18. Add target-selection evidence fields and independent glibc/musl/bionic runtime rows through the parent workflow, without promoting one runtime from another.

## Validation commands

- `dotnet build UrProtect.sln --configuration Release --no-restore`
- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore`
- `python3 -m unittest discover -s tests -p 'test_*.py'`
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
- `python3 tests/test_regression_matrix.py`
- `git diff --check`
- `./scripts/run-protection-e2e.sh --tier pr --runtime glibc`
- `./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc`

Native musl/bionic target-selection rows are parent/runtime-child gates and must retain explicit environment/toolchain evidence. The local architecture-boundary tests must pass before any semantic-domain implementation is enabled.

## Risky files and rollback points

- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs`, `src/UrProtect.Cli/CliApplication.cs`, and `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs`: first correction boundary; preserve structural validation and report compatibility while removing the global scan prerequisite.
- `src/UrProtect.Core/Aarch64/FunctionAnalysis.cs`, `Aarch64SemanticPlanFactory.cs`, `SemanticPlanSnapshot.cs`: selected-function and canonical handoff contracts.
- `src/UrProtect.Core/Protect/FunctionProtectionService.cs`: selected-function integration and protection closure.
- `src/UrProtect.Core/Elf/ElfLayout.cs`: physical table/code/veneer placement only; no semantic target guessing.
- `src/UrProtect.Core/Protect/ProtectedImageV1.cs` and workflow artifacts: versioned operation/evidence evolution remains a parent workflow boundary.

Rollback order:

1. revert indirect resolver/table changes while retaining the analysis-boundary correction;
2. keep structural validation decoder-independent;
3. never restore the whole-image scanner as a silent production fallback;
4. publish no artifact when a required target/preservation contract is invalid.

## Start gate

Do not run `task.py start` or implement product code until the parent architecture correction and this selected-function/demand-driven design are explicitly reviewed and approved.
