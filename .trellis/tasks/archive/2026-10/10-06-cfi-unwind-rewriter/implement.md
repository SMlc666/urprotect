# Implementation plan

## Phase 1: Plan and contract

1. Add bounded unwind diagnostic codes and shared parser limits.
2. Add UnwindMetadata records for encodings, CIE/FDE records, CFI
   instructions, .eh_frame_hdr, rewrite results, and evidence.
3. Add design-level tests for sectionless/not-applicable, malformed length,
   unknown augmentation, and stable diagnostics.

## Phase 2: Structural parser

4. Implement bounded ULEB128/SLEB128 and DW_EH_PE decoding/encoding.
5. Implement .eh_frame record parser with 32/64-bit lengths, CIE/FDE
   relationships, augmentation payloads, and common AArch64 CFA opcodes.
6. Implement .eh_frame_hdr parser with pointer encodings, FDE count, sorted
   table validation, and source section bounds.
7. Add valid GCC/Clang-shaped synthetic fixtures, extended-length records,
   truncated/overflow/invalid-CIE/header-table negatives, and round-trip tests.

## Phase 3: Rewrite planner

8. Implement old/new range mapping through AddressMap for identity and
   piecewise-linear ranges.
9. Implement CIE-preserving FDE remap and canonical CFI effect injection for
   the promoted CFA operations.
10. Rebuild .eh_frame_hdr table entries and section-relative pointers using
    the original encodings.
11. Add deterministic UnwindMetadataUnavailable, UnwindMetadataMalformed,
    UnwindMetadataUnsupported, UnwindAddressMapMissing, and
    UnwindRewriteOverlap diagnostics.

## Phase 4: Shared layout/materialization

12. Add ElfLayoutEditKind.UnwindMetadata.
13. Feed unwind edits through ElfLayoutPlan and materializer overlap checks.
14. Reparse output ELF/unwind model and require CIE/FDE/header identity and
    digest equivalence before returning output.
15. Add publication rollback tests proving no output/evidence is retained after
    malformed CFI, mapping conflict, or reparse mismatch.

## Phase 5: Native behavior evidence

16. Dedicated native transformed CFI behavior fixtures (backtrace, exception,
    cancellation/signal, and register/frame state) remain an explicit downstream
    evidence slice; the current task records them as not-promoted rather than
    inferring runtime support from managed parser/materializer tests.
17. Preserve the existing runtime evidence contract: glibc, musl, and bionic
    rows are independent, and unavailable toolchains/runtimes are recorded as
    `environment-unavailable` without promotion.
18. Current managed/native verification completed: 403 managed tests, 309 Python
    tests, native runtime self-tests, fixture/regression matrices, architecture
    checks, and AArch64 encoding boundary checks.

## Validation commands

- DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet restore UrProtect.sln --locked-mode
- DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
- DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build --no-restore
- python3 -m unittest discover -s tests -p 'test_*.py'
- python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
- python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
- make -C native/urprotect-runtime test
- python3 scripts/check-architecture-boundaries.py --self-test
- git diff --check

## Risky files and rollback points

- src/UrProtect.Core/UnwindMetadata/: parser, model, encoder, rewrite planner.
- src/UrProtect.Core/Diagnostics/Diagnostic.cs: stable diagnostic additions.
- src/UrProtect.Core/ElfLayout/ElfLayoutContracts.cs,
  ElfLayoutPlanner.cs, ElfLayoutMaterializer.cs: edit ownership and
  overlap/reparse behavior.
- src/UrProtect.Core/SemanticPlanning/: address-map and CFI effect binding.
- tests/UrProtect.Core.Tests/UnwindMetadata/ and integration fixtures.
- fixtures/manifest.json, tests/regression-matrix.json, native fixture scripts,
  and CI evidence checkers.

Rollback is per phase: parser/model, rewrite planner, layout integration, then
runtime evidence. Every phase must leave the source tree buildable and
publication transactional.

## Review gates before activation

- Design and plan are present and correspond to the CFI PRD.
- Parent G0-G2 and TLS prerequisite remain complete/archived.
- No parallel artifact or direct writer is introduced.
- task.py validate .trellis/tasks/10-06-cfi-unwind-rewriter passes.
- task.py start .trellis/tasks/10-06-cfi-unwind-rewriter is run only after
  this plan review.
