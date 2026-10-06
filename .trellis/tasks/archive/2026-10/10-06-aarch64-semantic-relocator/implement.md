# Implementation plan

## Ordered checklist

1. Add semantic instruction/reference records and target-resolution enums without exposing AsmStone types.
2. Extend the decoder adapter projection with PC-relative, literal, call, branch, register, flag, and memory-reference annotations.
3. Build `AddressMap` and `SemanticRewritePlan` contracts with checked source ranges and typed address domains.
4. Add symbolic encoders/fixups for direct/conditional branch, `BL`, ADR/ADRP, literal loads, and the first AArch64 relocation families.
5. Add branch relaxation hooks for Branch26, near veneer, and long-address forms; leave placement decisions to the layout planner.
6. Replace raw-copy assumptions in the transformation plan with semantic instruction emission and post-encode decode validation.
7. Add canonical serialization fields required by the next Protected Image artifact version.
8. Add positive, nearest-negative, overflow, malformed, and relocation-round-trip tests.
9. Publish the semantic snapshot/extension contract and parent integration handoff; three-runtime fixture descriptors and behavior checks remain parent workflow acceptance, with runtime-specific loader claims in their own evidence cells.
10. Publish the shared contract for sibling child tasks and run the parent integration checks.

## Validation commands

- `dotnet build UrProtect.sln --configuration Release --no-restore`
- `dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore`
- `python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr`
- `python3 tests/test_regression_matrix.py`
- `git diff --check`

Feature-specific native commands are added with the promoted fixture rows and must run independently for glibc, musl, and bionic.

## Rollback points

- Semantic records and decoder projections are additive until consumers switch.
- Old direct writer output remains only as a migration test oracle; no production fallback is introduced.
- A failed encoder/layout binding returns a stable diagnostic and leaves publication paths untouched.
- Artifact ABI changes require a versioned codec and migration fixture update rather than in-place interpretation changes.
