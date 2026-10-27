# Unified ELF Protection Infrastructure Work Plan

**Status:** in progress; migrated from the active parent workstream on
2026-10-24. The source task showed 6/7 plan phases done, but these product
acceptance criteria remain open.

## Goal

Keep `protect`, `protect-image`, and `rehydrate-image` on one bounded,
structural ELF layout/materialization and publication pipeline. Preserve the
selected-function analysis boundary and expand indirect-control, TLS, and CFI
semantics only with typed source-derived plans and independent evidence.

## Architecture and implementation already in place

- One production protection workflow owns planning, Protected Image emission,
  rehydration/materialization, and publication; no direct writer path is kept as
  an alternate production route.
- Generic parse/validation/packing/materialization is structural by default.
  Instruction analysis is rooted at selected functions and bounded dependency
  queries.
- Layout supports occupied program-header tables, legal load extension/table
  relocation, typed address maps, byte edits, branch decisions, TLS fixes, and
  one materializer. Generated AArch64 instruction words go through the
  AsmStone-backed project adapter.
- Managed TLS semantics include the currently implemented models. Four
  transformed HostContext current-thread rows (initial-exec, local-dynamic,
  general-dynamic, TLSDESC) have native AArch64/glibc evidence.
- CFI parsing/layout and one native AArch64/glibc HostContext typed C++ unwind
  observation through transformed code exist.
- See [engineering specifications](../../engineering/specs/README.md) for durable
  contracts and the
  [indirect-control child plan](./2026-10-24-indirect-control-jump-tables.md)
  for its detailed remaining work.

## Acceptance state

- [ ] **open: parent.indirect-control** — implement and behaviorally exercise
  bounded indirect targets and ambiguous jump tables beyond the completed
  scoped slices. The child remains open on general ownership inference,
  cross-runtime evidence, and remaining encodings/call families.
- [ ] **open: parent.tls-runtime-tuples** — complete the declared per-model,
  profile, lifecycle, and runtime evidence matrix. The four glibc HostContext
  current-thread rows do not cover other declared tuples, musl/Bionic, outer
  profile, or threaded lifecycle behavior.
- [ ] **open: parent.cfi-unwind-tuples** — complete the valid/malformed CFI
  contract and remaining runtime/profile cases. The native glibc transformed
  C++ exception observation is scoped evidence only; musl/Bionic and the other
  declared CFI/unwind scenarios remain unpromoted.

## Required evidence and scope rules

- This parent requires separately evidenced glibc, musl, and Bionic cells for
  every claimed row. No runtime's result promotes another runtime.
- For each promoted semantic row, preserve a controlled positive, nearest
  malformed negative, stable diagnostic, actual producer/runtime status and
  streams, runtime identity, hashes, and independent behavior comparison.
- Parser/model acceptance, managed materialization, loader execution, and
  runtime-specific acceptance are separate claims. Keep unknown/unavailable
  states explicit and do not infer promotion from CI registration or a green
  unrelated suite.
- One unresolved failing row or historical artifact does not disappear when a
  later unrelated test passes. Investigate the failure or retain it as an
  explicit limitation.
- No stale compatibility adapter or second production writer may be added to
  preserve obsolete internal behavior.

## Execution and verification

1. Work one owner boundary at a time from the engineering specifications.
2. Add a regression first and verify the intended failure before implementation.
3. Implement the smallest typed change, run focused tests, then the appropriate
   managed/native/Python and registry checks.
4. Require independent review for source-derived evidence checker changes and
   fresh exact-root runtime evidence. Keep evidence per runtime and profile.
5. Close an acceptance marker only when its specific proof and independent
   runtime criteria are met. Do not close the parent because the project
   workflow or six of seven source-task phases are complete.

## Baseline commands

```sh
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test tests/UrProtect.Core.Tests/UrProtect.Core.Tests.csproj --configuration Release --no-restore
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 tests/test_regression_matrix.py
python3 scripts/check-runtime-matrix-evidence.py
```

Required native/runtime work must run on its declared native AArch64
architecture/runtime. A skipped or unavailable lane is not successful evidence.
