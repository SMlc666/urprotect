# Refactor ELF model and parser for feature growth

## Goal

Refactor the managed ELF model/parser into cohesive, testable ownership
boundaries and implement the first frequency-prioritized common AArch64 ELF
feature slices without weakening bounded reads or fail-closed validation.

## Dependencies and constraints

- Depends on the architecture foundation and the first real-sample histogram.
- Must reuse `BoundedReader`, typed address domains, and `LoadMap`.
- Parser observation, static acceptance, outer execution, and HostContext
  support remain separate statuses.
- Every new feature requires a real-toolchain positive fixture and a nearest
  malformed/negative fixture; no loader anecdote promotes support.

## Requirements

- Extract parser responsibilities only where the audit identifies cohesive
  feature/table ownership and preserve the public parse result contract.
- Select common feature families from measured frequency, product value,
  semantic risk, and dependency order.
- Add typed model records, checked range/address logic, stable diagnostics, and
  bounded unknown preservation for each selected family.
- Synchronize feature IDs, manifest rows, reports, contract inventory, tests,
  and compatibility documentation.
- Promote minimized fuzz findings to deterministic regressions.

## Acceptance Criteria

- [x] Parser/model ownership map has no duplicated active address arithmetic or
      dynamic-table interpretation.
- [x] First selected feature slice has positive, nearest-negative, malformed,
      property/model, and diagnostic tests.
- [x] Existing parser, malformed corpus, property, golden, and fuzz tests pass.
- [x] Any new acceptance is reflected only at the proven layer and retains a
      separate runtime/profile claim where required.
- [x] Refactored code has a documented rollback and no unbounded binary read or
      speculative recovery path.
