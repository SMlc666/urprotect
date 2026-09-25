# Expand AArch64 runtime environment matrix

## Goal

Build a reproducible covering array for AArch64 runtime compatibility across
representative glibc, musl, and bionic loaders, kernel/page-size facts,
producers, and ELF feature combinations.

## Dependencies and constraints

- Depends on architecture/evidence owners and corpus fingerprints; matrix
  design may proceed in parallel with sample growth.
- Use covering-array selection, not a blind Cartesian product.
- Runtime claims require native AArch64 execution evidence. Emulation or
  native-bridge evidence remains separately labeled and cannot impersonate
  native runtime evidence.
- Missing tools/runtime/capabilities remain explicit unavailable results and
  fail any lane declared required.

## Requirements

- Select representative older/current glibc and musl environments, a locked
  native bionic baseline, and 4K/16K page-size witnesses.
- Cover producer/toolchain and ELF-feature interactions from sample
  fingerprints, using a documented selection rationale.
- Record host arch, kernel, page size, loader/libc identity, toolchain,
  container/image digest, package/hash locks, isolation, and evidence paths.
- Keep PR, nightly, release registries and oracle semantics aligned; tiers vary
  only coverage strength, repetition, and retention.
- Update regression matrix budgets and evidence gates as cells are added.

## Acceptance Criteria

- [ ] Covering-array selection covers all required main effects and named
      high-risk interactions with no unexplained unsupported cell.
- [ ] Every required row runs on the declared native AArch64 environment and
      retains non-empty environment and oracle evidence.
- [ ] 4K and 16K behavior is measured for applicable parser/runtime contracts.
- [ ] Environment-unavailable cannot be mistaken for success or a product
      rejection.
- [ ] Release claims name exactly the runtime cells validated by the release
      artifacts.
