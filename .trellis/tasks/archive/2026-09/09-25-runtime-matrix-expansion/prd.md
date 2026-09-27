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

- Select Ubuntu 24.04/glibc 2.39 on the native AArch64 runner, older
  glibc in a digest-pinned ARM64 container, two distinct musl runtime versions
  on AArch64, and the existing locked native bionic/Termux baseline.
- Measure 4K kernel-page behavior in available native/container cells; add
  real-linker ELF fixtures with 4K and 16K `PT_LOAD.p_align` and test those
  fixtures across available loaders. A distinct 16K kernel-page runtime cell
  must be probed and represented as `environment-unavailable` unless a native
  AArch64 16K-page runner is available. Structural 16K ELF alignment evidence
  must not be described as a 16K kernel runtime.
- Cover producer/toolchain and ELF-feature interactions from sample
  fingerprints, using a documented selection rationale.
- Record host arch, kernel, page size, loader/libc identity, toolchain,
  container/image digest, package/hash locks, isolation, and evidence paths.
- Pin and verify the musl 1.2.4 source archive before building its native
  AArch64 compiler/runtime; retain the source hash, compiler/runtime hashes,
  complete build logs, and loader version. The runtime evidence gate consumes
  the bionic package archives, lock, verification records, linker oracle, and
  HostContext fixture/self-test produced by its required upstream CI job.
- Keep PR, nightly, release registries and oracle semantics aligned; tiers vary
  only coverage strength, repetition, and retention.
- Update regression matrix budgets and evidence gates as cells are added.

## Acceptance Criteria

- [x] Covering-array selection covers all required main effects and named
      high-risk interactions with no unexplained unsupported cell.
- [x] Every required row runs on the declared native AArch64 environment and
      retains non-empty environment and oracle evidence.
- [x] 4K and 16K behavior is measured for applicable parser/runtime contracts.
- [x] Environment-unavailable cannot be mistaken for success or a product
      rejection.
- [x] Release claims name exactly the runtime cells validated by the release
      artifacts.

## Initial covering-set proposal

- Current runner glibc: record exact loader/glibc/kernel/page size; run default
  Ubuntu 24.04/glibc 2.39 loader with default GCC PIE and linker-produced 16K
  `PT_LOAD.p_align` payload.
- Pinned Ubuntu 22.04 ARM64 image (glibc 2.35): run the 16K-aligned GNU PIE
  fixture and record loader, page size, and output.
- Ubuntu 24.04 native AArch64 musl 1.2.4 built from a SHA-256-locked release
  archive with the recorded runner GCC; run 4K/16K PIEs and the existing
  no-op/outer-wrapper smoke, then remove the test-owned loader link.
- Digest-pinned Alpine 3.22.2 ARM64 musl 1.2.5: run a compatible 16K-aligned
  musl PIE produced on the native runner.
- Existing pinned Termux/bionic native-container cell remains separate and
  cannot substitute for glibc or musl evidence.
- Probe runtime page size explicitly. If the available ARM64 kernel is 4K,
  retain a distinct 16K runtime `environment-unavailable` result and leave the
  runtime claim unknown; no emulator or fabricated page-size value is a
  substitute.
