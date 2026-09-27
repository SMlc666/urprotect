# AArch64 compatibility expansion final audit

## Parent outcome

All ten planned child deliverables have reviewed planning/context artifacts;
the first nine are archived and the final release-integration child is the
only active implementation at this audit point. The resulting product keeps
the AArch64-only scope and layered claim model while completing the approved
100-identity public ecology target, bounded ELF/outer/HostContext feature
expansion, runtime covering set, and release evidence reconciliation.

The current fixture manifest has 38 unique feature rows: 25 validated, 7
proven, and 6 rejected. The real-sample registry has 100 unique upstream
identities, 78 glibc, 21 musl, and one bionic observation, with complete PR,
nightly, and release evidence and no raw sample inputs in uploaded roots.

## Ownership and claim audit

- Bounded ELF reads and address conversion remain owned by the Core parser,
  `BoundedReader`, and `LoadMap`; profile acceptance remains in the packer.
- Frame/HostContext ABI layout remains synchronized by managed/native contract
  tests, `ContractInventory.md`, and the native contract probe.
- Native HostContext preflight remains in `host_image_validation.c`; memfd
  sealing, loader handoff, symbol lookup, and release remain in
  `host_adapter.c`.
- Feature status, result vocabulary, aggregate reports, and evidence paths are
  manifest/validator-owned; the release documents project those results.
- Outer execution and HostContext entry claims are separate, and normal
  public samples do not become HostContext claims from loader acceptance.
- Current v3/profile language is used for production; legacy v1/v2 and Wrapper
  0.2 references are explicitly migration evidence.

## Verification evidence

- Managed Release test suite: 140 passed.
- Native runtime contract and self-tests: passed, including dependency graph
  order/environment/rollback, import-version, weak-PLT, and threaded TLS
  ownership checks.
- Fixture matrix, regression matrix, real-sample manifest/fingerprint/
  aggregate/evidence/security tests, release fixture validation, stress, and
  coverage-guided fuzz gates: passed locally where the host provided the
  required toolchain, with native CI covering the complete required release
  tier.
- The final integration commit passed PR run `36305535021`, nightly rehearsal
  `36306172678`, and release rehearsal `36306514702`; all required jobs passed,
  including full real-sample, bionic, runtime-matrix, fixture-nightly, and
  release-package/release-smoke coverage.
- The downloaded release package passed checksums and contained both ARM64
  libc archives, launcher provenance/self-test, SBOM, compatibility contract,
  and fixture manifest. GitHub release publication was intentionally skipped
  for the non-tag rehearsal.

## Explicit limitations

The product does not claim arbitrary shared-object loading, arbitrary
dependency/path graphs, dynamic TLS, unmanaged worker teardown, Android device
compatibility, emulator/QEMU substitution, or a native 16KiB-kernel result
when the runner reports 4KiB. Missing local musl/Zig tools are recorded as
environment-specific local limitations; the required native CI lanes passed
the corresponding gates. Sample frequency remains prioritization evidence and
never independently upgrades a feature status.
