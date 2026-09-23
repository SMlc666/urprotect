# Build compatibility matrix and evidence gates

## Goal

Replace project-owned compatibility-profile terminology with a machine-readable
feature/evidence matrix that is the source of truth for supported AArch64 PIE
behavior, proof status, fixture selection, and CI gates.

## Requirements

- Replace the top-level profiles fixture collection with a name that
  describes matrix cases; replace --profile selection with a tier/selection
  term that reflects whether a run is PR, nightly, release, or manual.
- Rename project-owned container/profile metadata to actual image, host, or
  environment facts. Preserve external tool concepts such as Cargo's
  profile.release.
- Define schema fields for feature ID, case ID, artifact shape, toolchain,
  runtime assumptions, Host Contract version, status, proof obligation,
  positive/negative fixtures, oracle, and evidence paths.
- Use statuses proven, validated, rejected, and unknown; only proven and
  explicitly approved validation states may gate a support claim, and unknown
  must fail closed.
- Generate or validate human-readable matrix documentation from the machine
  manifest; prevent drift between manifest, fixture scripts, README, and CI.
- Require every claimed row to have a fixture or model witness and a stable
  evidence path. A test pass without a mapped row is informative but not a
  compatibility claim.
- Represent the native ARM64 bionic userspace lane as a host case with explicit
  kernel, page-size, rootfs, linker, and execution-mode facts. Do not label it
  as full Android or allow glibc, QEMU, native-bridge, AVD, or Waydroid
  fallback to satisfy the case.
- Keep runtime bionic as a first-class peer of runtime glibc and runtime musl;
  distinguish the Termux userspace from Android framework execution with host
  and execution facts.
- Avoid a full Cartesian product; encode feature interactions and use a
  documented covering strategy.

## Dependencies and Ordering

- Consumes the Host Contract version and feature IDs from
  09-13-unified-runtime-host-contract and
  09-13-expand-aarch64-pie-compatibility.
- Naming/schema migration may proceed early, but the final support gate waits
  for the runtime and PIE feature obligations.
- The parent task owns the final matrix review and cross-child acceptance.

## Acceptance Criteria

- [x] The manifest and scripts no longer expose project-owned
      profiles/--profile compatibility terminology.
- [x] A schema validator rejects missing, duplicate, contradictory, or
      evidence-free matrix rows.
- [x] The current fixture set is represented as matrix cases with explicit
      toolchain/runtime/artifact facts.
- [x] At least one positive, one rejected, and one unknown row flow through the
      validator and CI reporting.
- [x] CI fails when a claimed row lacks its required proof/model/fixture
      evidence, while optional execution evidence remains clearly labeled.
- [x] Native ARM64 bionic evidence is retained and mapped to the features it
  actually exercises, without upgrading Android framework/device claims.
- [x] The matrix records the pinned Termux Docker source commit and ARM64 image
      digest, and rejects a bionic row whose direct linker or architecture
      checks are absent.
- [x] Generated documentation explains the conditional Host Contract claim and
      does not claim universal physical-device compatibility.

## Out of Scope

- Renaming external package/build concepts that use the word profile.
- Treating a single emulator/device run as a universal proof.
- Adding a new runtime backend without the Host Contract and feature evidence
  owned by the other child tasks.
