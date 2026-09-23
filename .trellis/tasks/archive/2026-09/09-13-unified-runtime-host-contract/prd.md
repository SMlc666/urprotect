# Unified in-process runtime and Host Contract

## Goal

Define the single host-neutral runtime contract selected by the parent task:
an in-process AArch64 ET_DYN entry image with a versioned explicit
HostContext ABI and no executable temporary pathname.

## Requirements

- Specify the binary entry ABI, structure size/version rules, ownership,
  alignment, error returns, lifecycle, and reentrancy/threading guarantees.
- Keep payload decoding, integrity verification, ELF mapping, relocation, and
  entry dispatch in one runtime model; do not expose Linux/Android branches.
- Define the minimum Host Contract capabilities and their semantics, including
  memory mapping/protection, symbol/dependency resolution, TLS/thread state,
  synchronization, file descriptors or equivalent I/O, and diagnostics.
- Ensure recovered bytes never need to be written as an executable temporary
  pathname. Any host-backed storage must have explicit lifetime and
  immutability semantics.
- Define the observable-equivalence boundary for the explicit entry ABI rather
  than attempting to emulate a kernel _start, process stack, or main startup
  sequence.
- Preserve bounded parsing, digest verification, fail-closed errors, and
  deterministic payload framing from the current implementation.

## Dependencies and Ordering

- This child owns the source-of-truth Host Contract for the parent task.
- The AArch64 compatibility child must not claim a feature until this child
  defines how the runtime handles it.
- The matrix child consumes the ABI and Host Contract identifiers but may
  migrate fixture naming independently.

## Acceptance Criteria

- [x] A versioned HostContext ABI is documented with stable layout and
      ownership rules.
- [x] A runtime design describes the no-temporary-path handoff and all host
      capabilities required by the accepted image language.
- [x] The design states which ELF mapping, relocation, TLS, dependency, and
      lifecycle behaviors are proven, validated, rejected, or unknown.
- [x] Unit/property tests cover ABI validation, bounds, ownership, integrity,
      and fail-closed behavior.
- [x] An integration witness enters an image through HostContext without
      replacing the host process or executing a recovered temporary pathname.
- [x] Existing Wrapper 0.2 behavior is retained only as a documented baseline
      or explicitly rejected migration path.

## Out of Scope

- Emulating arbitrary standalone _start/main process startup.
- Stealth, anti-analysis, or vendor-specific behavior.
- Declaring all existing executable fixtures compatible before an entry adapter
  exists.
