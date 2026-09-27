# Expand HostContext relocation and symbol support

## Goal

Expand the AArch64 relocation, PLT/GOT, dynamic binding, and symbol-version
forms supported by declared HostContext entry images, selected from observed
real-sample frequency and validated with native runtime oracles.

## Dependencies and constraints

- Depends on architecture/contract ownership, real-sample fingerprints, and
  the typed ELF model/parser feature boundary.
- HostContext acceptance requires defined callback, symbol-scope, memory,
  dependency, and release semantics; loader acceptance alone is insufficient.
- Current validated RELATIVE/RELR/GLOB_DAT slices remain unchanged unless a
  coordinated replacement is independently proven.
- Keep dependency-side import version requirements distinct from versioned
  definitions and versioned HostContext entry-symbol selection; do not infer
  either form from the other.
- Unsupported forms must be rejected before loader handoff and entry side
  effects.

## Requirements

- Define per-family symbol lookup scope, binding timing, weak/visibility and
  conflict resolution, target alignment/permissions, and stable failure status.
- Prioritize relocation and version forms from the corpus histogram.
- Add linker-produced positive fixtures and paired malformed/nearest-negative
  mutations; make entry behavior observe the resolved values.
- Validate native glibc, musl, and bionic only where the claim includes them.
- Update managed/native contracts, matrix, test inventory, diagnostics, and
  documentation coherently.

## Acceptance Criteria

- [x] Every newly accepted relocation/symbol family has a typed model rule,
      positive fixture, negative fixture, stable diagnostic, and runtime oracle.
- [x] PLT/GOT and symbol versions have explicit semantics rather than implicit
      system-loader pass-through.
- [x] Unsupported or malformed variants fail before handoff with a zero output
      handle and no entry call.
- [x] Managed/native ABI and frame layout drift gates pass.
- [x] Only evidence-backed profile/runtime rows are promoted.
