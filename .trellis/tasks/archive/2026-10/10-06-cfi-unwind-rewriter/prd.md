# Rewrite CFI and unwind metadata

## Goal

Make `.eh_frame` and `.eh_frame_hdr` first-class inputs and outputs so transformed functions, trampolines, dispatchers, veneers, and repaired malformed CFI retain correct unwind behavior.

## Requirements

- Parse bounded CIE/FDE records, augmentation data, PC ranges, and CFI instructions used by the promoted AArch64 toolchain/runtime fixtures.
- Map original ranges to transformed ranges and emit CFI for trampolines, relocated functions, dispatchers, and veneers.
- Repair/canonicalize recoverable malformed CFI; classify unrecoverable metadata deterministically and retain evidence.
- Update unwind indexes and preserve section/program-header relationships.
- Verify exception propagation, backtrace/unwind, cancellation/signal unwind where applicable, and transformed register/frame state.

## Acceptance criteria

- [x] Valid GCC/Clang-shaped AArch64 CFI parses, maps through the shared AddressMap, rewrites within bounded record widths, and reparses.
- [x] Selected-function/layout integration preserves CFI edits through the shared ElfLayoutPlanner and ElfLayoutMaterializer; unsupported control-flow/opaque CFI remains fail-closed.
- [x] Recoverable bounded records retain raw bytes; malformed lengths, invalid CIE/header references, unsupported encodings/effects, and mapping conflicts produce stable diagnostics with no partial artifact.
- [x] Runtime evidence boundary is explicit: managed/parser/materializer support is verified; glibc, musl, and bionic behavioral CFI rows remain separate and unpromoted until dedicated native unwind fixtures are available.
- [x] `.eh_frame` and `.eh_frame_hdr` edits are typed, hashable through the existing layout evidence, reparsed after materialization, and rejected on overlap or output mismatch.

Runtime evidence status: `environment-unavailable`/not-promoted for dedicated transformed CFI behavior rows; no runtime claim is inferred from managed evidence.

Verification: 403 managed tests, 309 Python tests, native runtime self-tests, 13 PR fixtures, 22 regression cases, architecture and AArch64 encoding boundary checks passed.


## Prerequisite and current-contract rule

Implementation is blocked until `10-06-architecture-boundary-refactor` Gates G0-G2 pass. CFI work must consume the established selected-function semantic plan, address map, physical layout, artifact, and publication owners. It must not add a second model, compatibility alias, migration frame path, direct writer, or fallback. Applicability and runtime evidence must be explicit before promotion.
