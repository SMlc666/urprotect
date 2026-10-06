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

- [ ] Valid GCC/Clang AArch64 CFI survives transformation and reparse.
- [ ] Control-flow flattening, register permutation, call, and veneer fixtures have unwind behavior checks.
- [ ] Recoverable malformed CFI is canonicalized; unrecoverable cases produce stable diagnostics and no partial artifact.
- [ ] Glibc, musl, and bionic evidence covers the promoted CFI rows separately.
- [ ] `.eh_frame`, `.eh_frame_hdr`, source/native hashes, and stage records agree after publication.


## Prerequisite and current-contract rule

Implementation is blocked until `10-06-architecture-boundary-refactor` Gates G0-G2 pass. CFI work must consume the established selected-function semantic plan, address map, physical layout, artifact, and publication owners. It must not add a second model, compatibility alias, migration frame path, direct writer, or fallback. Applicability and runtime evidence must be explicit before promotion.
