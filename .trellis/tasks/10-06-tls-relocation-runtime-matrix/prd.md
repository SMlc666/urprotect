# Support TLS relocation across runtimes

## Goal

Add first-class PT_TLS and AArch64 TLS relocation semantics to the rewrite/materialization pipeline and prove them independently on glibc, musl, and bionic.

## Requirements

- Parse and model PT_TLS template/zero-fill/lifecycle metadata.
- Cover local-exec, initial-exec, local-dynamic, general-dynamic, and TLSDESC families as they enter the supported matrix.
- Rewrite TLS instruction sequences, GOT/TLSDESC references, and dynamic relocation records with correct module/thread-relative semantics.
- Preserve constructor/destructor, per-thread initialization, worker-thread, unload, and failure rollback behavior.
- Keep runtime claims separate and retain pinned toolchain, loader, image, and artifact identity evidence.

## Acceptance criteria

- [ ] Each promoted TLS model has positive and malformed/nearest-negative fixtures.
- [ ] Per-thread data and zero-fill remain equivalent after transformation.
- [ ] Worker lifecycle and TLS teardown are verified where the feature row claims them.
- [ ] Glibc, musl, and bionic each have native execution evidence or an explicit feature-specific environment result; no cross-runtime promotion occurs.
- [ ] TLS relocation and lifecycle diagnostics are stable and publication remains transactional.
