# Support TLS relocation across runtimes

## Goal

Add complete first-class PT_TLS and all five AArch64 TLS relocation model semantics—local-exec, initial-exec, local-dynamic, general-dynamic, and TLSDESC—to the rewrite/materialization pipeline, then prove each model independently on glibc, musl, and bionic.

## Requirements

- Parse and model PT_TLS template/zero-fill/lifecycle metadata.
- Fully model and rewrite all five TLS families—local-exec, initial-exec, local-dynamic, general-dynamic, and TLSDESC—before runtime-matrix promotion begins; each family must have typed access semantics, instruction-sequence recognition, relocation/GOT/TLSDESC bindings, layout/materialization rules, and stable malformed/unsupported diagnostics.
- Rewrite TLS instruction sequences, GOT/TLSDESC references, and dynamic relocation records with correct module/thread-relative semantics.
- Preserve constructor/destructor, per-thread initialization, worker-thread, unload, and failure rollback behavior.
- Keep runtime claims separate and retain pinned toolchain, loader, image, and artifact identity evidence.

## Semantic-first scope decision

The complete semantic/rewrite contract is a prerequisite to runtime promotion. The
implementation must not treat the existing native initial-exec adapter rows as a
complete managed TLS implementation. It must provide one typed TLS model shared
by StructuralElf, Aarch64Semantics, SemanticPlanning, ElfLayout, and the current
Protected Image v1 SemanticPlanSnapshot operation contract.

The semantic gate covers all five models: local-exec, initial-exec,
local-dynamic, general-dynamic, and TLSDESC. For every model it must define:

- the access-model and relocation-family types;
- PT_TLS/template/zero-fill/module facts;
- AArch64 instruction-sequence recognition and register/resource ownership;
- symbol/module/addend and GOT/TLSDESC bindings;
- thread-relative or module-relative address expressions;
- transformed instruction and relocation fixups;
- output layout/materialization preservation rules;
- canonical snapshot encode/decode and validation;
- nearest malformed, inconsistent, unsupported, and publication-rollback cases.

The runtime matrix consumes only plans that pass this semantic gate. It remains a
separate evidence layer with one row per model/profile/runtime/lifecycle tuple.
The Payload Frame v3 contract, Protected Image ABI identifier/version, and existing
operation meanings remain unchanged. Extend the sole Protected Image v1 operation
grammar with one bounded SemanticPlanSnapshot operation carrying canonical bytes
and its digest, encoded and decoded only by SemanticPlanSnapshotCodec. Do not add a
migration reader or parallel TLS codec. Transformed TLS plans require this operation;
incomplete streams are rejected before publication.

## Acceptance criteria

- [ ] All five TLS models have typed semantic contracts, sequence recognizers, relocation-family bindings, rewrite/materialization paths, canonical snapshot coverage, and positive plus nearest-negative fixtures.
- [ ] PT_TLS template, zero-fill, module identity, thread-relative/module-relative expressions, GOT/TLSDESC bindings, and relocation addends remain equivalent after transformation.
- [ ] Per-thread data and zero-fill remain equivalent after transformation for every model/profile/runtime row that is promoted.
- [ ] Worker lifecycle and TLS teardown are verified where the feature row claims them.
- [ ] Glibc, musl, and bionic each have native execution evidence or an explicit feature-specific environment result for every promoted model/profile row; no cross-runtime promotion occurs.
- [ ] TLS relocation, semantic-model, lifecycle, malformed-input, and publication-rollback diagnostics are stable and publication remains transactional.


## Prerequisite and current-contract rule

Implementation is blocked until `10-06-architecture-boundary-refactor` Gates G0-G2 pass. TLS work must consume the established semantic/layout/artifact workflow and current HostContext materialization owner. It must not add a second model, compatibility alias, migration frame path, direct writer, or fallback. Runtime unavailability is never promoted as support.
