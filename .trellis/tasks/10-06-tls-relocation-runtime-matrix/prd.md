# Support TLS relocation across runtimes

## Goal

Add complete first-class PT_TLS and all five AArch64 TLS relocation model semantics—local-exec, initial-exec, local-dynamic, general-dynamic, and TLSDESC—to the rewrite/materialization pipeline, then prove each model independently on glibc, musl, and bionic.

## Runtime promotion scope

Complete transformed TLS promotion remains in this task and is keyed by
`model × profile × runtime × lifecycle`: all five models (local-exec,
initial-exec, local-dynamic, general-dynamic, and TLSDESC), the current
`outer-execveat` and `host-context-entry` profiles, each applicable lifecycle,
and each of `glibc`, `musl`, and `bionic`. Musl and bionic transformed rows are
required scope here, not an optional follow-up or a new task. Every in-scope
row receives its own result, even when a required toolchain, loader, or runtime
is unavailable.

A transformed row is promoted only after that same row independently retains
managed rewrite/materialization, loader handoff, baseline/transformed behavior
comparison, PT_TLS template and zero-fill facts, per-thread values,
constructor/destructor/worker/release ordering, source/protected/native
artifact hashes, toolchain/runtime/loader identity, first-failure stage, and
rollback evidence. `environment-unavailable` is a feature-specific result and
never inherits glibc evidence or promotes another runtime.

The only currently promoted transformed TLS row is
`initial-exec x host-context-entry x glibc x current-thread`. It remains the
sole promoted row until independent musl and bionic rows and the other model,
profile, and lifecycle rows satisfy the same gate.

The evidence ladder remains explicit: StructuralElf observation records bounded
ELF/PT_TLS facts; managed semantic/layout acceptance proves typed recognition,
rewrite, and materialization; native HostContext adapter acceptance proves only
its loader/ABI slice; transformed runtime promotion requires the complete row
contract above. A lower layer never upgrades a higher layer. The six-cell
`fixtures/runtime-matrix.json` runtime covering set is environment/loader
coverage only, not a TLS promotion matrix.

Before any additional transformed row is promoted, this task must retain the
following prerequisite decisions and probes:

- Reconcile the high-severity managed/native Android packed-relocation tag
  mismatch (`ElfTypes`/`ProfileMaterializationPolicies` versus
  `host_image_validation.c`) and run one bounded rejection probe per canonical
  tag, with matching managed/native classification and no handle/publication.
- Compare managed and native PT_TLS predicates for count, range/size,
  alignment, flags, owning `PT_LOAD`, and template/zero-fill; resolve any
  intentional difference as an explicit layer boundary before promotion.
- Keep the sectionless decision explicit: StructuralElf and the managed parser
  may observe/accept sectionless images, glibc has a positive adapter oracle,
  but bionic requires section headers. The common three-runtime transformed
  promotion shape is therefore sectioned; the bionic sectionless boundary is
  loader-specific evidence, not transformed support.
- Keep current-thread and registered-worker lifecycle rows independent. Where
  worker lifetime is claimed, creation/join, TLS teardown, constructor/
  destructor, release, and image destruction order are retained; missing
  worker capability is feature-specific `environment-unavailable`.

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

- [x] All five TLS models have typed semantic contracts, sequence recognizers, relocation-family bindings, rewrite/materialization paths, canonical snapshot coverage, and positive plus nearest-negative fixtures.
- [x] PT_TLS template, zero-fill, module identity, thread-relative/module-relative expressions, GOT/TLSDESC bindings, and relocation addends remain equivalent after transformation.
- [x] Per-thread data and zero-fill remain equivalent after transformation for the promoted glibc control row; every other row records an independent non-promotion result until its own oracle exists.
- [x] Worker lifecycle and TLS teardown are verified where the feature row claims them; transformed worker rows remain explicit non-applicable boundaries, while the native glibc worker baseline remains separate.
- [x] The required matrix retains an independent result for every in-scope `model × profile × runtime × lifecycle` tuple across glibc, musl, and bionic. The 60-row producer/checker retains row-local hashes, PT_TLS facts, native preflight, first-failure, publication, and rollback fields; only the independently verified glibc initial-exec current-thread control row is promoted.
- [x] The managed/native Android packed-relocation mismatch is corrected and probed across all eight canonical tags, and PT_TLS predicate parity plus the sectionless common-contract decision are recorded before further promotion.
- [x] The six-cell runtime covering set remains separate environment evidence and is not used as a TLS promotion matrix; StructuralElf observation, managed semantic/layout acceptance, native HostContext adapter acceptance, and transformed runtime promotion remain distinct.
- [x] TLS relocation, semantic-model, lifecycle, malformed-input, and publication-rollback diagnostics are stable and publication remains transactional.


## Prerequisite and current-contract rule

Implementation is blocked until `10-06-architecture-boundary-refactor` Gates G0-G2 pass. TLS work must consume the established semantic/layout/artifact workflow and current HostContext materialization owner. It must not add a second model, compatibility alias, migration frame path, direct writer, or fallback. Runtime unavailability is never promoted as support.

## Architecture and test correction: AsmStone-backed instruction encoding

This task has an explicit encoding-boundary correction. AsmStone is the project's pinned AArch64 instruction decoder/encoder backend, not only a decode and register-permutation helper. The managed pipeline must use a project-owned AArch64 encoder adapter backed by AsmStone for every final AArch64 instruction word that it generates or re-encodes.

The boundary is:

- AsmStone owns instruction encodings, operands, register/width/scale legality, and generic PC-relative target encoding.
- StructuralElf owns ELF relocation records, symbols, PT_TLS, GOT/TLSDESC ranges, and bounded address facts.
- SemanticPlanning owns TLS models, relocation pairing, sequence recognition, addends, module/symbol ownership, and TLS address expressions.
- ElfLayout owns source/output placement, target calculation, materialization, reparse, and publication validation.
- GNU assembler/linker fixtures remain independent ABI/toolchain oracles; they do not replace the managed AsmStone-backed encoder.

ELF/TLS relocation-aware semantics and TLS sequence-level semantics remain UrProtect responsibilities. They must calculate and validate the target, addend, relocation family, ownership, and sequence contract, then pass structured operands or resolved PC-relative targets to the AsmStone-backed encoder. They must not reconstruct instruction words through local opcode constants and bitfield masks.

The existing manual AArch64 instruction writers in protection emission, semantic fixup encoding, TLS encoding, and layout branch encoding are migration debt. No new production manual opcode/bitfield writer is permitted. Existing raw-field recognition may remain only as a bounded transition implementation and must be paired with AsmStone decode/operand validation; new recognizers must consume project-owned records projected from AsmStone rather than duplicate its instruction catalog.

Test fixtures and golden tests follow the same boundary. Positive fixture instruction words are produced by an AsmStone-backed builder or by a retained GNU assembler oracle. Nearest-negative tests mutate structured operands or relocation metadata from a valid AsmStone-produced instruction; they do not introduce unexplained hand-written opcode literals. Golden bytes remain allowed as independent expected values only when they also pass AsmStone decode and, where applicable, GNU differential verification.

Add these criteria to the semantic gate:

- [x] Final generated/re-encoded AArch64 instruction words flow through the AsmStone-backed project encoder adapter; no new manual opcode/bitfield writer is introduced.
- [x] TLS semantic tests prove the separation between UrProtect relocation/sequence decisions and AsmStone instruction encoding.
- [x] Positive, nearest-negative, fixture, and golden tests use AsmStone-backed construction or an explicitly named GNU assembler oracle and retain round-trip evidence.
- [x] The task records every remaining manual production encoder as migration debt with an owner and a focused replacement test.
