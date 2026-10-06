# Unify ELF protection rewriting infrastructure

## Goal

Replace the PT_NULL-dependent direct writer with one production ELF protection pipeline. The pipeline must unify `protect`, `protect-image`, and `rehydrate-image`, preserve the existing AArch64 protection contract, and make ELF layout rewriting and instruction-semantic relocation first-class infrastructure rather than separate fallback paths.

The user value is a protection artifact that remains executable and behaviorally equivalent after function transformation, while retaining reproducible provenance, bounded failure behavior, and evidence that covers loader, relocation, TLS, indirect control-flow, jump-table, and unwind semantics.

## Confirmed requirements

### R1. One production pipeline

- `protect` becomes a high-level one-command facade over the same producer/materializer workflow used by `protect-image` and `rehydrate-image`.
- The old direct `FunctionProtectionService.Protect` writer is removed from production behavior after migration; it may remain temporarily as a test oracle only.
- Producer, layout/materialization, validation, and publication logic each have one owner.
- Intermediate Protected Image, role, stage, native-image, and rehydration evidence remains available for CI or an explicit evidence-directory mode.

### R2. General ELF program-header and layout rewriting

- Successful layout planning must not require a pre-existing `PT_NULL` slot.
- The planner/materializer must be able to choose a legal placement by extending a compatible executable load segment or rebuilding/relocating the program-header table and adding a new executable `PT_LOAD`.
- The plan must represent file offsets, virtual addresses, segment permissions, alignment, program-header table placement/count, address mappings, veneers, and all byte edits before writing output.
- Existing runtime semantics such as `PT_LOAD`, `PT_INTERP`, `PT_DYNAMIC`, `PT_TLS`, `PT_GNU_RELRO`, `PT_GNU_STACK`, `PT_GNU_PROPERTY`, `PT_PHDR`, and `PT_NOTE` are preserved or explicitly modeled.
- Layout planning and writing remain atomic, bounded, re-parseable, and behaviorally validated.

### R3. AArch64 semantic rewrite and relocation

- The rewrite model must represent semantic operands and address-dependent references rather than copying raw instruction bytes as the primary abstraction.
- PC-relative instructions, direct calls, internal and external branch targets, literal references, and branch-range relaxation are included in the supported rewrite model.
- The system must maintain old-to-new address maps for functions, basic blocks, literals, veneers, jump tables, and relocation targets.
- AArch64 ELF relocation records are parsed, remapped, regenerated, or applied according to their declared semantics; unresolved relocation behavior is explicit and machine-readable.
- The design must cover `B`, `BL`, conditional branches, `ADR/ADRP`, literal loads, call/jump relocation families, and the relevant relocation pairs before promoting a feature row.

### R4. Indirect control flow and jump tables

- Indirect branches and calls are a positive support goal, not a permanent rejected boundary.
- The infrastructure must resolve statically bounded target sets from CFG, value ranges, relocations, function tables, and compiler-generated jump-table patterns where possible.
- Ambiguous jump tables must be modeled, bounded, relocated, and validated as tables rather than treated as arbitrary bytes.
- Runtime target translation or a stable-address veneer strategy must be designed for targets that remain opaque until execution.
- Every transformed indirect-control-flow target must either map to a validated destination or produce a deterministic first-failure record before publication.

### R5. TLS relocation and lifecycle semantics

- `PT_TLS` and AArch64 TLS relocation models are included in the support matrix, including local/initial-exec and dynamic/TLSDESC families as their semantics are implemented.
- TLS relocation rewriting must preserve module-relative, thread-pointer-relative, GOT/TLSDESC, initialization, zero-fill, constructor/destructor, and worker-thread behavior.
- Runtime evidence must cover the declared glibc, musl, and bionic boundaries separately; one runtime observation must not promote another runtime.

### R6. CFI and unwind semantics

- `.eh_frame` and `.eh_frame_hdr` are first-class rewrite inputs and outputs.
- Valid CIE/FDE coverage for original trampolines, transformed functions, dispatchers, and generated veneers must be preserved or regenerated.
- Malformed CFI is a supported input class: it receives bounded parsing, repair/canonicalization when its semantics are recoverable, and deterministic diagnostics or regenerated CFI when the original rules are not recoverable.
- Runtime validation must cover backtrace/unwind, exception propagation, cancellation/signal unwind where applicable, and transformed register/frame state.

### R7. Evidence and compatibility contract

- Each promoted semantic feature requires a controlled positive fixture, nearest negative/malformed fixture, stable diagnostic, artifact hashes, environment identity, and behavior comparison against an unprotected baseline.
- Evidence distinguishes parser/model support, materialization support, loader execution, and runtime-specific support.
- The unified workflow publishes no partial artifact or evidence set after a failed stage.
- Existing bounded-reader, program-header authority, no-general-purpose-ELF-library, stable-diagnostic, atomic-publication, and provenance contracts remain in force.

## Confirmed repository facts

- `src/UrProtect.Core/Protect/FunctionProtectionService.cs` currently finds a `PT_NULL` slot, appends an RX `PT_LOAD`, patches an entry `B imm26`, and rejects direct calls, indirect branches, and most non-terminal PC-relative instructions.
- `src/UrProtect.Core/Protect/ProtectedImageV1.cs` currently models only `EmitRegion` and `ApplyEntryBranch26` operations.
- `src/UrProtect.Core/Rehydrate/GenericRehydrationEngine.cs` currently materializes the `outer-execveat` layout and reports the HostContext materializer as a later boundary.
- The repository has no general `.eh_frame`/CFI rewrite engine or complete TLS semantic rewriter today.
- The current narrow glibc vertical slice is healthy: Release build succeeds with zero warnings/errors, 175 managed tests pass, protection E2E passes, and rehydration/native-handoff/behavioral-oracle evidence passes.

## Acceptance criteria

- [ ] `protect`, `protect-image`, and `rehydrate-image` use one production rewrite/materialization workflow; no direct writer remains as a separate production behavior.
- [ ] A valid fixture with every program-header slot occupied is transformed through the unified path without requiring `PT_NULL`, and the resulting ELF passes structural and native behavior checks.
- [ ] Layout plans and emitted ELF preserve required program-header semantics and record their chosen placement strategy and address mappings.
- [ ] The semantic rewrite model handles the agreed initial PC-relative, call, literal-pool, and relocation families with positive and nearest-negative fixtures.
- [ ] Bounded indirect targets and ambiguous jump tables are resolved/rewritten and behaviorally exercised; opaque targets follow the declared runtime mapping strategy.
- [ ] The agreed TLS relocation models execute with preserved per-thread values and lifecycle evidence on every runtime claimed by the feature row.
- [ ] Valid CFI is preserved or regenerated for transformed code, and malformed CFI follows the repair/canonicalization contract with retained evidence.
- [ ] Branch-range, relocation, TLS, indirect-target, jump-table, CFI, layout, overflow, and publication failures return stable diagnostics and publish no partial output.
- [ ] Existing narrow protection, rehydration, native handoff, regression, fuzz, and compatibility tests remain green after migration.
- [ ] Documentation, compatibility matrix, contract inventory, reports, fixtures, CI commands, and evidence checkers describe the unified workflow and each promoted semantic feature accurately.

## Scope decision

- The first complete semantic-rewriter milestone claims glibc, musl, and bionic separately, with native evidence for each runtime. The semantic/layout core remains runtime-neutral, but no runtime is promoted from another runtime's observation. Every promoted feature row carries its own positive, negative, loader, TLS/lifecycle, CFI, and behavioral evidence for all three declared runtimes.

## Constraints

- Production code remains .NET 8 and AArch64-focused.
- Program headers and load maps remain the runtime authority; section headers may be absent.
- Untrusted binary reads, counts, offsets, sizes, and address arithmetic remain bounded and checked.
- Unknown or unrecoverable semantics are never guessed; the contract must classify them deterministically.
- Native loader/runtime claims remain conditional on retained host-specific evidence.
