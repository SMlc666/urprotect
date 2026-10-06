# Technical design: architecture boundary refactor and current-contract purge

## Design goal

Refactor the managed/native protection stack around explicit ownership boundaries and one current production contract. The result must be strict rather than transitional: retired APIs, CLI aliases, payload versions, legacy branches, and direct-writer fallbacks are deleted from production and from repository test/evidence data. The refactor does not implement new TLS, CFI, or indirect-control semantics; it creates the seams and gates those features must consume.

## Hard invariants

1. **One current contract:** each production boundary has one canonical API, command grammar, frame/artifact format, profile set, and workflow owner.
2. **No historical path:** no production alias, forwarding wrapper, Boolean compatibility switch, retired frame encoder/decoder, legacy runtime projection, direct-writer fallback, or migration feature row remains.
3. **No historical test data:** v1/v2 and other retired migration-format positive or negative fixtures are deleted. Current tests use only the selected current contract and generic malformed-input cases.
4. **Fail early:** a public command/profile is either supported end to end or rejected before artifact creation; no accepted-then-rejected path remains.
5. **One workflow:** `protect`, `protect-image`, and `rehydrate-image` share semantic planning, layout/materialization, validation, and publication ownership. Staged commands expose stages, not alternate implementations.
6. **Selected-function analysis:** structural ELF operations never construct a whole-image decoder. Semantic decoding starts from explicit function selectors and uses bounded demand-driven dependency queries.
7. **Bounded publication:** every stage plans immutably, validates before writing, publishes atomically, and removes partial output/evidence on failure.

## Ownership boundaries

The initial implementation is namespace-first inside the existing managed projects. A new assembly is introduced only when it enforces a dependency rule that namespaces and internal contracts cannot enforce.

### 1. Structural ELF context

Owns bounded byte-to-model conversion and structural facts:

- ELF headers, program headers, load maps, typed file/virtual/runtime ranges;
- dynamic metadata, symbols, relocations, TLS and raw-range facts;
- structural diagnostics and parser limits.

It does not decode instructions, choose protection passes, publish files, or know CLI options.

### 2. AArch64 semantic context

Owns project-owned decoder adaptation and selected-function analysis:

- decoder adapter and project-owned instruction projection;
- selected-function CFG/data-flow and register-resource facts;
- semantic operands, references, target states, fixups, and address maps.

It does not choose output paths, write ELF bytes, or own native runtime evidence.

### 3. Semantic rewrite planning

Owns transformation intent independently of physical placement:

```text
source structural index + selected-function request + pass set
    -> SemanticRewritePlan / ProtectionPlan
```

The plan carries source ownership, transformed blocks, target bindings, relocation/TLS/CFI/indirect extensions, and diagnostics. It contains no filesystem operation and does not embed final file offsets prematurely.

### 4. Physical layout and materialization

Owns `ElfLayoutPlan`, placement strategies, address mapping, veneers, program-header edits, bounded byte edits, reparse, and output validation. It consumes semantic plans and never rescans the source image to rediscover code meaning.

### 5. Current artifact/protocol context

Owns one current Payload Frame, Protected Image operation contract, profile contract, HostContext ABI contract, and managed/native offset checks. The managed codec, native launcher, and native runtime implement the same current contract; launcher policy and runtime policy remain separate from frame parsing.

### 6. Application workflow context

Owns the current use cases:

```text
Validate
Pack
Protect
ProduceProtectedImage
Rehydrate
```

A shared protection workflow coordinates selector normalization, semantic planning, layout/materialization, validation, publication, and evidence. Commands may choose output detail, but not alternate implementation paths.

### 7. Infrastructure context

Owns filesystem reads/writes, atomic publication, identity/digest verification, resource measurement, JSON/report/evidence serialization, and native handoff adapters. Domain models do not call `File`, `Process`, `memfd_create`, or `execveat` directly.

### 8. CLI context

Owns canonical command grammar, argument-to-request translation, output rendering, and process exit mapping. It has no ELF parsing, semantic transformation, frame encoding, or native handoff implementation.

### 9. Native peer context

`native/urprotect-launcher` and `native/urprotect-runtime` remain peer implementations of the current wire/ABI contracts. They do not expose retired version branches or migration adapters.

## Target dependency direction

```text
Structural ELF models/index
        ↓
AArch64 decoder adapter + selected-function semantics
        ↓
Semantic rewrite/protection plan
        ↓
Physical layout plan/materializer
        ↓
Current artifact/protocol contract
        ↓
Application workflow
        ↓
Infrastructure publication/native handoff
        ↓
CLI adapter and report rendering
```

Allowed inward dependencies are one-way. CLI and infrastructure may depend on application contracts; domain/semantic/layout code must not depend on CLI, filesystem, process, or native handoff details.

## Current workflow data flow

```text
canonical CLI request
  -> application use-case request
  -> structural ELF index
  -> selected-function semantic plan
  -> semantic rewrite plan
  -> physical ElfLayoutPlan
  -> NativeImage/ProtectedImage materialization
  -> reparse + structural/semantic validation
  -> atomic publication and evidence
  -> current report
```

`protect` invokes this workflow and returns the final output. `protect-image` publishes the same intermediate contract for evidence. `rehydrate-image` consumes the same current artifact and calls the same materializer; it is not a second writer.

## Responsibility extraction map

| Current hotspot | First extraction boundary |
|---|---|
| `CliApplication` | command dispatcher, per-command parsers/handlers, output writer, atomic writer, embedded launcher |
| `NoOpPipeline` | structural validator, explicit observation service, identity-copy publisher |
| `FunctionProtectionService` | request validator, shared protection planner, code emitter, layout adapter, output validator, thin workflow |
| `SemanticModel` | semantic value models, fixup/plan models, plan builder/validator |
| `SemanticPlanSnapshot` | snapshot models, canonicalizer, encoder, decoder, extension codecs |
| `ElfLayout` | layout contracts, planner, materializer, output/evidence validation |
| `ElfPackService` | packability policy, wrapper/frame builder, artifact publisher, thin orchestration |
| `GenericRehydrationEngine` | artifact authenticator, materializer, native-image validator, resource sampler, evidence factory |
| `PayloadFrame` | current contracts, encoder, decoder, compression, wrapper/trailer handling |

Existing project-owned models and adapters are reused. No second semantic model, raw-byte writer, or duplicate protocol grammar is introduced.

## Strict purge shape

The purge is a breaking current-contract change, not a migration:

- remove `Aarch64Analyzer` compatibility wrapper;
- remove Boolean analysis overloads and `--no-analysis`;
- remove all protected-image option aliases and retain one spelling per field;
- remove managed/native v1/v2 frame encode/decode/dispatch paths and legacy host projection;
- remove direct `FunctionProtectionService.Protect` production routing after the shared workflow owns the command;
- remove historical v1/v2/migration rows and test data from manifests, tests, and evidence gates;
- replace current documentation that says older paths remain available with current rejection/absence rules;
- update all current callers in one atomic change set so no compatibility adapter is needed.

Current names containing a version (for example a sole current ABI named `V1`) are not historical paths by themselves. The decision is based on whether a second current behavior is executable or selectable.

## HostContext profile decision

This task includes the complete `HostContextEntry` materialization path. After responsibility extraction, `GenericRehydrationEngine` must dispatch to a profile-specific materializer that consumes the same current Protected Image operation contract, emits a valid AArch64 `ET_DYN` HostContext entry image, validates the declared entry/profile/ABI bindings before publication, and records the profile-specific handoff/evidence contract. The HostContext path must not call the outer `execveat` materializer or silently reinterpret an outer image. The native HostContext launcher/handoff remains the execution oracle; the managed rehydrator remains responsible for deterministic image materialization and publication.

Malformed, mismatched, or unsupported HostContext profile metadata must be rejected before output publication. A profile is never accepted into an artifact and rejected only by a generic materializer.

## Assembly trade-off

Start with namespaces/directories, `internal` contracts, and dependency-graph checks inside the existing projects. Split assemblies only after an identified dependency violation cannot be prevented otherwise. This preserves incremental compilation while preventing a cosmetic project explosion.

## Rollback and operations

Each refactor slice is independently buildable and committed. A failed slice is reverted at its own commit boundary; no compatibility alias or alternate runtime path is added to recover it. Product output is written only through existing atomic publication contracts. Historical data is removed in the same contract-purge slice and is not regenerated by tests.
