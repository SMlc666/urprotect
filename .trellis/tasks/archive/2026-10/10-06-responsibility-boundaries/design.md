# Technical design: namespace-first responsibility boundaries

## Target ownership tree

```text
UrProtect.Core/
  StructuralElf/
  Aarch64Semantics/
  SemanticPlanning/
  ElfLayout/
  ArtifactProtocol/
  Application/
  Infrastructure/
UrProtect.Cli/
  Parsing/
  Commands/
  Rendering/
```

The initial change may preserve the existing projects, but namespace and directory names must express the ownership tree. Native handoff is owned by `Core.Infrastructure.Native`; the CLI only invokes that typed adapter. New assemblies are justified only by a concrete dependency that cannot be made `internal`/forbidden inside the existing project.

## Allowed dependency direction

```text
StructuralElf
    ↓
Aarch64Semantics
    ↓
SemanticPlanning
    ↓
ElfLayout
    ↓
ArtifactProtocol
    ↓
Application
    ↓
Infrastructure
    ↓
UrProtect.Cli adapter
```

Structural and semantic layers may expose typed contracts to upper layers but may not reference CLI, `System.IO` publication helpers, `System.Diagnostics.Process`, P/Invoke, or report renderers. Application code coordinates contracts; infrastructure implements side effects; CLI translates external arguments and renders results.

## Extraction seams

- `CliApplication` → dispatcher, canonical parsers, one handler per command, output/report writer, atomic file writer, embedded payload launcher.
- `ValidationWorkflow` → structural validator, explicit observation service, identity-copy publisher.
- `FunctionProtectionService` → request validator, shared selected-function planner, code emitter, layout adapter, output validator, thin workflow coordinator.
- `SemanticModel` → semantic targets/instructions, fixups/plans, plan builder/validator.
- `SemanticPlanSnapshot` → immutable model, canonicalizer, encoder, decoder, extension codecs.
- `ElfLayout` → contracts, planner, materializer, validation/evidence.
- `PayloadFrame` → current contract records, current encoder/decoder, compression, wrapper/trailer handling.
- `ElfPackService` → pack policy, current wrapper builder, artifact publisher, orchestration.
- `GenericRehydrationEngine` → authentication, profile materializer dispatch, native-image validator, resource sampler, evidence factory.

Existing `IAarch64Decoder`, `ElfLayoutPlanner`/`ElfLayoutMaterializer`, semantic projectors, and publishers remain the owned seams. No second model is introduced.

## Test ownership

Move or rename tests so structural/parser tests, semantic tests, layout tests, artifact/protocol tests, CLI tests, workflow integration tests, and native contract tests are identifiable. A cross-layer test may reference multiple owners only when its purpose is a workflow/evidence contract.

## Dependency enforcement

Add a deterministic source/namespace check or build-time rule that rejects forbidden references from StructuralElf/Aarch64Semantics/SemanticPlanning/ElfLayout to CLI/application infrastructure. Add a positive fixture that deliberately violates the rule in the checker input, not in production source.

## G1 blocker-fix boundary

The current implementation keeps the public `CliApplication` facade but routes
filesystem snapshots, atomic byte/report publication, build/environment evidence,
Protected Image stage publication, pack file handling, rehydration publication,
resource sampling, and native handoff through `Core.Infrastructure` adapters and
Application command workflows. `FunctionProtectionService` now delegates request
validation and selected-function analysis to named seams; code emission, layout
adaptation, and output validation are separate partial ownership files. The
semantic model, semantic-plan snapshot, ELF layout, and v3 payload-frame buckets
are split into contract, planner/materializer, canonicalization, validation,
encode/decode, and wrapper files without changing wire/layout contracts.

Cross-layer tests now use directory-owned namespaces. CLI/report and structural
parser tests that exercise another layer are separate CLI-owned tests rather than
forbidden imports from structural/application ownership.

## Rollback

Split changes by ownership seam and keep each commit buildable. If a split causes a dependency cycle, revert that split and refine the contract; do not add a compatibility wrapper or reverse dependency to preserve old file locations.
