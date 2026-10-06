# Architecture audit findings

## Scope and method

Read-only audit of the clean repository at `18ba50a` on `main`. Four independent passes examined managed project references and namespaces, high-centrality source files and tests, production compatibility/version branches, and active parent/child task ordering. No code was changed and no tests were run during the audit.

## Executive findings

- The project reference graph is acyclic and broadly directional (`UrProtect.Cli -> UrProtect.Core -> AsmStone`). The primary issue is not a project-reference cycle; it is that the single Core assembly contains domain models, parsing, application orchestration, wire codecs, filesystem publication, process metrics, and native handoff concerns.
- Production still contains reachable historical compatibility paths and aliases despite current documentation describing some older behavior as migration-only.
- There are multiple public production paths for protection and rehydration; the direct `protect` writer differs from the `protect-image` producer and `rehydrate-image` materializer path.
- Several central files mix independent responsibilities, making feature work cross-cutting and encouraging duplicate validation/workflow logic.
- A profile contract mismatch is reachable: CLI/producers accept `HostContextEntry`, while `GenericRehydrationEngine.Materialize` rejects profiles other than `OuterExecveat`.
- The existing roadmap places workflow convergence too late and has incomplete designs/plans for remaining feature children. It permits migration-path language contrary to the user's hard rule.

## Confirmed production historical paths

1. `src/UrProtect.Core/Pipeline/NoOpPipeline.cs`
   - Public boolean `analyzeInstructions` parameters remain on `Validate` and `ValidateAndCopy`, alongside explicit mode APIs.
2. `src/UrProtect.Core/Aarch64/Aarch64Analyzer.cs`
   - Public obsolete `Aarch64Analyzer` wrapper forwards to `Aarch64ObservationAnalyzer` as a legacy name.
3. `src/UrProtect.Cli/CliApplication.cs`
   - `--no-analysis` is accepted as a legacy alias for structural mode.
   - `TryParseProtectedImageOptions` accepts several aliases for artifact, role, manifest, stage, producer build, rehydrator, source digest, and request digest options.
4. `src/UrProtect.Core/Pack/PayloadFrame.cs`
   - Public APIs encode and decode v1, v2, and current v3 payload frame layouts; wrapper readers and header detection accept the historical formats.
5. `native/urprotect-runtime/runtime.c` and `native/urprotect-runtime/include/urp/payload_frame.h`
   - Production parsing accepts v1/v2/v3; old versions can reach runtime dispatch.
   - The runtime has a legacy host projection associated with historical frames.
6. `src/UrProtect.Core/Protect/FunctionProtectionService.cs`
   - `Protect` remains the direct production writer called by CLI `protect`; it is separate from the staged Protected Image and rehydration routes.
7. Current fixture/evidence contracts include historical rows in `fixtures/manifest.json`, including `runtime.host-context-v1`, `runtime.host-context-v2`, and `runtime.wrapper-v1-baseline`. These are consumed by current validation/evidence gates, not merely unreferenced notes.

Additional aliases remain in production parsing for `protect-image`, including `--artifact-path`, `--artifact-output`, `--output`, `--role-path`, `--role-output`, `--manifest-path`, `--manifest-output`, `--stage-path`, `--stage-output`, `--producer-build`, `--rehydrator-consumer`, `--expected-source-sha256`, and `--expected-request-sha256`.

These are reachable behavior, not dead code. The invariant for this task is that production has one current contract and no alias/fallback/dual-version migration branch. The user resolved the planning decision by requiring deletion of all retired-format test data, including negative vectors; no historical decoder/encoder or format-specific fixture remains.

## Confirmed responsibility and structure problems

- `src/UrProtect.Cli/CliApplication.cs` (about 2,400 lines) combines dispatch, five command grammars, workflow orchestration, report/human rendering, exit mapping, atomic writes, path conflict checks, digest/build identity, and Linux `memfd_create`/`execveat` handoff.
- `src/UrProtect.Core/Protect/FunctionProtectionService.cs` (about 1,400 lines) combines selector validation, parsing, selected-function analysis, register planning, code emission, ELF layout, materialization, output validation, and evidence-facing plan construction. `Plan` and `Protect` duplicate substantial setup and analysis.
- `src/UrProtect.Core/Aarch64/SemanticModel.cs` combines value objects, instruction/fixup/plan records, resolution results, and `SemanticRewritePlanBuilder` validation.
- `src/UrProtect.Core/Aarch64/SemanticPlanSnapshot.cs` (about 3,500 lines) combines snapshot models, canonicalization, semantic/bounds validation, binary encode/decode, extension dispatch, and digest handling.
- `src/UrProtect.Core/Elf/ElfLayout.cs` (about 2,400 lines) combines planning contracts, strategy selection, PHDR relocation, branch placement, edit generation, materialization, reparse/output validation, and evidence creation, despite having separate planner/materializer types.
- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs` combines structural validation, optional observation, output identity checking, file reads, mode preservation, temporary file handling, and atomic copy publication.
- `src/UrProtect.Core/Pack/ElfPackService.cs` combines input policy, file access, structural validation, launcher contract checks, frame encoding, wrapper assembly/recovery, hashes, result construction, and atomic publication.
- `src/UrProtect.Core/Rehydrate/GenericRehydrationEngine.cs` combines artifact authentication, parsing, layout/materialization, native image validation, process resource measurement, and evidence record creation.
- `src/UrProtect.Core/Pack/PayloadFrame.cs` combines protocol records, version support, compression, encoding/decoding, trailer discovery, name validation, bounds, and digests.

The repository already has useful seams (`IAarch64Decoder`, `ElfLayoutPlanner`/`ElfLayoutMaterializer`, `ProtectedImagePublisher`, semantic projector/validator/encoder), so the refactor should strengthen existing concepts rather than introduce parallel models.

## Contract and roadmap inconsistencies

- `HostContextEntry` is accepted by `ProtectedImageProfile`, producer options, and CLI parsing, but `GenericRehydrationEngine.Materialize` rejects non-`OuterExecveat` profiles. The user selected complete implementation of the owning profile-specific materialization path in this architecture task; no early-removal alternative is part of the plan.
- The current parent implementation plan describes old direct writer/migration oracles as temporary and retains Protected Image v1 as migration evidence, conflicting with the hard no-production-migration-path rule.
- The workflow child currently requires migration evidence and retention of historical v1 migration behavior; revise it to current-contract-only production and no runtime fallback.
- TLS, CFI, and unified-workflow children lack `design.md` and `implement.md`, and their ordering, artifact ABI owner, profile responsibility, rollback, and runtime gates are incomplete.
- The archived indirect-control task has target-resolution requirements not met by the current `SemanticTargetResolution` lattice and jump-table extension model. This must be re-planned against the current model before indirect-control implementation resumes.
- Runtime environment unavailability must never promote a feature row; each claimed runtime needs independent native evidence.

## Suggested conceptual ownership boundaries

1. ELF structural model/index and bounded parser.
2. AArch64 decoder adapter and selected-function semantic analysis.
3. Semantic rewrite plan/model and transformations.
4. ELF layout planning, physical materialization, and output validation.
5. One current payload/artifact protocol contract and its managed/native implementations.
6. Application use cases/workflows for validate, pack, protect, staged artifact production, and rehydration.
7. Infrastructure adapters for file access/publication, report/evidence writing, process metrics, and native handoff.
8. Thin CLI parsing/rendering/dispatch.
9. Native runtime as a peer implementation of explicit wire/ABI contracts.

Separate assemblies should be introduced only where they enforce stable dependency direction; splitting files/namespaces without ownership contracts is not sufficient, while excessive project count is also a risk. This tradeoff remains to be decided in planning.

## Recommended gate ordering

```text
G0 Current contract and history policy
  -> G1 ownership/dependency boundaries and coherent module structure
  -> G2 one current production workflow; remove direct writer and resolve profile scope
  -> G3 TLS / CFI / indirect-control features against the stable semantic/layout/artifact seams
  -> G4 independent glibc / musl / bionic evidence for each promoted claim
  -> G5 reports, manifests, docs, and checker convergence
```

The task tree does not encode dependencies automatically. The parent and affected child plans must explicitly state that feature implementation is blocked until G0-G2 pass. The current architecture task is intended to become the P0 prerequisite under the ELF protection parent.
