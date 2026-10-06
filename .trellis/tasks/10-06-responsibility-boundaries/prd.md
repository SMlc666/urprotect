# Refactor module and responsibility boundaries

## Goal

Make the managed code structure express one-way ownership: structural ELF, selected-function AArch64 semantics, rewrite planning, physical layout, current artifacts/protocols, application workflows, infrastructure, and CLI each have one cohesive responsibility.

## Requirements

- Depend on completed G0 current-contract purge; do not reintroduce aliases, retired formats, migration data, or alternate writers.
- Establish namespace/directory boundaries for Structural ELF, AArch64 semantics, Semantic Planning, Elf Layout, Artifact Protocol, Application, Infrastructure, and CLI.
- Split central god objects and bucket files without creating a duplicate semantic model or protocol grammar.
- Extract `CliApplication` dispatch/parsing/commands/rendering/atomic writing/native handoff responsibilities.
- Extract `NoOpPipeline` structural validation, observation, and identity-copy publication responsibilities.
- Extract `FunctionProtectionService` request validation/planning/code emission/layout adaptation/output validation/workflow responsibilities.
- Split `SemanticModel`, `SemanticPlanSnapshot`, `ElfLayout`, `PayloadFrame`, `ElfPackService`, and `GenericRehydrationEngine` around cohesive reasons to change.
- Establish one-way dependency checks: domain/semantic/layout code cannot depend on CLI, filesystem, process, or native-handoff details.
- Reclassify cross-layer tests into structural/core, CLI/application, integration/workflow, artifact/protocol, and native contract ownership.
- Introduce a new assembly only when namespaces/internal contracts cannot enforce a concrete forbidden dependency.

## Acceptance Criteria

- [ ] A checked-in ownership map names each namespace/directory owner, allowed dependencies, forbidden dependencies, and the contract types at each seam.
- [ ] Central files are split or redesigned so each extracted type has one cohesive reason to change; no duplicate semantic model, codec, writer, or validator is introduced.
- [ ] CLI files contain argument translation/rendering/dispatch only; application workflows own use-case orchestration; infrastructure owns file/process/native publication.
- [ ] Structural ELF and AArch64 semantic code have no dependency on CLI, filesystem, process metrics, or native handoff.
- [ ] Protection and rehydration share typed plan/materializer contracts without direct cross-layer implementation coupling.
- [ ] Automated namespace/dependency checks fail on a deliberately forbidden reference and pass for the current tree.
- [ ] Test projects/namespaces reflect ownership, with cross-layer tests explicitly integration-owned.
- [ ] Release build, managed tests, static checks, and `git diff --check` pass without adding compatibility paths.

## Out of Scope

- New TLS, CFI, or indirect-control semantics.
- Payload frame version changes; G0 owns the sole current frame contract.
- Completing the unified workflow or HostContext materializer; G2 consumes the boundaries created here.

## Ordering

This is Gate G1 of `10-06-architecture-boundary-refactor` and starts only after `10-06-purge-historical-contract` (G0) passes. G2 and all downstream feature tasks remain blocked until this task passes.
