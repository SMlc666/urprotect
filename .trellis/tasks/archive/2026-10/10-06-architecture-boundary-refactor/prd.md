# Refactor architecture boundaries and purge migration paths

## Goal

Make ELF protection code easier to change safely by establishing explicit, enforceable ownership boundaries and one current production workflow. Delete historical migration paths, aliases, and parallel legacy implementations rather than retaining them as fallbacks.

## Background

A read-only audit of clean `main` at `18ba50a` found a simple acyclic project-reference graph but a monolithic `UrProtect.Core` with mixed domain, application, serialization, publication, process, and native-handoff responsibilities. The current protection commands use separate production routes; central files combine multiple reasons to change; production still accepts retired APIs/CLI spellings and payload frame versions; and `HostContextEntry` is accepted by public producer/CLI paths while generic rehydration rejects it late. Detailed file/symbol evidence is in `research/architecture-audit.md`.

The user requires a strict current-only architecture: no historical migration path, compatibility alias, fallback implementation, or parallel legacy writer may remain in production. The user selected deletion of all historical migration-format test data, including both positive and negative vectors. The user also selected a namespace-first module refactor, introducing separate assemblies only when they prevent a concrete forbidden dependency, and requires complete `HostContextEntry` materialization in this task.

## Hard decisions

- **D1 — No historical data or paths:** Delete retired Payload Frame v1/v2 and other retired migration-format encoders, decoders, runtime branches, aliases, positive/negative format fixtures, and current support-manifest rows. Current tests cover only the selected current contract and generic malformed inputs. Do not add format-specific rejection fixtures for retired formats. A single current ABI whose identifier happens to contain `V1` (such as the current Protected Image ABI or HostContext ABI) is not a migration path and remains current.
- **D2 — Namespace-first ownership:** Establish directories, namespaces, internal contracts, and dependency checks first. Add a small number of .NET assemblies only when an assembly boundary demonstrably prevents an invalid dependency; do not create a project per folder.
- **D3 — Complete HostContext path:** Implement current `HostContextEntry` rewrite/rehydration/materialization end to end through the shared workflow, including current v3 metadata binding, profile-specific validation, atomic publication, and native handoff evidence. Do not narrow or remove the existing current HostContext profile.
- **D4 — Serial prerequisite:** This task gates all TLS, CFI/unwind, indirect-control/jump-table, and final workflow/runtime-promotion implementation. The feature tasks consume these boundaries; they do not introduce parallel models or writers.

## Requirements

- **R1 — G0: Purge and freeze the current contract.** Inventory one canonical API, CLI spelling, current Payload Frame format/profile contract, artifact contract, and workflow owner for each boundary. Remove all deprecated APIs, aliases, duplicate forwarding names, retired frame versions, legacy native projections, alternate writers, migration fixtures, and current migration evidence rows. Update current docs and tests to describe only the current contract. Retain current single-version ABI contracts such as Protected Image ABI v1 and HostContext ABI v1.
- **R2 — G1: Establish module and responsibility boundaries.** Separate ownership for structural ELF parsing/indexing, selected-function AArch64 analysis, semantic rewrite planning, physical layout/materialization, artifact/protocol codecs, application workflows, infrastructure publication/native handoff, and CLI translation/rendering. Split/reorganize central god objects identified in the audit. Enforce allowed dependency direction with namespaces, internal contracts, and automated checks. Avoid duplicate models/codecs and unnecessary assembly proliferation.
- **R3 — G2: One production workflow.** Route `protect`, `protect-image`, and `rehydrate-image` through one Core owner for request normalization, selected-function planning, layout/materialization, output validation, and publication. `protect` is the one-command facade; staged commands expose the same contracts. Remove `FunctionProtectionService.Protect` as a distinct production writer and do not retain an alternate runtime fallback or historical test oracle.
- **R4 — Complete current HostContext materialization.** The shared workflow must support both current profiles. The HostContext path must consume the same Protected Image operation and semantic/layout contracts, emit a valid AArch64 `ET_DYN` entry image, validate profile/entry/ABI bindings before publication, and bind the current v3 HostContext metadata. It must use the profile-specific HostContext native handoff oracle, never reinterpret an outer image or call the outer `execveat` materializer.
- **R5 — Structural/code-analysis boundary.** Generic validation, packing, layout, and rehydration remain structural and decoder-independent. Instruction semantics begin at explicit selected-function roots and use bounded demand-driven dependency queries. Whole-image observation remains only as an explicitly named current observation API and is not a publication prerequisite; its legacy wrapper and Boolean/CLI compatibility surfaces are removed.
- **R6 — Current evidence and diagnostics.** Current manifests, reports, CLI help, specs, and tests describe only current production behavior. Retired payload formats and migration evidence are removed from current registries and tests. All failures remain bounded and deterministic; no stage publishes partial artifacts/evidence. Runtime claims remain independent, and unavailable runtimes are not promoted.
- **R7 — Downstream ordering.** Parent and child plans explicitly state that G0-G2 must pass before TLS, CFI/unwind, indirect-control/jump-table, or runtime-promotion production work begins. The task tree is not itself treated as a dependency mechanism.

## Acceptance Criteria

- [x] G0 provides a current-contract inventory with exactly one canonical production API/CLI/frame/artifact/workflow route per boundary.
- [x] No retired Payload Frame v1/v2 encoder/decoder/dispatch branch, legacy host projection, old CLI alias, deprecated public wrapper/API, direct writer, migration-format test data, or current migration feature row remains. Current Protected Image ABI v1 and HostContext ABI v1 remain as the sole current ABI contracts.
- [x] Current frame packaging and both native consumers use only the current v3 format and explicitly selected current profile contract.
- [x] G1 establishes the documented namespace-first ownership map, dependency rules are automatically checked, and central files no longer mix unrelated domain, application, codec, publication, process, or native-handoff concerns.
- [x] G2 makes `protect`, `protect-image`, and `rehydrate-image` use the same planning/layout/materialization/publication owners; no separate production writer or fallback remains.
- [x] Both `OuterExecveat` and `HostContextEntry` produce and validate their profile-specific native image through the shared workflow. HostContext materialization passes a native AArch64 handoff oracle and does not fail later in a generic outer-only materializer.
- [x] Structural validation remains decoder-independent by default, unrelated executable bytes do not affect selected-function analysis, and whole-image observation is explicit and non-gating.
- [x] The parent and remaining feature-child plans record G0-G2 as hard implementation prerequisites and prohibit migration paths, aliases, and parallel models/writers.
- [x] Managed, native, CLI, fixture, regression, evidence, and applicable runtime checks pass for the sole current contract; unavailable runtime environments remain unpromoted.
- [x] No failure path publishes a partial image, role, stage, report, or evidence set.

Completion evidence: archived G0/G1/G2 children `purge-historical-contract`, `responsibility-boundaries`, and `unified-protection-workflow`; 390 managed tests at architecture completion, 309 Python tests, native HostContext/launcher checks, structural-default validation, architecture boundary checks, and current-contract evidence gates passed. Downstream CFI and TLS tasks consumed these boundaries without adding migration paths or alternate writers.

## Child-task map and ordering

1. **`10-06-purge-historical-contract` (G0):** remove retired production paths and migration-format data; freeze canonical current contracts.
2. **`10-06-responsibility-boundaries` (G1):** depends on G0; perform namespace-first responsibility/dependency refactor and split central files/tests.
3. **`10-06-unified-protection-workflow` (G2):** depends on G0 and G1; unify all commands, complete both profiles including HostContext materialization, and remove the direct writer.

The G0→G1→G2 ordering is recorded in each child plan. TLS, CFI, indirect-control, and runtime-promotion children remain downstream of the architecture parent’s G0-G2 completion gate.

## Out of Scope

- Implementing new TLS relocation families, CFI/unwind transformations, or indirect-target/jump-table resolvers. This task establishes the owners and shared workflow those features must use.
- Promoting a runtime feature without that feature’s independent native evidence.
- Retaining any retired API, CLI spelling, frame format, test vector, migration oracle, or writer as a production fallback.

## Resolved User Decisions

- Retired migration-format test data: **delete all**, including negative fixtures; current tests use only the selected current contract and generic malformed cases.
- Module boundaries: **namespace-first**, with a limited number of new assemblies only when needed to enforce a forbidden dependency.
- HostContext: **implement the complete `HostContextEntry` materialization path in this task**.
