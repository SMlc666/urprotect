# Namespace-first ownership map

This map is the G1 source-of-truth for managed ownership. The repository keeps
one Core assembly; directory and namespace boundaries are enforced by
`scripts/check-architecture-boundaries.py`. A new assembly is only justified
when a concrete dependency cannot be blocked by these rules and `internal`
contracts.

## Ownership and dependency direction

| Owner (directory / namespace) | Owns | Allowed dependencies | Forbidden dependencies | Contract types at the seam |
| --- | --- | --- | --- | --- |
| Structural ELF / `src/UrProtect.Core/StructuralElf` / `UrProtect.Core.StructuralElf` | Bounded ELF64 parsing, headers/program headers, load maps, typed address ranges, symbols, relocations, TLS facts, structural diagnostics | `UrProtect.Core.Binary`, `UrProtect.Core.Diagnostics`, pure BCL | AArch64 decoding/semantics, semantic planning, layout, artifact/application/infrastructure, CLI, filesystem/process/native handoff (`System.IO`, `System.Diagnostics`, P/Invoke) | `ElfFile`, `ElfParseResult`, `ElfValidationReport`, `LoadMap`, `FileOffset`, `VirtualAddress`, `RuntimeAddress` |
| AArch64 semantics / `src/UrProtect.Core/Aarch64Semantics` / `UrProtect.Core.Aarch64Semantics` | Decoder adapter, project-owned instruction projection, selected-function analysis, observation-only whole-image inspection, CFG/register facts | `StructuralElf`, `Binary`, `Diagnostics`, pure BCL and the AsmStone adapter | Semantic-plan publication, layout, artifact/application/infrastructure, CLI, filesystem/process/native handoff | `IAarch64Decoder`, `Aarch64DecodeResult`, `Aarch64FunctionAnalysis`, `Aarch64AnalysisReport` |
| Semantic planning / `src/UrProtect.Core/SemanticPlanning` / `UrProtect.Core.SemanticPlanning` | Semantic IR, selected-function rewrite plans, fixups, address maps, canonical snapshots/codecs, extension contracts and plan validation | `StructuralElf`, `Aarch64Semantics`, `Binary`, `Diagnostics`, pure BCL | Physical layout, artifact/application/infrastructure, CLI, filesystem/process/native handoff | `SemanticRewritePlan`, `AddressMap`, `SemanticPlanSnapshot`, `ISemanticPlanExtension`, `SemanticPlanValidationResult` |
| ELF layout / `src/UrProtect.Core/ElfLayout` / `UrProtect.Core.ElfLayout` | Placement strategy, program-header edits, physical byte edits, materialization, reparse/output validation, layout evidence | `StructuralElf`, `SemanticPlanning`, `Binary`, `Diagnostics`, pure BCL | Decoder/semantic rescans, artifact/application/infrastructure, CLI, filesystem/process/native handoff | `ElfLayoutPlan`, `ElfLayoutPlanner`, `ElfLayoutMaterializer`, `ElfLayoutValidationReport` |
| Artifact protocol / `src/UrProtect.Core/ArtifactProtocol` / `UrProtect.Core.ArtifactProtocol` | The sole current Payload Frame and profile/launcher contracts; Protected Image records/codecs remain owned by the Application protection seam | `StructuralElf`, `Binary`, `Diagnostics`, compression/crypto BCL | CLI parsing/rendering, application workflows, infrastructure publication, alternate codecs/writers | `PayloadFrameCodec`, `PayloadDispatchProfile`, `LauncherContract`, `HostContextContract` |
| Application / `src/UrProtect.Core/Application` / `UrProtect.Core.Application.*` | Validate, pack, protect, Protected Image production (including its current records/codec), rehydration use cases and typed request/results; workflow orchestration | Structural/semantic/planning/layout/artifact contracts, diagnostics, Infrastructure adapter ports | CLI grammar/rendering, direct filesystem/process/native APIs; no alternate workflow owner | `ValidationCommandWorkflow`, `FunctionProtectionService`, `SelectedFunctionProtectionPlanner`, `ProtectedImageCodec`, `ElfPackService`, `GenericRehydrationEngine`, `ProtectionPlan` |
| Infrastructure / `src/UrProtect.Core/Infrastructure` / `UrProtect.Core.Infrastructure` | Filesystem snapshots, atomic publication, identity/build/environment digest verification, resource/evidence adapters, Protected Image/rehydration publication, and native handoff | Application/domain contracts, diagnostics, BCL side-effect APIs | Semantic model ownership, parser/plan/layout reimplementation, CLI command grammar | `FileSystemAdapter`, `IdentityCopyPublisher`, `ElfPackFileAdapter`, `ProtectedImagePublisher`, `RehydrationPublisher`, `ProcessResourceSampler`, atomic publication result contracts |
| CLI parsing / `src/UrProtect.Cli/Parsing` / `UrProtect.Cli.Parsing` | Canonical argument grammar and translation into typed command options | CLI command contracts and Core application/artifact types | ELF parsing, semantic transforms, protocol reimplementation, native handoff | `CliOptions`, `PackOptions`, `ProtectOptions`, `ProtectedImageOptions`, `RehydrationCliOptions` |
| CLI commands / `src/UrProtect.Cli/Commands` / `UrProtect.Cli.Commands` | Command selection and exit-code dispatch; `CliApplication` is the one public facade | Parsing, Core application contracts, rendering, native adapter | Domain implementation and alternate writers | `CliApplication`, `ProductExitCode` |
| CLI rendering / `src/UrProtect.Cli/Rendering` / `UrProtect.Cli.Rendering` | Human/JSON report projections and stream rendering; report publication delegates to Infrastructure | Core result/report contracts, `Infrastructure.FileSystemAdapter`, BCL output APIs | Parsing grammar, ELF/semantic/protocol implementation, native handoff | `ProductReportFactory`, `ProductReport`, `ProtectedImageCommandReport`, `RehydrationCommandReport`, `CommandOutputWriter` |
| Native handoff infrastructure / `src/UrProtect.Core/Infrastructure/Native` / `UrProtect.Core.Infrastructure.Native` | Linux `memfd_create`/`fchmod`/`execveat` handoff for the already-decoded current frame | Artifact protocol, validation workflow, Infrastructure platform APIs | Structural/semantic/layout implementation, CLI command grammar, alternate frame parsing | `EmbeddedPayloadLauncher` |

The arrows are one-way: structural facts feed selected-function semantics;
semantics feed planning; plans feed physical layout; layout and current
artifact contracts feed application workflows; side effects are performed by
infrastructure and the CLI is the outer adapter. Observation is explicit and
never a publication prerequisite.

## Single-owner invariants

- There is one semantic model (`SemanticPlanning`), one current frame codec
  (`ArtifactProtocol.PayloadFrameCodec`, split into contract/encode/decode/wrapper
  files), one current Protected Image codec (`Application.Protection.ProtectedImageCodec`),
  one physical ELF writer (`ElfLayoutMaterializer`), and one structural validator
  (`StructuralElf.ElfValidator` composed by `ValidationWorkflow`).
- `ValidationWorkflow` owns the no-op validation workflow. It composes
  decoder-independent structural validation, explicitly requested observation,
  and `Infrastructure.IdentityCopyPublisher`; no historical `NoOpPipeline`
  surface or boolean analysis mode remains.
- `FunctionProtectionService`, `ElfPackService`, and
  `GenericRehydrationEngine` remain application owners. This G1 map does not
  introduce the unified G2 HostContext materializer or new TLS, CFI, or
  indirect-control semantics.
- Cross-layer tests are classified below by directory. A test may cross owners
  only when its purpose is a workflow/evidence contract.

## Test ownership

| Test directory | Ownership |
| --- | --- |
| `tests/UrProtect.Core.Tests/Structural` | Structural ELF parser, bounds, malformed input and load-map behavior |
| `tests/UrProtect.Core.Tests/Semantics` | AArch64 decoder/selected-function semantic and semantic-plan behavior |
| `tests/UrProtect.Core.Tests/Layout` | Physical layout planning/materialization and output validation |
| `tests/UrProtect.Core.Tests/ArtifactProtocol` | Payload frame, HostContext and managed/native contract layout |
| `tests/UrProtect.Core.Tests/Application` | Validation, pack, protection and rehydration use cases |
| `tests/UrProtect.Core.Tests/Cli` | CLI parsing, dispatch, reports, exit codes and JSON/human rendering |
| `tests/UrProtect.Core.Tests/Integration` | Concurrency, large-input, Protected Image publication, rehydration publication, workflow and evidence contracts spanning owners |
| `tests/ArchitectureFixtures` | Non-production checker inputs; deliberately forbidden references live here only |

The deterministic gate is:

```sh
python3 scripts/check-architecture-boundaries.py
python3 scripts/check-architecture-boundaries.py \
  --fixture tests/ArchitectureFixtures/ForbiddenStructuralDependency.cs \
  --self-test
```

The fixture command succeeds only when the production tree passes and the
fixture produces the expected forbidden-dependency diagnostic. The fixture is
not part of any production project and is intentionally not compiled.
