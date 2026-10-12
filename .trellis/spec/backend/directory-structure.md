# Directory Structure

## Repository Layout

UrProtect is a single .NET repository. Production code, tests, fixtures, CI
helpers, native runtime code, and vendored sources have separate ownership:

```text
src/
├── UrProtect.Core/
│   ├── StructuralElf/            # bounded ELF model/parser and address domains
│   ├── Aarch64Semantics/        # decoder adapter and selected-function analysis
│   ├── SemanticPlanning/        # semantic IR, rewrite plans, snapshots/codecs
│   ├── ElfLayout/               # physical placement/materialization/validation
│   ├── ArtifactProtocol/        # sole current frame and profile contracts
│   ├── Application/             # validate, pack, protect, rehydrate workflows
│   ├── Infrastructure/          # filesystem, evidence, and native handoff adapters
│   ├── Binary/                  # bounded binary readers
│   └── Diagnostics/             # stable diagnostic types and codes
└── UrProtect.Cli/
    ├── Parsing/                 # canonical command grammar and typed options
    ├── Commands/                # dispatch and exit-code mapping
    └── Rendering/               # report projections and output writer
tests/
├── UrProtect.Core.Tests/        # ownership-classified xUnit tests
└── ArchitectureFixtures/        # non-production dependency-checker fixtures
benchmarks/
└── UrProtect.Benchmarks/        # native ARM64 parser/copy measurements
fixtures/
├── manifest.json                # fixture matrix cases and runtime contracts
└── samples/                     # C, C++, Rust, Go, Zig, NativeAOT, Android
scripts/                         # fixture, fuzz, release, CI, and architecture checks
.github/scripts/                 # CI environment and Android probes
native/
├── urprotect-launcher/          # static AArch64 current launcher
└── urprotect-runtime/           # HostContext ABI, preflight, and native adapter
third_party/                     # pinned AsmStone and miniz source/notices
```

There is currently no web frontend, HTTP endpoint, database, ORM, or service
host. Do not create those directories as part of a parser or packer change.

## Module Boundaries

- Keep untrusted byte access in `Binary/` and `StructuralElf/`. `ElfParser.Parse` returns
  an `ElfParseResult`; it does not throw to report malformed input.
- Keep ELF class observation separate from launch policy: the parser/model may
  represent `ET_DYN` and `ET_EXEC`, while `Application/Pack/ElfPackService.cs` decides
  class support under the explicitly selected profile and the native launcher
  validates the recovered image before `execveat`. A successful parse never
  implies outer launchability or HostContext support.
- Keep address arithmetic in `StructuralElf/LoadMap.cs` and use the explicit
  `FileOffset`, `VirtualAddress`, and `RuntimeAddress` types from
  `StructuralElf/AddressTypes.cs`.
- Keep AArch64 backend details behind `Aarch64Semantics/IAarch64Decoder`; production
  code uses the project adapter rather than AsmStone types directly.
- Keep orchestration in `Application/Validation/ValidationWorkflow.cs` and `Application/Pack/ElfPackService.cs`.
  These services coordinate existing models instead of duplicating parser
  logic.
- Keep CLI formatting and exit-code mapping in `UrProtect.Cli`; Core must not
  write to stdout or stderr.
- Keep fixture generation and external tool invocation in `scripts/` and
  `fixtures/`, never in parser or model code.
- Keep bounded HostContext ELF preflight in
  `native/urprotect-runtime/host_image_validation.c`; it owns checked image
  metadata, dynamic-table, relocation, and program-header validation before
  loader handoff.
- Keep memfd, sealing, loader, symbol lookup, and image-release ownership in
  `native/urprotect-runtime/host_adapter.c`; it calls the preflight boundary
  before creating an image handle and must not duplicate its byte validation.

## Naming

- Use file-scoped namespaces, PascalCase types and public members, and camelCase
  private fields and locals. The repository enforces four-space indentation and
  LF endings through `.editorconfig`.
- Name address values by domain (`FileOffset`, `VirtualAddress`,
  `RuntimeAddress`) rather than using an unqualified `long` or `ulong`.
- Keep machine-readable failure categories in `DiagnosticCode`. Do not encode a
  new stable error category only in human-readable text.
- Use immutable records for parse, validation, frame, and report results where a
  result crosses a package boundary.

## Examples

- `src/UrProtect.Core/Binary/BoundedReader.cs` is the shared checked-read owner.
- `src/UrProtect.Core/StructuralElf/LoadMap.cs` is the shared address-conversion owner.
- `src/UrProtect.Core/Application/Validation/ValidationWorkflow.cs` is the orchestration example for
  snapshot validation, atomic copy, and byte identity verification.
- `src/UrProtect.Core/ArtifactProtocol/PayloadFrameCodecContracts.cs`, together with the
  adjacent encode/decode/wrapper files, owns the fixed frame ABI rather than spreading
  frame offsets across the CLI and native launcher.
- `src/UrProtect.Cli/Rendering/ProductReport.cs` is the report projection boundary.

## Namespace and dependency enforcement

`python3 scripts/check-architecture-boundaries.py` is the deterministic ownership
check for every production C# source file under `src/UrProtect.Core` and
`src/UrProtect.Cli`. It verifies that each owned directory declares its matching
namespace, rejects forbidden dependency directions and side-effect APIs, and
ignores comments and string/character literals so diagnostic text cannot create
a false dependency. Qualified, global, and aliased project references are
checked as source references rather than as raw text fragments. `ElfLayout`
may depend one-way on `Aarch64Semantics` for the project-owned instruction
encoder; `Aarch64Semantics` must not depend on layout, and AsmStone types must
remain private to the adapter.

The non-production fixture gate is:

```sh
python3 scripts/check-architecture-boundaries.py \
  --fixture tests/ArchitectureFixtures/ForbiddenStructuralDependency.cs \
  --self-test
```

The production tree must pass, while the fixture must produce a forbidden
reference diagnostic and be excluded from compilation. A boundary change is
incomplete until both outcomes are asserted by
`tests/test_architecture_boundaries.py`.
