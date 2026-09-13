# Directory Structure

## Repository Layout

UrProtect is a single .NET repository. Production code, tests, fixtures, CI
helpers, native runtime code, and vendored sources have separate ownership:

```text
src/
├── UrProtect.Core/              # parser, ELF model, analysis, pack pipeline
│   ├── Aarch64/                 # decoder abstraction and analysis
│   ├── Binary/                  # bounded binary readers
│   ├── Diagnostics/             # stable diagnostic types and codes
│   ├── Elf/                     # ELF model, parser, load/address mapping
│   ├── Pack/                    # frame codec and wrapper pack service
│   └── Pipeline/                # validation and byte-preserving copy flow
└── UrProtect.Cli/               # command-line boundary and reports
tests/
└── UrProtect.Core.Tests/        # xUnit tests and synthetic ELF fixtures
benchmarks/
└── UrProtect.Benchmarks/        # native ARM64 parser/copy measurements
fixtures/
├── manifest.json                # fixture profiles and runtime contracts
└── samples/                     # C, C++, Rust, Go, Zig, NativeAOT, Android
scripts/                         # fixture, fuzz, release, and CI helpers
.github/scripts/                 # CI environment and Android probes
native/urprotect-launcher/       # static AArch64 Wrapper 0.2 runtime
third_party/                     # pinned AsmStone and miniz source/notices
```

There is currently no web frontend, HTTP endpoint, database, ORM, or service
host. Do not create those directories as part of a parser or packer change.

## Module Boundaries

- Keep untrusted byte access in `Binary/` and `Elf/`. `ElfParser.Parse` returns
  an `ElfParseResult`; it does not throw to report malformed input.
- Keep address arithmetic in `Elf/LoadMap.cs` and use the explicit
  `FileOffset`, `VirtualAddress`, and `RuntimeAddress` types from
  `Elf/AddressTypes.cs`.
- Keep AArch64 backend details behind `Aarch64/IAarch64Decoder`; production
  code uses the project adapter rather than AsmStone types directly.
- Keep orchestration in `Pipeline/NoOpPipeline.cs` and `Pack/ElfPackService.cs`.
  These services coordinate existing models instead of duplicating parser
  logic.
- Keep CLI formatting and exit-code mapping in `UrProtect.Cli`; Core must not
  write to stdout or stderr.
- Keep fixture generation and external tool invocation in `scripts/` and
  `fixtures/`, never in parser or model code.

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
- `src/UrProtect.Core/Elf/LoadMap.cs` is the shared address-conversion owner.
- `src/UrProtect.Core/Pipeline/NoOpPipeline.cs` is the orchestration example for
  snapshot validation, atomic copy, and byte identity verification.
- `src/UrProtect.Core/Pack/PayloadFrame.cs` owns the fixed frame ABI rather than
  spreading frame offsets across the CLI and native launcher.
- `src/UrProtect.Cli/ProductReport.cs` is the report projection boundary.
