# Quality Guidelines

## Build and Language Contract

- Production code targets the pinned .NET SDK `8.0.424` from `global.json`.
- Restore uses committed `packages.lock.json` files and CI uses
  `dotnet restore --locked-mode`.
- Nullable reference types and the SDK analyzers remain enabled; warnings are
  treated as errors in the native launcher build and should not be suppressed
  in C# production code.
- `.editorconfig` requires UTF-8, LF endings, a final newline, four-space
  indentation, file-scoped namespaces, and System directives sorted first.
- Keep public binary/report contracts as explicit records, enums, and typed
  address values. Avoid exposing third-party AsmStone model types.

## Required Design Patterns

- Use `BoundedReader` and checked arithmetic for all untrusted binary reads.
- Use program headers as the authoritative ELF runtime layout; section headers
  may be absent or stripped.
- Use `FileOffset`, `VirtualAddress`, and `RuntimeAddress` instead of mixing
  address domains as raw integers.
- Keep `DiagnosticCode` stable and machine-readable. Preserve unknown ELF data
  and report unsupported semantics rather than guessing.
- Keep the no-op pipeline byte-preserving. Any output must be compared to the
  source before publication.
- Pin and retain licenses for AsmStone and miniz. Native source, compiler
  inputs, specs hashes, and output hashes belong in provenance.

## Forbidden Patterns

- Do not use a general-purpose ELF library in the production parser.
- Do not cast ELF counts, offsets, or sizes directly to array lengths or `int`
  without a checked bounded conversion.
- Do not duplicate `LoadMap` address arithmetic or frame offsets in consumers.
- Do not rewrite unknown instructions, relocations, dynamic tags, or sections
  as a best effort.
- Do not add a dynamic dependency to the static launcher, require a source
  payload path from the environment, or use a shell for payload execution.
- Do not hide missing toolchains, wrong host architecture, emulator use, or
  profile failures as successful native coverage.

## Testing Requirements

Every parser, pipeline, CLI, frame, launcher, or release change needs focused
tests plus the relevant malformed-input path:

- `ElfParserTests.cs` covers valid models and targeted parser behavior.
- `ElfMalformedCorpusTests.cs` and `ElfParserFuzzTests.cs` cover truncation,
  mutation, overflow, and no-throw safety.
- `BinaryPropertyTests.cs` covers bounded reads, range overflow, and load-map
  round trips.
- `GoldenReportTests.cs` protects JSON diagnostic/report projections.
- `NoOpPipelineTests.cs` and `CliApplicationTests.cs` cover atomic output,
  stable exit codes, JSON stream behavior, and byte identity.
- `PayloadFrameTests.cs` and `ElfPackServiceTests.cs` cover deterministic
  frames, limits, digests, launcher profiles, and publication failures.
- Native `self_test.c` and `test_launcher.sh` cover SHA-256, raw deflate,
  malformed frames, handoff behavior, and signal/status preservation.

Use external `readelf`/`llvm-readelf` checks for produced ELF structure when a
change affects a launcher, fixture, or release. Compare runtime behavior using
status, stdout, stderr, signals, cwd, environment, and declared files; exclude
ASLR addresses and timing.

## CI and Release Contract

- Required native Linux jobs run on `aarch64` and retain an environment report.
- `fixtures/manifest.json` is the source of truth for fixture IDs, tiers,
  toolchains, runtimes, and execution profiles.
- Required toolchain or runtime failures fail the job. Optional Android native
  bridge capability is reported explicitly and is not relabeled as native
  ARM64 hardware.
- NuGet caching belongs to `actions/setup-dotnet`; Gradle caching belongs to
  `gradle/actions/setup-gradle`. Do not cache build outputs, APKs, or dirty AVDs.
- Release packages contain normalized checksums, source/provenance, third-party
  notices, and SBOM-equivalent inventory. The static launcher must be ELF64
  AArch64 `ET_DYN` with no `PT_INTERP` or `DT_NEEDED`.

## Review Checklist

- Are all offsets, lengths, counts, additions, multiplications, and address
  conversions bounded before use?
- Is the owning parser/codec/report helper reused rather than reimplemented?
- Does every failure return a stable diagnostic and avoid publishing output?
- Are stripped ELF files, unknown records, and unsupported semantics handled
  without guessing?
- Are tests present for both the valid path and the nearest malformed path?
- Does CI retain enough environment and failure evidence to distinguish a
  product failure from a missing capability?

## Examples

- `src/UrProtect.Core/Elf/ElfParser.cs` demonstrates bounded program-header,
  dynamic-table, note, relocation, and symbol-version parsing.
- `src/UrProtect.Core/Pack/ElfPackService.cs` demonstrates source/launcher
  separation, atomic wrapper publication, and final recovery verification.
- `tests/UrProtect.Core.Tests/GoldenReportTests.cs` demonstrates stable report
  snapshots rather than assertions on incidental console formatting.
- `native/urprotect-launcher/Makefile` demonstrates the pinned static-PIE
  compile/link contract and strict AArch64 build checks.
