# Error Handling

## Fail-Closed Binary Boundary

ELF files, payload frames, launchers, and fixture outputs are treated as
hostile or malformed byte inputs. Every offset, size, count, multiplication,
address conversion, and dynamic-table traversal must be checked before a read,
allocation, or conversion. The parser reports structured diagnostics instead
of repairing bytes or guessing code/data boundaries.

## Error Types

Use `DiagnosticCode` for stable machine-readable categories and `Diagnostic` for
severity, code, message, and an optional file offset. `DiagnosticBag` owns
ordered aggregation while result records carry diagnostics to the caller.

Important parser categories include `InputTooSmall`, `InvalidHeader`,
`TableOutOfBounds`, `InvalidProgramHeader`, `InvalidSegment`,
`DynamicTableMalformed`, `DynamicPointerUnmapped`, `AddressOverflow`,
`AddressUnmapped`, `SymbolVersionTableMalformed`, and
`VersionNeedTableMalformed`.

Pack categories include `UnsupportedPackInput`, `UnsupportedInterpreter`,
`LauncherUnavailable`, `PayloadMalformed`, `PayloadUnsupported`,
`PayloadLimitExceeded`, `PayloadIntegrityMismatch`, `WrapperMalformed`,
`OutputIdentityMismatch`, and `OutputIoFailure`.

## Propagation Rules

- `ElfParser.Parse(ReadOnlyMemory<byte>)` returns `ElfParseResult`; malformed
  input becomes diagnostics and a missing `File`, not an exception.
- `NoOpPipeline.Validate` preserves the parsed file when safe, appends analysis
  diagnostics, and creates output bytes only after all errors are absent and
  byte identity is proven.
- `NoOpPipeline.ValidateAndCopy` accepts an optional `inputOverride` snapshot so
  report hashes and copied bytes describe the same source. It writes a flushed
  temporary sibling and removes it on every failure path.
- `PayloadFrameCodec` validates version, flags, architecture, names, bounds,
  encoded digest, exact decompressed size, and source digest before returning
  source bytes.
- `ElfPackService` validates source and launcher independently, validates the
  assembled wrapper and recovered payload, and publishes only after a final
  byte comparison.
- Catch only expected I/O, argument, and codec exceptions at boundaries. Do not
  catch all exceptions and continue with a partial model. The CLI top level
  maps an unexpected exception to `Internal` and includes a correlation id.

## CLI Contract

`src/UrProtect.Cli/CliApplication.cs` owns product exit codes:

| Code | Meaning |
|------|---------|
| `0` | success |
| `2` | usage or argument error |
| `3` | input/output or filesystem failure |
| `4` | invalid or unsupported ELF, launcher, frame, or wrapper |
| `5` | output identity or payload integrity failure |
| `10` | unexpected internal failure |

When `--json -` is selected, emit one report to stdout and keep stderr empty
for normal validation diagnostics. A report file is written atomically only on
successful validation/pack operations.

## Address and Range Safety

All file/virtual/runtime address conversion goes through `LoadMap`; callers do
not reproduce arithmetic. `BoundedReader` performs little-endian reads only
after checked range validation. Unknown program headers, dynamic tags, and
relocation kinds are preserved or warned about rather than guessed.

## Examples

Correct range handling:

```csharp
if (!loadMap.TryVirtualAddressToFileOffset(address, size, out var fileOffset))
    return failure.With(DiagnosticCode.AddressUnmapped);
```

Correct snapshot reuse:

```csharp
pipeline.ValidateAndCopy(
    options.InputPath,
    options.CopyPath,
    options.Analyze,
    inputOverride: input);
```

Relevant regressions live in `ElfMalformedCorpusTests.cs`,
`ElfParserFuzzTests.cs`, `BinaryPropertyTests.cs`, `NoOpPipelineTests.cs`,
`CliApplicationTests.cs`, `PayloadFrameTests.cs`, and
`ElfPackServiceTests.cs`.

## Forbidden Recovery Behavior

Do not treat an unmapped table as empty, truncate a declared count to fit a
buffer, use an unchecked cast from an ELF field as an array length, execute a
payload after an integrity failure, use a payload-controlled directory path,
or silently fall back from a required native ARM64 job to QEMU, another host
architecture, or the C# packer as a wrapper launcher.
