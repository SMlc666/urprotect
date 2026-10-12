# Error Handling

## Fail-Closed Binary Boundary

ELF files, payload frames, launchers, and fixture outputs are treated as
hostile or malformed byte inputs. Every offset, size, count, multiplication,
address conversion, and dynamic-table traversal must be checked before a read,
allocation, or conversion. The parser reports structured diagnostics instead
of repairing bytes or guessing code/data boundaries.

Native HostContext image validation follows the same fail-closed rule in
`native/urprotect-runtime/host_image_validation.c`; `host_adapter.c` performs
no memfd or loader handoff until that preflight succeeds.

## Error Types

Use `DiagnosticCode` for stable machine-readable categories and `Diagnostic` for
severity, code, message, and an optional file offset. `DiagnosticBag` owns
ordered aggregation while result records carry diagnostics to the caller.

Important parser categories include `InputTooSmall`, `InvalidHeader`,
`TableOutOfBounds`, `InvalidProgramHeader`, `InvalidSegment`,
`DynamicTableMalformed`, `DynamicPointerUnmapped`, `AddressOverflow`,
`AddressUnmapped`, `SymbolVersionTableMalformed`,
`VersionDefinitionTableMalformed`, and `VersionNeedTableMalformed`.

Pack categories include `UnsupportedPackInput`, `UnsupportedInterpreter`,
`LauncherUnavailable`, `PayloadMalformed`, `PayloadUnsupported`,
`PayloadLimitExceeded`, `PayloadIntegrityMismatch`, `WrapperMalformed`,
`OutputIdentityMismatch`, and `OutputIoFailure`.

## Propagation Rules

- `ElfParser.Parse(ReadOnlyMemory<byte>)` returns `ElfParseResult`; malformed
  input becomes diagnostics and a missing `File`, not an exception.
- `ValidationWorkflow.ValidateStructurally` preserves the parsed file when safe.
  `ValidateObservationOnly` appends instruction-analysis diagnostics only when
  the explicitly selected observation-only mode is requested, and creates
  output bytes only after all errors are absent and byte identity is proven.
- `ValidationWorkflow.ValidateAndCopyStructurally` accepts an optional
  `inputOverride` snapshot so report hashes and copied bytes describe the same
  source. Observation-only copying is explicitly selected through
  `ValidateAndCopyObservationOnly`. Both APIs write a flushed temporary sibling
  and remove it on every failure path.
- `PayloadFrameCodec` validates version, flags, architecture, names, bounds,
  encoded digest, exact decompressed size, and source digest before returning
  source bytes.
- When a frame requires `URP_HOST_CAP_THREAD_LIFETIME`, preflight verifies the
  full table size and both callbacks before image loading. The native adapter
  reserves per-image ownership before thread start, returns no handle on failed
  creation, rejects foreign/repeated/self-join handles, and never reuses opaque
  thread handles. Release closes creation and joins registered workers; a join
  failure preserves the image mapping and descriptor so live code is not
  unloaded. The runtime passes the current HostContext table directly. Ordinary
  frames receive the 32-byte minimum launch-args view with image handle zero;
  frames requiring thread lifetime receive the current 40-byte view with the
  active image handle.
- `ElfPackService` validates source and launcher independently, validates the
  assembled wrapper and recovered payload, and publishes only after a final
  byte comparison.
- `ProtectionWorkflow` is the single owner for current `protect`,
  `protect-image`, and `rehydrate-image` planning/materialization decisions.
  `OuterExecveat` and `HostContextEntry` use explicit profile policies over the
  shared layout/materializer operations; profile mismatch, malformed operation,
  reparse, native-image, handoff, or publication failure records a deterministic
  first-failure stage and publishes no successful artifact, role, stage, report,
  Native Image, or evidence set.
- Rehydration records and Native Image descriptors bind the current workflow
  owner, profile, ABI, source/request/artifact/output hashes, and handoff fields
  before publication. An unavailable runtime remains explicit evidence and is
  not promoted by a different runtime's result.
- Catch only expected I/O, argument, and codec exceptions at boundaries. Do not
  catch all exceptions and continue with a partial model. The CLI top level
  maps an unexpected exception to `Internal` and includes a correlation id.

## CLI Contract

`src/UrProtect.Cli/Commands/CliApplication.cs` owns product exit codes:

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

## AArch64 Encoder Failure Propagation

`Aarch64InstructionEncoder` is the project-owned final-word boundary around
AsmStone. It returns a typed `Aarch64InstructionEncodeResult` with a zero word
on failure; it never returns a source-word fallback. Source/output instruction
addresses, target alignment/range, access width, and load/store scale are
validated before publication, and every successful word is decoded through
AsmStone and the project decoder before it is accepted.

Semantic fixup owners map adapter failures to stable `DiagnosticCode` values:
target alignment/range failures become semantic fixup alignment/range
diagnostics, while source/template/family/operand/backend/round-trip failures
remain malformed or unsupported semantic fixup diagnostics. TLS relocation,
GOT/TLSDESC ownership, PT_TLS identity, addends, and address-map conflicts are
validated separately by UrProtect; an individually encodable instruction does
not repair inconsistent ELF/TLS metadata.

No caller may catch an adapter failure and retain the original word, apply a
local opcode/bitfield fallback, or publish a partial layout. Layout branch
policy may choose direct, veneer, or long-branch placement, but final Branch26
and Call26 words still come from the adapter-backed layout helper. Remaining
raw masks are limited to recognition, invariant checks, ELF serialization, and
byte-preserving copies; they must not gain new instruction families.

## Examples

Correct range handling:

```csharp
if (!loadMap.TryVirtualAddressToFileOffset(address, size, out var fileOffset))
    return failure.With(DiagnosticCode.AddressUnmapped);
```

Correct snapshot reuse:

```csharp
pipeline.ValidateAndCopyStructurally(
    options.InputPath,
    options.CopyPath,
    inputOverride: input);
```

Relevant regressions live in `ElfMalformedCorpusTests.cs`,
`ElfParserFuzzTests.cs`, `BinaryPropertyTests.cs`, `ValidationWorkflowTests.cs`,
`CliApplicationTests.cs`, `PayloadFrameTests.cs`, and
`ElfPackServiceTests.cs`.

## Forbidden Recovery Behavior

Do not treat an unmapped table as empty, truncate a declared count to fit a
buffer, use an unchecked cast from an ELF field as an array length, execute a
payload after an integrity failure, use a payload-controlled directory path,
or silently fall back from a required native ARM64 job to QEMU, another host
architecture, or the C# packer as a wrapper launcher. Do not silently fall
back from an AsmStone encoding failure to source-word retention or manual
bitfield assembly.
