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
- Bionic evidence-only native-build statuses are a runner contract, not managed
  CLI exit codes: preserve each native build's command/stdout/stderr sidecars,
  then parse its status with the bounded no-follow parser and allow continuation
  only for canonical zero. Valid nonzero status is retained and propagated;
  missing or malformed status fails before downstream inspection or identity
  publication. Per-handoff argv/status/stdout/stderr sidecars likewise precede
  success-record parsing. The nested Bionic handoff validates its existing
  evidence-unit tree before launching the container and again after it returns;
  the capture helper retains status through a descriptor opened before launch
  and validates the tree before reading the success record. Invalid entries
  block later reads while preserving a nonzero container status. The capture
  helper still lacks a per-process timeout and stdout/stderr byte cap; track
  those as a non-blocking P3 follow-up, not an existing guarantee. Artifact
  permissions use explicitly declared host-group
  roots and no-follow ownership checks. A foreign/symlinked root or missing
  container supplementary group is a hard runner error; original artifact
  path components are opened with `O_NOFOLLOW` and descriptor-relative creation,
  so initial symlink-root/intermediate rejection precedes fixture writes. The
  fixture also runs the helper's bounded descriptor-relative `--validate-tree`
  pass before host writes and immediately after each container return; it rejects
  symlink, special, non-regular/non-directory, multiply-linked, and over-bound
  tree entries. A successful container with an invalid tree fails before later
  host output opens; if both container status and tree validation fail, preserve
  the exact container status and do not read unsafe failure-log paths. This is
  not a general race-free guarantee under the intentionally group-writable root.
  Apt partial-download/cache state stays in the disposable container and locked
  `.deb` files alone are copied to the prepared evidence root; no privileged
  host recursive chmod or EXIT cleanup traverses container-writable apt paths.
  No recursive repair, world-write fallback, or privileged host-write bypass
  is allowed. Host `readelf` report-open/command failures remain required
  failures after native status retention. See the single Bionic scenario in
  [`runtime-compatibility.md`](runtime-compatibility.md#scenario-native-bionic-indirect-control-evidence)
  for the exact schema, roots, and error table.

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

## Scenario: Managed external-provider failures

### 1. Scope / Trigger

Apply this contract at the `protect-image` / `rehydrate-image` host-input,
provider-reader, canonical-snapshot and final Native Image publication
boundaries. Managed admission alone does not establish runtime behavior. A
scoped native AArch64/glibc source-versus-rehydrated-Native-Image observation
and separate provider-loaded rollback evidence are retained, but the runtime row
remains unknown/non-promoted pending hosted CI and broader runtime gates. Owners
and exact proof/fixup checks are in
[external consumer publication](./external-consumer-proof.md); descriptor
requirements are in [safe provider input](./quality-guidelines.md#scenario-bounded-private-provider-file-input).

### 2. Signatures

```csharp
ExternalJumpTableProviderFileReader.Read(ExternalJumpTableProviderInput input)
    -> ExternalJumpTableProviderFileSnapshot // Bytes?, Diagnostics, IsSuccess

FileSystemAdapter.ReadBoundedPrivateSnapshot(string path, int maximumBytes)
    -> FileSnapshot // FullPath, Bytes, SourceMode?, Diagnostics, IsSuccess

SemanticExternalJumpTableProviderReader.Read(
    ReadOnlyMemory<byte> providerBytes, string expectedProviderSoname,
    string expectedBuildIdHex, string expectedSha256,
    SemanticExternalProviderTableIdentity tableIdentity)
    -> SemanticExternalJumpTableProviderReadResult
```

These are API summaries; the first two owners are Application coordination and
Infrastructure I/O respectively. The public semantic reader takes no path.
Its internal `ReadPrivateSnapshot` overload consumes the Infrastructure-owned
byte array; neither a reader result nor a constructed proof is publication
permission. The internal publication validator reports through `DiagnosticBag`
and returns no validated analysis on a source/provider validation failure.

### 3. Contracts

- The four provider flags are all-or-none, once per command, with canonicalized
  hex pins; partial/empty/duplicate or invalid hex groups fail command parsing.
  Absent flags do not implicitly select a provider from a payload or environment.
- The provider file coordinator must delegate all I/O. Expected filesystem,
  path, unsupported-platform and missing-native-entry failures become bounded
  diagnostics. Do not propagate the host path or `exception.Message` into the
  provider diagnostic/report; preserve the original diagnostic code rather
  than replacing it with an incidental parse failure.
- Failed bounded Infrastructure reads return empty `FileSnapshot.Bytes`;
  failed Application provider snapshots return `Bytes == null`. Consumers must
  check `IsSuccess` and never parse failure bytes as an empty ELF/provider.
- Only one private bounded observation is hashed/parsed. Wrong hash stops before
  parsing, even if the input is also malformed. Truncation/growth during the
  same-handle read rejects the whole snapshot, never a prefix. Unsupported safe
  open/statx hosts have no `ReadAllBytes` fallback.
- Snapshot local validation is necessary, not sufficient: rederive source
  instructions, fixups and full consumer/provider owner facts, then check the
  complete physical emitter result, producer offsets, entry/dependencies and
  unchanged GOT before publication. Refreshing all nested/outer digests must
  not bypass these semantic checks. No caught encoder/validation failure may
  retain source words as a success fallback.
- Failure may retain a failed record, diagnostics and raw failure evidence;
  it must not publish a successful Protected Image/role, Native Image/role or
  loader/behavior success. No native loader is invoked by these managed tests.

### 4. Validation & Error Matrix

| Condition | Stable boundary/result |
|---|---|
| Partial/duplicate/empty provider CLI group or malformed hex pin | usage error, CLI 2; no publication |
| Incomplete direct `ExternalJumpTableProviderInput`, invalid path or negative byte limit | `InvalidArgument`, sanitized message |
| Safe-open failure, final symlink, non-regular input, unaudited host or missing `statx` fields | `InputIoFailure`; no bytes; path/raw exception redacted |
| Initial provider input > 8 MiB | `SemanticPlanSnapshotLimitExceeded` before copy/read/parse |
| Short read, growth probe or final descriptor mismatch | `InputIoFailure`; discard snapshot |
| Snapshot SHA differs from host pin | `OutputIdentityMismatch` before ELF parsing |
| Wrong pinned SONAME/build ID | `OutputIdentityMismatch`; no provider extension |
| Invalid provider ELF/profile/table/target range | existing bounded parser/provider diagnostic; no proof input |
| Missing host provider or unique consumer owner at executable rehydration, provider/source proof mismatch | `SemanticPlanSnapshotMalformed`; no Native Image |
| Canonically valid forged source instruction/fixup, including jointly omitted instruction/fixup | `SemanticPlanSnapshotMalformed` with `source-derived projection` message |
| Forged GOT/page or producer source/file/output mapping, invalid neutral output chain | `SemanticPlanSnapshotMalformed` with `GOT output mapping` message |
| Final symbol/DT_NEEDED, entry stub, dispatcher, bounds/default, producer chain, GOT owner/bytes or complete emission mismatch | `SemanticPlanSnapshotMalformed` with final `instruction/reference chain` message |
| Invalid nested version/kind or digest | `SemanticPlanSnapshotUnsupported` / `SemanticPlanSnapshotMalformed` / `SemanticPlanSnapshotIntegrityMismatch` as owned by the codec; no historical decoder |

Do not create a new public diagnostic code for the proof query's `false` /
`failure` string. Test the intended diagnostic **and** failing boundary, not
only that some earlier malformed input happened to reject.

### 5. Good / Base / Bad Cases

- Good: a nonexistent provider yields sanitized `InputIoFailure`; a wrong hash
  yields `OutputIdentityMismatch` before parse; a forged valid-canonical fixup
  reaches source-projection validation and fails without a Native Image.
- Base: ordinary structural parser behavior, non-provider imports and the
  earlier external-table nearest-negative retain their separate contracts.
- Bad: echoing an absolute provider path in JSON, reporting a FIFO hang as a
  successful rejection, or accepting a dead chain because checksums agree.

### 6. Tests Required

- `CliApplicationTests.ProtectImageAcceptsAllPinnedProviderFlagsAndRejectsPartialProviderConfiguration`
  covers the producer and rehydrator groups. Path-redaction tests require a
  sentinel host path absent from diagnostics and report text, not just stderr.
- `LinuxSafeFileInputTests` asserts sanitized errors, exact-limit/plus-one,
  special-file refusal, descriptor replacement, deterministic growth and
  truncation; the no-writer FIFO must return within two seconds.
- Provider-reader tests assert wrong-hash-before-parse and no caller-memory
  access at maximum-plus-one. Publication tests assert exact diagnostics,
  no artifact/native bytes and checksum-refreshed semantic rejection for each
  fixup/map/output/owner mutation, including coordinated co-omission and dead
  copies with live BR removed. Keep original regressions unchanged.
- Keep the native negative boundaries distinct: a wrong provider SHA fails at
  rehydration before Native Image publication and loader invocation; the
  provider-loaded source-loader oracle injects failure after provider/consumer
  binding and verifies cleanup plus successful retry/release; the transformed
  Native Image rollback record verifies the corresponding post-binding failure
  path for the produced image. Root-bound checkers validate each record and
  refreshed-checksum regressions. These local artifacts do not replace the
  hosted CI result or promote other runtime profiles.

### 7. Wrong vs Correct

```text
Wrong: catch IOException and append exception.Message (host path), parse an
       empty/short snapshot, or publish after matching only a retained BR chain.
Correct: return sanitized boundary diagnostics, discard every partial snapshot,
         rederive source semantics, compare complete physical emission and
         owners, and publish no success artifact on any failure.
```
