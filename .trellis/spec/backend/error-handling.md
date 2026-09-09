# Error Handling

> How errors are handled in this project.

---

## Overview

<!--
Document your project's error handling conventions here.

Questions to answer:
- What error types do you define?
- How are errors propagated?
- How are errors logged?
- How are errors returned to clients?
-->

The binary parser is a hostile-input boundary. It must fail closed: no unchecked
count, offset, multiplication, address conversion, or dynamic pointer may be
used to read or allocate. The parser returns structured diagnostics instead of
repairing input or guessing code/data boundaries.

---

## Error Types

<!-- Custom error classes/types -->

Use `DiagnosticCode` for stable machine-readable categories and `Diagnostic`
for severity, code, message, and optional file offset. Aggregate diagnostics in
`DiagnosticBag`; callers decide whether errors make a pipeline unsuccessful.

Important codes include `TableOutOfBounds`, `InvalidSegment`,
`DynamicTableMalformed`, `AddressOverflow`, `AddressUnmapped`,
`AsmStoneUnavailable`, `OutputIdentityMismatch`, and I/O failure codes.

---

## Error Handling Patterns

<!-- Try-catch patterns, error propagation -->

Parsing and validation should return result records containing the model (when
safe) and diagnostics. Warnings such as an unknown instruction may be reported
for analysis, but a missing decoder backend is an error. The no-op pipeline must
not emit an artifact when validation has errors.

All conversions between file offsets, ELF virtual addresses, and runtime
addresses go through `LoadMap`; callers must not reproduce address arithmetic.

---

## API Error Responses

<!-- Standard error response format -->

The CLI prints diagnostics to stdout for non-errors and stderr for errors, then
returns a non-zero exit code when `NoOpValidationResult.IsSuccess` is false.
Machine consumers should use the stable diagnostic code rather than matching
human-readable text.

---

## Common Mistakes

<!-- Error handling mistakes your team has made -->

Do not catch all exceptions and continue with a partial ELF model. Do not treat
an unmapped dynamic table as an empty table, silently truncate a count, or
convert an unknown instruction into a guessed opcode. When a future writer is
added, unsupported relocations and range overflow must reject the planned
mutation.

## Scenario: ELF validation and byte-preserving output

### 1. Scope / Trigger

- Trigger: parsing ELF64 AArch64 `ET_DYN` PIE/shared-object inputs and optionally
  emitting a no-op artifact.

### 2. Signatures

```csharp
ElfParseResult ElfParser.Parse(ReadOnlyMemory<byte> bytes);
NoOpValidationResult NoOpPipeline.Validate(
    ReadOnlyMemory<byte> input,
    bool emitOutput = false,
    bool analyzeInstructions = true);
NoOpValidationResult NoOpPipeline.ValidateAndCopy(
    string inputPath,
    string outputPath,
    bool analyzeInstructions = true);
```

### 3. Contracts

- Input: ELF64, little-endian, `EM_AARCH64`, `ET_DYN`, user-space, with
  `PT_LOAD` and `PT_DYNAMIC`; stripped section headers are allowed.
- Output: optional copy whose bytes are exactly equal to the validated input;
  no parsed model is serialized in the MVP.
- Environment: no external ELF library; AArch64 decoding is through the pinned
  AsmStone adapter.

### 4. Validation & Error Matrix

| Condition | Result |
| --- | --- |
| bad magic/class/endianness/version | error diagnostic; no model/output |
| table or segment range overflow | error diagnostic; no output |
| unsupported file type/machine | error diagnostic; no output |
| unknown instruction | warning and analysis boundary |
| missing decoder backend | `AsmStoneUnavailable` error |
| copied bytes differ | `OutputIdentityMismatch`; temporary output removed |
| baseline and no-op runtime behavior differ | E2E failure |

### 5. Good/Base/Bad Cases

- Good: a GCC/Clang AArch64 PIE or dynamic `.so` with valid program headers;
  parse, validate, and byte-copy successfully.
- Base: stripped ELF with no usable section table; program-header-based parsing
  still works.
- Bad: a truncated dynamic table or overflowed `p_offset + p_filesz`; reject
  before reading the table.

### 6. Tests Required

- Unit tests assert stable diagnostics for truncation, wrong machine, overflow,
  invalid segments, and entry-point mapping.
- Property tests assert range arithmetic and LoadMap round trips.
- Integration tests assert no-op byte identity and atomic output behavior.
- Runtime tests compare baseline and no-op exit status/output on native ARM64
  glibc/musl profiles and Android APK/JNI profiles where available.

### 7. Wrong vs Correct

#### Wrong

```csharp
var fileOffset = (int)(virtualAddress - segment.VirtualAddress + segment.FileOffset);
```

#### Correct

```csharp
if (!loadMap.TryVirtualAddressToFileOffset(address, size, out var fileOffset))
    return failure.With(DiagnosticCode.AddressUnmapped);
```
