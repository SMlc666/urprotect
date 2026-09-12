# Technical Design

## 1. Product Boundary

The first protector is an outer ELF wrapper, not a replacement dynamic
linker. It accepts one validated Linux ARM64 executable and produces a new
Linux ARM64 `ET_DYN` PIE wrapper:

```text
input ELF
  -> validate with UrProtect.Core
  -> deterministic payload frame
  -> wrapper launcher + payload
  -> verify and decompress to a private temporary ELF
  -> execve the temporary ELF
  -> host kernel/platform loader owns normal startup
```

The source ELF is never rewritten. The wrapper is the only transformed file;
the payload recovers exactly to the input bytes.

Initial support is deliberately narrower than the existing validator:

- ELF64, little-endian, `EM_AARCH64`;
- user-space `ET_DYN` PIE executable with `PT_INTERP`;
- dynamically linked input with a supported interpreter;
- native Linux ARM64 glibc first, pinned ARM64 musl as the next profile;
- no shared-object packing, Android wrapper execution, or static `ET_EXEC`.
- no `RPATH`/`RUNPATH` inputs whose loader search origin would change after
  temporary extraction;

The packer must reject a validated shared object even though the validator can
inspect one. The first launcher has an executable handoff contract, not a
`System.loadLibrary` contract.

## 2. Layer Boundaries

```text
CLI `pack`
  -> PackApplication / option and exit-code mapping
  -> ElfPackService (validation + payload + wrapper transaction)
  -> PayloadFrame (format, compression, digest, bounded decode)
  -> WrapperBuilder (fixed launcher template + deterministic data layout)
  -> native AArch64 launcher runtime
  -> temporary file + execve
```

Responsibilities:

| Layer | Owns | Must not own |
| --- | --- | --- |
| `ElfPackService` | input snapshot, profile gate, orchestration, atomic output | instruction rewriting or dynamic linking |
| `PayloadFrame` | versioned header, compression, SHA-256, limits, decode | path selection or process startup |
| `WrapperBuilder` | launcher template, ELF layout, payload placement, deterministic bytes | parsing arbitrary source ELF into a new load model |
| launcher runtime | payload discovery, checks, extraction, argv/env handoff | interpreting source relocations |
| host loader | source ELF mapping, dependencies, relocations, TLS, constructors | payload integrity policy |

Production C# owns the frame and wrapper contract. For this first slice, the
launcher is the published self-contained AArch64 `urprotect` executable itself;
its existing entrypoint detects the trailing frame before normal CLI parsing.
This makes the first artifact large but reuses the tested C# runtime and avoids
introducing a second native build. A smaller checked-in native launcher remains
a future optimization, with its own ABI/source/license pin.

## 3. Payload Frame

The frame is stored in a non-loadable or read-only data area of the wrapper and
has a fixed little-endian header. Suggested fields:

```text
magic[8]              = "URPCK01\0"
formatVersion:u16     = 1
headerSize:u16
flags:u32             (compression algorithm, reserved bits must be zero)
sourceArch:u16        = EM_AARCH64
sourceType:u16        = ET_DYN
sourceNameLength:u32
sourceSize:u64
encodedSize:u64
payloadOffset:u64     (wrapper file offset of compressed bytes)
sourceSha256[32]
encodedSha256[32]
```

The fixed header is followed by a bounded UTF-8 source basename and then the
compressed source bytes. The basename is used as `argv[0]` and as the final
component of the temporary extraction path so multi-call binaries that inspect
`AT_EXECFN` retain their normal invocation name. Separators and NULs are
rejected; no user-controlled directory is ever used. The initial compression
algorithm should be a deterministic, already-supported runtime codec such as
zlib/deflate; the exact codec is a versioned contract and cannot be inferred
from a filename. If the native launcher would need a third-party decompressor,
its source/license/provenance is part of the launcher supply chain.

Limits are checked before allocation and decompression:

- maximum source size configured by the packer and launcher;
- encoded size cannot exceed wrapper file bounds;
- checked `offset + size` and header-size arithmetic;
- decompressed byte count must equal `sourceSize` exactly;
- both encoded and source digests must match;
- source basename length and UTF-8 validity must pass before using it for a
  filename or argument;
- reserved flags and unsupported versions fail closed.

The frame is stored in a deterministic trailing data region after the launcher's
original program headers. The host loader ignores that trailing region; the
launcher reads it from its own executable file. The frame is not encrypted.
Integrity is not authenticity: a modified wrapper can be repacked by an
authorized user. Signing/key management is deferred.

## 4. Wrapper ELF Contract

The wrapper is a deterministic AArch64 `ET_DYN` PIE executable with:

- a small executable launcher entrypoint;
- frame/header/payload bytes in a trailing region outside the launcher's mapped
  program-header ranges;
- a valid `PT_INTERP` for the target profile;
- load segments with page alignment and non-overlapping file ranges;
- no source ELF program headers copied into the wrapper's load model;
- no writable/executable payload mapping;
- a fixed launcher ABI version in the frame and provenance.

The wrapper builder uses the published launcher bytes unchanged and appends
only bounded frame/trailer data. It never changes the launcher's entrypoint or
dynamic link model. The launcher ABI is therefore the published CLI's
`TryRunEmbeddedPayload` contract rather than a separately linked stub.
It does not serialize `ElfFile`, copy source program headers, or try to make
the embedded source part of the wrapper's dynamic link map.

Wrapper output is written to a destination-local temporary file, flushed,
validated, and atomically renamed. Existing output is never replaced until all
wrapper and payload checks pass. The source path and payload path are not
trusted at runtime; the launcher locates its own frame relative to its
executable image or a launcher-defined sealed data contract.

## 5. Runtime Handoff

The launcher:

1. locates and parses only its fixed frame;
2. checks architecture, version, flags, bounds, encoded digest, and source
   digest;
3. creates a private temporary file in a safe runtime directory;
4. writes decompressed bytes with restrictive permissions and flushes them;
5. verifies the recovered file as an ELF payload using the launcher boundary
   checks;
6. preserves `argv`, environment, current working directory, and inherited
   standard streams;
7. invokes `execve` so the normal interpreter and dynamic loader start the
   original program;
8. removes the temporary file on pre-exec failure. Post-`execve` cleanup is
   platform-dependent and documented rather than promised.

Because the first handoff changes `/proc/self/exe` and the extraction
directory, the packer rejects inputs with `RPATH` or `RUNPATH` metadata. This
prevents `$ORIGIN`-dependent library resolution from silently changing. A
future handoff backend must either preserve origin semantics or expand the
rejection/compatibility contract.

The initial launcher must not silently fall back to shell execution, invoke a
payload path supplied by an environment variable, or continue after an
integrity failure. `memfd_create`/`execveat` is a future backend behind the same
handoff contract; it is not part of the initial acceptance gate.

The wrapper's process identity may differ briefly before `execve`; tests must
compare observable behavior, not addresses, timing, or transient process names.

## 6. Core API and CLI

Suggested core records and service:

```csharp
public sealed record ElfPackOptions(
    ulong MaximumSourceSize,
    PayloadCompression Compression);

public sealed record ElfPackResult(
    string? OutputPath,
    ulong SourceSize,
    ulong EncodedSize,
    string SourceSha256,
    string WrapperSha256,
    IReadOnlyList<Diagnostic> Diagnostics);

public interface IElfPackService
{
    ElfPackResult Pack(string inputPath, string outputPath, ElfPackOptions options);
}
```

The CLI adds a stable command:

```text
urprotect pack <input> --output <wrapper>
urprotect pack <input> --output <wrapper> --json <report.json>
```

It reuses the existing validator and product diagnostic projection. Validation
errors map to the existing validation class; payload/wrapper integrity errors
use an explicit pack/output diagnostic class without publishing output.

## 7. Testing and CI Data Flow

```text
baseline fixture
  -> run and capture status/stdout/stderr/files
  -> pack
  -> validate wrapper structure
  -> run wrapper on native ARM64
  -> compare observable result
  -> retain wrapper, frame metadata, logs on failure
```

Tests include:

- frame round trips, deterministic encoding, unknown flags/version;
- truncation, integer overflow, maximum-size, digest and wrong-architecture
  rejection;
- source snapshot and atomic output behavior;
- wrapper ELF identity and `readelf` structural oracle;
- baseline/wrapper glibc fixtures;
- pinned musl-container wrapper execution;
- stripped and unstripped PIE fixtures, with C/C++, Rust, and Go prioritized;
- failure artifact retention and environment/profile metadata.

The fixture harness remains outside production parsing code. Android and shared
objects are explicit skips/rejections in this task, not hidden fallback paths.

## 8. Security, Reproducibility, and Rollback

- No anti-debugging, stealth, process hiding, detection evasion, or malware
  concealment behavior.
- Compression is deterministic; timestamps, source paths, random IDs, and
  host-specific metadata are excluded from the wrapper bytes.
- The launcher template, codec, toolchain, compiler flags, and source revision
  are pinned and included in provenance.
- Any failed validation, frame check, wrapper check, or atomic publish removes
  the temporary output and leaves the source untouched.
- A future custom loader must be a separate task with its own threat model,
  supported relocation/TLS/dependency matrix, and runtime equivalence evidence.
