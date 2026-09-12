# Technical Design

## 1. Product Shape

Wrapper 0.2 separates the C# packer from the runtime launcher:

```text
published C# packer
  -> existing ELF validator and source snapshot
  -> existing v1 payload frame encoder
  -> native AArch64 launcher bytes + frame + trailer
  -> deterministic wrapper ELF

native static AArch64 launcher
  -> /proc/self/exe
  -> bounded trailer/frame checks
  -> raw-deflate decode + SHA-256 checks
  -> minimal recovered-ELF identity checks
  -> private temporary file
  -> execve temporary ELF
  -> host kernel/interpreter/dynamic loader
```

The C# packer remains responsible for policy, ELF parsing, frame generation,
reports, and atomic publication. The native launcher is not a dynamic linker or
a general ELF parser. It performs only the checks needed to avoid executing an
invalid or different-architecture recovered file.

The native launcher is a separate artifact under
`native/urprotect-launcher/`. The C# `urprotect` executable continues to
provide `validate` and `pack`; `pack` receives the native launcher through
`--launcher` (or an explicitly configured package-local path) and never
silently uses the .NET packer itself as the Wrapper 0.2 launcher. Release
bundles contain both artifacts and their provenance.

## 2. Compatibility Boundaries

### Source payload

The source accepted by `ElfPackService` remains:

- ELF64, little-endian, `EM_AARCH64`;
- `ET_DYN` executable with `PT_INTERP`;
- dynamic Linux AArch64 interpreter ending in
  `ld-linux-aarch64.so.1` or `ld-musl-aarch64.so.1`;
- no `RPATH` or `RUNPATH`, because temporary extraction changes `$ORIGIN`;
- not a shared object, static-only file, Android library, or other ABI.

The source boundary does not broaden merely because the native launcher is
static. The launcher itself may be a static-pie `ET_DYN` with no interpreter;
the ELF model should classify an `ET_DYN` whose entry is inside an executable
`PT_LOAD` as a static PIE launcher rather than confusing it with a shared
object. Source policy and launcher policy remain separate.

### Launcher

The launcher must be:

- AArch64 ELF64 little-endian;
- `ET_DYN` static PIE with no required interpreter;
- entry point inside an executable `PT_LOAD`;
- free of dynamic dependencies on glibc, musl, zlib, libcrypto, .NET, or the
  host loader;
- built with pinned native tools and deterministic flags.

The C# packer validates the launcher as a launcher profile, not as a packable
source. It rejects a dynamic launcher with an unsupported interpreter, wrong
machine/class, missing executable entry mapping, or unresolved runtime
dependencies.

## 3. Stable Frame ABI

Wrapper 0.2 keeps the Wrapper 0.1 frame version so existing v1 frames remain
decodable. All multi-byte fields are little-endian and all offsets are absolute
wrapper file offsets.

### Header: 112 bytes

```text
offset  size  field
0       8     magic = "URPCK01\\0"
8       2     formatVersion = 1
10      2     headerSize = 112
12      4     flags = 1 (raw deflate); other values are reserved
16      2     sourceMachine = EM_AARCH64 (183)
18      2     sourceType = ET_DYN (3)
20      4     sourceNameLength, UTF-8 bytes
24      8     sourceSize
32      8     encodedSize
40      8     encodedPayloadOffset
48      32    sourceSha256
80      32    encodedSha256
```

The header is followed by `sourceNameLength` UTF-8 basename bytes and then
`encodedSize` raw-deflate bytes. The header's encoded offset equals:

```text
frameOffset + 112 + sourceNameLength
```

The final 24-byte trailer is:

```text
offset  size  field
0       8     magic = "URTRAIL1"
8       8     frameOffset
16      8     frameLength
```

The trailer is the final wrapper bytes and satisfies:

```text
frameOffset + frameLength + 24 == wrapperFileSize
```

All additions and conversions are checked. Native v1 limits match the managed
codec: source <= 256 MiB, encoded <= 256 MiB, wrapper <= 512 MiB, basename <=
4096 bytes.

### Basename rules

The basename is used for `argv[0]` and the final temporary filename. Managed
and native implementations reject empty/whitespace-only, invalid UTF-8, NUL,
`/`, `\\`, `.`, and `..` values. The private temporary directory prevents any
other directory component from entering the path.

### Codec rules

`flags = 1` means raw Deflate as emitted by current .NET `DeflateStream`; it is
not a zlib or gzip stream. Native code uses pinned low-level miniz/tinfl with
`TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF` and without the zlib-header flag.
It requires exact declared output and consumes the complete encoded region;
short streams, oversized output, invalid Huffman data, and trailing encoded
bytes fail. A codec change requires a new flag/version and managed/native
compatibility tests.

## 4. Native Components and Provenance

The native launcher has three small boundaries:

1. `launcher_main.c`: file discovery, frame checks, temporary handoff, and
   `execve`.
2. `sha256.c/.h`: project-owned SHA-256 following FIPS 180-4 primitives, with
   standard vectors and .NET cross-checks.
3. pinned miniz tinfl sources: raw-deflate decoding only, with upstream notice.

Pin miniz at Git commit `77d0dce8627735138c51770d1799a1ef48f2117d` and retain
the exact `miniz_tinfl.c`, `miniz_tinfl.h`, `miniz_common.h`, required export
header, and MIT license/source notice. Exclude compressor, ZIP, stdio, time,
optional heap, and zlib-header APIs. If trimming miniz changes source files,
record the patch and checksums.

Build with the pinned native ARM64 musl/static toolchain using static-PIE
flags, hidden build paths, no build ID, and stripped symbols. The build
manifest records compiler/linker versions, flags, miniz commit/file hashes,
SHA-256 source revision, and resulting launcher hash. Release notices include
the native source and applicable MIT notice.

## 5. Launcher Runtime

### Frame discovery

Open `/proc/self/exe` read-only and use `fstat` plus `pread` or read-only
`mmap` to inspect the complete wrapper. Never use `argv[0]`, an environment
variable, the current directory, or a payload-provided path to locate it. A
missing/unreadable self path, short file, missing trailer, bad magic, overflowed
range, or non-EOF frame fails before allocation or execution.

Copy trailer/header bytes into fixed-size local storage using explicit
little-endian loads; never cast unaligned file bytes to C structs.

### Integrity and source identity

Check, in order:

1. header/trailer version, sizes, flags, architecture/type, basename, and
   absolute bounds;
2. encoded payload SHA-256;
3. raw-deflate status and exact source byte count;
4. recovered source SHA-256;
5. minimal ELF identity: magic, ELF64, little-endian, version, `ET_DYN`,
   `EM_AARCH64`, bounded program-header table, executable `PT_LOAD` containing
   the entry point, and valid source `PT_INTERP`.

The minimal source check does not apply relocations or interpret dynamic tags;
the full C# validator remains the pack-time policy owner. A failure prints a
stable diagnostic, returns non-zero, and never calls `execve`.

### Temporary handoff

Create a fresh fixed-base directory such as `/tmp/urprotect-payload-XXXXXX`
with mode `0700`, then create the final file with exclusive creation,
`O_NOFOLLOW` where available, and mode `0700`. Write exactly the recovered
bytes, call `fsync`, close, and use the stored basename only inside that
directory. Retain current working directory, inherited descriptors, and
environment.

Reconstruct `argv` with stored basename as `argv[0]` and original `argv[1..]`
unchanged. Pass original `envp` to `execve`; do not invoke a shell or an
environment-controlled command. Remove file/directory on pre-exec failure.
Successful `execve` replaces the launcher, so post-exec cleanup is best effort
and the private-directory behavior is documented. An unlink-before-exec,
`fexecve`, or `memfd_create` backend is deferred.

## 6. Managed Packer Integration

`ElfPackService` reads source and launcher as separate immutable snapshots. It
appends frame/trailer bytes without changing launcher program headers, accepts
the static-PIE launcher profile, validates the resulting wrapper, decodes the
frame with the managed codec, compares recovered bytes, and atomically
publishes the destination.

`pack` requires `--launcher <native-launcher>` or an explicit package-local
configuration. It must not silently use the .NET packer as a Wrapper 0.2
launcher. Existing Wrapper 0.1 frames remain supported by the v1 frame ABI and
existing managed runtime path.

Pack reports include wrapper/frame version, launcher ABI and hash, codec/flags,
source/encoded/wrapper sizes and hashes, launcher provenance, publication
status, and ordered diagnostics. Absolute paths and temporary names are
excluded by default.

## 7. Test and CI Architecture

### Unit and cross-language tests

- SHA-256 vectors, empty input, block boundaries, and .NET parity;
- managed-generated raw-deflate vectors decoded by tinfl;
- frame round trips, deterministic bytes, and all bounds/version/flag/name
  rejection cases;
- native frame fuzzing with fixed size/time budgets;
- managed/native diagnostic-class comparison for malformed frames.

### Wrapper tests

- launcher is static AArch64 PIE with no interpreter dependency and an
  executable entry mapping;
- wrapper is ELF64 AArch64 `ET_DYN`, differs from source, and preserves the
  complete source payload;
- repeated pack operations with identical inputs produce identical wrappers;
- output conflict, write failure, launcher mismatch, and source validation
  failure leave no destination;
- Wrapper 0.1 frames execute through the compatibility path or fail with a
  stable ABI diagnostic.

### Runtime matrix

```text
baseline -> capture status/stdout/stderr/signals/files
pack with native launcher
wrapper -> capture the same observables
compare baseline and wrapper
```

PR runs native ARM64 glibc GCC/Clang C/C++, Rust, and Go fixtures. Nightly and
release run pinned ARM64 musl container payload coverage plus expanded
arguments/environment/cwd/file-output cases. Missing native launcher or a
profile mismatch fails the claimed job; no QEMU, .NET, or host-architecture
fallback is allowed.

Upload launcher, source hash, frame metadata, wrapper on failure, toolchain
manifest, environment report, baseline/wrapper logs, and minimized malformed
frames.

## 8. Rollout and Rollback

1. Build/test the native launcher independently against managed frame vectors.
2. Add explicit `--launcher` pack integration while retaining Wrapper 0.1.
3. Require native glibc packed fixtures, then add musl container evidence.
4. Add native launcher and notices to release packages.
5. Promote the native launcher as the documented Wrapper 0.2 path.

If native decoding or runtime handoff fails, retain Wrapper 0.1, mark Wrapper
0.2 unavailable, and do not weaken the source boundary. The source input is
never modified and failed wrappers are removed before publication.

## 9. Deferred Work

- `memfd_create`, `execveat`, and unlink-before-exec handoff;
- custom in-process ELF loading and relocation/TLS handling;
- shared-object/Android wrapping;
- code encryption, signatures, instruction rewriting, and stealth behavior;
- multiple native launcher variants unless measured compatibility requires it.
