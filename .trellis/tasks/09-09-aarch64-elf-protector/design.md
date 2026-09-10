# Technical Design

## 1. Scope and Invariants

The first implementation is an analysis and validation foundation, not a protection transformer.

Supported input profile:

- ELF64, little-endian (`ELFCLASS64`, `ELFDATA2LSB`)
- `EM_AARCH64`
- user-space `ET_DYN` files
- PIE executables and dynamically linked shared objects
- stripped and unstripped inputs

The no-op contract is strict:

1. The source is opened read-only.
2. The parser and validators inspect the source without rebuilding it.
3. An optional output artifact is copied from the source, not serialized from the parsed model.
4. The output bytes must equal the input bytes exactly.
5. Unknown sections, segments, dynamic tags, notes, padding, and trailing data are preserved because they are never rewritten.
6. An input that is structurally valid but not eligible for a future rewrite may still pass the no-op validation path; rewrite eligibility is a separate future contract.

All arithmetic that derives a file range, virtual address, allocation size, or table count is bounds-checked. Ambiguous or unsupported data is represented explicitly and never guessed.

## 2. Layer Boundaries

```text
CLI / test harness
        |
Validation pipeline and report contracts
        |
Conservative analysis and AArch64 adapter
        |
ELF dynamic metadata, symbols, relocations, and LoadMap
        |
Bounds-checked binary primitives
        |
Immutable input bytes / output copy
```

Suggested source boundaries:

| Boundary | Responsibility | Must not own |
| --- | --- | --- |
| `Binary` | endian reads, slices, checked arithmetic, file ranges | ELF policy or instruction semantics |
| `Elf.Model` | immutable headers, segments, dynamic entries, symbols, relocations, notes | file I/O policy |
| `Elf.Parse` | bounds-checked parsing from bytes | code discovery or rewriting |
| `Elf.Validate` | structural and profile validation | silently repairing input |
| `Elf.Addressing` | file-offset/virtual-address/runtime-address mappings | instruction decoding |
| `Aarch64.Adapter` | local AsmStone DTOs and decode diagnostics | ELF layout decisions |
| `Analysis` | executable-region scan, control-flow candidates, confidence and unknowns | complete function recovery claims |
| `Pipeline` | orchestration, no-op identity proof, reports, failure policy | opcode-specific workarounds |
| `Fixtures`/`Harness` | compiler samples, runtime execution, external-tool comparisons | production parsing logic |

The exact project and namespace names can be chosen during implementation, but these ownership boundaries should remain stable.

## 3. Binary Primitives

Use a small, dependency-free binary layer:

- `ReadOnlyMemory<byte>` or equivalent immutable source ownership.
- A `BoundsCheckedReader` that checks every read against the source length.
- Explicit little-endian readers for unsigned and signed 16/32/64-bit values.
- `FileRange`, `VirtualRange`, and `RuntimeRange` value types instead of naked integer pairs.
- Checked conversion helpers for `ulong`/`long` differences and `nuint`-sized values.
- Allocation limits derived from file length and configured safety limits before creating arrays from ELF counts.

The parser must never trust `e_phnum`, `e_shnum`, table sizes, string offsets, or dynamic pointers before checking both multiplication and final range boundaries.

## 4. ELF Parsing and Validation

### 4.1 Header and table policy

Validate the ELF identification bytes, class, data encoding, version, machine, type, header sizes, program-header entry size, and table ranges. Extended numbering forms should be detected explicitly; if an extended count cannot be safely resolved within the initial boundary, return a typed unsupported diagnostic instead of interpreting it as a normal count.

Section headers are optional for runtime analysis. If present, they may enrich reports, but an absent or malformed section table must not invalidate an otherwise usable program-header-based load model unless the selected validation profile explicitly requires section metadata.

### 4.2 Program headers

Build an immutable program-header list and validate, at minimum:

- every file-backed range is inside the source;
- `p_filesz <= p_memsz` for loadable segments;
- `p_offset`, `p_vaddr`, `p_filesz`, `p_memsz`, and `p_align` arithmetic cannot overflow;
- `PT_LOAD` alignment congruence is valid when alignment requires it;
- dynamic, interpreter, TLS, RELRO, GNU property, GNU EH frame, stack, and note ranges resolve safely;
- overlapping load ranges are modeled deliberately, including page-boundary overlap, rather than rejected by a simplistic interval test;
- unknown program types are preserved and reported.

The validator must distinguish a malformed input from a valid but unsupported profile. Both are failures for any future mutation operation, but diagnostics must make the difference visible.

### 4.3 LoadMap

`LoadMap` is the only component allowed to convert between:

```text
file offset <-> ELF virtual address <-> runtime address
```

For a file-backed address, mapping requires containment in the file-backed part of a `PT_LOAD`; zero-filled memory after `p_filesz` is not treated as file data. Runtime addresses for `ET_DYN` are represented relative to a load bias unless a test harness supplies an observed process base.

Every conversion returns a success/failure result with the segment that established the mapping. No caller may reconstruct the mapping using `p_vaddr + offset` independently.

### 4.4 Dynamic metadata

The first dynamic model should cover the tags needed to locate and validate:

- string and symbol tables, including GNU hash and SysV hash;
- `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and `DT_RUNPATH`;
- RELA tables, PLT relocation tables, and their entry sizes;
- `DT_RELR`, `DT_RELRSZ`, and `DT_RELRENT`;
- Android RELR tags and legacy packed-relocation tags when encountered;
- initialization/finalization arrays and flags;
- symbol-version tables where present;
- PLT/GOT metadata and GNU property references.

The model keeps the raw dynamic entry and a typed interpretation. Unknown tags remain available in the raw list and are not discarded.

### 4.5 Relocations

For the initial no-op path, relocation records are parsed, bounded, classified, and reported; they are not applied or rewritten. The initial AArch64 classification should cover the common dynamic forms used by the fixture matrix, including relative, absolute, global-data, jump-slot, branch/call, ADR/ADRP, literal/load-store, and TLS-related forms encountered in the selected profiles.

The implementation should retain the raw relocation type and addend even when the semantic classifier returns `Unknown`. A future rewrite planner may accept only a strict supported subset and must reject the rest.

## 5. AsmStone Adapter and Analysis

Pin one AsmStone revision in the dependency manifest. The adapter should expose project-owned records such as:

- instruction address and raw 32-bit word;
- decode status (`Decoded`, `UnknownEncoding`, `UnsupportedFeature`);
- normalized instruction family;
- operands needed by the analysis layer;
- direct target, if safely resolved;
- control-flow effect and memory-effect flags;
- source provenance and diagnostic details.

Do not expose AsmStone model types through the rest of the project. Do not add handwritten opcode dispatch to compensate for a missing upstream instruction. An upstream defect gets a minimized regression case, an upstream report/fix, and a pinned-version decision.

The initial analyzer only scans executable bytes in executable `PT_LOAD` regions and starts from trusted candidates such as `e_entry`, dynamic symbols, relocation targets, and explicitly configured fixture entry points. It must not claim complete function recovery from arbitrary stripped binaries. Indirect branches, unknown instructions, data-in-code ambiguity, and out-of-range targets become explicit analysis boundaries.

The adapter contract suite covers the instruction families used by the project: direct and conditional branches, `CBZ/CBNZ`, `TBZ/TBNZ`, `ADR/ADRP`, literal loads, common load/store forms, and unknown/unsupported feature reporting. It does not duplicate AsmStone's exhaustive catalog tests.

## 6. Validation Pipeline and No-op Artifact

The pipeline is transactional even though the MVP does not mutate content:

```text
Open read-only
  -> parse immutable model
  -> validate profile and ranges
  -> build LoadMap and dynamic/relocation reports
  -> analyze selected executable regions
  -> emit report
  -> copy source to temporary output (optional)
  -> compare output bytes with source
  -> atomically publish output and metadata
```

The output copy must be written to a temporary file in the destination directory, flushed and closed, compared byte-for-byte, and renamed only after identity succeeds. A failed identity check removes the temporary output and returns a failure. Source permissions and metadata preservation should be explicit rather than accidental; byte identity is mandatory, while metadata preservation can be a separate documented policy.

Diagnostics should have stable machine-readable codes for malformed headers, truncated tables, address overflow, unsupported file profile, unknown relocation, unresolved mapping, unknown instruction, and runtime-test failure. Human-readable messages are derived from the structured diagnostic.

## 7. Fixture and Runtime Design

Fixtures are small source programs with a manifest, not opaque checked-in binaries only. Each manifest record includes language, compiler distribution/version, linker, target triple, libc/runtime, flags, artifact kind, expected ELF features, and baseline behavior.

The checked-in fixture manifest is schema version 2. Its covering set currently
contains required PR profiles for GCC/Clang C and C++, Rust, and Go, plus
optional nightly profiles for musl, Zig, NativeAOT, and Android NDK/JNI. The
native runner builds each selected artifact on the ARM64 host, executes the
baseline, validates and byte-copies it through the CLI, then compares baseline
and no-op output exit status/stdout/stderr. Missing optional toolchains are
reported as `SKIP`; missing required PR toolchains or invalid outputs fail.

The Android fixture is a small Gradle/CMake APK with an arm64-v8a JNI library.
`scripts/run-android-avd.sh` pins API 35, the `google_apis;arm64-v8a` system
image, NDK 27.2, and an explicit `-no-accel` emulator mode. It installs the APK,
starts `System.loadLibrary`, invokes JNI, and checks the expected logcat result.
Missing Android command-line tools or Gradle are recorded as
`ANDROID_AVD_UNAVAILABLE`; this is an informational feasibility result, not a
physical-device or native-hardware claim.

Priority profiles:

- PR: representative GCC/Clang C/C++, one glibc and one musl profile, NDK JNI smoke, and one representative fixture for Rust, Go, Zig, and NativeAOT where supported by the pinned SDK.
- Nightly: compiler and linker version matrix, optimization/LTO, stripped/unstripped, TLS, C++ exceptions, constructors, `dlopen`, Go cgo, Rust musl, Zig musl, and expanded NDK/API profiles.
- Release: all required profiles, reproducible rebuild checks, complete no-op identity checks, and full runtime E2E.

The matrix is a covering set, not a Cartesian product. Apple LLVM is included only if a reproducible `aarch64-linux-*` toolchain produces ELF; normal Darwin output belongs to a future Mach-O project.

Linux runtime jobs use a versioned GitHub-hosted ARM64 label, for example `ubuntu-24.04-arm`, with glibc on the host. Musl fixtures run from a pinned `linux/arm64` container on that ARM64 host; a QEMU fallback is not accepted for the native Linux gate.

Android jobs are separate:

1. Static APK/ELF inspection always runs.
2. An ARM64 Waydroid-like container is attempted only after a capability probe confirms Binder/BinderFS, namespaces/cgroups, LXC, headless graphics, and matching ARM64 system/vendor images.
3. An ARM64 AVD in software emulation is labeled `tcg`/`software` and never treated as physical or native-hardware validation.

Both Android runtime modes must install a test APK and exercise the real library-loading/JNI path. If the container cannot run on the hosted kernel, the failure is visible and the project does not claim container E2E coverage.

The initial GitHub ARM64 hosted-runner probe confirmed that the runner provides
an AArch64 host, namespaces, and cgroups but does not expose Binder/BinderFS,
LXC, or a Wayland/headless compositor. Until a supported runner or explicit
container image strategy supplies those capabilities, the container workflow is
an informational, non-gating capability probe; Linux build/test and benchmark
jobs remain independent of it.

## 8. CI, Coverage, Fuzzing, and Benchmarks

### CI gates

```text
PR-fast:
  build/analyzers, unit/property tests, parser fixtures, AsmStone adapter contract,
  byte-identity no-op checks, and static ELF/APK validation

PR-integration:
  native ARM64 glibc, ARM64 musl container, and Android container/AVD smoke where
  the capability contract is available

Nightly:
  compiler/language matrix, malformed corpus, fuzzing, expanded Android profiles,
  native ARM64 runtime tests, and benchmarks

Release:
  pinned full required matrix, reproducibility, SBOM/license/provenance reports,
  and retained failure artifacts
```

Infrastructure failures may be retried according to a bounded policy, but test failures must not be hidden by automatic retries or `allow_failure`.

### Coverage and properties

Coverage is measured for project code, not AsmStone internals. Critical modules use branch and error-path targets in addition to overall line coverage. Property tests cover range arithmetic, load-map round trips, dynamic-table bounds, relocation decoding, and byte identity. Malformed fixtures cover truncation, overflow, invalid segment relationships, unterminated strings, inconsistent table sizes, and unknown tags.

### Fuzzing

Fuzz targets begin at the immutable ELF parser and validation boundary. A fuzz iteration must never write outside a bounded buffer, allocate from an unchecked count, hang, or mutate the input. Minimized crashes and interesting structural cases become permanent corpus entries with toolchain/environment metadata.

### Benchmarks

Use a repeatable .NET benchmark harness on native ARM64 Linux. Measure parsing, LoadMap construction, dynamic/relocation indexing, instruction scanning, report generation, no-op copying, allocations, and peak memory over small, medium, large, stripped, and relocation-dense fixtures. Do not use Android TCG timing as a native performance baseline.

## 9. Reproducibility and Supply Chain

Lock the .NET SDK, AsmStone commit, compiler/linker versions, NDK/API levels, container image digests, Android system/vendor image hashes, and runner image labels. Build jobs record all versions and target triples. Runtime dependencies used only as test oracles are kept out of the product runtime dependency graph.

Package and fixture distribution must retain AsmStone's MIT notice and the upstream LLVM/AARCHMRS source/license notices required by its generated catalog. Android/container image licenses and checksums are recorded in the fixture manifest.

## 10. Deferred Work and Rollback

Deferred until the infrastructure has stable evidence:

- `ET_EXEC` and static ELF;
- ELF rewriting and layout serialization beyond byte-preserving copy;
- applying or regenerating dynamic relocations;
- complete function recovery in stripped binaries;
- code layout randomization, encryption, runtime checks, or virtualization;
- physical Android/OEM compatibility;
- A32/T32, other architectures, PE, and Mach-O;
- hardware-specific PAC/BTI and 16 KiB validation where the hosted environment cannot provide it.

Every future mutation phase must keep the original file untouched, produce a planned patch set, validate the plan before writing, and retain a rollback path to the original bytes.
