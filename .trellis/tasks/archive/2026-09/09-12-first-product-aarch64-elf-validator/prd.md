# First AArch64 ELF validator product

## Goal

Turn the existing UrProtect AArch64 ELF infrastructure into the first
publishable product: `UrProtect Validator 0.1`. The product validates supported
Linux/Android AArch64 ELF inputs, emits a stable human or JSON report, and can
produce a byte-identical no-op copy. It must be installable and demonstrable
without requiring users to understand the internal parser or CI fixture code.

The product is an analysis and validation tool, not yet a protection
transformation. A successful result means that the supported structural checks
completed; it does not claim that arbitrary stripped code was fully recovered
or that a future rewrite would be safe.

## User Value

A user can run one command against a native AArch64 executable or shared object
and receive a deterministic answer about whether the input is inside the
supported ELF boundary. The same command can emit a no-op artifact whose bytes
are proven identical to the validated input, making the pipeline safe to adopt
before any future mutation feature exists.

## Confirmed Scope

- Product name and first release shape: `UrProtect Validator 0.1`.
- Implementation: C#/.NET 8, with the existing self-owned ELF model and pinned
  AsmStone adapter.
- Supported input: ELF64, little-endian, `EM_AARCH64`, user-space `ET_DYN`
  PIE executables and dynamically linked shared objects, stripped or
  unstripped.
- Supported runtime evidence: native ARM64 Linux glibc, native ARM64 musl,
  and Android bionic through the already-established APK/JNI native-bridge
  experiment. No physical-device claim is added.
- Observable behavior: validation report plus an optional byte-for-byte copy;
  no executable transformation, runtime injection, encryption, virtualization,
  relocation application, or code-layout mutation.
- Release artifacts: versioned Linux ARM64 glibc and musl command-line bundles,
  checksums, provenance/license data, and reproducible CI evidence.

## Product Requirements

### P1. Stable CLI contract

The CLI must provide:

```text
urprotect validate <input>
urprotect validate <input> --copy <output>
urprotect validate <input> --json <report.json>
urprotect validate <input> --json - --no-analysis
```

Required behavior:

- `validate` reads the input without modifying it.
- `--copy` uses the existing transactional no-op path and publishes only after
  byte identity is proven.
- `--json <path>` writes the schema-versioned report atomically; `-` writes
  machine-readable JSON to stdout.
- `--no-analysis` skips instruction scanning but never skips structural
  validation, address mapping, dynamic metadata, or relocation parsing.
- Unknown options, missing option values, and missing input paths return usage
  errors without creating an artifact.
- Human diagnostics go to stderr when the command fails; JSON mode must not
  mix human text into the JSON stream.

### P2. Stable exit codes

The first product must document and test these exit classes:

| Code | Meaning |
| --- | --- |
| `0` | Input validated; any requested no-op copy/report was published successfully |
| `2` | CLI usage or argument error |
| `3` | Input/output filesystem or permission failure |
| `4` | Malformed, unsupported, or fail-closed ELF validation result |
| `5` | Requested artifact failed byte-identity or atomic publication checks |
| `10` | Unexpected internal failure with a diagnostic correlation id |

The exact numeric mapping is part of the 0.1 compatibility contract and must
not be inferred from human-readable messages.

### P3. JSON report schema

Report schema version 1 must contain, at minimum:

- tool version and report schema version;
- input byte length and SHA-256, without exposing an absolute path by default;
- ELF identity: class, endianness, machine, type, and PIE/shared-object kind;
- program-header/load-map summary;
- dynamic metadata, symbol/version, note/property, RELA/RELR/Android packed
  relocation, and analysis counts;
- ordered diagnostics with severity, stable code, message, and optional file
  offset;
- no-op output status, output SHA-256, and byte-identity result when requested.

The schema must preserve unknown data through counts/raw-preservation claims
without pretending to semantically understand it. JSON field names and enum
spellings are tested by golden reports and are not changed casually after the
0.1 release.

### P4. Product safety contract

- A validation error never produces a copy or successful JSON artifact.
- A warning may be included in a successful report only when the no-op path is
  still structurally valid; unknown instructions and unknown relocations remain
  explicit boundaries/warnings.
- Output publication is atomic and destination-local, and source bytes are
  never overwritten.
- The product never serializes the parsed ELF model back into the output.
- No external general-purpose ELF library is added to the runtime dependency
  graph.

### P5. Release and distribution

Each release candidate must produce:

- `urprotect-linux-arm64-glibc-<version>.tar.gz`;
- `urprotect-linux-arm64-musl-<version>.tar.gz`;
- SHA-256 checksums and a release manifest;
- AsmStone, LLVM/AARCHMRS, compiler, SDK, and fixture provenance/license
  notices;
- SBOM or an equivalent dependency inventory;
- a usage README with supported input boundary and explicit non-goals.

The bundles must run on the corresponding native ARM64 CI profile and must not
silently use QEMU or another host architecture.

### P6. Acceptance fixture set

The product release gate must execute the existing covering fixture matrix and
the Android JNI/native-bridge path where that tier is selected. For each ELF
fixture it must prove:

1. baseline execution succeeds;
2. validator report succeeds;
3. optional no-op copy is byte-identical;
4. no-op output executes through the real loader;
5. baseline and no-op observable output/status match.

Android remains an APK plus `System.loadLibrary`/JNI test, not an extracted
`.so`-only claim.

## Explicit Non-Goals

- Any protection transformation or mutation of executable semantics.
- PE, Mach-O, A32/T32, non-AArch64 architectures, or .NET assembly protection.
- Complete function recovery, decompilation, or a guarantee that every unknown
  instruction is understood.
- Physical Android devices, OEM ROMs, hardware acceleration, or full ARM64
  Android guest validation.
- A full compiler-version/runtime Cartesian product on every pull request.
- A stable public library API beyond the CLI/report contract in 0.1.

## Acceptance Criteria

- [x] `validate`, `--copy`, `--json`, and `--no-analysis` behavior is covered by
  CLI tests, including usage and filesystem failures.
- [x] Exit codes are stable, documented, and tested for success, validation,
  usage, I/O, identity, and internal-failure classes.
- [x] JSON report schema v1 has golden tests, deterministic ordering, and
  byte/hash/output fields that match the actual no-op result.
- [x] A release candidate validates representative GCC/Clang, Rust, Go, musl,
  Zig, NativeAOT, stripped/unstripped, and Android JNI artifacts through the
  existing evidence paths.
- [x] Linux ARM64 glibc and musl bundles are built from pinned inputs, run on
  their native profiles, and have checksums/provenance/SBOM artifacts.
- [x] Invalid or unsupported inputs cannot produce a successful artifact, and
  no-op output remains byte-for-byte identical.
- [x] The product README gives a copy-paste demo and clearly states the
  infrastructure-only boundary.
- [x] GitHub release-tier CI passes without requiring the slow Android AVD on
  ordinary push/PR runs; manual AVD execution remains explicit.

## Deferred Follow-Up

- A separately planned transformation product with its own patch/fixup/layout
  model and runtime equivalence gates.
- Public library API stabilization.
- Broader symbol-version definitions, richer GNU property semantics, 16 KiB
  Android profiles, and physical/OEM compatibility.
