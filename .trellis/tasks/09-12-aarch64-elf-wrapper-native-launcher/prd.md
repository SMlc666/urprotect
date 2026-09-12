# AArch64 ELF Wrapper 0.2 native launcher hardening

## Goal

Replace the current approximately 70 MB self-contained .NET wrapper launcher
with a small, reproducible native AArch64 launcher while preserving the
working Wrapper 0.1 payload ABI, Linux loader handoff, and native glibc/musl
behavior evidence.

## User Value

The first wrapper proved that a complete ELF can be packaged, verified, and
executed without rewriting the source ELF. Wrapper 0.2 should make that result
usable as a product artifact: the launcher should be small, have a stable ABI,
have a narrow dependency surface, and fail closed under malformed or hostile
wrapper input.

## Repository Evidence

- Wrapper 0.1 stores a complete source ELF in a trailing versioned frame and
  uses raw deflate plus source/encoded SHA-256 values.
- `src/UrProtect.Core/Pack/ElfPackService.cs` validates the source and wrapper
  through the existing parser, rejects shared objects and `RPATH`/`RUNPATH`,
  and publishes launcher-plus-frame bytes atomically.
- `src/UrProtect.Cli/CliApplication.cs` remains the pack/report boundary, while
  the Wrapper 0.2 runtime path is implemented by the static launcher under
  `native/urprotect-launcher/`.
- The existing ARM64 CI has native glibc fixture coverage and a pinned ARM64
  musl container smoke. Release rehearsal `34681420471` passed package,
  release smoke, fixture, and musl payload checks.
- A cross compiler can produce a static AArch64 PIE (`ET_DYN` without
  `PT_INTERP`); the launcher profile must therefore not require the source
  program's dynamic interpreter.
- Current .NET `DeflateStream` output is raw deflate, not a zlib-wrapped stream;
  a native decoder must preserve this exact codec contract or the frame format
  must be versioned and migrated explicitly.

## Scope

### In scope

- A native AArch64 launcher with a frozen launcher ABI version.
- Frame discovery, bounded header/trailer parsing, raw-deflate decoding,
  SHA-256 verification, temporary extraction, and `execve` handoff.
- A launcher build/provenance contract for native ARM64 Linux.
- Wrapper builder changes needed to accept the native launcher while retaining
  valid `ET_DYN`/W^X/load-layout invariants.
- CLI/report changes needed to distinguish packer behavior from launcher
  runtime failures.
- glibc native, musl container, malformed-frame, tamper, argument/environment,
  working-directory, signal, exit-status, and file-output tests.
- Size and startup measurements comparing Wrapper 0.1 and Wrapper 0.2.

### Out of scope

- Custom in-process ELF loading or relocation application.
- `memfd_create`/`execveat` as the default handoff; it remains a later backend.
- Shared-object wrapping, Android execution, code encryption, signatures,
  anti-debugging, stealth, process hiding, or detection evasion.
- Broadening the source input boundary beyond validated Linux ARM64 executable
  `ET_DYN` PIE files.
- Changing the source payload semantics or silently changing the frame codec.

## Requirements

### R1. Native launcher ABI

- The launcher ABI has an explicit version and provenance record.
- The launcher reads only its own executable bytes and a fixed trailing
  trailer; it never trusts a payload path or directory from the environment.
- The launcher accepts the existing frame version only when all fields and
  limits are supported; incompatible versions fail closed.
- The launcher is a native AArch64 `ET_DYN` PIE artifact suitable for the
  selected static/dynamic dependency profile and is not mistaken for the
  source payload.

### R2. Bounded runtime safety

- Header, trailer, frame offset, source-name length, encoded length, source
  length, and all additions are checked before allocation or decompression.
- Decompression has an exact output-size limit and rejects trailing/short
  output according to the codec contract.
- Encoded and recovered source SHA-256 values are checked before `execve`.
- Temporary directories/files use restrictive permissions, do not follow
  payload-controlled directories, and are removed on pre-exec failure.
- `argv`, environment, current working directory, inherited descriptors,
  signal disposition expectations, and exit status are preserved within the
  documented `execve` handoff contract.

### R3. Compatibility profiles

- The same native launcher contract is tested on native ARM64 glibc and inside
  the pinned ARM64 musl container, or the reason for profile-specific launchers
  is explicit in the design.
- Missing launcher runtime dependencies fail the claimed profile; no QEMU,
  host-architecture substitution, or silent .NET fallback is allowed.
- Source programs with `RPATH`/`RUNPATH` remain rejected until a handoff mode
  can preserve their origin semantics.

### R4. Packer and release integration

- C# remains the owner of ELF validation, frame generation, report projection,
  and atomic wrapper publication; native code owns only runtime launch duties.
- `pack` can select a pinned native launcher and records launcher ABI/source
  provenance in its JSON report and release metadata.
- Wrapper 0.2 is deterministic for identical source, launcher, codec, and
  toolchain inputs.
- Release packages contain the launcher source/license/provenance required by
  its codec and cryptographic implementation.

### R5. Evidence and regression protection

- Wrapper 0.1 remains a compatibility fixture until Wrapper 0.2 passes all
  equivalent tests.
- Tests cover valid launch, tampered/truncated/wrong-version/wrong-architecture
  frames, decompression bombs, source digest mismatch, invalid basename,
  missing interpreter/dependency, output publication failures, and exec failure.
- Baseline and wrapped programs compare exit status, stdout, stderr, signals,
  declared files, arguments, environment, and working directory; ASLR address
  and timing differences are excluded from equality.
- CI retains launcher, wrapper, frame metadata, environment, and failure logs.

## Resolved Decision

The native dependency strategy is resolved for this task: use one statically
linked AArch64 PIE launcher built with a pinned musl/static toolchain. It embeds
a narrowly scoped raw-deflate inflater and SHA-256 implementation, minimizing
runtime dependencies so the same launcher can run on glibc and musl hosts.
The trade-off is vendored native code, license/provenance work, and a larger
correctness surface in the launcher.

The launcher itself may be `ET_DYN` without `PT_INTERP`; the source program
remains subject to the packer's executable input boundary and must be a
dynamically linked `ET_DYN` PIE with a supported interpreter. `memfd`/
`execveat`, custom loading, and separate profile-specific launchers remain
deferred. All native source, licenses, and checksums must be recorded.

The frozen Wrapper 0.2 launcher marker is
`URPROTECT-AARCH64-LAUNCHER-V1`; the packer rejects static PIE binaries without
that marker, and reports the launcher ABI, marker, and digest.

## Acceptance Criteria

- [ ] Native launcher size is materially smaller than the Wrapper 0.1 .NET
  launcher and its exact build inputs are recorded.
- [ ] Existing Wrapper 0.1 frames either execute through a documented
  compatibility path or are rejected with a stable version diagnostic.
- [ ] Wrapper 0.2 packs and runs the native ARM64 glibc PR fixture covering set.
- [ ] Pinned ARM64 musl container payload smoke passes with the native launcher
  strategy claimed by CI.
- [ ] Valid arguments, environment, cwd, stdout/stderr, exit status, signals,
  and declared files match baseline behavior.
- [ ] Tamper, truncation, malformed bounds, decompression-limit, wrong ABI,
  digest, and exec failures fail closed without launching the payload.
- [ ] Repeated builds with pinned inputs produce identical launcher and wrapper
  bytes, or any intentional nondeterminism is explicitly excluded and tested.
- [ ] Release artifacts include native launcher provenance, notices, SBOM data,
  and environment evidence.
