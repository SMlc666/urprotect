# AArch64 ELF self-extracting protector 0.1

## Goal

Plan the first runnable ELF packaging shell for Linux ARM64 ET_DYN PIE executables with payload integrity and behavioral equivalence.

## User Value

Produce a demonstrable first protection artifact that accepts a validated
AArch64 ELF executable, emits a different runnable outer ELF, and proves that
the wrapped program has the same observable behavior as the baseline. The
artifact is a packaging/integrity shell, not an anti-analysis or stealth
feature.

## Confirmed Background

- The existing product owns ELF64 little-endian AArch64 parsing, validation,
  address mapping, dynamic metadata, relocation reporting, and AsmStone-backed
  analysis.
- The current supported input boundary is user-space `ET_DYN` PIE executables
  and dynamically linked shared objects, with stripped and unstripped inputs.
- The existing no-op pipeline preserves source bytes and has stable diagnostic,
  JSON report, CLI exit-code, fixture, and ARM64 CI contracts.
- Native ARM64 glibc fixtures and a pinned ARM64 musl container smoke path are
  available; Android bionic coverage is an x86_64 guest/native-bridge
  experiment and is not a native Android guest.
- The requested first shell must not add stealth, detection evasion, malware
  concealment, or anti-debugging behavior.

## Proposed MVP Shape

The recommended first implementation is an outer self-extracting ELF wrapper:

1. Validate the input with the existing pipeline.
2. Store the complete original ELF as a versioned, compressed payload with a
   cryptographic digest and metadata.
3. Emit a new AArch64 `ET_DYN` executable containing a small launcher and the
   payload.
4. At runtime, verify and materialize the payload, then transfer execution to
   the original program through the platform loader.
5. Compare baseline and wrapped exit status, standard streams, signals, and
   declared generated files in native ARM64 CI.

This intentionally avoids rewriting the original ELF's code, relocations, or
load layout in the first shell. A future in-process code-packing mode is a
separate product scope.

## Requirements

### R1. Input and output boundary

- The first shell accepts only validated ELF64 little-endian `EM_AARCH64`
  user-space `ET_DYN` PIE executables.
- Shared objects, `ET_EXEC`, static-only binaries, other architectures, and
  malformed or unsupported inputs fail closed with stable diagnostics.
- Inputs using `RPATH` or `RUNPATH` are rejected in 0.1 because temporary
  extraction changes the executable origin directory used by the system
  loader.
- The output is a different runnable ELF wrapper; the original input remains
  untouched and is retained byte-for-byte as the payload.

### R2. Payload and launcher contract

- The payload has an explicit version, compression/encoding identifier, source
  size, source SHA-256, and bounded offsets/lengths.
- The launcher rejects truncated, tampered, oversized, or unsupported payloads
  before execution.
- The launcher does not trust payload-provided paths or execute a different
  architecture.
- The handoff preserves `argv`, relevant environment behavior, exit status,
  signals, stdout/stderr, and working-directory semantics as far as the
  selected runtime handoff permits.

### R3. No semantic transformation claim

- The MVP does not encrypt or rewrite original machine-code instructions,
  apply relocations, virtualize control flow, inject anti-analysis logic, or
  promise in-memory execution.
- Any temporary extraction behavior, permissions, cleanup policy, and process
  identity differences are documented and covered by tests.

### R4. Tool and API boundary

- Packing is exposed through a testable core service and a CLI command such as
  `urprotect pack <input> --output <output>`.
- The existing validator/report path remains the single input validation owner.
- The packer does not expose AsmStone types or add a general-purpose ELF
  library.

### R5. Verification and CI

- Unit tests cover payload framing, bounds/overflow checks, digest validation,
  deterministic output, and rejection diagnostics.
- Integration tests prove the output is ELF64 AArch64 `ET_DYN`, differs from
  the source, and preserves the embedded source bytes.
- Native ARM64 glibc and musl tests run baseline and wrapped fixtures through
  the real loader and compare observable behavior.
- Unsupported inputs and failed identity/integrity checks never publish a
  runnable output.
- CI records launcher/profile/toolchain metadata and retains failing wrapped
  ELF artifacts and logs.

## Resolved Planning Decision

The first implementation uses the recommended boundary:

- Linux ARM64 only;
- executable-only validated `ET_DYN` PIE inputs;
- temporary payload materialization followed by `execve` or the equivalent
  system-loader handoff;
- no custom in-process ELF loader in this task.

This is approved as the first product shape because the kernel and platform
dynamic loader continue to own relocations, dependencies, TLS, constructors,
and process startup. `memfd_create`/`execveat` may be a later handoff backend,
and an in-process custom loader is a separate task with its own compatibility
matrix and runtime evidence.

The payload protection level is intentionally limited: compression and
integrity validation are distinct from confidentiality or tamper resistance.
The first implementation uses compressed payloads with a cryptographic digest
and strict framing checks, without payload encryption.
Payload signing/tamper resistance is deferred until a separate key-management
and threat-model decision is made.

## Acceptance Criteria

- [x] The approved input boundary and runtime handoff are implemented as
  explicit validation rules, not implicit best effort.
- [x] `pack` emits a runnable AArch64 `ET_DYN` wrapper containing a complete
  byte-identical source payload, with deterministic framing and digest metadata.
- [x] A tampered, truncated, unsupported, oversized, or wrong-architecture
  payload fails closed without launching the payload.
- [x] Baseline and wrapped native ARM64 glibc and musl fixtures produce matching
  exit status, stdout, stderr, signals, and declared file outputs.
- [x] The wrapper's source bytes differ from the input while the embedded
  payload bytes recover exactly to the original input.
- [x] The CLI reports stable machine-readable errors and never publishes a
  partial output.
- [x] CI retains reproducibility metadata, failure artifacts, and the exact
  runtime profile used for each wrapped fixture.
- [x] Documentation clearly distinguishes packaging/integrity wrapping from
  future code encryption or protection transformation.

## Notes

- Keep `prd.md` focused on requirements, constraints, and acceptance criteria.
- Lightweight tasks can remain PRD-only.
- For complex tasks, add `design.md` for technical design and `implement.md` for execution planning before `task.py start`.
