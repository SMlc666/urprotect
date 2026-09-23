# Unify runtime and expand AArch64 PIE compatibility

## Goal

Create one host-neutral runtime and compatibility contract for packaged
AArch64 ELF payloads. The runtime must not expose operating-system or vendor
profiles, must not depend on materializing the recovered payload as an
executable temporary path, and must broaden the set of AArch64 PIE inputs that
can be accepted with a defensible correctness argument.

The task also establishes a machine-readable compatibility matrix that records
the supported ELF/runtime feature language, proof obligations, executable
witnesses, and explicit rejection or unknown states.

## User Value

The same packaged artifact and runtime semantics should apply across correctly
implemented AArch64 host environments. Platform-specific system calls or
loader details may exist behind a small Host Contract implementation boundary,
but they must not become separate product profiles or user-selected modes.

The primary compatibility claim is conditional and auditable:

```text
Host satisfies the Host Contract
and payload satisfies the accepted AArch64 ELF invariants
=> packaged execution is observationally equivalent to the baseline payload
```

Real-device or emulator execution may provide implementation evidence, but it
is not the foundation of the compatibility proof.

## Confirmed Repository Facts

- The current wrapper materializes the recovered ELF under a private temporary
  directory and calls `execve`; the managed path is visible in
  `src/UrProtect.Cli/CliApplication.cs` and the native path in
  `native/urprotect-launcher/launcher_main.c`.
- The current wrapper documentation explicitly describes `execve`, defers
  `memfd_create`/`execveat`, and defers Android wrapper execution. These are
  prior implementation boundaries, not decisions that constrain this task.
- The current Android fixture verifies an unwrapped `arm64-v8a` JNI library via
  `System.loadLibrary`; it does not execute a packed output.
- Existing Android research shows the hosted ARM64 runner is a native Linux
  environment with glibc; the current Android container probe lacks some
  Binder/LXC/graphics prerequisites, while the existing AVD lane uses an
  x86_64 guest and native bridge.
- The pinned Termux Docker source at commit
  7033c7639eb86107a4fdf8b72bd6388c07b1284a builds an AArch64 rootfs whose
  documented contents include AOSP/bionic libc and linker. The corresponding
  ARM64 OCI image currently resolves to
  sha256:e19ea56dd687563849826cbda57da714ae23277ee463e21f39917dbc0a59bab4.
- The Termux Docker image is a bionic userspace, not a complete Android
  runtime: its upstream documentation excludes DalvikVM and other Android
  runtime components. A native ARM64 bionic userspace runner can therefore add
  stronger AArch64 bionic linker/ELF evidence without requiring AVD, Waydroid,
  QEMU, or native bridge, but it cannot by itself prove Android framework,
  OEM, SELinux, or device-kernel behavior.
- The managed parser already models AArch64 ELF program headers, dynamic
  entries, RELA/RELR data, Android packed relocations, dynamic symbols, symbol
  versions, notes, and load maps. The validator currently has a conservative
  ET_DYN/`PT_DYNAMIC` boundary and warns when relocation kinds are not
  classified.
- Existing tests cover parser malformed inputs, golden reports, properties,
  fuzz cases, pack framing, CLI behavior, and native launcher integration.
- The archived Wrapper 0.2 task intentionally used temporary extraction and
  deferred custom loading and FD-based handoff. This task supersedes those
  deferrals for the new compatibility direction.

## Requirements

### R1. One runtime contract

- Define one host-neutral runtime contract for payload loading and execution;
  do not introduce Linux/Android product branches or compatibility profiles.
- The first runtime target is an in-process AArch64 `ET_DYN` entry image rather
  than a standalone process replacement.
- The entry surface is an explicit, versioned `HostContext` ABI rather than a
  synthesized `_start`/`main` process startup environment.
- Keep host-specific operations behind a narrow interface whose semantics are
  explicit enough to support a conditional correctness argument.
- Use one payload/frame/integrity contract across conforming host
  implementations.
- Preserve fail-closed behavior for malformed, unsupported, or unverifiable
  payloads.

### R2. No temporary executable handoff

- The target runtime path must not require writing the recovered payload to an
  executable temporary pathname.
- The design must specify how decoded bytes are handed to the common runtime
  and how the host loader or mapping layer observes them without trusting a
  payload-controlled path.
- Any compatibility fallback that retains path-based extraction must be
  explicitly treated as legacy or unavailable, not silently presented as the
  unified solution.
- Payload byte identity, digest verification, bounds, lifetime, and cleanup
  must remain testable without relying on a device-specific filesystem.

### R3. Expand provable AArch64 PIE compatibility

- Broaden the accepted AArch64 ELF64 little-endian `ET_DYN` PIE language only
  when its loader and runtime obligations are specified.
- Evaluate, classify, and test variations in load-segment layout/alignment,
  section-table presence, `PT_INTERP`, `PT_DYNAMIC`, dynamic tags, RELA/RELR,
  TLS, GNU properties, RELRO, BTI/PAC metadata, symbol versions, constructors,
  and dynamic dependencies as applicable to the selected entry contract.
- Expand producer coverage across the existing GCC, Clang, Rust, Go, Zig, and
  NativeAOT fixture families where their outputs exercise distinct ELF or
  runtime behavior.
- Keep unsupported ELF features explicitly rejected with stable diagnostics;
  do not convert unknown relocation or runtime behavior into an implicit
  compatibility claim.

### R4. Machine-readable compatibility matrix

- Store the matrix in a repository-owned machine-readable manifest and derive
  human-readable documentation and CI selection from it.
- Organize rows by objectively testable ELF, ABI, runtime, and handoff
  features, not by operating-system or vendor names.
- Remove project-owned `profile`/`profiles` terminology from the fixture
  manifest, fixture scripts, matrix reports, and user-facing documentation;
  use names such as matrix cases, tiers, variants, or host facts according to
  the actual meaning. Do not rename unrelated external tool concepts such as
  Cargo's `profile.release`.
- Each row records at least: feature identifier, required invariants, status,
  proof obligation, positive fixture/witness, negative fixture where relevant,
  oracle, and evidence location.
- Use explicit statuses: `proven`, `validated`, `rejected`, and `unknown`.
  `unknown` must never count as supported.
- Avoid a blind Cartesian product; use a documented covering strategy for
  feature interactions and record constraints that make combinations invalid.
- Treat runtime bionic as a peer runtime fact alongside glibc and musl. The
  native Termux userspace case must be distinguished from the existing Android
  JNI/native-bridge case by host and execution facts, not by a project-owned
  compatibility profile.

### R5. Proof and evidence

- Define the observable-equivalence boundary for the packaged payload,
  including entry behavior, memory image, dynamic dependencies, constructors,
  threads/TLS where applicable, arguments, environment, file descriptors,
  signals, exit status, and declared output behavior.
- Map each accepted matrix row to a static invariant, model/property test, or
  runtime oracle; no supported row may exist only because one device happened
  to run it.
- Distinguish theoretical proof, deterministic host-model validation, and
  representative emulator/device evidence in reports and CI artifacts.
- Include a native ARM64 bionic userspace case as implementation evidence for
  the Host Contract, with a pinned rootfs or OCI image, direct architecture
  and linker checks, recorded kernel/page-size facts, and no glibc/QEMU/
  native-bridge fallback.
- Document what can be concluded about conforming host implementations and
  avoid an unqualified statistical claim about the majority of vendors.

### R6. Regression and migration safety

- Preserve the existing v1 frame and current validation/report behavior unless
  a deliberate compatibility migration is specified.
- Add regression coverage for every current supported case before changing
  the runtime handoff.
- Record the old temporary/`execve` path as a compatibility baseline and make
  any behavior change observable through reports and diagnostics.
- Keep all new native or loader dependencies pinned, reproducible, and covered
  by provenance and license records.

## Acceptance Criteria

- [x] A design document defines one runtime core, one Host Contract, the
      versioned `HostContext` entry ABI, no-temporary-path handoff, and the
      observable-equivalence boundary.
- [x] The current wrapper and Android fixture limitations are represented as
      baseline evidence rather than separate product profiles.
- [x] The compatibility manifest is machine-readable, has explicit status and
      proof/evidence fields, and is consumed by at least one automated check.
- [x] Project-owned fixture and matrix interfaces no longer expose
      `--profile`, a top-level `profiles` collection, or compatibility-profile
      claims; remaining variant names describe their actual build/test meaning.
- [x] The first matrix slice covers the current AArch64 PIE fixture set and
      records both supported and intentionally rejected cases.
- [x] At least one expanded ELF compatibility slice is implemented with paired
      positive/negative fixtures and a documented proof obligation.
- [x] The runtime no longer requires an executable temporary pathname for the
      target handoff, or the task records a concrete blocking invariant and
      leaves the feature explicitly unsupported.
- [x] CI distinguishes proof/model checks from runtime smoke evidence and
      fails when a claimed matrix row lacks its required evidence.
- [x] A native ARM64 bionic userspace lane runs without AVD, Waydroid, QEMU, or
      native bridge, records pinned Termux source/image, rootfs, kernel,
      linker, and page-size evidence, and is represented in the matrix with
      its narrower scope clearly stated.
- [x] Existing managed tests continue to pass, and all changed behavior has
      regression coverage.

## Out of Scope

- Treating physical device runs, emulator runs, or vendor anecdotes as a
  substitute for the Host Contract and proof obligations.
- Adding product-visible Linux/Android profiles or vendor-specific modes.
- Expanding to non-AArch64 architectures, PE, Mach-O, or .NET assembly
  protection.
- Claiming support for an ELF type or entry model that is not covered by the
  resolved unified runtime contract.
- Stealth, anti-analysis, detection evasion, or malware-oriented behavior.

## Resolved Decision

- The first implementation targets an in-process AArch64 `ET_DYN` entry image.
  The runtime must not replace the host process or require an executable
  temporary pathname.
- The entry surface is an explicit, versioned `HostContext` ABI. Existing
  standalone executable fixtures require an adapter or a separately compiled
  entry image; the runtime will not emulate a kernel `_start` environment.
- Add a native ARM64 bionic userspace evidence lane based on the pinned
  Termux Docker source/image as a host case, not as a product profile or a
  replacement for complete Android app/device evidence. The matrix records
  bionic beside glibc and musl as a runtime fact.
