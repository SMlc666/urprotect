# Quality Guidelines

> Code quality standards for backend development.

---

## Overview

<!--
Document your project's quality standards here.

Questions to answer:
- What patterns are forbidden?
- What linting rules do you enforce?
- What are your testing requirements?
- What code review standards apply?
-->

Production code targets .NET 8 with nullable reference types, analyzers,
deterministic builds, warnings as errors, and locked restore. Keep the MVP
read-only and preserve unknown ELF data; do not add speculative rewrite paths.

---

## Forbidden Patterns

<!-- Patterns that should never be used and why -->

Do not use a general-purpose ELF library in the runtime parser, unchecked casts
from ELF counts to array sizes, duplicated address conversion helpers, local
opcode workarounds for AsmStone gaps, or silent fallback from native ARM64 to
QEMU/emulation in a required CI job.

---

## Required Patterns

<!-- Patterns that must always be used -->

Use immutable/bounds-checked binary reads, project-owned adapter DTOs, typed
diagnostic codes, and explicit file/virtual/runtime address types. Pin AsmStone
and preserve its license/source notices. Keep fixture and benchmark tooling
outside production parsing code.

---

## Testing Requirements

<!-- What level of testing is expected -->

Every parser or pipeline change needs focused unit tests plus malformed-input
coverage. New ELF behavior should include a valid fixture, a rejection fixture,
and an external `readelf`/`llvm-readelf` comparison when applicable. No-op
output tests must compare bytes, and runtime tests must compare observable
behavior rather than addresses affected by ASLR.

Coverage is measured for project code, not AsmStone internals. Track line and
branch coverage, with higher error-path expectations for binary primitives,
LoadMap, relocation indexing, and output publication. Benchmarks record
throughput, allocations, and peak memory on native ARM64 Linux.

---

## Code Review Checklist

<!-- What reviewers should check -->

Reviewers must check:

- all offsets, sizes, counts, and address arithmetic are checked;
- program headers remain authoritative when sections are absent;
- unknown data and instructions are preserved/reported rather than guessed;
- diagnostics fail closed at the correct boundary;
- no-op output is byte-identical and atomically published;
- CI records runner/toolchain/emulation metadata and does not hide failures;
- tests cover the changed behavior and the relevant rejection path.

## Fixture and Android CI Contract

The manifest at `fixtures/manifest.json` is the single source of truth for
language/toolchain profiles. `scripts/validate-fixtures.py` must reject
duplicate/unsafe IDs, missing fields, unsupported tiers, and source paths that
escape the repository. `scripts/run-fixture-matrix.sh` must execute selected
native profiles only on `aarch64`, validate/copy every produced ELF through the
CLI, and compare baseline/no-op exit status and stdout/stderr. Optional profile
toolchain failures are explicit `SKIP` records only for optional profiles;
required nightly musl-gcc, Zig, and NativeAOT profiles fail the job. The
nightly ARM64 job must install the pinned Ubuntu Noble musl packages and the
checksum-verified Zig archive before invoking the matrix; it must not silently
substitute glibc, QEMU, or another host architecture.

Native Linux jobs must invoke `.github/scripts/record-environment.sh` with an
expected `aarch64` host and retain its atomic key-value report as a CI artifact.
The probe records the kernel, libc, page size, runner image, emulation
indicators, and available tool versions; an architecture mismatch fails the
job rather than being relabeled as native execution. The x86_64 Android
native-bridge job records its separate `x86_64` host and explicit translated
execution mode.

The independent musl-container smoke uses the pinned platform-specific
`mcr.microsoft.com/dotnet/sdk` ARM64 Debian digest matching the pinned .NET SDK
in the workflow, bootstraps
the repository without relying on a host checkout, and runs the product CLI
against a dynamically linked musl PIE. The container must report `aarch64`,
retain its image digest, and fail on baseline/no-op behavior or byte-identity
mismatch; it is not allowed to silently run the glibc host fixture instead.

The Android script uses an x86_64 API 35 AVD on an x86_64 runner with
`-accel off` and software graphics. The APK contains only the `arm64-v8a`
library, and the guest must expose `libndk_translation.so` plus the ARM64 ISA
mapping before this is counted as native-bridge coverage. Missing SDK, AVD,
emulator, or Gradle tools produces `ANDROID_AVD_UNAVAILABLE` evidence; boot,
install, ABI, native-bridge, linker, or JNI failures remain test failures. The
result must not be presented as physical-device, native-hardware, or full
ARM64-guest validation.

The Android container probe receives pinned Waydroid ARM64 system/vendor image
URLs and SHA-256 values from `fixtures/manifest.json`. It verifies local image
files when provisioned and reports missing files/checksum mismatches as
capability evidence; until Binder/LXC/graphics and both matching images are
available, the probe remains informational and must not claim bionic E2E.

The slow native-bridge AVD job is optional on manual `workflow_dispatch` runs:
the `run_android_native_bridge` boolean input defaults to `false`. Scheduled
runs retain automatic Android coverage, while core build/test and fixture jobs
must remain independent of the optional AVD job.

Fixture, benchmark, and Android jobs upload their environment and runtime
evidence with `if: always()`. Build outputs and AVD state remain excluded from
cache paths; failure artifacts may include logs, ELF/APK outputs, linker
diagnostics, and toolchain manifests.

## CI Cache Contract

`actions/setup-dotnet` owns the NuGet cache for every job that restores the
solution. Its key must hash `global.json` and all project `packages.lock.json`
files, while restore remains `--locked-mode`. `gradle/actions/setup-gradle`
owns Gradle caching; do not add a second cache for `~/.gradle`.

The Android native-bridge job may cache only the pinned SDK package
directories: command-line tools, emulator, platform-tools, API 35
platform/build-tools, CMake 3.22.1, NDK 27.2.12479018, and the API 35 Google
APIs x86_64 system image.
The SDK root must be a runner-writable directory such as `${{ runner.temp }}`;
do not restore an archive over root-owned preinstalled SDK paths. The key must
include the runner OS/architecture, manifest/script inputs, and the cache
schema version. Do not cache `bin/`, `obj/`, Gradle build outputs, APK outputs,
or a running/dirty AVD. Cache hit/miss status belongs in the step summary so
timing regressions remain visible. A cache hit that falls back to a package
redownload or reports tar permission errors is not considered effective.

Parser fuzz smoke runs use `scripts/run-parser-fuzz.sh`, bounded random and
mutated-valid inputs, a maximum input size enforced by the test, and an
explicit process timeout. Fuzz results and minimized corpus additions belong
in CI artifacts; a fuzz failure must not be converted into a successful skip.

Symbol-version parsing must derive the `DT_VERSYM` extent from the bounded
dynamic-symbol count and must bound `DT_VERNEED` traversal by
`DT_VERNEEDNUM`. Version-chain offsets must make forward progress and names
must resolve through the validated dynamic string table; raw records remain
available without applying or rewriting them.

The product CLI owns stable exit codes and report schema serialization. JSON
stream mode (`--json -`) reserves stdout for one document, report files are
written through a flushed temporary sibling and atomic rename, and copy-mode
reports must use the same input snapshot passed to the no-op writer.

When a test project references a production project, its `packages.lock.json`
must be regenerated with `dotnet restore --force-evaluate` and committed. A
locked restore is required in CI and must fail on a stale project-reference
graph rather than silently updating it.

Release bundles must be self-contained single-file outputs built with the
matching pinned runtime identifier (`linux-arm64` or `linux-musl-arm64`). The
package script must validate ELF class/machine/interpreter, include third-party
notices and an SBOM-equivalent inventory, create relative checksum entries, and
use normalized tar ownership/order/timestamps. Release smoke must execute both
bundles on native ARM64, using the pinned ARM64 musl container when the host
does not provide all musl-compatible native dependencies.

The first packer is an outer wrapper only. `PayloadFrameCodec` owns the fixed
little-endian frame, deterministic deflate payload, source/encoded SHA-256
digests, bounded source basename, and overflow/size checks. `ElfPackService`
must reuse the existing parser/validator, accept only executable AArch64
`ET_DYN` inputs with a supported `PT_INTERP`, and publish a launcher-plus-frame
wrapper atomically. The launcher verifies the frame, extracts to a private
directory using the stored basename, preserves the argument/environment
contract through `execve`, and fails closed before launching on corruption.
It must not become an in-process ELF loader, use payload-controlled directory
paths, encrypt code, or add stealth behavior. `scripts/run-packed-fixture-matrix.sh`
must run the native ARM64 glibc PR covering set and compare baseline/wrapper
status and standard streams; `scripts/run-musl-container-smoke.sh` owns the
pinned ARM64 musl payload smoke using the same static native launcher. The
recovered fixture must still enter through the musl interpreter, and
launcher/compiler/provenance evidence must be retained. `pack` requires the
native launcher explicitly and never falls back to the C# packer executable.

## Scenario: Wrapper 0.2 native launcher build and handoff

### 1. Scope / Trigger

- Trigger: building or packaging the static AArch64 runtime used by `pack`.

### 2. Signatures

```text
make -C native/urprotect-launcher CC=musl-gcc all self-test
urprotect pack INPUT --output OUTPUT --launcher NATIVE_LAUNCHER
```

### 3. Contracts

- `CC=musl-gcc` compiles against the pinned ARM64 musl headers and libraries;
  the link step uses the checked-in `musl-static-pie.specs` fragment after the
  distribution specs so `rcrt1.o` is selected.
- Link flags include `-static-pie`, `--no-dynamic-linker`, no build ID, section
  garbage collection, RELRO, immediate binding, and stripped symbols.
- The output is ELF64 little-endian AArch64 `ET_DYN`, has an executable entry
  `PT_LOAD`, contains `URPROTECT-AARCH64-LAUNCHER-V1`, and has no `PT_INTERP`
  or `DT_NEEDED` entries.
- Provenance records ABI/marker, compiler and linker inputs, specs hashes,
  miniz commit/file hashes, source revision, `SOURCE_DATE_EPOCH`, and the
  resulting launcher hash.

### 4. Validation & Error Matrix

- missing compiler, base specs, or native ARM64 host -> required job failure;
- injected interpreter or shared dependency -> `LauncherUnavailable` / build
  validation failure;
- missing `--launcher` -> `LauncherUnavailable` and no wrapper output;
- malformed frame, digest mismatch, unsafe basename, or failed `execve` ->
  stable non-zero launcher diagnostic and no payload launch.

### 5. Good/Base/Bad Cases

- Good: pinned musl-gcc plus the static-PIE specs fragment produces one
  launcher that executes on both glibc and musl ARM64 hosts.
- Base: older musl specs inject a dynamic interpreter unless the fragment and
  explicit no-dynamic-linker flag are applied.
- Bad: a dynamic PIE, unrelated static PIE, host-architecture binary, or
  launcher without the frozen marker is rejected before frame generation.

### 6. Tests Required

- native self-test asserts SHA-256 vectors and raw-deflate output;
- native integration asserts arguments, `argv[0]`, environment, cwd, files,
  stdout/stderr, status, signals, truncation, bounds, version, flags, digest,
  interpreter, and deflate failures;
- pack tests assert marker/ABI/hash report fields, atomic output, deterministic
  bytes, and rejection of unmarked or dynamic launchers;
- ARM64 CI runs the packed glibc matrix and the pinned musl container smoke,
  retaining launcher, frame, wrapper, environment, and failure logs.

### 7. Wrong vs Correct

#### Wrong

```text
musl-gcc -static-pie objects.o -o urprotect-launcher
```

#### Correct

```text
make -C native/urprotect-launcher CC=musl-gcc \
  MUSL_STATIC_PIE_SPECS="$PWD/native/urprotect-launcher/musl-static-pie.specs" \
  all self-test
```
