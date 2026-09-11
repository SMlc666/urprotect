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

The Android script uses an x86_64 API 35 AVD on an x86_64 runner with
`-accel off` and software graphics. The APK contains only the `arm64-v8a`
library, and the guest must expose `libndk_translation.so` plus the ARM64 ISA
mapping before this is counted as native-bridge coverage. Missing SDK, AVD,
emulator, or Gradle tools produces `ANDROID_AVD_UNAVAILABLE` evidence; boot,
install, ABI, native-bridge, linker, or JNI failures remain test failures. The
result must not be presented as physical-device, native-hardware, or full
ARM64-guest validation.

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
