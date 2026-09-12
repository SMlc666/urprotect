# urprotect

`urprotect` is **UrProtect Validator 0.1**, a C#/.NET command-line product for
conservative ELF64 AArch64 validation. It validates supported `ET_DYN` PIE
executables and dynamically linked shared objects, emits a stable JSON report,
and can produce a byte-identical no-op copy.

It does not yet implement binary protection transformations, relocation
rewriting, runtime injection, code encryption, or control-flow virtualization.

## Build

The project targets .NET 8 and keeps AArch64 decoding behind a project-owned
AsmStone adapter. The pinned AsmStone implementation is integrated separately
from the ELF model so the parser does not depend on a general-purpose ELF
library.

The vendored AsmStone revision and its attribution files are under
`third_party/AsmStone`. The project uses AsmStone only through the adapter and
does not duplicate its generated AArch64 instruction catalog.

```sh
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
```

## Quickstart

Validate an AArch64 ELF and print the human-readable result:

```sh
urprotect validate ./program
```

Create a safe no-op copy and a machine-readable report:

```sh
urprotect validate ./program \
  --copy ./program.checked \
  --json ./program.report.json
```

Stream exactly one JSON document to stdout:

```sh
urprotect validate ./program --json - --no-analysis > report.json
```

Exit codes are stable: `0` success, `2` usage, `3` filesystem failure, `4`
invalid/unsupported ELF, `5` output identity/publication failure, and `10`
unexpected internal failure. The `--copy` path never serializes the parsed
model; it publishes only after byte-for-byte identity is proven.

This release does not rewrite code, encrypt code, inject runtime logic,
virtualize control flow, or claim physical Android-device compatibility.

Release bundles are produced only for native ARM64 glibc and musl profiles:

```sh
./scripts/package-release.sh 0.1.0 .artifacts/release
./scripts/release-smoke.sh .artifacts/release
```

Each archive contains the single-file executable, supported-boundary README,
third-party notices, provenance, and an SBOM-equivalent inventory. The musl
bundle must be smoke-tested in an environment providing
`/lib/ld-musl-aarch64.so.1`.

## Fixture Matrix

The fixture manifest covers a small, explicit set of ELF producers instead of
claiming a full language/toolchain Cartesian product:

```sh
./scripts/run-fixture-matrix.sh --profile pr
./scripts/run-fixture-matrix.sh --profile nightly
```

The native Linux fixture runner builds and executes C/C++ (GCC and LLVM/Clang),
Rust, Go, musl-gcc, Zig, and NativeAOT samples. Nightly ARM64 CI installs
Ubuntu Noble musl packages at the pinned `1.2.4-2` version and Zig 0.13.0 from
the official checksum-verified archive before running the required profiles.
Each executable is validated and copied through the no-op CLI, then the
baseline and copied output behavior are compared. A missing required toolchain
or invalid output fails the job rather than falling back to glibc; only the
Android profile is handled by the separate Android runtime job.

The Android sample is an APK/JNI fixture. The released Android Emulator cannot
boot an `arm64-v8a` system image on an x86_64 host, even with `-accel off`. On
the GitHub x86_64 runner the project therefore uses an x86_64 API 35 AVD in
TCG/software CPU mode with Android's `libndk_translation.so` native bridge to
load the arm64-v8a library:

```sh
./scripts/run-android-avd.sh
```

The script never claims physical-device, native ARM64 hardware, or a full
ARM64 Android guest. It exercises bionic, the Android linker,
`System.loadLibrary`, and JNI with an AArch64 native library through the
native-bridge translation path. If the host lacks Android command-line tools,
an emulator, or Gradle, it records an `ANDROID_AVD_UNAVAILABLE` report instead
of silently skipping the capability.

The native-bridge AVD job is intentionally optional for manual CI runs because
software-emulated boot can take many minutes. Scheduled runs execute it
automatically, and published releases execute the release validation tier; use
the `run_android_native_bridge` workflow-dispatch input to opt in when manually
validating the Android path. Core build/test and native fixture jobs do not
depend on this optional manual job.

Native CI jobs retain an environment manifest with the host architecture,
kernel/libc, page size, toolchain versions, and emulation indicators. Native
ARM64 jobs fail if the runner is not `aarch64`; the Android native-bridge job
records its x86_64 host and translated execution mode separately. Fixture,
benchmark, and Android evidence is uploaded even when the job fails.

## CI Cache Policy

CI caches NuGet packages from the pinned project lock files, while
`gradle/actions/setup-gradle` owns Gradle caching. The Android job restores its
SDK cache before Android setup into a runner-writable SDK root and caches only
the pinned command-line tools, API 35 emulator, platform-tools, build-tools,
CMake, NDK, and x86_64 Google APIs system-image directories. Build outputs,
APKs, and AVD runtime state are intentionally not cached. Android cache
hit/miss status is reported in the workflow summary; clean AVD snapshot caching
remains deferred until it has a deterministic reset contract. The SDK cache
uses a writable runner-temp root rather than the root-owned preinstalled SDK;
this avoids tar permission failures during cache restore.

## CLI

```sh
dotnet run --project src/UrProtect.Cli -- validate ./program --copy ./program.checked
```

The copy path is published only after the output bytes have been compared with
the input. Unknown or unsupported data is never rebuilt by the no-op pipeline.
