# urprotect

`urprotect` is **UrProtect Validator 0.1** with the **AArch64 ELF Wrapper 0.2**
runtime shell, a C#/.NET command-line product for conservative ELF64 AArch64
validation and outer ELF packaging.
It validates supported `ET_DYN` PIE executables and dynamically linked shared
objects, emits a stable JSON report, can produce a byte-identical no-op copy,
and can wrap a supported executable in a new self-extracting AArch64 ELF.

The wrapper stores the complete source ELF as a deterministic compressed
payload, verifies its SHA-256 digest, writes it to an anonymous Linux memfd,
and uses `execveat(AT_EMPTY_PATH)` so the normal kernel/interpreter/dynamic
loader starts the original program. No executable temporary pathname is
created. It is an outer packaging and integrity result, not a custom ELF
loader or an in-process code protection transformation.

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
virtualize control flow, implement a custom in-process loader, or claim
physical Android-device compatibility.

The conditional compatibility claim and its proof boundary are documented in
[`COMPATIBILITY.md`](COMPATIBILITY.md). The machine-readable obligations and
evidence map live in `fixtures/manifest.json`.

## Current AArch64 Packaging Profiles

Pack a Linux ARM64 dynamically linked `ET_DYN` PIE executable with a
`PT_INTERP` interpreter through the explicit outer profile:

```sh
urprotect pack ./program \
  --output ./program.wrapped \
  --launcher ./urprotect-launcher \
  --profile outer-execveat \
  --json ./program.pack.json
```

Pack a declared HostContext entry image through its matching launcher:

```sh
urprotect pack ./entry-image.so \
  --output ./entry-image.host.wrapped \
  --launcher ./host-context-launcher \
  --profile host-context-entry \
  --entry-symbol urp_entry \
  --json ./entry-image.pack.json
```

Build the small native launcher on a native AArch64 host with the pinned musl
toolchain used by CI:

```sh
./native/urprotect-launcher/build.sh
./native/urprotect-launcher/build.sh test
```

The outer launcher is a static AArch64 `ET_DYN` PIE with no interpreter or
shared-library dependencies. The HostContext launcher is a profile-matched
AArch64 runtime executable that uses the sealed-memfd adapter. `pack` requires
an explicit profile-matched `--launcher`; it never silently turns the C# packer
into a runtime wrapper or falls back between profiles. Current production
packaging emits frame v3. Legacy v1/v2 behavior remains historical migration
evidence only and is rejected by current launchers.

The outer profile supports native ARM64 Linux glibc and is exercised by the PR
covering fixture matrix. The first HostContext production slice supports a
declared AArch64 `ET_DYN` entry image exposing `urp_entry` through the native
sealed-memfd adapter. Shared objects without the entry profile, static
`ET_EXEC`, Android/bionic production packaging, payload encryption, and full
custom in-process loading remain rejected or deferred. The frame stores a source basename for
`argv[0]`;
path separators are rejected and no payload directory is taken from the
environment. Both the native launcher and the managed self-contained host use
the same anonymous memfd handoff; the managed handoff has a dedicated ARM64
integration smoke.

Release bundles are produced only for native ARM64 glibc and musl runtime variants:

```sh
./scripts/package-release.sh 0.2.0 .artifacts/release
./scripts/release-smoke.sh .artifacts/release
```

Each archive contains the single-file executable, supported-boundary README,
third-party notices, provenance, and an SBOM-equivalent inventory. The musl
bundle must be smoke-tested in an environment providing
`/lib/ld-musl-aarch64.so.1`.

The release workflow also runs the musl bundle inside a pinned ARM64 musl
container when the host does not provide compatible C++/zlib runtime libraries.

## Regression profiles

The repository keeps a machine-readable regression map in
[`tests/regression-matrix.json`](tests/regression-matrix.json). Validate its
coverage and evidence schema with:

```sh
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
python3 tests/test_regression_matrix.py
```

The managed concurrency and large-input smoke profile is bounded and
deterministic:

```sh
./scripts/run-regression-stress.sh --tier pr
```

Nightly increases workers, iterations, and the multi-megabyte input profile;
both profiles retain a parameter manifest and test result artifact. The
coverage-guided fuzzer uses a pinned SharpFuzz/libFuzzer bridge and has
separate ELF and payload-frame targets:

```sh
./scripts/run-coverage-fuzz.sh --tier pr
./scripts/run-coverage-fuzz.sh --tier nightly
```

PR fuzzing uses a fixed seed and run count. Nightly and release profiles use a
bounded wall-clock budget, RSS limit, maximum input size, crash/timeout artifact
prefix, and retained corpus. The existing deterministic parser mutation tests
remain independent regression coverage. The fuzzer bridge uses a verified
file-backed mmap portability patch because some native ARM64 CI kernels do not
expose System V shared memory; this changes only the test transport, not the
instrumented coverage signal.

## Fixture Matrix

The fixture manifest covers a small, explicit set of ELF producers instead of
claiming a full language/toolchain Cartesian product:

```sh
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-fixture-matrix.sh --tier nightly
./scripts/run-fixture-matrix.sh --tier release
./scripts/run-packed-fixture-matrix.sh --tier pr
```

The native Linux fixture runner builds and executes C/C++ (GCC and LLVM/Clang),
Rust, Go, musl-gcc, Zig, and NativeAOT samples. Nightly ARM64 CI installs
Ubuntu Noble musl packages at the pinned `1.2.4-2` version and Zig 0.13.0 from
the official checksum-verified archive before running the required tiers.
Each executable is validated and copied through the no-op CLI, then the
baseline and copied output behavior are compared. The release tier adds one
explicit GCC C PIE hardening witness using the existing `gcc-c` builder; its
readelf oracle requires GNU RELRO and BIND_NOW, and the release CI job gates
its retained evidence separately from PR/nightly selection. A missing required
toolchain or invalid output fails the job rather than falling back to glibc;
Android and bionic lanes are handled by their separate runtime jobs.

The packed fixture runner first builds the native PR covering set and the
static native ARM64 launcher, runs the native codec/integration checks, packs
each executable, verifies that wrapper bytes differ, and compares
baseline/wrapped status and standard streams through the real loader.

The native bionic lane is separate from Android framework testing:

```sh
./scripts/run-bionic-fixture.sh
```

It runs the pinned `termux/termux-docker` ARM64 image and uses the live Termux
package index only to locate the exact compiler packages listed in
`fixtures/manifest.json`. Every newly installed package has a locked version,
repository-relative artifact name, SHA-256, license identifiers, and license
source; the lane verifies the downloaded set and every digest before installing
it, and fails if the package closure changes. The digest-pinned image fixes the
base package set. The lane builds an AArch64 PIE with `/system/bin/linker64`,
verifies normal execution and the linker's direct identity probe, and retains
the before/after package inventories, lock, hash-verification output, apt logs,
image digest, Termux source revision, linker identity, and page-size facts.
This makes the compiler inputs reproducible even though the index used to find
the pinned artifacts is live. The lane also builds and runs the native
HostContext self-test inside Termux: a current HostContext frame reaches the real
adapter, which checks sealed memfd bytes, dispatches `urp_entry`, and releases
the image without an executable temporary pathname. The result, build log,
shared-object ELF report, package lock, and hash verification are retained.
This validates the bionic implementation of the narrow adapter slice; the
managed production-pack row has its separate native-glibc v3 oracle. The lane
refuses AVD, Waydroid, QEMU, and
non-ARM fallback and does not claim Android framework or physical-device
behavior.

Render the same manifest into a reviewable matrix report:

```sh
python3 scripts/render-compatibility-matrix.py \
  fixtures/manifest.json --output .artifacts/compatibility-matrix.md
```

The Android sample is an APK/JNI baseline fixture, not a packed-output test.
The released Android Emulator cannot boot an `arm64-v8a` system image on an
x86_64 host, even with `-accel off`. On
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

## Public real-sample CI corpus

The repository also tracks a locked ecology corpus in
[`fixtures/real-samples/manifest.json`](fixtures/real-samples/manifest.json). It
contains exactly 20 distinct public AArch64 project identities, including
Debian/glibc applications, an Alpine/musl BusyBox rootfs, a public
Termux/bionic Node.js artifact, and real ET_EXEC boundaries. `candidates.json` retains rejected/deferred
public candidates and `selection.md` explains the feature/runtime covering
rationale. No raw archive or ELF binary is committed.

Local validation remains metadata-only and sample-free:

```sh
python3 scripts/validate-real-samples.py \
  fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 tests/test_real_sample_manifest.py
```

Every pull request runs the full 20-project suite on the native
`ubuntu-24.04-arm` runner; no affected-path or sample filter can reduce it.
Scheduled runs use the same registry and runner as `nightly`, and published
releases use it as `release`, adding retention/repeat strength without
replacing PR coverage. The CI-only runner downloads into `RUNNER_TEMP`, checks
archive and extracted-file SHA-256 values, rejects archive traversal, records a
bounded `readelf`/UrProtect report, compares ELF64/little-endian/AArch64/ET_DYN
identity and interpreter against the registry policy, and removes raw inputs
on exit. It never uploads the downloaded archive, ELF, or runtime rootfs.

The result gate distinguishes `accepted-and-runs`, `expected-rejected`,
`unexpected-rejection`, `unexpected-acceptance`, `runtime-failure`,
`environment-unavailable`, and `not-applicable`. A missing isolation capability
for an applicable oracle fails the required CI gate. Ordinary packages are
explicitly `not-applicable` to HostContext unless they declare `urp_entry`; a
real-sample observation discovers or locks a regression and does not
automatically promote an ELF/HostContext support claim.

Compatibility changes must include a real-sample impact table in the plan:
project IDs, feature/layer, oracle, expected result, and evidence path. A new
support claim still requires a controlled positive fixture, nearest-negative
fixture, stable diagnostic, layer-specific oracle, contract update, and
retained real-sample evidence.

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

`dotnet run` is suitable for validation and packing when paired with the
native launcher. For `pack`, pass the static ARM64 launcher with `--launcher`;
a framework host such as `dotnet` and the C# packer itself are never used as
the wrapper launcher.

The copy path is published only after the output bytes have been compared with
the input. Unknown or unsupported data is never rebuilt by the no-op pipeline.
