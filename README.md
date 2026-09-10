# urprotect

`urprotect` is a C#/.NET infrastructure foundation for conservative ELF64
AArch64 analysis. The current MVP is intentionally read-only: it validates
supported `ET_DYN` PIE executables and dynamically linked shared objects,
reports bounded ELF metadata, and can emit a byte-identical copy.

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

## Fixture Matrix

The fixture manifest covers a small, explicit set of ELF producers instead of
claiming a full language/toolchain Cartesian product:

```sh
./scripts/run-fixture-matrix.sh --profile pr
./scripts/run-fixture-matrix.sh --profile nightly
```

The native Linux fixture runner builds and executes C/C++ (GCC and LLVM/Clang),
Rust, Go, Zig, and NativeAOT samples when the pinned/hosted toolchain is
available. Each executable is validated and copied through the no-op CLI, then
the baseline and copied output behavior are compared. Optional profiles are
reported as `SKIP` with the reason; required PR profiles fail the job when
their toolchain is missing or their output is invalid.

The Android sample is an APK/JNI fixture. On the GitHub x86_64 runner it is
attempted in an explicitly software-emulated `arm64-v8a` AVD:

```sh
./scripts/run-android-avd.sh
```

The script never claims physical-device or native-hardware validation. It is
specifically intended to exercise bionic, the Android linker,
`System.loadLibrary`, and JNI with an AArch64 native library. If the host lacks
Android command-line tools, an emulator, or Gradle, it records an
`ANDROID_AVD_UNAVAILABLE` report instead of silently skipping the capability.

## CLI

```sh
dotnet run --project src/UrProtect.Cli -- validate ./program --copy ./program.checked
```

The copy path is published only after the output bytes have been compared with
the input. Unknown or unsupported data is never rebuilt by the no-op pipeline.
