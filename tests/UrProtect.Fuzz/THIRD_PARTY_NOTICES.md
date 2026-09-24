# Fuzzing dependencies

The fuzz target uses the following pinned MIT-licensed components:

- SharpFuzz instrumentation tool 2.3.0: the runner installs the exact
  `SharpFuzz.CommandLine` tool version. Source/license:
  https://github.com/Metalnem/sharpfuzz/blob/v2.3.0/LICENSE
- SharpFuzz.Common 2.2.0: the instrumenter emits this stable strong-named
  runtime dependency; the locked NuGet package carries the MIT expression and
  repository metadata. Source/license:
  https://github.com/Metalnem/sharpfuzz/blob/v2.2.0/LICENSE
- The local `third_party/SharpFuzzCompat/SharpFuzz` runner is a small MIT
  compatibility layer with the same public `Fuzzer.LibFuzzer` surface. It
  replaces the upstream SysV shared-memory transport with file-backed mmap for
  kernels where SysV IPC is unavailable.
- libfuzzer-dotnet `v2025.05.02.0904`: the runner downloads
  `libfuzzer-dotnet.cc` from the tag and verifies SHA-256
  `90f019e2e9ad3a0b93c7ecc2c5afb2fbfc8b5aab6aac51c7e0d349ec79354f36` before
  applies the checked-in file-backed-mmap portability patch, and compiles it
  with clang. Source repository:
  https://github.com/Metalnem/libfuzzer-dotnet

The generated fuzz executable and corpus are CI artifacts; they are not part
of the product runtime or compatibility claim.
