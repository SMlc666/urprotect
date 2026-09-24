# Coverage-guided fuzzing research

## Decision

Use SharpFuzz `2.3.0` instrumentation with the pinned SharpFuzz.Common `2.2.0`
runtime dependency and the libFuzzer bridge for the first managed
coverage-guided targets. The repository includes a small MIT compatibility
runner that uses file-backed mmap instead of SysV IPC; this is required on the
current native ARM64 kernel while preserving SharpFuzz's trace bitmap signal.
Keep the existing deterministic xUnit random/mutation tests as a separate
regression layer.

## Evidence inspected

- SharpFuzz's repository documents `Fuzzer.LibFuzzer.Run(ReadOnlySpanAction)`
  and a separate libFuzzer runner on Linux.
- The repository's libFuzzer instructions build the bridge with
  `clang -fsanitize=fuzzer` and run it against an instrumented managed
  assembly.
- The SharpFuzz package page reports current `net8.0` compatibility and
  version `2.3.0`; the package and libfuzzer-dotnet repositories expose MIT
  license files.
- The project already pins the .NET SDK and package lock files, has clang in
  its native fixture environment, and retains CI artifacts. The fuzz job must
  still verify the exact compiler/package/source inputs rather than relying on
  an ambient tool.
- The current ARM64 host reports `ENOSYS` for the upstream bridge's SysV
  `shmget` path. A file-backed mmap transport was implemented and exercised;
  both ELF and payload-frame targets reported libFuzzer coverage counters and
  completed bounded runs.

## Consequences

- A separate fuzz console project avoids changing xUnit process behavior and
  allows libFuzzer's process-level timeout/RSS controls.
- The runner downloads the pinned bridge source, verifies its SHA-256, applies
  the checked-in portability patch, records the compiler and run manifest, and
  fails visibly when the bridge or instrumented target cannot be prepared.
- SharpFuzz instrumentation and libFuzzer coverage are distinct from
  Coverlet's line/branch report. The coverage floor remains a separate CI
  contract; fuzz evidence records the fuzzer's corpus/coverage artifacts.
- If the bridge cannot be made reproducible on the pinned ARM64 runner, stop at
  the research gate and record the exact blocker before selecting a different
  engine; do not relabel the current random loop as coverage-guided fuzzing.

## Sources

- https://github.com/Metalnem/sharpfuzz
- https://github.com/Metalnem/sharpfuzz/blob/master/docs/libFuzzer.md
- https://github.com/Metalnem/libfuzzer-dotnet
- https://www.nuget.org/packages/SharpFuzz
<!-- End of task artifact. -->
