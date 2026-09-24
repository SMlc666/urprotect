# Expand Outer AArch64 ELF Wrapper Coverage

## Goal

Expand the `outer-execveat` profile across real AArch64 ELF producers and input
classes while preserving the original program's observable behavior.

## Dependencies

- P0 current packaging contract and profile selection must be complete.
- P2-P4 HostContext semantics are outside this child unless a fixture exposes a
  separate outer-wrapper observation.

## Requirements

- Inventory current `ElfParser`, `ElfValidator`, and `ElfPackService` rejection
  boundaries against real AArch64 producer outputs.
- Add positive fixtures for stripped and sectionless images, realistic PT_LOAD
  layouts/alignment, and representative GCC, Clang, Rust, Go, Zig, musl,
  glibc, bionic, and NativeAOT outputs where the toolchain is available.
- Evaluate dynamic PIE, static PIE, static ET_EXEC, and shared object inputs as
  separate contracts; parseability alone does not establish launchability.
- For every newly accepted class, retain baseline/wrapped comparisons for exit
  status, stdout, stderr, argv, environment, signals, and relevant file
  observations.
- Keep unsupported classes explicit in the matrix with a paired negative
  witness and a reason tied to the launch contract.

## Acceptance criteria

- [ ] Every accepted input class has a model rule, positive producer fixture,
      paired boundary test, execution oracle, and retained evidence path.
- [ ] Wrapper bytes remain integrity-checked and are published atomically.
- [ ] The native interpreter, not an accidental host fallback, executes the
      recovered AArch64 image.
- [ ] Runtime-specific claims are separated for glibc, musl, and bionic.
- [ ] Shared objects receive an explicit entry/lifecycle result rather than
      being treated as ordinary executables.
- [ ] The rendered matrix distinguishes parser, outer-wrapper, and runtime
      evidence for each new case.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```
