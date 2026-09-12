# Implementation Plan

This checklist is for the infrastructure-only MVP. Do not run `task.py start` until the planning artifacts have been reviewed and approved.

## 1. Bootstrap and repository contracts

- [x] Confirm the repository layout and add a .NET solution targeting the pinned SDK/runtime chosen for AsmStone compatibility.
- [x] Add build-wide settings for nullable/reference safety, analyzers, deterministic builds, warnings-as-errors policy, and test categories.
- [x] Record the pinned AsmStone revision and dependency/license provenance.
- [x] Create separate production, test, fixture, benchmark, and CI/tooling boundaries; do not put fixture generation into runtime parsing code.
- [x] Define the CLI/report contract for validate, analyze, and optional no-op copy operations.

Validation:

```text
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build
```

Rollback point: retain the empty solution and dependency lock before adding parser behavior.

## 2. Binary primitives

- [x] Implement bounded byte reads and immutable slices.
- [x] Implement explicit little-endian integer decoding and checked address/range arithmetic.
- [x] Add property tests for range containment, overflow, empty ranges, and offset/length conversions.
- [x] Add diagnostics that retain source offset, field name, and stable error code.

Validation:

```text
dotnet test --filter Category=Binary
dotnet test --collect:"XPlat Code Coverage"
```

Rollback point: binary primitives must be independently usable before ELF parsing is added.

## 3. ELF header and program-header model

- [x] Add immutable models for the ELF header and program headers.
- [x] Parse only after all header/table ranges pass bounds checks.
- [x] Validate the agreed `ELF64`/little-endian/AArch64/`ET_DYN` profile.
- [x] Make section headers optional for runtime analysis.
- [x] Model unknown program types and extended numbering as explicit results.
- [x] Add valid, truncated, overflowed, stripped, and unknown-extension fixtures.

Validation:

```text
dotnet test --filter Category=ElfHeader
```

Risk: over-rejecting valid page-boundary segment layouts. Keep segment overlap policy in one validator and compare fixtures with `readelf`/`llvm-readelf`.

## 4. LoadMap and dynamic metadata

- [x] Implement file-offset, ELF-virtual-address, and runtime-address value types.
- [x] Build `LoadMap` only from validated `PT_LOAD` records.
- [x] Parse and bounds-validate `PT_DYNAMIC`, interpreter, TLS, RELRO, GNU property, EH frame, stack, and note program-header records; specialized TLS/property semantics remain raw/deferred.
- [x] Add bounded string, hash, symbol, dynamic-tag, and relocation-table views.
- [x] Add symbol-version views for `DT_VERSYM`/`DT_VERNEED` with bounded chain traversal and malformed-input tests.
- [x] Recognize common AArch64 RELA, RELR, Android RELR, and legacy Android packed-relocation forms without applying or rewriting them.
- [x] Add raw-preservation tests for unknown tags and unmodeled payloads.

Validation:

```text
dotnet test --filter Category=ElfMetadata
readelf -hW -lW -dW <fixture>
llvm-readelf -hW -lW -dW <fixture>
```

Rollback point: keep metadata parsing read-only until all table-range tests are stable.

## 5. AsmStone adapter and AArch64 analysis

- [x] Add the pinned AsmStone dependency behind a local adapter.
- [x] Map decode outcomes into project-owned records and diagnostics.
- [x] Scan only executable `PT_LOAD` file-backed bytes.
- [x] Add conservative entrypoint/symbol/relocation candidate discovery.
- [x] Classify the selected branch, PC-relative, literal, and common load/store instruction families.
- [x] Preserve unknown instructions and unresolved indirect control flow as explicit boundaries.
- [x] Add small contract vectors, not an exhaustive duplicate ISA suite.

Validation:

```text
dotnet test --filter Category=Aarch64Adapter
```

Risk: an AsmStone defect must produce a minimized upstream reproducer, not a permanent local opcode fork.

## 6. No-op validation pipeline

- [x] Orchestrate parse, validate, LoadMap construction, metadata indexing, analysis, and report generation.
- [x] Add optional source-to-destination byte copy without reserialization.
- [x] Compare source and destination bytes before publishing the destination.
- [x] Use a temporary destination and atomic publish semantics.
- [x] Add baseline/re-output tests for every fixture class.
- [x] Define which file metadata is copied or intentionally not promised; keep content byte identity mandatory.

Validation:

```text
dotnet test --filter Category=NoOp
cmp original.elf output.elf
```

## 7. Fixture generation and runtime harness

- [x] Add a manifest schema containing language, toolchain, linker, target triple, runtime, flags, artifact kind, expected features, and behavior oracle.
- [x] Implement minimal C/C++ GCC and Clang fixtures first.
- [x] Add musl, Rust, Go, Zig, NativeAOT, and NDK/JNI fixtures according to the priority matrix.
- [x] Keep source fixtures small and deterministic; store generated binaries only when required for regression or provenance.
- [x] Implement baseline and output execution with captured exit code, stdout, stderr, generated files, signals, and Android JNI results.
- [x] Add a `readelf` structural oracle comparison for ELF64 little-endian AArch64 `ET_DYN` fixture outputs without making the tool a runtime dependency; `llvm-readelf` remains an optional cross-check.

Validation:

```text
dotnet test --filter Category=Fixtures
./scripts/run-fixture-matrix.sh --profile pr
```

## 8. GitHub ARM64 CI

- [x] Add explicit native ARM64 Linux jobs for glibc and musl-loader execution; the current native-host fixture gate uses the pinned Ubuntu musl packages below.
- [x] Add a separately pinned ARM64 musl runtime container for an independent libc profile; the container smoke builds and validates a musl PIE through the CLI.
- [x] Add pinned checksum-verified native ARM64 musl-gcc and Zig provisioning for the nightly fixture job; do not fall back to QEMU, glibc, or another host architecture.
- [x] Add a runner/environment probe that records architecture, kernel, libc, page size, toolchain versions, and emulation indicators.
- [x] Add the Android container capability probe for Binder/BinderFS, namespaces/cgroups, LXC, and headless graphics prerequisites.
- [ ] Add matching ARM64 system/vendor image hashes and promote the container probe only after the hosted capability contract is available.
- [x] Add ARM64 AVD software-emulation smoke only with explicit `tcg`/`software` labeling and no KVM assumption.
- [x] Add x86_64-hosted x86_64-guest TCG E2E with the `arm64-v8a` native bridge for bionic, Android linker, `System.loadLibrary`, and JNI; keep it nightly/manual/release until stability is demonstrated. A full ARM64 Android guest remains a separate capability target because the released emulator rejects it on x86_64 hosts.
- [x] Make the slow native-bridge AVD job opt-in for manual workflow dispatches while retaining scheduled execution; core build/test and fixture jobs remain independent.
- [x] Add lockfile-keyed NuGet caching to all .NET CI jobs and an exact-package Android SDK cache to the x86_64 native-bridge job; keep Gradle caching owned by `setup-gradle` and exclude build outputs/AVD state.
- [x] Cancel superseded CI runs and report Android SDK cache hit/miss status in the workflow summary.
- [x] Measure cache hit rate and job timing across several scheduled/manual runs before considering clean AVD snapshot caching. The writable SDK-root cache reached an exact 3.0 GB hit on run `34594255238`; all jobs passed, while the Android TCG/JNI step remained dominated by the cold guest boot.
- [x] Fail required jobs when a claimed runtime profile silently falls back to an unsupported execution mode; native jobs enforce host architecture and the Android script verifies its explicit translated execution mode.
- [x] Upload logs, environment manifests, failing binaries/APKs, and linker output from fixture, benchmark, and Android jobs; minimized parser/fuzz inputs remain part of the fuzzing work below.

Validation:

```text
uname -m
dotnet --info
clang --version
gcc --version
```

The first Android-container workflow should be an explicit feasibility experiment. Promote it to a required gate only after the hosted runner capability is stable.

## 9. Fuzzing, coverage, and benchmarks

- [x] Add parser fuzz targets with bounded allocations and timeouts.
- [x] Seed deterministic malformed corpus entries for the current parser rejection classes, plus mutated valid ELF seeds.
- [x] Add coverage collection for project code and module-specific thresholds after a baseline run.
- [x] Add property/fuzz tests for parser/model invariants and no-op byte identity.
- [x] Add native ARM64 benchmarks for parse, map, metadata, analysis, copy, allocations, and peak memory.
- [x] Store benchmark results with runner image, SDK, Git SHA, and fixture manifest hash metadata in the CI artifact; historical comparison remains a release-process concern.

Validation:

```text
dotnet test --collect:"XPlat Code Coverage"
dotnet run --project <benchmark-project> --configuration Release
```

## 10. Final planning and review gate

- [ ] Run the PRD convergence pass and remove temporary brainstorm wording.
- [ ] Confirm `design.md` and `implement.md` match the final PRD without contradictory scope.
- [ ] Curate `implement.jsonl` and `check.jsonl` with real applicable spec/research entries.
- [ ] Run repository checks for task artifacts and manifest syntax.
- [ ] Present the final planning summary to the user.
- [ ] Only after a subsequent explicit approval, run `python3 ./.trellis/scripts/task.py start` and begin implementation.

Rollback point: if feasibility, fixture scope, or no-op identity cannot be demonstrated, return to planning rather than widening the MVP.
