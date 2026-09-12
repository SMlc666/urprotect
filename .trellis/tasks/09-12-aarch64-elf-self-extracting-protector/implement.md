# Implementation Plan

Do not run `task.py start` until this plan and the final planning summary are
reviewed and explicitly approved.

## 1. Contracts and launcher decision

- [x] Add the pack command, stable option grammar, and product error mapping.
- [x] Freeze the payload frame version, compression identifier, size limits,
  digest fields, and launcher ABI.
- [x] Choose and pin the AArch64 launcher template/toolchain with a checked-in
  provenance record and license notices.
- [x] Document the supported interpreter/runtime profile and reject shared
  objects, static inputs, non-PIE `ET_DYN`, other architectures, and Android.

Validation:

```text
python3 ./.trellis/scripts/task.py validate .trellis/tasks/09-12-aarch64-elf-self-extracting-protector
dotnet restore UrProtect.sln --locked-mode
```

Rollback: retain the validator-only CLI and do not add a partial pack command.

## 2. Payload frame

- [x] Implement immutable frame records and bounded little-endian encode/decode.
- [x] Add deterministic compression and exact source/encoded SHA-256 checks.
- [x] Enforce source, encoded, header, and wrapper limits before allocation.
- [x] Add stable diagnostics for magic/version/flags/architecture/bounds/hash
  failures and distinguish corruption from unsupported format.
- [x] Add focused tests for round trips, overflow, truncation, and malformed
  frames.

Validation:

```text
dotnet test --filter Category=PackFrame
dotnet test --filter Category=PackMalformed
```

Rollback: keep frame code independent of ELF output and launcher execution.

## 3. Wrapper builder

- [x] Add a bounded launcher-plus-trailing-frame wrapper API.
- [x] Preserve the launcher's valid `PT_LOAD`, `PT_INTERP`, alignment, W^X, and
  `ET_DYN` invariants without rebuilding its program headers.
- [x] Never serialize the source `ElfFile` or copy its program headers into the
  wrapper.
- [x] Implement destination-local temporary output and atomic publication.
- [x] Add structural parser tests and deterministic payload/wrapper byte tests.

Validation:

```text
dotnet test --filter Category=PackWrapper
readelf -hW -lW -dW <wrapped>
cmp <recovered-payload> <input>
```

Risk: template or linker changes can silently alter the launcher ABI. Pin the
template revision and reject incompatible frame versions.

## 4. Runtime launcher

- [x] Implement fixed-frame discovery without trusting user-controlled paths.
- [x] Verify all frame fields and both digests before extraction.
- [x] Extract with restrictive permissions, flush, and safely handle cleanup.
- [x] Preserve arguments, environment, working directory, inherited streams,
  and exit/signal behavior through `execve`.
- [x] Reject integrity, architecture, size, and decompression failures without
  launching the payload.
- [x] Add frame and native launcher tests for tamper, truncation, wrong
  architecture, and pre-exec failure paths.

Validation:

```text
dotnet test --filter Category=PackLauncher
./scripts/run-packed-fixture-matrix.sh --profile pr
```

Rollback: retain the wrapper artifact but disable runtime execution if the
launcher cannot prove pre-exec integrity.

## 5. CLI and report integration

- [x] Add `pack <input> --output <wrapper>` and optional JSON report output.
- [x] Reuse the existing validator snapshot and report diagnostic projection.
- [x] Ensure invalid inputs, output conflicts, and failed wrapper publication
  leave no output artifact.
- [x] Add CLI tests for success, usage, filesystem, validation, frame, and
  internal error classes.
- [x] Add pack report coverage with source/wrapper sizes, hashes, codec, and
  launcher ABI, without absolute paths by default.

Validation:

```text
dotnet test --filter Category=PackCli
```

## 6. Native fixture and runtime E2E

- [x] Add a packed fixture runner for the existing executable covering set and
  expected behavior outputs.
- [x] Run baseline and wrapper with identical arguments/environment/cwd.
- [x] Compare exit status, stdout, stderr, signals, and declared generated
  files; do not compare ASLR addresses or process timing.
- [x] Cover representative GCC/Clang, Rust, and Go PIE fixtures in PR/native
  ARM64 glibc.
- [ ] Verify the musl wrapper path in the pinned ARM64 container smoke.
- [x] Preserve wrapped ELF, recovered payload metadata, logs, and environment
  evidence for every failure.

Validation:

```text
./scripts/run-packed-fixture-matrix.sh --profile pr
./scripts/run-packed-fixture-matrix.sh --profile nightly
```

## 7. CI, reproducibility, and documentation

- [x] Add pack tests to fast PR gates and native pack E2E to ARM64 integration.
- [x] Add pinned musl-container pack E2E to nightly/release tiers.
- [x] Add deterministic wrapper-byte comparison; retain launcher/toolchain
  provenance through the self-contained publish and release manifests.
- [x] Keep Android and shared-object paths visibly rejected/deferred.
- [x] Document that this is an outer packaging/integrity shell, not encrypted
  code protection or a custom dynamic loader.
- [x] Update backend specs with frame, wrapper, and runtime handoff contracts.

Validation:

```text
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test UrProtect.sln --configuration Release --no-build
python3 scripts/check-coverage.py
git diff --check
```

## 8. Final review gate

- [ ] Run the PRD convergence pass and ensure no unresolved product decisions
  remain.
- [ ] Validate `prd.md`, `design.md`, `implement.md`, `implement.jsonl`, and
  `check.jsonl`.
- [ ] Confirm the latest final planning summary with the user.
- [ ] Only after subsequent explicit approval run `task.py start`.
