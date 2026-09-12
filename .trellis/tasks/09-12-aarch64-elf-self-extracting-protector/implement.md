# Implementation Plan

Do not run `task.py start` until this plan and the final planning summary are
reviewed and explicitly approved.

## 1. Contracts and launcher decision

- [ ] Add the pack command, stable option grammar, and product error mapping.
- [ ] Freeze the payload frame version, compression identifier, size limits,
  digest fields, and launcher ABI.
- [ ] Choose and pin the AArch64 launcher template/toolchain with a checked-in
  provenance record and license notices.
- [ ] Document the supported interpreter/runtime profile and reject shared
  objects, static inputs, non-PIE `ET_DYN`, other architectures, and Android.

Validation:

```text
python3 ./.trellis/scripts/task.py validate .trellis/tasks/09-12-aarch64-elf-self-extracting-protector
dotnet restore UrProtect.sln --locked-mode
```

Rollback: retain the validator-only CLI and do not add a partial pack command.

## 2. Payload frame

- [ ] Implement immutable frame records and bounded little-endian encode/decode.
- [ ] Add deterministic compression and exact source/encoded SHA-256 checks.
- [ ] Enforce source, encoded, header, and wrapper limits before allocation.
- [ ] Add stable diagnostics for magic/version/flags/architecture/bounds/hash
  failures and distinguish corruption from unsupported format.
- [ ] Add property tests for round trips, overflow, truncation, and random
  malformed frames.

Validation:

```text
dotnet test --filter Category=PackFrame
dotnet test --filter Category=PackMalformed
```

Rollback: keep frame code independent of ELF output and launcher execution.

## 3. Wrapper builder

- [ ] Add a fixed AArch64 wrapper template and a bounded patching API.
- [ ] Place launcher and read-only payload data into valid `PT_LOAD` regions;
  ensure `PT_INTERP`, alignment, W^X, and `ET_DYN` invariants.
- [ ] Never serialize the source `ElfFile` or copy its program headers into the
  wrapper.
- [ ] Implement destination-local temporary output and atomic publication.
- [ ] Add readelf/file structural oracle tests and deterministic byte tests.

Validation:

```text
dotnet test --filter Category=PackWrapper
readelf -hW -lW -dW <wrapped>
cmp <recovered-payload> <input>
```

Risk: template or linker changes can silently alter the launcher ABI. Pin the
template revision and reject incompatible frame versions.

## 4. Runtime launcher

- [ ] Implement fixed-frame discovery without trusting user-controlled paths.
- [ ] Verify all frame fields and both digests before extraction.
- [ ] Extract with restrictive permissions, flush, and safely handle cleanup.
- [ ] Preserve arguments, environment, working directory, inherited streams,
  and exit/signal behavior through `execve`.
- [ ] Reject integrity, architecture, size, and decompression failures without
  launching the payload.
- [ ] Add launcher-level tests for tamper, truncation, wrong architecture, and
  pre-exec failure paths.

Validation:

```text
dotnet test --filter Category=PackLauncher
./scripts/run-packed-fixture-matrix.sh --profile pr
```

Rollback: retain the wrapper artifact but disable runtime execution if the
launcher cannot prove pre-exec integrity.

## 5. CLI and report integration

- [ ] Add `pack <input> --output <wrapper>` and optional JSON report output.
- [ ] Reuse the existing validator snapshot and report diagnostic projection.
- [ ] Ensure invalid inputs, output conflicts, and failed wrapper publication
  leave no output artifact.
- [ ] Add CLI tests for success, usage, filesystem, validation, frame, and
  internal error classes.
- [ ] Add golden pack reports with source/wrapper sizes, hashes, codec, and
  launcher ABI, without absolute paths by default.

Validation:

```text
dotnet test --filter Category=PackCli
```

## 6. Native fixture and runtime E2E

- [ ] Extend the manifest with packable executable profiles and expected
  behavior/file outputs.
- [ ] Run baseline and wrapper with identical arguments/environment/cwd.
- [ ] Compare exit status, stdout, stderr, signals, and declared generated
  files; do not compare ASLR addresses or process timing.
- [ ] Cover representative GCC/Clang, Rust, and Go PIE fixtures in PR/native
  ARM64 glibc; cover musl in the pinned ARM64 container nightly/release.
- [ ] Preserve wrapped ELF, recovered payload metadata, logs, and environment
  evidence for every failure.

Validation:

```text
./scripts/run-packed-fixture-matrix.sh --profile pr
./scripts/run-packed-fixture-matrix.sh --profile nightly
```

## 7. CI, reproducibility, and documentation

- [ ] Add pack tests to fast PR gates and native pack E2E to ARM64 integration.
- [ ] Add pinned musl-container pack E2E to nightly/release tiers.
- [ ] Add deterministic rebuild comparison and launcher/toolchain provenance.
- [ ] Keep Android and shared-object paths visibly rejected/deferred.
- [ ] Document that this is an outer packaging/integrity shell, not encrypted
  code protection or a custom dynamic loader.
- [ ] Update backend specs with frame, wrapper, and runtime handoff contracts.

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
