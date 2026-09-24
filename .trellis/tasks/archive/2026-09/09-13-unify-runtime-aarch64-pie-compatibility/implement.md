# Implementation Plan

## Preconditions

- Child design artifacts and execution plans were reviewed before the parent
  task was activated.
- The parent task was started after the planning review; this file now records
  its verified execution and completion state.
- The HostContext ABI and matrix schema remained cross-child contracts, and
  dependent artifacts were updated when their compatibility boundaries grew.

## Ordered Work

### 1. Baseline and contract freeze

- [x] Record current managed test, fixture, wrapper, and Android evidence.
- [x] Extract current v1 frame and launcher behavior into a legacy baseline
      matrix row.
- [x] Freeze HostContext versioning, entry signature, ownership, lifecycle,
      error, and capability semantics in the runtime child design.
- [x] Freeze matrix schema, status vocabulary, and naming migration in the
      matrix child design.

### 2. Matrix schema migration

- [x] Rename project-owned fixture manifest records from profiles to matrix
      cases and replace --profile selection with run-tier terminology.
- [x] Rename project-owned container/package metadata to accurate host/image or
      variant fields; leave external Cargo terminology unchanged.
- [x] Add schema validation for IDs, statuses, feature constraints, evidence,
      and positive/negative cases.
- [x] Backfill the existing compiler, runtime, Android, and wrapper cases.
- [x] Add the pinned native ARM64 Termux/bionic case as a peer runtime fact,
      with direct linker identity, page-size, kernel, and no-fallback evidence.
- [x] Generate or validate human-readable matrix documentation.

Rollback: retain a read-only legacy-manifest adapter while all CI callers are
migrated; do not keep two writable schemas.

### 3. Runtime skeleton and no-path handoff

- [x] Add the versioned native HostContext ABI and validation helpers.
- [x] Add a native runtime core that reads its embedded frame, verifies bounds
      and digests, and exposes the HostContext entry dispatch.
- [x] Implement one immutable no-executable-path image handoff through the
      selected host capability.
- [x] Add a minimal HostContext payload fixture and an integration oracle that
      proves the host process is not replaced.
- [x] Add ABI mismatch, capability absence, ownership, and lifecycle failures.

Rollback: keep the legacy v1 launcher selectable for legacy inputs; new
HostContext inputs must fail closed rather than fall back to a temporary file.

### 4. AArch64 PIE language expansion

- [x] Map existing parser models, validator rules, and relocation classifiers
      to matrix feature IDs.
- [x] Add sectionless/stripped, segment-layout/alignment, PT_TLS, GNU
      property/RELRO, dynamic metadata, RELA/RELR, Android packed-relocation,
      and symbol-version cases in small independently reviewable slices.
- [x] Add compiler/toolchain cases only when they exercise a new feature or
      lifecycle obligation.
- [x] Add paired malformed/rejected cases for each new accepted feature.
- [x] Integrate loader/runtime oracles for every feature marked proven.

Rollback: mark a feature unknown or rejected and retain parser preservation
rather than making the runtime accept unproven semantics.

### 5. Cross-child integration

- [x] Connect matrix feature IDs to HostContext version and runtime evidence.
- [x] Make CI fail for claimed rows without required proof, model, or fixture
      evidence.
- [x] Keep optional emulator/native-bridge evidence labeled as implementation
      evidence, not universal compatibility proof.
- [x] Update README and release metadata to describe one unified contract and
      remove project-owned profile claims.

### 6. Quality gate

- [x] Run the full managed test suite with the pinned .NET SDK and locked
      restore.
- [x] Run parser malformed/property/fuzz checks and native runtime tests.
- [x] Run fixture/matrix validation and relevant native AArch64 jobs.
- [x] Run external readelf/llvm-readelf structure checks for every generated
      ELF runtime and fixture.
- [x] Run the final cross-layer check for schema, scripts, reports, README, and
      CI references.
- [x] Run the post-run evidence gate in each producing CI job; local fixture or
      runtime runs do not count as retained matrix evidence.
- [x] Review changed diagnostics, provenance, licenses, and rollback behavior.

## Validation Commands

    PATH=/root/.dotnet:$PATH dotnet restore UrProtect.sln --locked-mode
    PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release
    PATH=/root/.dotnet:$PATH FUZZ_RESULTS_DIRECTORY=.artifacts/fixtures/pr/fuzz ./scripts/run-parser-fuzz.sh
    python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
    ./scripts/run-fixture-matrix.sh --tier pr
    ./scripts/run-packed-fixture-matrix.sh --tier pr
    make -C native/urprotect-runtime test

Native AArch64 commands must run on an AArch64 host and must fail closed on
another architecture. The release fixture tier and native bionic lane are
verified as retained CI evidence; local tool availability is not substituted
for those required GitHub gates.

## Review Gates

- [x] Gate A: HostContext ABI and matrix schema have no unresolved product
  decisions.
- [x] Gate B: runtime entry and no-path semantics have a deterministic integration
  witness.
- [x] Gate C: every matrix row marked proven has a proof obligation and evidence
  path.
- [x] Gate D: full-scope quality check passes without weakening legacy behavior.

## Completion Evidence

- `dotnet test UrProtect.sln --configuration Release --no-restore`: 101 passed.
- `make -C native/urprotect-runtime test`: native HostContext self-test passed;
  `scripts/run-parser-fuzz.sh`: 2 passed; fixture matrix tests: 22 passed.
- Fixture manifest validation passed for `pr`, `nightly`, and `release` tiers.
- PR run [35934602944](https://github.com/SMlc666/urprotect/actions/runs/35934602944)
  passed `build-and-test` and `bionic-native-arm64` at commit `57a0d1f`.
- Release-tier run [35934619123](https://github.com/SMlc666/urprotect/actions/runs/35934619123)
  passed the release fixture/evidence gate, `build-and-test`, bionic, musl,
  benchmark, and environment-evidence jobs at commit `57a0d1f`.
- Production managed HostContext packaging remains explicitly `unknown` in the
  matrix until a v2-capable managed launcher path and end-to-end oracle exist;
  the implemented native adapter boundary is separately validated.
