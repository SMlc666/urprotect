# Implementation Plan

## Preconditions

- Keep the parent task in planning until all child design and execution
  artifacts are reviewed.
- Do not run task.py start or edit product code from this planning pass.
- Treat the HostContext ABI and matrix schema as cross-child contracts; update
  all dependent artifacts when either changes.

## Ordered Work

### 1. Baseline and contract freeze

- [ ] Record current managed test, fixture, wrapper, and Android evidence.
- [ ] Extract current v1 frame and launcher behavior into a legacy baseline
      matrix row.
- [ ] Freeze HostContext versioning, entry signature, ownership, lifecycle,
      error, and capability semantics in the runtime child design.
- [ ] Freeze matrix schema, status vocabulary, and naming migration in the
      matrix child design.

### 2. Matrix schema migration

- [ ] Rename project-owned fixture manifest records from profiles to matrix
      cases and replace --profile selection with run-tier terminology.
- [ ] Rename project-owned container/package metadata to accurate host/image or
      variant fields; leave external Cargo terminology unchanged.
- [ ] Add schema validation for IDs, statuses, feature constraints, evidence,
      and positive/negative cases.
- [ ] Backfill the existing compiler, runtime, Android, and wrapper cases.
- [ ] Add the pinned native ARM64 Termux/bionic case as a peer runtime fact,
      with direct linker, page-size, kernel, and no-fallback evidence.
- [ ] Generate or validate human-readable matrix documentation.

Rollback: retain a read-only legacy-manifest adapter while all CI callers are
migrated; do not keep two writable schemas.

### 3. Runtime skeleton and no-path handoff

- [ ] Add the versioned native HostContext ABI and validation helpers.
- [ ] Add a native runtime core that reads its embedded frame, verifies bounds
      and digests, and exposes the HostContext entry dispatch.
- [ ] Implement one immutable no-executable-path image handoff through the
      selected host capability.
- [ ] Add a minimal HostContext payload fixture and an integration oracle that
      proves the host process is not replaced.
- [ ] Add ABI mismatch, capability absence, ownership, and lifecycle failures.

Rollback: keep the legacy v1 launcher selectable for legacy inputs; new
HostContext inputs must fail closed rather than fall back to a temporary file.

### 4. AArch64 PIE language expansion

- [ ] Map existing parser models, validator rules, and relocation classifiers
      to matrix feature IDs.
- [ ] Add sectionless/stripped, segment-layout/alignment, PT_TLS, GNU
      property/RELRO, dynamic metadata, RELA/RELR, and symbol-version cases in
      small independently reviewable slices.
- [ ] Add compiler/toolchain cases only when they exercise a new feature or
      lifecycle obligation.
- [ ] Add paired malformed/rejected cases for each new accepted feature.
- [ ] Integrate loader/runtime oracles for every feature marked proven.

Rollback: mark a feature unknown or rejected and retain parser preservation
rather than making the runtime accept unproven semantics.

### 5. Cross-child integration

- [ ] Connect matrix feature IDs to HostContext version and runtime evidence.
- [ ] Make CI fail for claimed rows without required proof, model, or fixture
      evidence.
- [ ] Keep optional emulator/native-bridge evidence labeled as implementation
      evidence, not universal compatibility proof.
- [ ] Update README and release metadata to describe one unified contract and
      remove project-owned profile claims.

### 6. Quality gate

- [ ] Run the full managed test suite with the pinned .NET SDK and locked
      restore.
- [ ] Run parser malformed/property/fuzz checks and native runtime tests.
- [ ] Run fixture/matrix validation and relevant native AArch64 jobs.
- [ ] Run external readelf/llvm-readelf structure checks for every generated
      ELF runtime and fixture.
- [ ] Run the final cross-layer check for schema, scripts, reports, README, and
      CI references.
- [ ] Run the post-run evidence gate in each producing CI job; local fixture or
      runtime runs do not count as retained matrix evidence.
- [ ] Review changed diagnostics, provenance, licenses, and rollback behavior.

## Validation Commands

    PATH=/root/.dotnet:$PATH dotnet restore UrProtect.sln --locked-mode
    PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release
    python3 scripts/validate-fixtures.py --tier pr
    ./scripts/run-fixture-matrix.sh --tier pr
    ./scripts/run-packed-fixture-matrix.sh --tier pr

The exact command names are updated with the matrix schema before this plan is
started. Native AArch64 commands must run on an AArch64 host and must fail
closed on another architecture.

## Review Gates

- Gate A: HostContext ABI and matrix schema have no unresolved product
  decisions.
- Gate B: runtime entry and no-path semantics have a deterministic integration
  witness.
- Gate C: every matrix row marked proven has a proof obligation and evidence
  path.
- Gate D: full-scope quality check passes without weakening legacy behavior.
