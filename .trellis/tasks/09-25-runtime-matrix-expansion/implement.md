# Implementation plan: AArch64 runtime matrix expansion

## Dependencies

- Architecture foundation defines evidence owners.
- Real-sample expansion supplies observed producer/feature combinations.
- Feature children specify which runtime cells their oracles require.

## Checklist

- [x] Inventory existing environment IDs, runner facts, image/package locks,
      page-size observations, and regression matrix cases.
- [x] Select versioned glibc/musl/bionic/page-size cells as a covering array.
- [x] Add stable environment IDs and selection rationale to manifests.
- [x] Extend environment recording and evidence validators with loader/page-size
      and toolchain facts.
- [x] Add linker-produced glibc/musl `PT_LOAD.p_align=16KiB` witnesses and
      distinguish ELF alignment evidence from an actual 16KiB kernel runtime.
- [x] Record a native 16KiB kernel probe; when no native AArch64 16KiB host is
      available, retain `environment-unavailable` evidence and keep the kernel
      support cell unknown (no emulation fallback).
- [x] Update PR/nightly/release budgets and artifact ownership.
- [x] Execute cells on native AArch64 CI and classify unavailable capabilities; retained PR, nightly, and release CI artifacts prove each selected cell and preserve the 16KiB kernel probe as `environment-unavailable` on the measured 4KiB host.
- [x] Render a reviewable registry with release tier mapping; CI artifacts hold runtime report and claims.

## Validation

```sh
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json --tier pr --emit
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-fixture-matrix.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```

## Rollback

Revert only newly added matrix cells, budgets, and claim rows while retaining
the last reproducible environment catalog and evidence validator.


## Implementation correction and acceptance audit (2025-09-25)

Local implementation and regression checks now enforce these task criteria:

- [x] Runtime registry is typed and tier-checked, with producer/toolchain and
      ELF-shape descriptions, older-glibc x 16KiB ELF alignment and musl-1.2.5
      x 16KiB ELF alignment interactions, and a distinct native 16KiB page probe.
- [x] A bounded all-PT_LOAD readelf alignment checker has focused positive,
      nearest-negative, and malformed-row tests for the 4KiB/16KiB witnesses.
- [x] The 16KiB probe is mandatory evidence collection (`probeRequired`), but
      its product claim is optional (`claimRequired: false`) and stays unknown
      when unavailable. A declared required claim cannot pass as unavailable.
- [x] The bionic native producer is a runtime job dependency; its downloaded
      result, native/non-emulated execution facts, package lock/hash evidence,
      direct linker identity, and HostContext self-test/fixture evidence are
      consumed by the runtime evidence gate.
- [x] All tiers restore/build the managed CLI and record validate/no-op-copy
      evidence, application assembly hash, SDK version, statuses, and streams.
- [x] Build musl 1.2.4 from the committed SHA-256-pinned source archive, record
      the native GCC/loader hashes and complete build logs, and clean up the
      test-owned loader symlink on all runtime-run exits. Preserve all eight
      bionic package archives so the downstream matrix gate verifies their
      bytes against the package lock.
- [x] Runtime fixtures include 4KiB/16KiB `PT_LOAD.p_align` GNU evidence and,
      in extended tiers, musl producer evidence. Container invocations use
      pinned OCI digests, bounded networkless/read-only Docker isolation, exact
      runtime identity checks, measured inherited page size, and per-command
      status/stdout/stderr records.
- [x] Regression-matrix artifact declarations name concrete generated outputs,
      tier budgets account for pinned image pulls and runtime probes; validators
      and focused tests pass locally.
- [x] Native container and bionic facts are backed by required AArch64 CI
      execution and retained post-run evidence; local checks remain separate
      from runtime claims.

## Final CI acceptance audit (2026-09-27)

- Pull-request run `36290915990` passed build-and-test, the full locked
  20-identity real-sample matrix, native bionic evidence, and the PR runtime
  cell on commit `9856887648ad6aef8c36d0a1c1d8a9c9e6cefff6`.
- Nightly run `36291070139` passed the extended fixture, runtime, bionic,
  real-sample, musl-container, and evidence jobs on the same commit. The
  runtime artifact contains all six selected cells and retains a complete
  SHA256SUMS manifest; an independent post-download check verified all 4,484
  listed runtime and bionic files, including hidden source-build files.
- Release rehearsal run `36292019899` passed the release fixture tier, release
  runtime matrix, bionic lane, package-and-smoke job, and all other workflows
  after retrying one transient `packages.termux.dev` timeout in the public
  real-sample acquisition. Its release run manifest lists exactly the five
  validated claims and keeps the 16KiB kernel claim unknown because the
  observed native page size is 4096 bytes. A second independent checksum pass
  verified all 4,484 listed release runtime and bionic files.
- Release smoke produced and checked the glibc and musl bundles; publishing
  assets remained skipped for this non-publishing workflow-dispatch rehearsal.
- Earlier runtime CI failures found and fixed in this task were: missing host
  OS facts in the native musl row, loader identity validation tied to a SONAME
  rather than the pinned source-built musl image, evidence re-execution after
  intentional interpreter-link cleanup, and Alpine loader selection resolving
  a nonexistent glibc path. The corresponding fixes are covered by the final
  passing PR and extended CI runs.

The PRD acceptance criteria are satisfied by the retained PR/nightly/release
CI evidence above. The only unavailable claim is the distinct 16KiB kernel
runtime, explicitly reported as `unknown` on the measured 4KiB host.

## Implemented artifacts

- `fixtures/runtime-matrix.json` is the named covering registry with reviewed
  Ubuntu 22.04 and Alpine 3.22.2 OCI index digests and tier selection.
- `scripts/run-runtime-matrix.sh` builds real GNU/musl 4KiB and 16KiB-aligned
  PIEs, runs native/container cells directly through Docker, and records host
  kernel/page facts separately from container loader facts.
- `scripts/install-runtime-musl-toolchain.sh` verifies the upstream musl source
  digest, builds the native 1.2.4 runtime, and records tool/build provenance.
- `scripts/check-runtime-matrix-evidence.py` gates retained environment, oracle,
  and explicit 16KiB native page probe results.
- `.github/workflows/ci.yml` runs the native AArch64 PR cell and nightly/release
  extended cells. Bionic continues through its existing required producer.
- Container jobs await native GitHub Actions execution; local Docker availability
  is not used as an execution result.
