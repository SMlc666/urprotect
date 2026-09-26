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
- [ ] Execute cells on native AArch64 CI and classify unavailable capabilities; this remains pending until retained CI output proves each selected cell.
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
- [ ] Native container and bionic facts still require required AArch64 CI
      execution and retained post-run evidence. Local checks are not runtime
      claims.

Acceptance criteria remain open until that CI evidence is retained: especially
that every selected runtime row has non-empty environment/oracle artifacts and
that release claims exactly match validated cells.

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
