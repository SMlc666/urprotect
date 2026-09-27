# Audit: HostContext dependency graph and path policy

## Result

Implemented the bounded native AArch64 glibc dependency-pair row while
preserving the recognized single-libc behavior. `host_image_validation.c`
allows only a singleton system-libc dependency or exactly one each of
`libc.so.6` and `ld-linux-aarch64.so.1`; duplicate, unknown, missing, excess,
path-search, filter, and auxiliary forms are rejected before loader handoff.
The pair-only `LD_LIBRARY_PATH`, `LD_PRELOAD`, and `LD_AUDIT` gate runs after
preflight and before memfd creation. There are no payload-controlled roots or
new ABI fields. The additional graph claim is native AArch64 glibc-only.

The native oracle passes both `DT_NEEDED` orders, observes entry status 37 and
release/destructor completion, compares memfd-attempt counts for all three
environment rejections, and keeps the historical singleton loadable with a
nonempty `LD_LIBRARY_PATH`. A test-only fake loader's constructor marker is
verified independently; the managed run with its path set returns status 4
before handoff with no fake-loader or entry marker. A second valid-pair image
contains an unresolved strong `R_AARCH64_GLOB_DAT` import. It reaches
`RTLD_NOW`, returns `URP_STATUS_LOAD_FAILED` with a zero handle, records one
memfd attempt, and leaves the descriptor count unchanged.

## Local verification

- `make -C native/urprotect-runtime contract-check`: passed.
- `make -C native/urprotect-runtime -B test`: passed; base adapter, weak PLT,
  libc version-needs, both graph orderings, environment boundaries, singleton
  regression, and post-memfd rollback all passed.
- `dotnet test UrProtect.sln --configuration Release --no-restore`: 136 passed.
- `native/urprotect-runtime/test_managed_host_context.sh`: passed; managed
  pair dispatch returned 37 and the fake-loader environment returned 4 before
  handoff.
- `python3 tests/test_fixture_matrix.py`: 24 passed.
- `python3 tests/test_regression_matrix.py`: 5 passed.
- PR-tier fixture validation and evidence checks passed, including the
  `runtime.host-context.bounded-glibc-loader-dependency` gate over 27 declared
  paths.
- `scripts/run-regression-stress.sh --tier pr`: 6 passed.
- Trellis task-context validation, shell syntax, JSON parsing, and
  `git diff --check`: passed.
- An independent `trellis-check` review found no remaining issue.

## CI and PR evidence

- PR #16: https://github.com/SMlc666/urprotect/pull/16
- Commit: `429f62e196bb0fdbd86b60572774c94e9afb5eb2`
- PR workflow run `36247881357`: success; required `build-and-test`, native
  AArch64 `real-sample-matrix`, and `bionic-native-arm64` jobs passed.
- Push workflow run `36247879166`: success on the same commit.
- Retained test artifact: `test-evidence-36247881357` (36,258,085 bytes).
  The producing job ran the dependency feature evidence gate successfully.
- Real-sample corpus identities remain static-only evidence where applicable
  and HostContext `not-applicable`; the 16/20 observation does not promote
  general executable compatibility.

## Scope retained

The old singleton slice and exact `libc.so.6` import-side version semantics
remain unchanged. The new pair does not claim musl or bionic graph support,
arbitrary dependency recursion, custom search roots, RPATH/RUNPATH, `$ORIGIN`,
filters, or auxiliary dependencies. TLS/lifecycle work remains a separate
child task under the compatibility-expansion parent.
