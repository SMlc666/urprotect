# Implementation plan: AArch64 compatibility expansion and architecture quality

## Execution contract

- The parent task owns requirements, the architecture-quality bar, target
  calibration, cross-child integration, and final claim reconciliation. It is
  not the default implementation target while a child owns the next concrete
  deliverable.
- Each child must have a reviewed PRD, design, implementation plan, and real
  `implement.jsonl` / `check.jsonl` context entries before its `task.py start`.
- Dependencies are recorded in the child artifacts. Task-tree order alone does
  not authorize implementation.
- One compatibility slice is allowed to change the support claim only after
  its positive fixture, nearest-negative boundary, stable diagnostics, runtime
  oracle where applicable, retained evidence, and documentation all pass.
- Refactoring is part of every slice. New feature logic must not accumulate in
  a known monolith without an owner-boundary extraction plan and a rollback
  point.

## Stage 0 — Baseline and architecture audit

Owner: `09-25-architecture-quality-foundation`

- [ ] Map data flow from real-sample acquisition through fingerprinting,
      managed model/parser, profile pack, native runtime, evidence, and release
      report.
- [ ] Inventory public contracts: diagnostic codes/order, report JSON,
      frame layouts/digests, HostContext ABI, launcher markers, CLI exit codes,
      result vocabulary, fixture IDs, and evidence paths.
- [ ] Add or strengthen characterization tests for the contracts that each
      refactor must preserve.
- [ ] Audit `ElfParser`, `PayloadFrame`, `CliApplication`, `host_adapter`,
      native self-test mutation helpers, and repeated evidence-script logic for
      responsibility mixing, duplication, coupling, and testability risks.
- [ ] Choose the first extraction boundaries and document owner, migration
      order, behavior preserved, performance baseline, and rollback.
- [ ] Establish one owner for contract literals, typed address arithmetic,
      feature/result vocabulary, and evidence path validation.
- [ ] Refactor the first hotspots without changing compatibility claims.

Required gate before broad feature work:

```sh
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_security.py
make -C native/urprotect-runtime contract-check
dotnet test UrProtect.sln --configuration Release --no-restore
```

Environment-specific missing tools may be recorded, but no behavior-changing
refactor is complete without the affected managed/native gate or a documented
equivalent proof.

Rollback: revert the extraction as one structural change while retaining the
characterization tests and audit notes.

## Stage 1 — Real-sample expansion and failure taxonomy

Owner: `09-25-real-sample-expansion`; depends on the baseline evidence owners
from Stage 0.

- [ ] Extend the normalized fingerprint for relocation/PLT/GOT, dependency
      graph, symbol versions, TLS, GNU properties, hardening, stripping,
      interpreter, page size, producer, and loader.
- [ ] Add bounded aggregate feature-frequency and first-failure reporting.
- [ ] Grow the public corpus in reviewed increments from 20 toward 100 unique
      project identities without duplicating variants as identities.
- [ ] Keep acquisition, archive/extracted hashes, isolation, cleanup, and raw
      input non-publication guarantees unchanged.
- [ ] Ensure PR/nightly/release use the same registry and result semantics.
- [ ] Classify every observed feature cluster and every unexpected result at a
      named layer with a stable result and evidence path.
- [ ] Apply the approved 5% distinct-identity trigger for roadmap disposition;
      frequency prioritizes work but never bypasses semantic proof.

Validation:

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier pr
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_security.py
python3 scripts/check-real-sample-evidence.py --help
```

Rollback: remove only the newly added registry increment or aggregate output;
preserve the last hash-locked corpus and its evidence schema.

## Stage 2 — ELF model/parser foundation and common-feature selection

Owner: `09-25-elf-parser-feature-expansion`; depends on Stage 0 and the first
Stage 1 fingerprint report.

- [ ] Extract cohesive parser/model owners from the monolithic parser where the
      audit identifies real responsibility boundaries.
- [ ] Select the first feature families from frequency, product value,
      semantic risk, and dependency order.
- [ ] Add typed records and checked address/range handling for each selected
      feature; reuse `BoundedReader` and `LoadMap`.
- [ ] Add positive real-toolchain fixtures and paired malformed/nearest-negative
      fixtures.
- [ ] Preserve unknown data and stable diagnostics; never repair bytes or infer
      unsupported loader behavior.
- [ ] Update feature identifiers, matrix rows, contract inventory, reports,
      and parser/model tests as one cross-layer change.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
./scripts/run-coverage-fuzz.sh --tier pr
```

Rollback: keep the feature modeled/observed but `rejected` or `unknown`, remove
the acceptance branch, and retain the previous parser behavior.

## Stage 3 — Outer profile expansion

Owner: `09-25-outer-profile-expansion`; depends on Stage 0, the current frame
contract, and the relevant Stage 1 fingerprints. It may proceed in parallel
with HostContext feature work only after the current profile contract is stable.

- [ ] Define one executable class at a time: dynamic PIE, static PIE, ET_EXEC,
      shared object, interpreter variation, stripped/sectionless variants.
- [ ] Verify that the launcher and source process semantics are defined before
      widening pack acceptance.
- [ ] Add baseline/wrapped behavior probes for status, streams, argv/argv[0],
      environment, cwd, descriptors, signals, declared files, and loader
      failures.
- [ ] Keep outer and HostContext matrix rows separate.
- [ ] Add runtime-specific evidence only for the recorded native environments.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback: remove the new executable-class acceptance and its evidence row while
preserving the current outer profile and launcher contract.

## Stage 4 — HostContext relocation, PLT/GOT, and symbol semantics

Owner: `09-25-host-context-relocation-symbols`; depends on Stage 0, Stage 1
feature observations, and the Stage 2 typed ELF model. It must not broaden
HostContext merely because a system loader accepts an image.

- [ ] Define symbol scope, binding timing, weak/visibility/conflict behavior,
      target permissions, and status mapping before each relocation family.
- [ ] Implement the smallest prioritized AArch64 family, with shared model
      records and native adapter preflight.
- [ ] Add real-linker positive fixtures and mutation-based negative tests.
- [ ] Add managed frame/metadata behavior only when the HostContext capability
      contract requires it.
- [ ] Run separate glibc, musl, and bionic oracles where the feature claim
      names those environments.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime test
make -C native/urprotect-runtime contract-check
./scripts/run-coverage-fuzz.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback: retain the existing RELATIVE/RELR/GLOB_DAT claims, reject the new
family before loader handoff, and remove incomplete capability bits/evidence.

## Stage 5 — Dependency and path policy

Owner: `09-25-host-context-dependencies-paths`; depends on Stage 4 symbol
scope and the Stage 0 owner boundaries.

- [ ] Define allowed dependency roots, graph ownership, search precedence,
      environment influence, `$ORIGIN`, RPATH/RUNPATH, filters/auxiliary
      dependencies, sharing, cycles, missing dependencies, rollback, and
      release ordering.
- [ ] Implement one deterministic dependency subset; reject the rest before
      loader handoff.
- [ ] Add multi-dependency positive fixtures, path-search nearest negatives,
      and teardown/failure oracles.
- [ ] Keep payload-controlled search from becoming an accidental contract.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback: disable the new dependency/path subset at the adapter boundary and
restore the previous explicit rejection rows.

## Stage 6 — TLS, lifecycle, and runtime matrix expansion

Owners: `09-25-tls-lifecycle-expansion` and `09-25-runtime-matrix-expansion`;
the child artifacts must define their dependency ordering. Broader TLS and
live-thread claims wait for explicit image ownership semantics.

- [ ] Define current-thread and new-thread TLS initialization, constructor /
      entry / destructor ordering, reentrancy, live-thread release, and image
      ownership before accepting new models.
- [ ] Add deterministic threaded fixtures and teardown assertions.
- [ ] Select a covering array from sample fingerprints across older/current
      glibc, musl, bionic, loader identity, 4K/16K page size, toolchain, and
      artifact shape.
- [ ] Record complete runner, kernel, page-size, loader, image/package,
      toolchain, and isolation facts.
- [ ] Keep PR/nightly/release semantics identical while widening cells and
      repetition only by tier.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
./scripts/run-fixture-matrix.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```

Rollback: retain only the last validated TLS/lifecycle/runtime rows and mark
new cells or semantics unavailable/rejected with retained evidence.

## Stage 7 — Final integration and release claim reconciliation

Owner: `09-25-compatibility-release-integration`; waits for all selected child
deliverables.

- [ ] Reconcile `fixtures/manifest.json`, real-sample registry, compatibility
      report, README, `COMPATIBILITY.md`, runtime and quality specs, contract
      inventory, and release scripts.
- [ ] Verify no duplicate active parser/codec/feature/evidence implementation
      or stale profile/version wording remains.
- [ ] Render the final matrix and aggregate real-sample report.
- [ ] Run full managed/native/fixture/fuzz/stress/evidence/release gates.
- [ ] Record unresolved environments as explicit limitations rather than
      converting them into support claims.
- [ ] Complete final architecture/code-quality review and update durable specs.

Validation:

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
make -C native/urprotect-launcher test
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
python3 tests/test_real_sample_manifest.py
python3 tests/test_real_sample_fingerprint.py
python3 tests/test_real_sample_evidence.py
python3 tests/test_real_sample_security.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier release
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json \
  --candidates fixtures/real-samples/candidates.json --tier release
```

Rollback: revert only the unproven claim/integration changes; preserve the
last release matrix and all prior validated evidence.

## Parent review gates

- [ ] Every child has reviewed planning artifacts and explicit dependency text.
- [ ] Architecture foundation is complete before broad feature acceptance.
- [ ] The corpus is hash-locked, CI-only, and approaching the approved 100
      identity target through quality-gated increments.
- [ ] The 5% feature-frequency trigger is computed over distinct identities and
      every triggered cluster has a recorded disposition.
- [ ] Outer and HostContext claims remain independent.
- [ ] All support rows have owners, positive/negative witnesses, oracle output,
      and non-empty retained evidence.
- [ ] Full-scope check passes, specs are updated, and the parent is only
      archived after implementation commits exist.
