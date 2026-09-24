# Public real-sample CI corpus implementation plan

## Ordered work plan

### 1. Baseline and contract inventory

- Record the current CI jobs, native ARM64 runner assumptions, bionic/musl
  container conventions, evidence paths, and artifact upload behavior.
- Search existing scripts for download, hash, environment, timeout, `readelf`,
  baseline/packed comparison, and evidence-gate helpers before creating new
  utilities.
- Decide the exact public sample registry schema, result vocabulary, runtime
  policy fields, and artifact root before adding sample names.
- Preserve `fixtures/manifest.json` as the controlled feature matrix; document
  the separate ownership boundary.

### 2. Add metadata-only registry validation

- Add `fixtures/real-samples/candidates.json` with a public candidate ledger and
  provenance fields.
- Add `fixtures/real-samples/manifest.json` with the selected 20-project
  contract; initially populate it only after candidate fingerprinting and
  selection rationale are complete.
- Add `scripts/validate-real-samples.py` with schema, URL/path, hash, unique
  `projectId`, exactly-20, variant-count, policy, expected-status, and tier
  validation.
- Add Python tests for malformed hashes, duplicate projects, variant counting,
  missing provenance, unsupported result states, and required policy fields.
- Ensure this command performs no network access and requires no sample file.

### 3. Implement CI candidate acquisition and fingerprinting

- Add a CI-only orchestrator path that resolves registry entries, downloads
  pinned public archives into `${RUNNER_TEMP}`, verifies archive and extracted
  file hashes, rejects traversal/unexpected extraction, and cleans up.
- Add `scripts/inspect-real-sample.py` to emit a bounded normalized ELF
  fingerprint and retain external `readelf`/equivalent output.
- Record runner architecture, kernel/libc, page size, loader/rootfs digest,
  source URL/version, and all hashes in per-sample metadata.
- Keep downloaded binaries outside the repository and exclude raw binaries from
  uploaded artifacts.
- Run candidate discovery and selection on CI; do not provide a normal local
  execution command that accepts arbitrary sample paths.

### 4. Freeze and document the 20-project corpus

- Collect a sufficiently broad public candidate pool from pinned distribution
  snapshots, official release assets, and reproducible public builds.
- Scan candidates and choose exactly 20 unique upstream projects using project
  identity plus feature/runtime coverage, not libc/version multiplication.
- Add `fixtures/real-samples/selection.md` with per-project rationale,
  observed fingerprint, expected layer outcomes, discarded duplicates, and
  rejected/deferred boundary coverage.
- Validate that each selected project has a stable public source, archive/file
  hash, license/re-distribution record, and a reproducible acquisition recipe.

### 5. Add isolated sample oracles

- Implement policy dispatch for static validation, baseline execution, no-op
  copy, outer pack, and HostContext applicability.
- Prepare pinned ARM64 runtime/rootfs inputs for each applicable sample class;
  reuse existing bionic/musl conventions rather than adding a second ambient
  dependency path.
- Run target processes in a bounded isolated environment with no network,
  dropped capabilities, no-new-privileges, read-only inputs, temporary output,
  PID/CPU/memory/wall-clock limits, and cleanup traps.
- Compare baseline and packed observations while excluding ASLR/timing and
  preserving exit status, signal, stdout, stderr, cwd, environment, and
  declared file observations.
- Emit explicit `not-applicable`, `expected-rejected`,
  `environment-unavailable`, and unexpected statuses; never turn missing
  infrastructure into a pass.

### 6. Add evidence gate and aggregate report

- Add `scripts/check-real-sample-evidence.py` for registry-linked, tier-linked,
  non-empty artifact validation under `.artifacts/real-samples/`.
- Emit per-sample `result.json`, normalized metadata, tool reports, UrProtect
  report, oracle output, and environment facts.
- Emit an aggregate Markdown/JSON report with project, runtime, producer,
  feature, layer, and outcome coverage plus unexpected/first-seen features.
- Add Python tests for missing artifacts, empty artifacts, path escape, wrong
  sample/tier IDs, malformed result states, and successful complete evidence.

### 7. Integrate required full PR/nightly/release CI

- Add a dedicated `real-sample-matrix` job on `ubuntu-24.04-arm` with
  read-only contents permission, bounded timeout, and full 20-project execution
  on every PR.
- Reuse the same registry and runner for scheduled and release runs; allow
  nightly/release to add repeats or approved runtime variants without changing
  the PR required set.
- Upload evidence on success and failure, but never upload raw sample binaries
  or runtime rootfs contents.
- Record acquisition, isolation, runner, and cleanup facts in the job summary
  and artifacts.
- Make unexpected outcomes and missing evidence nonzero required-job failures.

### 8. Encode the CI-first contributor contract

- Update `.trellis/spec/backend/quality-guidelines.md` with public real-sample
  registry, no-local-execution, evidence, and full-PR gate conventions.
- Update `.trellis/spec/backend/runtime-compatibility.md` with the distinction
  between controlled fixtures and real-sample ecology evidence, plus the rule
  that real observations do not automatically promote support.
- Add `fixtures/real-samples/README.md` with the future compatibility-task
  impact table and a worked example of an unexpected result flowing into a
  contract/fixture/docs/evidence change.
- Update README/CI documentation with local-vs-CI boundaries, tier behavior,
  sample provenance, and artifact retrieval instructions.

### 9. Verification and integration review

- Validate registry and selection reports without downloading samples.
- Run all manifest/evidence Python tests and existing managed tests.
- Execute the 20-sample PR job on native ARM64 CI and inspect every sample's
  result classification and artifact.
- Run nightly/release rehearsals when available and confirm they use the same
  locked registry/oracle path.
- Review the diff for raw binaries, moving URLs, unbounded extraction, host
  execution fallbacks, silent skips, evidence path escapes, and accidental
  changes to existing compatibility claims.
- Update the task acceptance checklist only after required CI evidence exists.

## Validation commands

Metadata-only/local commands:

```sh
python3 scripts/validate-real-samples.py fixtures/real-samples/manifest.json
python3 tests/test_real_sample_manifest.py
python3 tests/test_fixture_matrix.py
python3 tests/test_regression_matrix.py
```

Existing local commands remain sample-free:

```sh
dotnet test UrProtect.sln --configuration Release
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
```

CI-only commands:

```sh
./scripts/run-real-sample-matrix.sh --tier pr
python3 scripts/check-real-sample-evidence.py \
  fixtures/real-samples/manifest.json --tier pr
```

The exact CI command must reject non-CI execution and a non-AArch64 runner
before acquiring any sample. The PR job is the required full 20-project gate;
nightly and release invoke the same command with their tier policy.

## Risk and rollback points

- **Source drift:** hash mismatch stops before extraction; update the registry
  explicitly rather than accepting a new artifact.
- **Archive hazards:** bounded download/extraction and path checks stop before
  sample execution.
- **Runtime escape:** container/rootfs and runner preflight checks must fail
  before launching a target when isolation guarantees are absent.
- **Flaky public services:** evidence records acquisition separately from
  product results; required CI retries only bounded, hash-verified downloads.
- **CI cost:** full PR execution is an intentional product decision. Optimize
  download/runtime caches only after hash and provenance checks, without making
  the sample set conditional.
- **Compatibility overclaim:** real-sample reports never edit support status;
  rollback any attempted automatic promotion and retain the observation as
  `unknown` or an explicit boundary.
