# Test infrastructure and regression coverage implementation plan

## Ordered work plan

### 1. Establish the baseline and contract map

- Record the current managed test count, coverage report shape, fuzz command,
  native self-test commands, fixture tiers, and CI budgets.
- Inventory contract-encoding literals across `src/`, `tests/`, `native/`,
  `scripts/`, and workflow files. Classify each as production contract,
  cross-language contract, intentional fixture byte, algorithm constant, or
  incidental test data.
- Add the inventory and the first regression-matrix schema before changing
  assertions, so later diffs have an auditable before/after boundary.

### 2. Implement constants and assertion foundations

- Centralize duplicated frame/ABI values within each language boundary and
  add the cross-language contract probe/check.
- Introduce focused managed assertion helpers and migrate repeated high-value
  tests first; preserve direct xUnit assertions for one-off checks.
- Add focused tests for the helpers and contract drift failure messages.
- Run the normal managed tests and native compile/self-test before moving on.

### 3. Add coverage-guided fuzzing

- Add the isolated fuzz project, pinned SharpFuzz/libFuzzer inputs, license and
  provenance records, seed corpora, and the runner script.
- Implement ELF and payload-frame modes with explicit input/resource limits.
- Add PR smoke and nightly/full profiles, artifact retention, minimization, and
  promotion instructions. Keep existing deterministic fuzz tests unchanged
  until the new target has equivalent no-throw coverage.
- Validate locally with a tiny fixed run, then with the configured nightly
  profile on the native ARM64 runner.

### 4. Add concurrency and large-input regressions

- Add fixed-profile managed tests for parser, validator, frame codec, and
  no-op pipeline sharing semantics.
- Add exact-limit, limit-plus-one, multi-megabyte, overflow, and failed
  publication cases. Capture parameters and enforce script-level timeout/
  memory budgets.
- Run PR profile repeatedly to detect flakiness, then run the amplified
  nightly profile and retain the stress manifest.

### 5. Expand end-to-end regression coverage

- Complete missing CLI and managed integration scenarios using existing test
  harnesses and temporary-directory conventions.
- Extend native launcher/managed handoff scripts only where a missing
  observable contract is identified; preserve architecture/capability failure
  semantics.
- Add the machine-readable regression matrix validator and wire existing
  fixture, packed, HostContext, musl, bionic, and Android commands to rows.

### 6. Integrate CI and evidence

- Add bounded PR smoke steps and nightly stress/fuzz steps at the agreed tiers.
- Upload fuzz, stress, matrix, environment, native, and test-result artifacts
  on success and failure.
- Update README/test documentation and the backend quality spec with durable
  conventions; do not update compatibility status without new proof.

### 7. Parent integration review

- [x] Run the complete relevant command set on the current host.
- [x] Validate every acceptance criterion against a matrix row and retained
      artifact.
- [x] Review the diff for accidental product-contract changes, duplicated
      owners, nondeterministic tests, unbounded allocations, and misleading
      capability claims.
- [x] Activate and archive each independently verifiable child after its
      implementation and verification; this parent owns the final integration
      and evidence review.

## Validation commands

Baseline and managed suite:

```sh
dotnet restore UrProtect.sln --locked-mode
dotnet build UrProtect.sln --configuration Release --no-restore
dotnet test UrProtect.sln --configuration Release --no-build --logger trx --collect:"XPlat Code Coverage"
python3 scripts/check-coverage.py
```

Repository scripts and native paths:

```sh
python3 tests/test_fixture_matrix.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
make -C native/urprotect-runtime test
```

Fuzz and stress profiles will expose stable wrappers with explicit `pr`,
`nightly`, and `release` options. Each wrapper must print its selected seed,
budget, host environment, and artifact root before execution.

## Review gates and rollback points

- **Gate A:** inventory and contract ownership are complete; no broad literal
  replacement has changed a wire value.
- **Gate B:** assertion migration passes with useful diagnostics and no new
  assertion dependency.
- **Gate C:** fuzz smoke is genuinely coverage-guided, bounded, reproducible,
  and fails visibly when its toolchain is unavailable.
- **Gate D:** concurrency/large-input tests are deterministic under the PR
  profile and retain stress parameters.
- **Gate E:** each E2E row has a real witness or an explicit unavailable status.
- **Gate F:** CI artifacts and documentation match the matrix.

If a stream introduces flakiness or a platform-specific blocker, revert its
runner and keep the focused deterministic tests while the stream remains open;
do not weaken the product contract or silently downgrade a required evidence
row.
<!-- End of task artifact. -->
