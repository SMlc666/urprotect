# Implementation plan: AArch64 runtime matrix expansion

## Dependencies

- Architecture foundation defines evidence owners.
- Real-sample expansion supplies observed producer/feature combinations.
- Feature children specify which runtime cells their oracles require.

## Checklist

- [ ] Inventory existing environment IDs, runner facts, image/package locks,
      page-size observations, and regression matrix cases.
- [ ] Select versioned glibc/musl/bionic/page-size cells as a covering array.
- [ ] Add stable environment IDs and selection rationale to manifests.
- [ ] Extend environment recording and evidence validators with loader/page-size
      and toolchain facts.
- [ ] Update PR/nightly/release budgets and artifact ownership.
- [ ] Execute cells on native AArch64 and classify unavailable capabilities.
- [ ] Render a reviewable matrix report and release claim mapping.

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
