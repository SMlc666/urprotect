# Implementation plan: compatibility and release integration

## Dependencies

- Wait for the selected architecture, sample, parser, profile, HostContext,
  TLS/lifecycle, and runtime-matrix children.
- Resolve all child evidence paths and statuses before changing the published
  claim.

## Checklist

- [ ] Compare child feature IDs/statuses with `fixtures/manifest.json` and
      real-sample registry.
- [ ] Render compatibility and aggregate sample reports.
- [ ] Search for stale frame/profile/version wording and duplicate contract
      owners.
- [ ] Reconcile README, `COMPATIBILITY.md`, native README, specs, contract
      inventory, release package, and release smoke.
- [ ] Run complete managed/native/fixture/fuzz/stress/evidence/release gates.
- [ ] Review architecture/code-quality changes and remaining legacy hotspots.
- [ ] Record explicit rejected/unknown/unavailable boundaries.

## Validation

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
./scripts/package-release.sh VERSION OUTPUT_DIR
./scripts/release-smoke.sh OUTPUT_DIR
```

## Rollback

Revert only unproven claim/report/release changes and retain the previous
release mapping. Child implementations remain isolated and can be re-integrated
after evidence is repaired.
