# Implementation plan: outer-execveat compatibility expansion

## Dependencies

- Architecture foundation complete enough to identify profile policy ownership.
- Current frame v3/profile/launcher contract remains stable.
- Sample fingerprint identifies the first executable class with useful impact.

## Checklist

- [ ] Capture current launcher and managed handoff behavior baseline.
- [ ] Select one input class and write its accepted/rejected contract.
- [ ] Add real-toolchain fixture and nearest-negative fixture.
- [ ] Extend baseline/wrapper process probe for the class.
- [ ] Validate launcher ELF, frame round-trip, source digest, and anonymous
      handoff invariants.
- [ ] Add runtime-specific evidence only for named native cells.
- [ ] Update feature matrix, report, docs, and release evidence.
- [ ] Refactor any touched legacy pack/launcher hotspot rather than stacking
      another branch without an extraction plan.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-launcher test
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

## Rollback

Revert the class-specific pack acceptance, fixture, launcher probe, and matrix
row as one slice. Retain the new negative test if it documents a still-valid
boundary.
