# P1 Implementation Plan

- [ ] Inventory current pack rejection reasons and producer fixture layouts.
- [ ] Add stripped/sectionless positive and malformed fixtures.
- [ ] Add baseline/wrapped argv, envp, stream, status, signal, cwd, and file
      observation comparisons.
- [ ] Add one new executable class at a time with a declared launch contract.
- [ ] Update parser/validator, fixture manifest, matrix renderer, README, and
      retained evidence paths together.
- [ ] Run the full managed, fixture, packed-fixture, and evidence gates.

```sh
dotnet test UrProtect.sln --configuration Release
./scripts/run-fixture-matrix.sh --tier pr
./scripts/run-packed-fixture-matrix.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

Rollback removes only the new input-class rule, fixture, and matrix row while
preserving the P0 frame/profile contract.
