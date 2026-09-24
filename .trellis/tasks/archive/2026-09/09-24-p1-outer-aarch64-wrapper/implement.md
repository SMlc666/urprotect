# P1 Implementation Plan

- [x] Inventory current pack rejection reasons and producer fixture layouts.
- [x] Add stripped/sectionless positive and malformed fixtures.
- [x] Add baseline/wrapped argv, envp, stream, status, signal, cwd, and file
      observation comparisons.
- [x] Add the static PIE executable class with a declared outer launch
      contract; shared objects remain explicit entry-profile inputs.
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
