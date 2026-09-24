# P4-B Implementation Plan

- [x] Select the first property-note subset and define host negotiation: AArch64
      FEATURE_1 BTI/PAC mask with unknown bits rejected.
- [x] Define BTI/PAC and memory-protection responsibilities for the bounded
      note/BTI slice.
- [x] Add a BTI-instrumented property-bearing positive fixture and malformed
      PT_GNU_PROPERTY rejection coverage.
- [x] Add the HostContext managed v3 oracle; outer-wrapper observations remain
      separate until a launcher property fixture is added.
- [x] Update matrix rows, evidence gates, and runtime documentation.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-fixture-matrix.sh --tier release
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier release
python3 scripts/check-evidence.py fixtures/manifest.json --tier release
```
