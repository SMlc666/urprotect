# P4-B Implementation Plan

- [ ] Select the first property-note subset and define host negotiation.
- [ ] Define BTI/PAC and memory-protection responsibilities.
- [ ] Add property-bearing positive fixtures and conflict/malformed negatives.
- [ ] Add independent outer-wrapper and HostContext oracles where claimed.
- [ ] Update matrix rows, evidence gates, and runtime documentation.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-fixture-matrix.sh --tier release
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier release
python3 scripts/check-evidence.py fixtures/manifest.json --tier release
```
