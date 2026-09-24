# P2 Implementation Plan

- [ ] Inventory relocation/symbol forms from real AArch64 fixtures.
- [x] Select and document the first family and all lookup/target semantics:
      `R_AARCH64_GLOB_DAT` with checked dynamic symbol metadata.
- [x] Add shared managed model constants and native preflight checks through
      the owning contract tables.
- [x] Add positive, malformed, unsupported, missing-symbol, conflict, and
      target-permission tests.
- [x] Add retained runtime evidence and matrix rows only after the oracle passes.
- [ ] Run managed, native, fuzz-smoke, manifest, and evidence gates.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-coverage-fuzz.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```
