# P3 Implementation Plan

- [ ] Define dependency roots, search precedence, ownership, sharing, cycles,
      rollback, and release order.
- [ ] Define constructor/destructor and reentrancy ordering around `urp_entry`.
- [ ] Implement the smallest deterministic metadata subset.
- [ ] Add positive dependency/lifecycle fixtures and paired fail-closed tests.
- [ ] Add teardown and handle-leak assertions to native oracles.
- [ ] Update HostContext spec, matrix, README, and evidence gates.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```
