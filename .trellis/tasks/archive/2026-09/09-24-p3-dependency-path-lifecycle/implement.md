# P3 Implementation Plan

- [x] Define dependency roots, search precedence, ownership, sharing, cycles,
      rollback, and release order.
- [x] Define constructor/destructor and reentrancy ordering around `urp_entry`.
- [x] Implement the smallest deterministic metadata subset: one system-libc
      `DT_NEEDED` basename, fixed loader roots, and system-loader lifecycle.
- [x] Add positive dependency/lifecycle fixtures and paired fail-closed tests.
- [x] Add teardown and handle-leak assertions to native oracles.
- [x] Update HostContext spec, matrix, README, and evidence gates.

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```
