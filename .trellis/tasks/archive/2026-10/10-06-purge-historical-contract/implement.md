# Implementation plan: current-contract purge

## Steps

1. Build the current-contract inventory and repository caller list.
2. Delete managed API/CLI aliases and update all current callers/tests.
3. Collapse semantic snapshot/codec forwarding aliases to canonical operations.
4. Remove managed Payload Frame v1/v2 constants, encode/decode branches, wrapper scans, and legacy host projection; retain current v3 only.
5. Remove native v1/v2 constants, parser branches, migration projections, self-test builders, and adapter-v2 targets.
6. Delete all retired-format test data and current manifest/evidence rows; update current docs and contract inventory.
7. Add current-only absence checks, generic malformed-input tests, and current v3 profile tests.
8. Run the G0 validation gate and inspect the complete diff for accidental compatibility restoration.

## Validation

```sh
python3 ./.trellis/scripts/task.py validate .trellis/tasks/10-06-purge-historical-contract
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
DOTNET_ROOT=/root/.dotnet PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build --no-restore
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/validate-regression-matrix.py tests/regression-matrix.json
make -C native/urprotect-runtime test
make -C native/urprotect-launcher test
git diff --check
```

The final absence check must show no retired production names, frame branches, migration rows, or format-specific fixtures. Environment-unavailable native lanes remain explicit failures, not fallback evidence.

## Rollback points

- Managed API/CLI purge.
- Managed/native v3-only contract purge.
- Historical data/manifest deletion.
- Current-only test/doc convergence.

Revert a failed slice rather than adding a compatibility shim.
