# Implementation plan: TLS and lifecycle expansion

## Dependencies

- Architecture foundation and current HostContext owner map.
- Relocation/symbol semantics for TLS relocation classification.
- Dependency/path semantics for constructor/destructor and release ordering.
- Runtime matrix cells selected for each threaded oracle.

## Checklist

- [ ] Characterize current initial-exec TLS, constructor, destructor, handle,
      entry-once, and release behavior.
- [ ] Define the first TLS/lifecycle subset and required capabilities.
- [ ] Add managed/native contract checks and stable failure statuses.
- [ ] Add positive threaded fixture, deterministic barrier/join oracle, and
      malformed/capability/lifetime negatives.
- [ ] Exercise repeated and concurrent paths permitted by the contract.
- [ ] Retain environment facts and evidence for each named runtime.
- [ ] Update matrix, docs, specs, and stress/regression profiles.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```

## Rollback

Remove only the new TLS/lifecycle capability and positive path, retain
characterization and negative tests, and keep the previous validated row.
