# Implementation plan: HostContext relocation and symbol expansion

## Dependencies

- Architecture foundation and ELF model ownership are required.
- Real-sample expansion supplies the first frequency-prioritized family.
- Dependency/path child owns graph/search semantics; this child must not invent
  a conflicting dependency policy.

## Checklist

- [ ] Record current RELATIVE/RELR/GLOB_DAT model, adapter, fixture, status,
      handle, and release behavior.
- [ ] Select one family and write its symbol/target/binding contract before
      touching acceptance code.
- [ ] Add managed model and static boundary tests.
- [ ] Add native adapter preflight and capability/layout checks.
- [ ] Add real-linker positive fixture and nearest-negative/malformed mutation.
- [ ] Add entry observation and release/handle assertions.
- [ ] Run named runtime oracles and retain evidence.
- [ ] Update manifest, report, docs, contract inventory, and specs.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
./scripts/run-coverage-fuzz.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

## Rollback

Keep the current validated rows and return the new family to explicit rejected
or unknown status if any runtime oracle, capability contract, or negative
boundary is incomplete.
