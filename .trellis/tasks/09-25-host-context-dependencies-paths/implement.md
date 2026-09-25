# Implementation plan: HostContext dependency and path semantics

## Dependencies

- Architecture foundation complete.
- Relocation/symbol child has defined symbol scope and binding interactions.
- TLS/lifecycle child consumes the dependency release-order contract.

## Checklist

- [ ] Document current single-libc roots and rejection behavior as baseline.
- [ ] Define policy and version/capability impact for the first graph/path
      subset.
- [ ] Add managed/native metadata checks with stable diagnostics.
- [ ] Add multi-dependency positive fixture and path/root/cycle/failure
      negatives.
- [ ] Verify handle clearing and no entry call on partial load.
- [ ] Run native glibc/musl/bionic rows included in the claim.
- [ ] Update matrix, evidence scripts, docs, and specs.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release --no-restore
make -C native/urprotect-runtime contract-check
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```

## Rollback

Disable the new dynamic-tag/path subset before loader handoff and restore its
explicit rejection rows. Do not retain a partially specified search behavior.
