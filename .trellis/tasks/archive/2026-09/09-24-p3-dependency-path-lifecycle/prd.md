# Define Dependency, Path, and Lifecycle Semantics

## Goal

Define and implement a deterministic HostContext subset for dependencies,
dynamic path search, constructors/destructors, and image ownership.

## Dependencies

- P0 current profile and HostContext entry oracle are required.
- P2 symbol scope, relocation ownership, and failure semantics must be settled
  before dependency resolution is enabled.
- P4 TLS/property work depends on the lifecycle and release ownership rules
  established here.

## Requirements

- Define `DT_NEEDED`, `DT_AUXILIARY`, and `DT_FILTER` dependency behavior,
  dependency graph ownership, sharing, cycles, rollback, and release order.
- Define explicit search roots and RPATH/RUNPATH precedence; document the role
  of environment variables and reproducible configuration.
- Define constructor/destructor ordering, callback failure, reentrancy,
  `urp_entry` ordering, and `release_image` ownership.
- Implement only a deterministic bounded subset and reject unspecified forms
  before loader handoff.
- Add dependency-bearing and lifecycle-bearing positive fixtures, paired
  rejection mutations, and teardown/release oracles.

## Acceptance criteria

- [ ] A HostContext contract specifies search, scope, ownership, rollback, and
      lifecycle ordering in testable terms.
- [ ] Positive dependency and lifecycle fixtures prove the declared ordering.
- [ ] A failed dependency or constructor leaves no leaked image handle or
      partially published support claim.
- [ ] RPATH/RUNPATH and environment behavior is reproducible under explicit
      roots.
- [ ] Concurrent or reentrant behavior is either specified and tested or remains
      an explicit rejected boundary.
- [ ] Matrix rows separate parser, adapter, and runtime evidence.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```
