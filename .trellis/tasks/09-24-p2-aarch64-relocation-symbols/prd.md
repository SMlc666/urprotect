# Expand AArch64 Relocation and Symbol Semantics

## Goal

Extend the `host-context-entry` profile beyond the current checked
`RELATIVE`/`RELR` slice using explicit AArch64 relocation and symbol semantics.

## Dependencies

- P0 supplies the current frame/profile and HostContext entry oracle.
- P1 supplies the common evidence and fixture shape; P2 may reuse its producer
  inventory but does not require every P1 input class.
- P3 depends on the symbol scope and ownership rules established here.

## Requirements

- Select the first relocation family from real AArch64 fixtures and document
  the selection rationale before implementation.
- Define symbol lookup scope, visibility, binding timing, weak-symbol behavior,
  conflict handling, version handling, relocation target permissions, and
  stable failures.
- Add managed model rules and native adapter checks at the layer that owns each
  invariant.
- Add positive real-toolchain fixtures, mutation-based malformed/unsupported
  tests, and retained runtime evidence for each accepted family.
- Keep unsupported relocation-table, Android-packed-relocation, and symbol
  version forms explicitly rejected until their contracts are complete.

## Acceptance criteria

- [ ] Each accepted relocation family has a named AArch64 rule and owner.
- [ ] Symbol lookup and binding behavior is observable in a positive fixture.
- [ ] Invalid targets, missing symbols, conflicts, and unsupported forms fail
      before an invalid entry dispatch and return stable statuses.
- [ ] The unchanged RELATIVE/RELR baseline remains green.
- [ ] glibc, musl, and bionic results are recorded as separate evidence facts.
- [ ] The compatibility matrix does not promote system-loader acceptance alone
      to HostContext support.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-coverage-fuzz.sh --tier pr
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
python3 scripts/check-evidence.py fixtures/manifest.json --tier pr
```
