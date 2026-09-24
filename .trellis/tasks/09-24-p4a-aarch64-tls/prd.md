# Implement AArch64 TLS Semantics

## Goal

Define and validate a bounded AArch64 TLS subset for HostContext image loading,
thread behavior, and image release.

## Dependencies

- P0 current HostContext profile is required.
- P2 relocation/symbol semantics and P3 lifecycle/ownership semantics are
  prerequisites for a meaningful TLS contract.

## Requirements

- Define the bounded first slice: AArch64 initial-exec TLS module allocation,
  current-thread initialization, `R_AARCH64_TLS_TPREL64`, and release ordering.
- Explicitly defer dynamic TLS, new-thread initialization, reentrancy, and
  unload while live TLS users exist; those combinations remain rejected or
  unknown until a threaded contract is added.
- Add a real TLS-backed fixture and deterministic managed entry oracle; static
  PT_TLS mutation alone is insufficient.
- Record separate runtime evidence for each glibc, musl, and bionic fact.
- Keep unspecified TLS models and unsafe unload cases fail-closed.

## Acceptance criteria

- [ ] The HostContext contract names the supported TLS model and lifetime rules.
- [ ] A future threaded child proves newly created threads observe TLS values.
- [x] The current single-thread release boundary is delegated to the system
      loader; live-thread unload remains explicitly deferred.
- [ ] Race, teardown, malformed, and unsupported cases have stable outcomes.
- [ ] The matrix has a positive TLS row only after retained threaded evidence.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```
