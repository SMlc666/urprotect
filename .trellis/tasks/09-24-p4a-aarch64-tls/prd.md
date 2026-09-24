# Implement AArch64 TLS Semantics

## Goal

Define and validate a bounded AArch64 TLS subset for HostContext image loading,
thread behavior, and image release.

## Dependencies

- P0 current HostContext profile is required.
- P2 relocation/symbol semantics and P3 lifecycle/ownership semantics are
  prerequisites for a meaningful TLS contract.

## Requirements

- Define TLS module allocation, current-thread initialization, new-thread
  initialization, TLS relocation models, thread exit, reentrancy, unload safety,
  and teardown relative to `release_image`.
- Select a bounded first TLS model from real AArch64 fixtures.
- Add a real threaded fixture and deterministic concurrent entry/lifecycle
  oracle; static PT_TLS mutation alone is insufficient.
- Record separate runtime evidence for each glibc, musl, and bionic fact.
- Keep unspecified TLS models and unsafe unload cases fail-closed.

## Acceptance criteria

- [ ] The HostContext contract names the supported TLS model and lifetime rules.
- [ ] Current and newly created threads observe the declared TLS behavior.
- [ ] Release waits for or rejects live TLS users according to the contract.
- [ ] Race, teardown, malformed, and unsupported cases have stable outcomes.
- [ ] The matrix has a positive TLS row only after retained threaded evidence.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-regression-stress.sh --tier nightly
python3 scripts/check-evidence.py fixtures/manifest.json --tier nightly
```
