# Implement GNU Property, BTI, and PAC Semantics

## Goal

Define and validate a bounded AArch64 GNU property subset for outer-wrapper and
HostContext execution without treating loader acceptance as semantic support.

## Dependencies

- P0 current packaging/profile contract is required.
- P3 lifecycle and image ownership rules must be available for HostContext
  property negotiation and release behavior.
- GNU property observations may be developed alongside P4-A, but this child has
  an independent oracle and matrix row.

## Requirements

- Define the accepted property-note subset and host negotiation behavior.
- Define BTI/PAC instruction-state obligations and memory-protection ownership.
- Distinguish parser recognition, outer-wrapper execution, and HostContext
  acceptance in the compatibility matrix.
- Add property-bearing fixtures, host-state observations, and paired unsupported
  or conflicting-property cases.
- Keep unspecified or conflicting properties fail-closed.

## Acceptance criteria

- [ ] The contract explains which property notes are accepted and which host
      state is required.
- [ ] A positive fixture proves the declared outer or HostContext behavior at
      the corresponding layer.
- [ ] Unsupported, malformed, and host-conflict cases fail before an invalid
      dispatch and preserve a zero/clean image handle.
- [ ] BTI/PAC and memory-protection claims are backed by retained ARM64 runtime
      evidence rather than ELF metadata alone.
- [ ] Matrix rows keep lower-layer property observations separate from
      HostContext support.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
./scripts/run-fixture-matrix.sh --tier release
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier release
python3 scripts/check-evidence.py fixtures/manifest.json --tier release
```
