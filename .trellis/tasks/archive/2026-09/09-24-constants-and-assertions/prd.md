# Centralize protocol constants and assertions

## Goal

Remove duplicated contract-encoding values from the managed/native test
surfaces and make the managed xUnit suite consistently diagnostic without
introducing a second assertion framework.

## Requirements

- Inventory ELF, payload-frame, HostContext, launcher, ABI, and test-harness
  values across C#, C, Python, and shell code; classify intentional byte-level
  samples separately from contract values.
- Establish named owners in each language boundary and remove duplicated frame
  offsets, sizes, ABI versions, tags, and limits where an existing owner can
  be reused. Preserve wire values and legacy frame behavior.
- Add a cross-language contract probe/check for frame layout and HostContext
  structure/ABI values. Drift must produce an actionable failure.
- Keep xUnit direct `Assert` as the managed convention. Add focused helpers for
  repeated diagnostic, frame-result, and byte-identity assertions only.
- Give helpers context labels and input descriptions so failures remain useful
  in parallel and fuzz-derived runs.

## Ordering and integration notes

This child has no implementation dependency on the other children. Its named
helpers and contract identifiers are integration inputs for the fuzz,
concurrency, and E2E children; those children may prototype locally but should
adopt the published names before final integration.

## Acceptance Criteria

- [x] The inventory covers all four repository language/tooling surfaces and
      distinguishes contract values from intentional sample bytes.
- [x] Managed and native frame/ABI values have named owners, and a drift test
      catches cross-language layout mismatch without changing the format.
- [x] Repeated managed assertions use focused xUnit helpers with diagnostics;
      no parallel assertion package is added.
- [x] Existing managed tests, Python matrix tests, and applicable native
      self-tests pass unchanged in behavior.
<!-- End of task artifact. -->
