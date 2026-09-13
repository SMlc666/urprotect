# Implementation Plan

## Ordered Checklist

1. [ ] Export the current parser/validator model as an initial feature
       inventory and map each current fixture to feature IDs.
2. [ ] Add explicit diagnostics for malformed, unknown, parser-compatible, and
       HostContext-runtime-incompatible inputs.
3. [ ] Add sectionless/stripped and varied PT_LOAD/alignment cases.
4. [ ] Add PT_TLS, GNU stack/RELRO/property, note, and dynamic metadata cases
       with paired malformed/rejected inputs.
5. [ ] Expand RELA/RELR/Android packed relocation classification only where the
       HostContext design supplies a runtime semantic.
6. [ ] Add dynamic symbol/version/dependency cases and lifecycle fixtures.
7. [ ] Add compiler cases that exercise new feature combinations, including
       HostContext entry adapters.
8. [ ] Connect every accepted feature to a deterministic parser or runtime
       oracle and update the matrix child inputs.
9. [ ] Run malformed corpus, property, fuzz, golden report, and fixture tests
       after each feature slice.

## Risk and Rollback Points

- Preserve unknown ELF bytes and existing address-domain conversions.
- If a feature requires process startup emulation, keep it out of the
  HostContext runtime set rather than widening the contract implicitly.
- If a relocation or lifecycle semantic is incomplete, retain parser support
  but classify runtime behavior as unknown/rejected.
- Revert a fixture claim by changing its matrix status and retaining the
  regression input; do not delete the negative case.

## Validation

    PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release
    python3 scripts/run-parser-fuzz.py
    python3 scripts/validate-fixtures.py --tier pr
    readelf -hW -lW -dW <fixture>

The final commands use the migrated matrix terminology and the existing
repository scripts where their names remain unchanged.
