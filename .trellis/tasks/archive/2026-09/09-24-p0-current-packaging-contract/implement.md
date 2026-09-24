# P0 Implementation Plan

## Ordered checklist

- [x] Add typed `PayloadDispatchProfile` and P0 pack options.
- [x] Define frame v3 owner constants in managed and native headers.
- [x] Extend managed encode/decode and native parse/dispatch with v3 profile
      validation, reserved-field checks, and profile-specific metadata.
- [x] Add launcher profile/ABI markers and reject mismatches.
- [x] Update `ElfPackService` and CLI parsing/reporting for explicit profiles.
- [x] Add a profile-matched HostContext production launcher/runtime entrypoint
      using the existing adapter and `urp_runtime_execute_frame`.
- [x] Add managed/native contract tests, malformed-frame tests, profile tests,
      and real end-to-end pack/dispatch tests.
- [x] Update README, runtime README, `COMPATIBILITY.md`, manifest, and contract
      inventory.
- [x] Retain old behavior only as clearly named migration evidence or remove it.

## Validation gates

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
make -C native/urprotect-runtime contract-check
native/urprotect-launcher/test_launcher.sh
native/urprotect-launcher/test_managed_handoff.sh
python3 tests/test_regression_matrix.py
python3 scripts/validate-fixtures.py fixtures/manifest.json --tier pr
```

Required ARM64 evidence additionally runs the managed pack/dispatch oracle and
`scripts/check-evidence.py` for each P0 production row.

## Rollback

Revert managed/native frame changes, launcher markers, and profile CLI changes
together. Keep the matrix production-pack row `unknown` until a complete
profile-matched oracle is retained.
