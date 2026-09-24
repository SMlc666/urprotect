# Converge the Current AArch64 Packaging Contract

## Goal

Replace the implicit legacy packaging path with one current versioned packaging
contract carrying explicit `outer-execveat` and `host-context-entry` profiles.
Connect managed pack, the matching launcher/adapter, and a real ARM64 execution
oracle for each profile.

## Dependencies

- This child is the first implementation phase of the parent task.
- P1-P4 child implementation waits for the current frame/profile contract and
  evidence schema established here.
- The parent task remains the integration owner; this child owns the P0
  contract and migration cut.

## Requirements

- Define the current frame version, profile enum, profile-specific metadata,
  bounds, reserved fields, and profile/launcher ABI matching rules.
- Prefer a new frame version over changing the meaning of existing v1/v2
  offsets; stale versions and profile mismatches return stable diagnostics.
- Make managed packing select a profile explicitly or derive it from a strict,
  declared input contract; no silent fallback between profiles.
- Keep `outer-execveat` responsible for standalone PIE recovery through
  anonymous memfd and `execveat(AT_EMPTY_PATH)`.
- Keep `host-context-entry` responsible for sealed-memfd loading, exact symbol
  lookup, one `urp_entry` call, release ordering, and returned status.
- Update managed/native contract owners, launcher/runtime consumers, tests,
  CLI/report output, compatibility docs, and matrix declarations together.

## Acceptance criteria

- [ ] A single current frame contract is represented in managed and native
      layout owners and checked by contract/layout tests.
- [ ] Both profiles reject stale versions, unknown profile values, and
      profile/launcher mismatches before dispatch.
- [ ] Managed pack produces a real outer-profile wrapper and a real
      HostContext-profile package through their matching artifacts.
- [ ] The outer oracle proves baseline/wrapped status, streams, argv, envp, and
      no executable temporary pathname.
- [ ] The HostContext oracle proves digest verification, required memfd seals,
      entry lookup, exactly-once dispatch, release, and status preservation.
- [ ] The production-pack matrix row has retained managed end-to-end evidence,
      or its scope is explicitly redefined with a documented reason.
- [ ] Existing v1/v2 behavior is either historical evidence or explicitly
      rejected; it is never selected implicitly by the current pack command.

## Validation

```sh
dotnet test UrProtect.sln --configuration Release
make -C native/urprotect-runtime test
make -C native/urprotect-runtime contract-check
native/urprotect-launcher/test_launcher.sh
native/urprotect-launcher/test_managed_handoff.sh
python3 tests/test_regression_matrix.py
```
