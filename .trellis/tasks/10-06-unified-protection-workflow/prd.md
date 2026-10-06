# Unify protection workflow and evidence

## Goal

Make `protect` a one-command facade over the same producer/layout/materializer pipeline used by `protect-image` and `rehydrate-image`, then integrate the semantic/layout feature rows across glibc, musl, and bionic.

## Requirements

- Remove the direct writer as an independent production behavior; retain it only as migration evidence until the new path is proven.
- Add a shared Core workflow that owns selector/pass normalization, producer bindings, layout/materialization, validation, atomic publication, and report projection.
- Keep explicit staged commands for CI/evidence and allow `protect` to retain intermediate evidence through an explicit directory option.
- Extend Protected Image operations/ABI as needed for semantic fixups, relocation, veneers, jump tables, TLS, and CFI while retaining historical v1 migration evidence.
- Update CLI reports, compatibility matrix, fixtures, CI jobs, and evidence checkers for the three-runtime claim.

## Acceptance criteria

- [ ] `protect` output is produced by the same workflow as `protect-image` plus `rehydrate-image`.
- [ ] No partial artifact, role, stage, native image, or report is published on any failed stage.
- [ ] Existing narrow protection tests and all new semantic/layout tests pass through the unified command path.
- [ ] Glibc, musl, and bionic lanes retain their own baseline/protected/native-handoff/behavior evidence.
- [ ] Documentation accurately states the unified workflow, profile limits, feature rows, and migration status.
