# Unify protection workflow and evidence

## Goal

Make `protect`, `protect-image`, and `rehydrate-image` one current production workflow with profile-specific materialization for both `outer-execveat` and `host-context-entry`, atomic publication, and evidence that names the exact current contract.

## Requirements

- Depend on completed architecture G0 current-contract purge and G1 namespace/responsibility refactor.
- Define one Core application workflow for selector/pass normalization, semantic planning, physical layout/materialization, validation, publication, reports, and evidence.
- Make `protect` a final-output facade over the same producer/materializer contracts exposed by `protect-image` and consumed by `rehydrate-image`.
- Remove `FunctionProtectionService.Protect` as a distinct production writer; no fallback or migration oracle remains.
- Complete the `HostContextEntry` materializer: validate current AArch64 ET_DYN entry-image invariants, consume the same current Protected Image operations and layout plan, bind current v3 HostContext metadata, publish atomically, and run the native HostContext handoff oracle against the rehydrated image.
- Keep profile-specific launch/materialization policies explicit. The HostContext path must not call or reinterpret the outer `execveat` path.
- Publish no partial artifact, role, stage, native image, report, or evidence on failure.
- Keep runtime claims independent for glibc, musl, and bionic; unavailable lanes are not promoted.
- Do not introduce retired frame/API/CLI paths, historical test data, duplicate semantic models, or duplicate protocol grammars.

## Acceptance Criteria

- [ ] `protect`, `protect-image`, and `rehydrate-image` invoke one current Core planning/layout/materialization/publication workflow.
- [ ] No direct writer or alternate production implementation remains reachable.
- [ ] Both current profiles produce valid profile-specific native images; HostContext rehydration passes native AArch64 HostContext handoff, entry-status, release-order, and hash evidence.
- [ ] Profile mismatch, malformed operation stream, layout failure, native-image failure, and publication failure fail before partial output/evidence is visible.
- [ ] Current reports, role/stage records, manifests, and evidence checkers agree on current profile, ABI, hashes, workflow owner, and first-failure stage.
- [ ] Existing structural, selected-function, layout, artifact, CLI, native, and runtime tests pass through the shared owners.
- [ ] Glibc, musl, and bionic evidence is independent for every promoted row; missing capability remains environment-unavailable and unpromoted.
- [ ] No historical migration path, alias, retired frame data, or compatibility fallback is added.

## Out of Scope

- New TLS, CFI/unwind, or indirect-control semantic families; those consume this workflow after it passes.
- Cross-runtime promotion without independent native evidence.

## Ordering

This is Gate G2 of `10-06-architecture-boundary-refactor`. It starts only after G0 `purge-historical-contract` and G1 `responsibility-boundaries` pass. TLS, CFI/unwind, indirect-control/jump-table, and final runtime-promotion implementation remain blocked until this task passes.
