# Technical design: current-contract purge

## Canonical current boundaries

- Validation: `NoOpPipeline.ValidateStructurally`, `ValidateObservationOnly`, `ValidateAndCopyStructurally`, and `ValidateAndCopyObservationOnly`; no Boolean mode overload.
- Observation: `Aarch64ObservationAnalyzer`; no compatibility wrapper.
- CLI: structural validation by default and `--observe-analysis` as the only observation flag; one canonical option spelling for every command.
- Semantic snapshot: one canonical create/encode operation and one canonical decode/validate operation; aliases are deleted after all callers are updated.
- Payload Frame: current v3 only, with explicit `outer-execveat` and `host-context-entry` profiles. Managed and native implementations use the same current layout owner.
- Protected Image: current sole ABI contract, including its current ABI identifier/version; this is not a retired frame migration path.

## Purge method

1. Inventory all current callers with repository search before editing.
2. Change production APIs and all current callers in one coherent slice; do not add forwarding wrappers.
3. Remove retired constants and code branches rather than leaving unreachable conditional code.
4. Delete historical positive and negative frame/migration data. Current malformed-input tests use generic truncation, overflow, digest, reserved-field, and unsupported-enum cases without encoding retired format values.
5. Remove migration rows from current manifests and evidence checkers. Archived task prose may remain as immutable planning history, but it is not loaded by current product/evidence paths.
6. Update docs/specs and the contract inventory to describe current behavior only.

## Managed/native frame contract

The managed codec and native peers accept exactly the selected v3 header, profile-specific metadata, bounded compressed payload, encoded digest, and source digest. Unknown/future values fail through the generic current-contract malformed/unsupported path. No code recognizes or reconstructs retired layout offsets. The outer launcher owns outer execution policy; the HostContext runtime owns HostContext dispatch policy; both consume the same v3 contract.

## Evidence and tests

Current tests cover:

- canonical v3 round trips for both current profiles;
- generic truncation, bounds, reserved-field, digest, compression, profile-mismatch, and malformed metadata cases;
- canonical CLI grammar and rejection of unknown/duplicate options;
- current native contract layout and profile marker checks;
- absence checks for retired names/branches/data;
- no partial output/evidence on current-contract failure.

No test contains a v1/v2 frame constructor, byte fixture, positive/negative migration row, or historical decoder.

## Rollback

This is a breaking contract slice. If it fails, revert the entire slice; do not restore an old alias or decoder. Downstream G1/G2 remains blocked until the tree contains one current contract.
