# Purge historical paths and freeze current contract

## Goal

Delete every retired production path and migration-format data, then freeze one current API, CLI, frame, profile, artifact, and evidence contract for the remaining architecture work.

## Requirements

- Remove the public `Aarch64Analyzer` compatibility wrapper and all Boolean analysis compatibility overloads.
- Keep only explicit current observation APIs and the canonical structural validation APIs.
- Remove `--no-analysis` and every protected-image option alias; retain one documented spelling per option.
- Select one canonical operation name for every public semantic snapshot/codec operation and delete forwarding aliases.
- Make the managed Payload Frame codec v3-only: one current encoder, decoder, wrapper reader, profile validator, and current v3 constants. Delete v1/v2 constants and branches.
- Make the native launcher/runtime v3-only and delete old parser branches, legacy host projection, v1/v2 self-test construction, and adapter-v2 targets.
- Delete all v1/v2 and other historical migration-format positive and negative test data from managed tests, native self-tests, fixtures, manifests, evidence checkers, and current docs. Do not add a historical decoder or format-specific rejection fixture.
- Remove current migration feature rows and report claims. Keep only current Protected Image ABI v1 and HostContext ABI v1 contracts where they are the sole current ABI.
- Update all current callers and tests atomically so production does not need compatibility shims.

## Acceptance Criteria

- [x] A checked-in current-contract inventory names one canonical API/CLI/frame/profile/artifact operation at each boundary.
- [x] Repository searches show no reachable `Aarch64Analyzer`, Boolean `analyzeInstructions`, `--no-analysis`, protected-image option alias, v1/v2 Payload Frame encoder/decoder/dispatch, legacy host projection, or migration-format test data in current source/tests/manifests/evidence.
- [x] Managed and native current frame tests cover current v3 encoding/decoding, profile validation, digest/bounds behavior, and generic malformed-input failure only.
- [x] Current CLI help, README, compatibility spec, native README, fixture manifest, and evidence validators contain no retired migration support claim.
- [x] All existing current callers compile against the canonical APIs without a compatibility forwarding layer.
- [x] Release build, managed tests, native runtime/contract tests, Python tests, fixture validation, regression validation, and `git diff --check` pass. The native launcher test remains an environment-unavailable gate because `musl-gcc` is absent; the available launcher translation-unit compile passed.

## Out of Scope

- Splitting the Core/CLI god objects or introducing namespace dependency checks; that is G1.
- Implementing the shared protect/protect-image/rehydrate workflow or HostContext materialization; that is G2.
- Implementing new TLS, CFI, or indirect-control semantics.

## Ordering

This is Gate G0 of `10-06-architecture-boundary-refactor`. G1 and G2, and all downstream semantic features, remain blocked until this task is complete. The task is a breaking current-contract change; no migration branch is used to land it.
