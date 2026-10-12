# TLS runtime evidence projection

## Scope

The Phase 5/6 increment adds an optional `tlsEvidence` projection to the existing Protected Image producer `stage.json` record. It is additive evidence validation only. It does not change Protected Image v1, Payload Frame v3, the semantic snapshot operation, fixture manifest support status, or strict evaluator claim semantics.

The complete transformed TLS evidence scope remains in this task and is keyed by
`model × profile × runtime × lifecycle` for all five typed models, the current
profiles, and glibc, musl, and bionic. Musl and bionic rows are required scope,
not optional follow-up work. The currently promoted transformed row is only
`initial-exec x host-context-entry x glibc x current-thread`; every other row
must remain independently classified until its own evidence passes.

The claim layers remain separate: StructuralElf observation, managed
semantic/layout acceptance, native HostContext adapter acceptance, and
transformed runtime promotion are not interchangeable. The six-cell runtime
covering set is environment/loader evidence and is not a TLS promotion matrix.

## Bounded contract

`scripts/check-protected-image-evidence.py` validates one record with:

- one of the five typed TLS models: `local-exec`, `initial-exec`, `local-dynamic`, `general-dynamic`, or `tlsdesc`;
- the enclosing `outer-execveat` or `host-context-entry` profile;
- exactly one explicit `glibc`, `musl`, or `bionic` runtime lane;
- `current-thread`, `registered-worker`, or `not-run` lifecycle;
- source, transformed, Protected Image, and native handoff/runtime artifact paths/digests, with each digest bound to the row's retained files;
- bounded PT_TLS template, file/memory/zero-fill, alignment, and owning-load facts;
- per-thread, zero-fill, teardown, first-failure, publication, and rollback projections.

All paths must remain inside the evidence root and identify retained regular files. Source/template digests must match their files. Transformed/artifact paths and digests must bind the enclosing published Protected Image. PT_TLS template size must equal `fileSize`; `fileSize <= memorySize`; and `memorySize - fileSize == zeroFillSize`. Numeric values are bounded and alignment must be a positive power of two. Unknown fields, unsupported values, symlinks, traversal, malformed numbers, and digest mismatches fail closed.

## Result boundaries

The result vocabulary is shared with the runtime matrix:

- `accepted-and-runs`: complete publication plus observed per-thread, zero-fill, and teardown facts, with no first failure;
- `environment-unavailable`: complete publication, `firstFailureStage=environment`, `lifecycle=not-run`, and no lifecycle observations;
- `runtime-failure`: complete publication and retained artifact hashes, with a non-environment first-failure stage. This describes a post-publication runtime failure and does not replace a failed producer stage.

A row is promoted only with its own managed rewrite/materialization, loader
handoff, baseline/transformed behavior comparison, PT_TLS template/zero-fill,
per-thread values, constructor/destructor/worker/release ordering,
source/protected/native artifact hashes, toolchain/runtime/loader identity,
first-failure stage, and rollback evidence. `environment-unavailable` is
feature-specific row evidence and never promotes another runtime. Worker
lifecycle evidence is separate from current-thread evidence and must show the
claimed join/teardown/release order.


## Evidence

`tests/test_protected_image_evidence.py` covers accepted-and-runs, environment-unavailable, runtime-failure, hash mismatch, lifecycle contamination, closed manifests, and existing producer success/failure behavior. The checked-in PR producer retains a 60-row model/profile/runtime/lifecycle matrix under `.artifacts/tls-runtime/pr`. The only accepted-and-runs transformed row is the independently rehydrated glibc initial-exec HostContext current-thread control; musl/bionic and other rows remain row-local not-applicable or environment-unavailable. Native glibc adapter self-tests, Android packed-tag probes, and PT_TLS parity probes pass locally; musl and bionic execution remain independent CI capability lanes.
