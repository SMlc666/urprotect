# TLS runtime evidence projection

## Scope

The Phase 5/6 increment adds an optional `tlsEvidence` projection to the existing Protected Image producer `stage.json` record. It is additive evidence validation only. It does not change Protected Image v1, Payload Frame v3, the semantic snapshot operation, fixture manifest support status, or strict evaluator claim semantics.

## Bounded contract

`scripts/check-protected-image-evidence.py` validates one record with:

- one of the five typed TLS models: `local-exec`, `initial-exec`, `local-dynamic`, `general-dynamic`, or `tlsdesc`;
- the enclosing `outer-execveat` or `host-context-entry` profile;
- exactly one explicit `glibc`, `musl`, or `bionic` runtime lane;
- `current-thread`, `registered-worker`, or `not-run` lifecycle;
- source, transformed, and Protected Image paths/digests, toolchain and loader identity;
- bounded PT_TLS template, file/memory/zero-fill, alignment, and owning-load facts;
- per-thread, zero-fill, teardown, first-failure, publication, and rollback projections.

All paths must remain inside the evidence root and identify retained regular files. Source/template digests must match their files. Transformed/artifact paths and digests must bind the enclosing published Protected Image. PT_TLS template size must equal `fileSize`; `fileSize <= memorySize`; and `memorySize - fileSize == zeroFillSize`. Numeric values are bounded and alignment must be a positive power of two. Unknown fields, unsupported values, symlinks, traversal, malformed numbers, and digest mismatches fail closed.

## Result boundaries

The result vocabulary is shared with the runtime matrix:

- `accepted-and-runs`: complete publication plus observed per-thread, zero-fill, and teardown facts, with no first failure;
- `environment-unavailable`: complete publication, `firstFailureStage=environment`, `lifecycle=not-run`, and no lifecycle observations;
- `runtime-failure`: complete publication and retained artifact hashes, with a non-environment first-failure stage. This describes a post-publication runtime failure and does not replace a failed producer stage.

A missing runtime capability is therefore explicit evidence and does not promote another runtime. Producer/layout/publication failure remains governed by the existing failed-stage contract and retains no successful artifact or role.

## Evidence

`tests/test_protected_image_evidence.py` covers accepted-and-runs, environment-unavailable, runtime-failure, hash mismatch, lifecycle contamination, closed manifests, and existing producer success/failure behavior. The current checked-in glibc outer and HostContext evidence trees pass the extended checker. Native glibc adapter self-tests pass locally; musl and bionic runtime cells remain environment-specific CI evidence.
