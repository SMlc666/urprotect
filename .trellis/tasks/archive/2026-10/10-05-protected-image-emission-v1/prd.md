# Emit versioned layout-neutral Protected Image ABI

## Goal

Establish the first real Protected Image producer boundary for the frozen explicit protection fixture. The producer must emit a typed, versioned, hash-bound artifact that is distinct from both the source/final ELF and the current complete-source PayloadFrame, while leaving final Native Image materialization and native loader handoff to a follow-on child.

## Requirements

- Add a product-owned Protected Image ABI v1 with explicit role/version, architecture/profile, source digest, producer build identity, transformation request, bounded region/fixup metadata, and artifact digest/size.
- Separate protection planning/emission from final ELF placement enough that Protected Image emission does not require an input spare `PT_NULL` slot or final executable `PT_LOAD` placement.
- Preserve explicit function selectors, deterministic pass order, AArch64 decoder ownership, stable diagnostics, checked arithmetic, atomic publication, and existing direct protected-ELF behavior as auxiliary evidence.
- Emit deterministic artifacts for the frozen protection fixture and include a declared rehydrator consumer ID, but do not implement rehydration or Native Image handoff in this child.
- Reject malformed/unknown/oversized/duplicate/overlapping records, digest/source mismatch, unsupported ABI/version, invalid selector/transform requests, and partial publication.
- Do not change evaluator protocol, corpus identity, baseline, Scheme-A manifest, 100x thresholds, or existing required tests/fixtures/fuzz targets.

## Local Gate: protected-image-emission-v1

For `compat.protection-symbolized-fixture.glibc.outer-execveat` and the existing explicit transform recipes:

1. A valid ABI v1 role record and raw artifact are emitted with matching hashes and sizes.
2. The artifact is structured Protected Image data, not a renamed final ELF, complete source ELF, or current generic compressed PayloadFrame.
3. The record binds source/unit/profile/request/producer/rehydrator identities.
4. The same input/request produces byte-identical output; failed requests publish nothing.
5. A fixture with no spare `PT_NULL` slot still emits Protected Image data; final ELF placement remains a later gate.
6. Nearest malformed cases fail before publication with stable diagnostics and retained test evidence.

## Acceptance Criteria

- [x] Managed typed ABI/codec and role records exist with bounded round-trip and malformed tests.
- [x] Function protection can produce a layout-neutral Protected Image artifact for the frozen fixture without requiring final ELF program-header placement.
- [x] Evidence includes source/request/producer/artifact/rehydrator hashes and a closed raw manifest; no raw artifact is silently omitted.
- [x] Existing `FunctionProtectionTests`, protection E2E, parser/frame/pack tests, and evaluator manifest checks remain passing.
- [x] New negative tests cover truncation, overflow, unknown ABI/op, duplicate/overlap, source/request mismatch, alias-to-final-ELF, and atomic publication failure.
- [x] CI retains new Protected Image evidence on success/failure and does not relabel legacy direct protected ELF as strict compatibility.
- [x] Benchmark fields for analysis/emission cost and artifact size are additive diagnostics only; existing benchmark and fuzz targets remain intact.

## Out of Scope

- Generic rehydration, Native Image materialization, memfd/execveat or HostContext handoff changes.
- Dynamic dependency/symbol/TLS/constructor/destructor loader semantics.
- Scheme-A attack tools or baseline calibration.
- Expanding instruction support beyond what the existing frozen protection fixture exercises.
