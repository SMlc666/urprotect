# Implement bounded Generic Rehydration and Native Image handoff

## Goal

Turn the emitted Protected Image v1 into a distinct, validated Native Image through a generic operation-driven rehydration boundary, then hand that Native Image to the existing native loader boundary. Establish the first complete end-to-end compatibility unit without relabeling the producer-only artifact or changing the existing direct `protect`, `pack`, or HostContext behavior.

## Requirements

- Add a product-owned Native Image descriptor/materialization API that consumes Source Image bytes plus a hash-bound Protected Image v1 artifact and returns exact Native Image bytes, source/protected/native hashes, consumer/build identity, and bounded stage diagnostics.
- Rehydrate only operation semantics (`EMIT_REGION` and entry/fixup operations) and final image structure. Do not implement dependency resolution, symbol lookup, TLS, constructors, destructors, or a replacement ELF loader.
- Require source digest, request digest, ABI/profile, producer identity, and declared rehydrator consumer to match before materialization. Reject wrong consumer, tampered artifact, unknown operations, duplicate/overlap, source mismatch, invalid permissions, incomplete image, and address/length overflow.
- Materialize a valid AArch64 ELF Native Image through a generic layout strategy. The first supported strategy may use the existing ELF program-header representation for the frozen fixture, but must consume operation records and must report a stable layout diagnostic rather than silently falling back to the direct protected-ELF path.
- Add a native handoff boundary that writes a sealed executable memfd and invokes `execveat(AT_EMPTY_PATH)` for the materialized Native Image, retaining target status/stdout/stderr and handoff resource evidence. Keep the target native loader responsible for loader semantics.
- Add a rehydration record binding Protected Image hash, Native Image hash/size, source hash, consumer/build identity, materialization status, handoff invocation, and raw evidence manifest. Failed stages retain bounded diagnostics and publish no Native Image or success record.
- Preserve legacy direct protected-ELF, outer `PayloadFrame`, and HostContext paths as auxiliary behavior. Do not change the frozen evaluator protocol, compatibility corpus identity, Scheme-A manifest, or 100x thresholds in this child.

## Local Gate: rehydration-native-handoff-v1

For `compat.protection-symbolized-fixture.glibc.outer-execveat`:

1. A passed producer artifact decodes and rehydrates into a distinct Native Image with continuous source/protected/native hashes.
2. The Native Image reparses as an AArch64 ELF and is not byte-identical to either Source Image or Protected Image.
3. The generic rehydration stage binds ABI v1, unit/profile, source/request, producer, consumer, Native Image, and materialization records.
4. The native handoff runs the Native Image through a sealed memfd/`execveat` path; target status and stdout/stderr match the frozen behavior oracle.
5. Tampered artifact, wrong source/request/consumer, malformed operation, incomplete materialization, failed handoff, and output publication failure retain failed evidence and publish no successful Native Image.
6. The evaluator receives distinct producer, rehydration, Native Image, loader, and behavior stage records; producer-only evidence is never counted as a complete strict unit.

## Acceptance Criteria

- [x] Managed bounded rehydrator/materializer and Native Image records exist with deterministic round-trip and malformed tests.
- [x] One frozen AArch64 glibc fixture completes Protected Image -> rehydration -> Native Image -> native loader -> behavior oracle.
- [x] Rehydration and handoff records are hash-bound, stage-specific, bounded, and retained on both success and failure.
- [x] Native handoff uses sealed memfd/`execveat` or the declared HostContext equivalent; no path-based fallback is accepted for the strict unit.
- [x] Existing full solution, protection, pack, HostContext, evaluator, fuzz, and runtime checks remain passing.
- [x] CI retains `.artifacts/protected-image/<tier>/<runtime>/<unit>/` plus rehydration/native-handoff evidence on success and failure and keeps evaluator claimability semantics unchanged.
- [x] Benchmark fields for rehydration CPU/RSS, Native Image size, handoff cost, and first-failure stage are additive diagnostics only.

## Out of Scope

- General ELF dynamic-loader implementation or dependency/symbol/TLS/lifecycle emulation.
- Scheme-A attack tools, baseline calibration, corpus expansion, or 100x threshold changes.
- Promotion of the first vertical slice to the final 100x claim without the independent evaluator and all required attack-family gates.
- Removing every legacy direct-layout limitation; later materializer/lowering children own measured compatibility expansion.
