# Protected Image ABI v1 Design

## Boundary

The child adds a managed Protected Image artifact and producer only. It does not create a loader. The artifact is a layout-neutral description of protected regions/operations that a later rehydrator can materialize into an ordinary Native Image.

## Artifact roles

```text
SourceImage -> ProtectionPlan -> ProtectedImage v1
                                      |
                                      +-> later rehydrator -> NativeImage -> native loader
```

`PayloadFrame` remains a transport envelope. The Protected Image must not be a complete source/final ELF compressed in the current frame, and must not be byte-identical to a final ELF.

## ABI v1

Use a bounded binary codec owned by `UrProtect.Core.Protect` or a dedicated `ProtectedImage` namespace. The typed model must include:

- magic and ABI/schema version;
- AArch64 architecture and selected profile;
- fixed unit/source/request/producer/rehydrator IDs;
- source digest and producer build digest;
- deterministic operation list with bounded region/fixup metadata;
- artifact digest/size computed over the canonical artifact bytes;
- no unbounded strings or unchecked offsets/counts.

Operations describe protected code/data materialization, not dynamic loader behavior. The first implementation may encode the existing generated protected-code bytes and entry/fixup intent as a structured operation stream while leaving final address/layout selection unresolved.

## Producer boundary

Refactor only enough of `FunctionProtectionService` to expose a `ProtectionPlan` or equivalent data result before `TryAppendExecutableSegment`/`TryFindRewriteSlot` final ELF writing. Preserve the legacy `Protect` output for existing CLI/E2E tests. The new Protected Image producer consumes the plan and does not call final program-header placement. The no-spare-`PT_NULL` test targets this producer boundary, not final execution.

## Validation

The codec owns checked lengths, arithmetic, ID/string bounds, operation count, region range, duplicate/overlap detection and digest validation. The producer owns source/request/profile binding and deterministic ordering. Tests cover valid round trip, truncation, overflow, unknown versions/operations, source/request mismatch, alias-to-final-ELF, overlap, and failed atomic publication.

## Evidence and CI

Emit a product-owned role record plus raw artifact and `SHA256SUMS` under `.artifacts/protected-image/<tier>/<runtime>/<unit>/`. Existing protection E2E remains auxiliary and is retained unchanged. CI uploads the new subtree on failure and success; it does not add the row to strict evaluator completion until the follow-on rehydration/native-handoff child binds every stage.

## Migration / rollback

The new producer is explicit/opt-in and has no effect on existing `protect`/`pack` behavior. If ABI validation or existing tests fail, disable the new producer path and retain its failed evidence. Never silently treat the legacy direct ELF as a Protected Image or strict unit.
