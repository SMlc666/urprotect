# Generic Rehydration and Native Image Handoff Design

## Boundary

```text
SourceImage + ProtectedImage v1
        -> bounded decoder/authentication
        -> GenericRehydrationEngine
        -> NativeImage bytes + rehydration record
        -> native memfd/execveat handoff
        -> target native loader + behavior oracle
```

`PayloadFrame` remains a transport envelope and the legacy direct protected ELF remains auxiliary evidence. The rehydrator owns only image materialization and structural validation. The native loader owns dynamic dependencies, relocations it understands, TLS, constructors, destructors, and process startup semantics.

## Managed contracts

Add a `Rehydrate` namespace with:

- `NativeImage` / `NativeImageDescriptor`: immutable source/protected/native hashes, byte length, architecture/profile, unit, producer and consumer identities, exact bytes, and structural-validation result.
- `RehydrationOptions`: expected source/request hash, expected consumer ID, materializer build hash, and bounded layout/permission limits.
- `RehydrationResult`: `NativeImage?`, `RehydrationRecord?`, stage diagnostics, and `IsSuccess`.
- `GenericRehydrationEngine.Rehydrate(source, protectedArtifact, options)`.

The engine calls `ProtectedImageCodec.Decode` with both expected bindings, validates the declared consumer and operation stream, parses the source ELF, maps each region's source virtual address to a file-backed executable range, and applies operations through a single layout strategy. It never accepts a complete ELF as the Protected Image input and never treats a producer role record as a Native Image.

The first layout strategy is deterministic and generic across operation records: patch an existing file-backed executable range when the emitted region fits; otherwise materialize an appended executable region through the existing validated ELF program-header representation and write the required entry/fixup branch. If the current source representation cannot express a required permission/entry transition, return a stable layout diagnostic and publish no bytes. No selector-specific or fixture-name branch is permitted.

## Native handoff

Add a small native handoff helper under `native/urprotect-runtime/` or the launcher boundary. It accepts a validated Native Image byte stream/path only as an input to a host-owned handoff command, creates `memfd_create`, writes and `fsync`s the bytes, sets executable mode, adds seals where supported, and calls `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. It emits a machine-readable handoff record with memfd/seal/execveat status and target status/streams. A path-based execution is not a strict success path.

The managed runner owns the producer and rehydrator records; the native helper owns only memfd/loader handoff facts. The runner closes the evidence tree after all processes stop writing and validates hashes and record ownership.

## Evidence

Under `.artifacts/protected-image/<tier>/<runtime>/<unit>/` retain:

- producer `protected-image.bin`, `protected-image.json`, `stage.json`;
- `native-image.bin` only after a passed rehydration stage;
- `rehydration.json` with protected/native/source/request/consumer/build hashes;
- `handoff.json`, `target.stdout`, `target.stderr`, and a bounded runner environment record;
- a closed LF `SHA256SUMS` manifest.

Failure records retain the failed stage and streams but not a successful Native Image or passed handoff record. The checker recomputes every digest and rejects traversal, symlinks, missing stage-specific bindings, stale files, and producer-only compatibility claims.

## Rollback

The new profile is explicit and additive. If materialization or handoff fails, disable only `rehydration-native-handoff-v1` in CI while preserving producer failures and all legacy jobs. Never execute the source or direct protected ELF as a fallback for a failed strict unit.
