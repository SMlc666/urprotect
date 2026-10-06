# Generic Rehydration and Native Image Handoff Implementation Plan

## 1. Managed Native Image and rehydration API

- Add `src/UrProtect.Core/Rehydrate/` records, stable diagnostics, bounded limits, and `GenericRehydrationEngine`.
- Decode Protected Image v1 with expected source/request/consumer bindings.
- Validate operation identity, source executable ranges, checked arithmetic, permissions, and complete output.
- Materialize exact Native Image bytes deterministically and reparse with `ElfParser` before returning success.

## 2. Native handoff boundary

- Add a small bounded AArch64 native handoff helper using `memfd_create`, `fchmod`, `fsync`, seals, and `execveat(AT_EMPTY_PATH)`.
- Keep the helper's input/output protocol machine-readable and host-owned; distinguish helper/setup status from target status.
- Add shell runner support for stdout/stderr/status and cleanup evidence.

## 3. Records and publication

- Add bounded `RehydrationRecord` and `NativeHandoffRecord` schemas with source/protected/native/consumer/build bindings, status, resource evidence, and first-failure stage.
- Extend the producer evidence checker or add a dedicated rehydration checker to close all retained files and reject stale/partial success trees.
- Publish Native Image only after decode, materialization, structural parse, and hash verification; retain failed stage evidence without successful output.

## 4. Tests and fixture

- Add unit tests for valid operation materialization, source/request/consumer mismatch, digest tamper, unsupported operation, overlap/overflow, invalid executable mapping, incomplete output, and deterministic hashes.
- Add native handoff tests for memfd/seal/execveat markers, target status/streams, helper timeout/failure, and no path fallback.
- Add an end-to-end frozen glibc fixture test comparing baseline and Native Image behavior and proving distinct Source/Protected/Native hashes.

## 5. CI/evaluator integration

- Add `scripts/run-rehydration-e2e.sh` and a checker under `.artifacts/protected-image/<tier>/<runtime>/<unit>/`.
- Run the new stage additively after producer evidence and upload the complete tree on success/failure with `if: always()`.
- Extend evaluator stage bindings only additively; do not change frozen corpus identity, Scheme-A baseline, or claim thresholds until the full gate is independently rerun.

## Validation command set

```sh
PATH=/root/.dotnet:$PATH dotnet restore UrProtect.sln --locked-mode
PATH=/root/.dotnet:$PATH dotnet build UrProtect.sln --configuration Release --no-restore
PATH=/root/.dotnet:$PATH dotnet test UrProtect.sln --configuration Release --no-build
python3 tests/test_protected_image_evidence.py
python3 tests/test_rehydration_evidence.py
python3 scripts/validate-evaluator-manifests.py
./scripts/run-protection-e2e.sh --tier pr --runtime glibc
./scripts/run-protected-image-e2e.sh --tier pr --runtime glibc
./scripts/run-rehydration-e2e.sh --tier pr --runtime glibc
python3 scripts/check-rehydration-evidence.py .artifacts/protected-image/pr/glibc/<unit> --tier pr --runtime glibc
```

## Rollback point

Disable only the rehydration/native-handoff producer profile and its CI step. Preserve failed evidence, negative tests, the Protected Image producer, and all existing direct/pack/HostContext/evaluator jobs.
